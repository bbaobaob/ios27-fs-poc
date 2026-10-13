//
//  MatrixViewModel.swift
//  FSProbe (App) — observable probe state, run orchestration, report persistence.
//
//  The view model owns everything that produces data: it runs the matrix off the
//  main actor, writes matrix.json / matrix.txt into Documents on every run, and
//  surfaces any failure verbatim. It never fabricates a value: every field here
//  either comes from FSProbeCore or from a real syscall (sysctl).
//

#if canImport(FSProbeCore)
// FSProbeCore is a separate module when this app is built as a SwiftPM package
// (the xtool path). The generated Xcode project compiles the probe engine into
// the same target, where it is not a module and the import is skipped.
import FSProbeCore
#endif

import Darwin
import Foundation
import Observation
import UIKit

// MARK: - Outcome semantics

/// Colour family an outcome belongs to. Four families, four hues:
/// success / denial / absent / other. `notFound` is deliberately *not* denial.
enum OutcomeFamily: String, Sendable {
    case success
    case denial
    case absent
    case other

    var title: String {
        switch self {
        case .success: return "granted"
        case .denial:  return "denied"
        case .absent:  return "absent"
        case .other:   return "other"
        }
    }
}

/// Non-colour encoding of an outcome, so the matrix never depends on hue alone.
enum MarkShape: Sendable {
    /// Solid disc.
    case disc
    /// Solid square with a diagonal slash — sandbox denial (EPERM).
    case blocked
    /// Solid square with a horizontal bar — POSIX permission denial (EACCES).
    case barred
    /// Hollow dashed ring — the path is not there at all.
    case dashedRing
    /// Triangle — a path component is not a directory.
    case triangle
    /// Diamond — failed with some other errno.
    case diamond
    /// Stop-sign octagon with a slash — a granted scope reached something it
    /// should not have. The silhouette is unique to this mark, so the finding is
    /// legible in greyscale and never depends on its hue.
    case breach
    /// Faint dashed box — no result was recorded for this cell.
    case unrecorded
}

// MARK: - Security-scoped grant verdicts

/// What one grant experiment means, read against what the grant policy predicts.
///
/// The matrix maps an outcome to a hue. This section has to do more: here a
/// *denial is the passing outcome*, so hue can no longer mean "good or bad" on
/// its own. Instead the shape always carries the verdict and the hue only says
/// whether the verdict was the expected one — and the verdict is always spelled
/// out in text next to the mark, so neither channel is ever load-bearing.
enum ScopeVerdict: String, Sendable, CaseIterable {
    /// Refused, and refusal is what the grant policy requires. The boundary held.
    case held
    /// Permitted, and permission is what the grant policy requires.
    case granted
    /// Permitted where the grant policy requires a refusal. The finding.
    case overGrant
    /// The control was refused: the grant never took effect, so the rest of the
    /// battery is not interpretable.
    case grantFailed
    /// The experiment's precondition failed. Nothing was observed.
    case notApplicable
    /// The experiment itself failed.
    case failed

    var title: String {
        switch self {
        case .held: return "HELD"
        case .granted: return "GRANTED"
        case .overGrant: return "VIOLATION"
        case .grantFailed: return "NO GRANT"
        case .notApplicable: return "N/A"
        case .failed: return "FAILED"
        }
    }

    var meaning: String {
        switch self {
        case .held:
            return "Refused where the grant policy requires a refusal. The scope is confined."
        case .granted:
            return "Permitted where permission was the prediction."
        case .overGrant:
            return "Permitted where the grant policy requires a refusal. The scope reached further than the item the user chose."
        case .grantFailed:
            return "The control was refused, so the grant never took effect and nothing else in this battery can be read."
        case .notApplicable:
            return "The experiment's precondition failed, so no observation was made."
        case .failed:
            return "The experiment itself failed."
        }
    }

    /// Whether this verdict is the outcome the grant policy predicts.
    var isExpected: Bool {
        switch self {
        case .held, .granted, .notApplicable: return true
        case .overGrant, .grantFailed, .failed: return false
        }
    }

    var family: OutcomeFamily {
        isExpected ? .success : .denial
    }

    var shape: MarkShape {
        switch self {
        case .held: return .blocked
        case .granted: return .disc
        case .overGrant: return .breach
        // The control came back refused and the denial is not the passing
        // outcome, so it stays amber rather than red: it is a broken
        // experiment, not a broken boundary.
        case .grantFailed: return .barred
        case .notApplicable: return .dashedRing
        case .failed: return .diamond
        }
    }
}

// MARK: - Row / cell models

/// One matrix cell: the outcome plus the exact errno that produced it.
struct MatrixCell: Identifiable, Sendable {
    let operation: FSOperation
    let outcome: ProbeOutcome?
    /// Compact, honest on-cell code: "ok", or the real errno name ("EPERM").
    let code: String
    let family: OutcomeFamily
    let shape: MarkShape
    /// `ProbeOutcome.rawValue`, or "not recorded" when the core has no result.
    let outcomeName: String
    let errnoName: String?
    let errnoNumber: Int
    let errnoDescription: String?

    var id: String { operation.rawValue }
    var isRecorded: Bool { outcome != nil }
    var isDenied: Bool { outcome == .deniedEPERM || outcome == .deniedEACCES }
}

/// One matrix row: a target path and a cell for every operation.
struct MatrixRowModel: Identifiable, Sendable {
    let target: FSTarget
    let cells: [FSOperation: MatrixCell]
    var id: String { target.path }

    var granted: Int { cells.values.filter { $0.outcome == .succeeded }.count }
    var denied: Int { cells.values.filter { $0.isDenied }.count }
    var absent: Int { cells.values.filter { $0.outcome == .notFound }.count }
    var other: Int { cells.filter { $0.value.outcome == .notDirectory || $0.value.outcome == .failedOther }.count }
    var unrecorded: Int { FSOperation.allCases.filter { cells[$0]?.isRecorded != true }.count }
}

// MARK: - View model

@Observable
final class MatrixViewModel {

    /// Honest lifecycle: the UI never renders a result set it does not have.
    enum Phase: Sendable {
        case idle      // has not been asked to run yet
        case running   // probe set in flight
        case complete  // a matrix exists (the write may still have failed)
    }

    struct ExportedFile: Identifiable, Sendable {
        let name: String
        let url: URL
        let byteCount: Int
        var id: String { name }
    }

    /// Everything one run produced, assembled off the main actor.
    struct RunReport: Sendable {
        let matrix: CapabilityMatrix
        let files: [ExportedFile]
        let issues: [String]
        let duration: Double
    }

    private(set) var phase: Phase = .idle
    private(set) var matrix: CapabilityMatrix?
    private(set) var rows: [MatrixRowModel] = []
    private(set) var discrepancies: [CapabilityMatrix.Discrepancy] = []
    private(set) var files: [ExportedFile] = []
    private(set) var issues: [String] = []
    private(set) var duration: Double = 0
    private(set) var runCount: Int = 0

    private var hasRequestedRun = false

    /// Probe order is fixed by the core: baselines first, then investigations.
    let targets: [FSTarget] = FSTargets.all

    var baselineRows: [MatrixRowModel] { rows.filter { $0.target.isBaseline } }
    var investigationRows: [MatrixRowModel] { rows.filter { !$0.target.isBaseline } }
    var canExport: Bool { !files.isEmpty }

    // MARK: Run control

    /// Called from `.task` on appear. Runs exactly once per launch.
    @MainActor
    func runIfNeeded() async {
        guard !hasRequestedRun, phase != .running else { return }
        await run()
    }

    /// "Run again": recompute the matrix and rewrite both report files.
    @MainActor
    func run() async {
        guard phase != .running else { return }
        hasRequestedRun = true
        runCount += 1
        phase = .running

        let environment = MatrixViewModel.makeEnvironmentRecord()
        let targets = self.targets
        let report = await Task.detached(priority: .userInitiated) {
            MatrixViewModel.execute(targets: targets, environment: environment)
        }.value

        matrix = report.matrix
        rows = MatrixViewModel.makeRows(matrix: report.matrix, targets: targets)
        discrepancies = report.matrix.discrepancies()
        files = report.files
        issues = report.issues
        duration = report.duration
        phase = .complete
    }

    // MARK: Execution + persistence (static: runs off the main actor)

    static func execute(
        targets: [FSTarget],
        environment: CapabilityMatrix.EnvironmentRecord
    ) -> RunReport {
        let started = Date()
        let container = documentsDirectory()?.deletingLastPathComponent().path
        let matrix = MatrixRunner().run(
            targets: targets,
            recordEntryNames: true,
            environment: environment,
            // Ascend from the app's own container. On a device the ancestors are
            // the /var/mobile/Containers chain, which is the actual research
            // surface; the fixed target list cannot reach them because they are
            // only known at runtime. The ascent is read-only.
            ascendFrom: container,
            // Boundary-mechanism experiments plus the app's own sandbox profile,
            // read out of its container metadata. These test how the boundary is
            // enforced rather than which paths are permitted.
            runBoundaryExperiments: true
        )

        var files: [ExportedFile] = []
        var issues: [String] = []

        guard let directory = documentsDirectory() else {
            issues.append(
                "Documents directory is unavailable on this system, so matrix.json and matrix.txt were not written."
            )
            return RunReport(matrix: matrix, files: files, issues: issues,
                             duration: Date().timeIntervalSince(started))
        }

        do {
            let data = try ReportExporter.json(matrix)
            let url = directory.appendingPathComponent("matrix.json")
            try data.write(to: url, options: .atomic)
            files.append(ExportedFile(name: "matrix.json", url: url, byteCount: byteCount(of: url)))
        } catch {
            issues.append("matrix.json was not written: \(describe(error))")
        }

        do {
            let text = ReportExporter.text(matrix, targets: targets)
            let url = directory.appendingPathComponent("matrix.txt")
            try text.write(to: url, atomically: true, encoding: .utf8)
            files.append(ExportedFile(name: "matrix.txt", url: url, byteCount: byteCount(of: url)))
        } catch {
            issues.append("matrix.txt was not written: \(describe(error))")
        }

        return RunReport(matrix: matrix, files: files, issues: issues,
                         duration: Date().timeIntervalSince(started))
    }

    static func documentsDirectory() -> URL? {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
    }

    // MARK: Row assembly

    static func makeRows(
        matrix: CapabilityMatrix,
        targets: [FSTarget]
    ) -> [MatrixRowModel] {
        targets.map { target in
            let results = matrix.results(for: target.path)
            var cells: [FSOperation: MatrixCell] = [:]
            for operation in FSOperation.allCases {
                cells[operation] = makeCell(operation: operation, result: results[operation])
            }
            return MatrixRowModel(target: target, cells: cells)
        }
    }

    static func makeCell(operation: FSOperation, result: ProbeResult?) -> MatrixCell {
        guard let result else {
            // Honest about the hole: a cell with no result says so.
            return MatrixCell(
                operation: operation,
                outcome: nil,
                code: "–",
                family: .absent,
                shape: .unrecorded,
                outcomeName: "not recorded",
                errnoName: nil,
                errnoNumber: 0,
                errnoDescription: nil
            )
        }

        let family: OutcomeFamily
        let shape: MarkShape
        switch result.outcome {
        case .succeeded:   family = .success; shape = .disc
        case .deniedEPERM: family = .denial;  shape = .blocked
        case .deniedEACCES: family = .denial;  shape = .barred
        case .notFound:    family = .absent;  shape = .dashedRing
        case .notDirectory: family = .other;  shape = .triangle
        case .isDirectory: family = .other;   shape = .triangle
        case .failedOther: family = .other;   shape = .diamond
        case .notAttempted: family = .other;  shape = .unrecorded
        }

        return MatrixCell(
            operation: operation,
            outcome: result.outcome,
            code: shortCode(for: result),
            family: family,
            shape: shape,
            outcomeName: result.outcome.rawValue,
            errnoName: result.errnoName,
            errnoNumber: result.errnoNumber,
            errnoDescription: result.errnoDescription
        )
    }

    /// The on-cell code is the real errno name where one exists — never a
    /// stand-in like "error".
    static func shortCode(for result: ProbeResult) -> String {
        if result.outcome == .succeeded { return "ok" }
        if let name = result.errnoName, !name.isEmpty {
            return name.count <= 7 ? name : String(name.prefix(6)) + "…"
        }
        return "E\(result.errnoNumber)"
    }

    // MARK: Environment record

    /// Builds the platform record from real sources only:
    /// UIDevice for the marketing version, sysctl for build and hardware id.
    @MainActor
    static func makeEnvironmentRecord() -> CapabilityMatrix.EnvironmentRecord {
        let version = UIDevice.current.systemVersion
        let resolvedVersion = version.isEmpty
            ? ProcessInfo.processInfo.operatingSystemVersionString
            : version

        return CapabilityMatrix.EnvironmentRecord(
            osName: UIDevice.current.systemName,
            osVersion: resolvedVersion,
            osBuild: osBuild(),
            deviceModel: deviceModel()
        )
    }

    /// `kern.osversion`, e.g. "23A344".
    static func osBuild() -> String {
        sysctlString("kern.osversion") ?? "unavailable (sysctl kern.osversion denied)"
    }

    /// `hw.machine` is the hardware identifier on iOS ("iPhone17,1").
    /// Falls back to `hw.model`, then to UIDevice.model — all real values.
    /// Main-actor isolated because UIDevice is; `sysctlString` is not.
    @MainActor
    static func deviceModel() -> String {
        if let machine = sysctlString("hw.machine") { return machine }
        if let model = sysctlString("hw.model") { return model }
        return UIDevice.current.model
    }

    static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return nil }
        let value = String(cString: buffer)
        return value.isEmpty ? nil : value
    }

    // MARK: Security-scoped grant

    /// The document-picker grant lifecycle.
    ///
    /// `.complete` is the only case that carries results, so the view can only
    /// ever render a result it actually holds. A cancelled picker is not a
    /// failure — it returns to `.idle`.
    enum GrantState: Sendable {
        case idle        // nothing granted yet
        case picking     // the document picker is on screen
        case probing     // the scope is being probed while held
        case complete(granted: SecurityScopeProbe.Result, afterRelease: SecurityScopeProbe.Result)
        /// A real failure, with the message exactly as it happened.
        case failed(String)
    }

    private(set) var grantState: GrantState = .idle

    /// The battery run while the scope was held, or nil when there is none.
    var grantedScopeResult: SecurityScopeProbe.Result? {
        if case .complete(let granted, _) = grantState { return granted }
        return nil
    }

    /// The battery run after the scope was released, or nil when there is none.
    var afterReleaseResult: SecurityScopeProbe.Result? {
        if case .complete(_, let afterRelease) = grantState { return afterRelease }
        return nil
    }

    /// Violations from both phases, scope-held first, deduplicated by id. The
    /// headline finding, when there is one.
    var grantViolations: [SecurityScopeProbe.Experiment] {
        var seen = Set<String>()
        var found: [SecurityScopeProbe.Experiment] = []
        for result in [grantedScopeResult, afterReleaseResult] {
            guard let result else { continue }
            for experiment in result.experiments where experiment.isBoundaryViolation {
                if seen.insert(experiment.id).inserted { found.append(experiment) }
            }
        }
        return found
    }

    var isGrantBusy: Bool {
        switch grantState {
        case .picking, .probing: return true
        case .idle, .complete, .failed: return false
        }
    }

    var grantStatusLabel: String {
        switch grantState {
        case .idle: return "IDLE"
        case .picking: return "PICKING"
        case .probing: return "PROBING"
        case .complete: return grantViolations.isEmpty ? "CONFINED" : "VIOLATION"
        case .failed: return "FAILED"
        }
    }

    /// Equatable projection of the lifecycle, for animation triggers.
    var grantStage: Int {
        switch grantState {
        case .idle: return 0
        case .picking: return 1
        case .probing: return 2
        case .complete: return 3
        case .failed: return 4
        }
    }

    // MARK: Grant control

    /// The user asked for a directory. Nothing has been granted yet.
    @MainActor
    func beginPicking() {
        guard !isGrantBusy else { return }
        grantState = .picking
    }

    /// The picker closed without a selection. Not an error: it is simply idle.
    @MainActor
    func pickerDidCancel() {
        if case .picking = grantState { grantState = .idle }
    }

    /// The user chose a directory. The grant is taken here and released inside
    /// `probeGrant`, after the first battery has finished.
    @MainActor
    func grantSelected(_ url: URL) {
        guard !isGrantBusy else { return }

        // Opened here rather than inside the probe task, so a grant that never
        // takes effect is reported at the moment it is discovered. Every
        // experiment would come back denied and none of that would say
        // anything about the boundary, so this is surfaced as the real failure
        // it is instead of being dressed up as a clean result.
        guard url.startAccessingSecurityScopedResource() else {
            grantState = .failed(
                """
                startAccessingSecurityScopedResource() returned false for \(url.path), so the \
                security scope never opened and no probe was run. Every experiment would \
                have reported a denial that says nothing about where the grant reaches.
                """
            )
            return
        }

        grantState = .probing
        Task { await probeGrant(url) }
    }

    /// Probe the extent of the scope, release it, then probe again.
    ///
    /// Main-actor throughout except the two batteries, which are detached
    /// because each one is a burst of syscalls that would otherwise stall the
    /// frame the user is watching. The caller must already have opened the
    /// scope; this method owns releasing it.
    @MainActor
    private func probeGrant(_ url: URL) async {
        let path = url.path

        // The scope is deliberately held across the `await` below: the first
        // battery only means anything while the grant is live, and the release
        // is not reached until it has returned.
        let granted = await Task.detached(priority: .userInitiated) {
            SecurityScopeProbe.probe(grantedPath: path)
        }.value

        url.stopAccessingSecurityScopedResource()

        // Every experiment in this battery expects a denial, so it turns entirely
        // on whether the scope really stopped.
        let afterRelease = await Task.detached(priority: .userInitiated) {
            SecurityScopeProbe.probeAfterRelease(grantedPath: path)
        }.value

        grantState = .complete(granted: granted, afterRelease: afterRelease)
    }

    // MARK: Small helpers

    /// Preserves the POSIX domain and code, which is the part worth recording.
    static func describe(_ error: Error) -> String {
        let nsError = error as NSError
        return "\(nsError.localizedDescription) [\(nsError.domain) \(nsError.code)]"
    }

    static func byteCount(of url: URL) -> Int {
        do {
            return try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
        } catch {
            return 0
        }
    }
}

// MARK: - Grant results, read for display

extension SecurityScopeProbe.Experiment {
    /// The verdict this observation earns once it is read against the grant
    /// policy. `isBoundaryViolation` is deliberately not consulted here: the
    /// core already defines it, and duplicating the rule would be a second place
    /// for it to drift.
    var verdict: ScopeVerdict {
        switch outcome {
        case .permitted:      return expectedDenied ? .overGrant : .granted
        case .denied:         return expectedDenied ? .held : .grantFailed
        case .notApplicable:  return .notApplicable
        case .error:          return .failed
        }
    }

    /// "EPERM (1)", or the bare number when no symbolic name was recorded.
    /// Never a substitute name.
    var errnoHeadline: String {
        guard let name = errnoName, !name.isEmpty else {
            return "errno \(errnoNumber) (no symbolic name recorded)"
        }
        return "\(name) (\(errnoNumber))"
    }
}

extension SecurityScopeProbe.Result {
    func count(of verdict: ScopeVerdict) -> Int {
        experiments.filter { $0.verdict == verdict }.count
    }

    /// 0 of the battery produced any observation at all.
    var observedCount: Int {
        experiments.count - count(of: .notApplicable)
    }
}