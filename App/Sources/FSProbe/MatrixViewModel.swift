//
//  MatrixViewModel.swift
//  FSProbe (App) — run orchestration and report persistence.
//
//  The view model owns everything that produces data: it runs the full probe set
//  off the main actor, writes matrix.json / matrix.txt into Documents on every
//  run, and surfaces any failure verbatim. It never fabricates a value: every
//  field here either comes from FSProbeCore or from a real syscall (sysctl).
//
//  Where the reports land: Documents is inside the app's data container, which
//  on iOS sits at /var/mobile/Containers/Data/Application/<UUID>/Documents. So
//  the test files are written under /var, automatically, on every run. Nothing
//  outside that container is writable — the sandbox denies it with EPERM, which
//  this project has measured and recorded — so the container is the only honest
//  destination and no fallback path is attempted.
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

// MARK: - View model

@Observable
final class MatrixViewModel {

    /// Honest lifecycle: the UI never renders a report it does not have.
    enum Phase: Sendable {
        case idle      // has not been asked to run yet
        case running   // probe set in flight
        case complete  // a report exists (the write may still have failed)
    }

    struct ExportedFile: Identifiable, Sendable {
        let name: String
        let url: URL
        let byteCount: Int
        var id: String { name }
    }

    /// Everything one run produced, assembled off the main actor.
    ///
    /// `text` is the report string that gets written to matrix.txt, so the
    /// screen shows the file itself rather than a second rendering of the same
    /// data — what you read on screen is what lands on disk.
    struct RunReport: Sendable {
        let matrix: CapabilityMatrix
        let text: String
        let files: [ExportedFile]
        let issues: [String]
        let duration: Double
    }

    private(set) var phase: Phase = .idle
    private(set) var matrix: CapabilityMatrix?
    private(set) var reportText: String = ""
    private(set) var files: [ExportedFile] = []
    private(set) var issues: [String] = []
    private(set) var duration: Double = 0
    private(set) var runCount: Int = 0

    private var hasRequestedRun = false

    /// Probe order is fixed by the core: baselines first, then investigations.
    let targets: [FSTarget] = FSTargets.all

    /// Export is only offered once there is something real to hand over.
    var canExport: Bool { !files.isEmpty }

    var resultCount: Int { matrix?.results.count ?? 0 }

    /// The directory the reports were written to, shown on screen so the save
    /// location is never a guess. Nil until a run has written something.
    var writtenDirectory: String? {
        files.first?.url.deletingLastPathComponent().path
    }

    // MARK: Run control

    /// Called from `.task` on appear. Runs exactly once per launch, so both
    /// report files exist in Documents before anyone asks for them.
    @MainActor
    func runIfNeeded() async {
        guard !hasRequestedRun, phase != .running else { return }
        await run()
    }

    /// The RUN button: recompute the matrix and rewrite both report files.
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
        reportText = report.text
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

        // Generated before the write attempt so the report is on screen even if
        // the disk write fails.
        let text = ReportExporter.text(matrix, targets: targets)

        var files: [ExportedFile] = []
        var issues: [String] = []

        guard let directory = documentsDirectory() else {
            issues.append(
                "Documents directory is unavailable on this system, so matrix.json and matrix.txt were not written."
            )
            return RunReport(matrix: matrix, text: text, files: files, issues: issues,
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
            let url = directory.appendingPathComponent("matrix.txt")
            try text.write(to: url, atomically: true, encoding: .utf8)
            files.append(ExportedFile(name: "matrix.txt", url: url, byteCount: byteCount(of: url)))
        } catch {
            issues.append("matrix.txt was not written: \(describe(error))")
        }

        return RunReport(matrix: matrix, text: text, files: files, issues: issues,
                         duration: Date().timeIntervalSince(started))
    }

    static func documentsDirectory() -> URL? {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
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