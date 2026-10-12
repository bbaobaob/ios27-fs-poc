//
//  MatrixView.swift
//  FSProbe (App) — the capability matrix screen.
//
//  Layout: a pinned leading column holding the target path, plus a horizontally
//  scrolling set of nine operation columns. Baselines and investigations are
//  separate sections because comparing them is the point of the experiment.
//

#if canImport(FSProbeCore)
// FSProbeCore is a separate module when this app is built as a SwiftPM package
// (the xtool path). The generated Xcode project compiles the probe engine into
// the same target, where it is not a module and the import is skipped.
import FSProbeCore
#endif

import SwiftUI
import UIKit
import UniformTypeIdentifiers

// MARK: - Screen

struct MatrixView: View {

    let model: MatrixViewModel

    @State private var selectedRow: MatrixRowModel?
    @State private var isExporting = false
    @State private var isLegendExpanded = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    InstrumentHeader(model: model)
                    // The grant control sits above the run controls on purpose:
                    // it is the only thing on this screen that needs the user to
                    // do something, and it is the whole reason this build exists.
                    GrantPanel(model: model)
                    RunControlBar(model: model, isExporting: $isExporting)

                    if !model.issues.isEmpty {
                        IssuePanel(issues: model.issues)
                    }
                    if !model.discrepancies.isEmpty {
                        DiscrepancyPanel(
                            discrepancies: model.discrepancies,
                            onSelect: { path in
                                selectedRow = model.rows.first { $0.target.path == path }
                            }
                        )
                    }

                    MatrixSection(
                        title: "Baseline — app container",
                        caption: "Documented capabilities. A denial here is a finding about the harness itself.",
                        rows: model.baselineRows,
                        onSelect: { selectedRow = $0 }
                    )
                    MatrixSection(
                        title: "Investigation — /var/",
                        caption: "The research surface. Read each row against the baseline above.",
                        rows: model.investigationRows,
                        onSelect: { selectedRow = $0 }
                    )

                    OutcomeStrip()
                    LegendPanel(isExpanded: $isLegendExpanded)
                    ExportPanel(model: model)
                }
                .padding(.horizontal, 14)
                .padding(.top, 10)
                .padding(.bottom, 32)
            }
            .background(InstrumentBackground())
            .navigationTitle("FSProbe")
            .navigationBarTitleDisplayMode(.inline)
            // Attached to the inner view on purpose: stacking two .sheet
            // modifiers on one view silently disables the first.
            .sheet(isPresented: $isExporting) {
                ShareSheet(activityItems: model.files.map(\.url))
            }
        }
        .task {
            // The matrix is computed on launch, with no user action required.
            await model.runIfNeeded()
        }
        .sheet(item: $selectedRow) { row in
            if let matrix = model.matrix {
                ResultDetailView(target: row.target, matrix: matrix)
            } else {
                Text("No matrix is loaded, so there is nothing to inspect.")
                    .padding()
            }
        }
    }
}

// MARK: - Instrument header

private struct InstrumentHeader: View {
    let model: MatrixViewModel

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("FSPROBE")
                        .font(.system(size: 15, weight: .heavy, design: .monospaced))
                        .tracking(2.4)
                    Text("filesystem capability matrix")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 8)
                StatusPill(phase: model.phase, scheme: scheme)
            }

            HairlineRule(axis: .horizontal)

            VStack(alignment: .leading, spacing: 4) {
                if let environment = model.matrix?.environment {
                    MetaLine(label: "platform", value: "\(environment.osName) \(environment.osVersion)")
                    MetaLine(label: "build", value: environment.osBuild)
                    MetaLine(label: "device", value: environment.deviceModel)
                    MetaLine(label: "captured", value: environment.timestampUTC)
                } else {
                    MetaLine(label: "platform", value: "not yet captured")
                }
                MetaLine(label: "run", value: runSummary)
            }
        }
        .padding(14)
        .background(Panel.background(scheme))
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Hairline.color(scheme), lineWidth: 1))
    }

    private var runSummary: String {
        if model.phase == .running {
            return "probing \(model.targets.count) targets × \(FSOperation.allCases.count) operations"
        }
        if model.phase == .idle { return "not started" }
        let results = model.matrix?.results.count ?? 0
        return "#\(model.runCount) · \(formatDuration(model.duration)) · \(results) results"
    }
}

private struct MetaLine: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label)
                .font(.system(size: 9.5, weight: .semibold, design: .monospaced))
                .tracking(0.8)
                .foregroundStyle(.secondary)
                .frame(width: 58, alignment: .leading)
            Text(value)
                .font(.system(size: 11, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct StatusPill: View {
    let phase: MatrixViewModel.Phase
    let scheme: ColorScheme

    var body: some View {
        HStack(spacing: 5) {
            Circle().fill(tint).frame(width: 7, height: 7)
            Text(label)
                .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                .tracking(1)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(Capsule().fill(Hairline.color(scheme)))
    }

    private var label: String {
        switch phase {
        case .idle: return "IDLE"
        case .running: return "RUNNING"
        case .complete: return "COMPLETE"
        }
    }

    private var tint: Color {
        switch phase {
        case .idle: return OutcomeFamily.absent.color(in: scheme)
        case .running: return OutcomeFamily.other.color(in: scheme)
        case .complete: return OutcomeFamily.success.color(in: scheme)
        }
    }
}

// MARK: - Run controls

private struct RunControlBar: View {
    let model: MatrixViewModel
    @Binding var isExporting: Bool

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(spacing: 8) {
            if model.phase == .running {
                RunningIndicator()
            }

            HStack(spacing: 10) {
                Button {
                    Task { await model.run() }
                } label: {
                    Label("Run again", systemImage: "arrow.clockwise")
                        .font(.system(size: 13, weight: .semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 9)
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.phase == .running)

                Button {
                    isExporting = true
                } label: {
                    Label("Export", systemImage: "square.and.arrow.up")
                        .font(.system(size: 13, weight: .semibold))
                        .padding(.vertical, 9)
                }
                .buttonStyle(.bordered)
                .disabled(!model.canExport)
                .accessibilityHint("Sends matrix.json and matrix.txt to Files, AirDrop, or any other destination.")
            }

            if !model.canExport && model.phase == .complete {
                Text("No report files are available to export. See the write failures above.")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(OutcomeFamily.other.color(in: scheme))
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}

private struct RunningIndicator: View {
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text("PROBING — \(FSOperation.allCases.count) operations per target")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .tracking(0.8)
                    .foregroundStyle(OutcomeFamily.other.color(in: scheme))
            }
            ScanningBar()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(Panel.background(scheme))
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Hairline.color(scheme), lineWidth: 1))
    }
}

/// Indeterminate sweep. The running state is shown explicitly — the screen
/// never implies completion by showing an empty table.
private struct ScanningBar: View {
    @Environment(\.colorScheme) private var scheme
    @State private var sweep: CGFloat = -1

    var body: some View {
        GeometryReader { geometry in
            LinearGradient(
                colors: [OutcomeFamily.other.color(in: scheme).opacity(0), OutcomeFamily.other.color(in: scheme), OutcomeFamily.other.color(in: scheme).opacity(0)],
                startPoint: .leading,
                endPoint: .trailing
            )
            .frame(width: geometry.size.width * 0.4)
            .offset(x: sweep * geometry.size.width)
            .onAppear {
                withAnimation(.linear(duration: 1.2).repeatForever(autoreverses: false)) {
                    sweep = 1
                }
            }
        }
        .frame(height: 3)
        .background(Hairline.color(scheme))
        .clipped()
    }
}

// MARK: - Document picker grant

/// The grant control, and the evidence it produced.
///
/// Placement: directly under the header and above the matrix, because it is the
/// only thing on this screen that needs the user to act. Every value rendered
/// below comes from `SecurityScopeProbe`; nothing here infers an outcome, and
/// the results are reachable only through `.complete`, which is the only case
/// that carries them.
private struct GrantPanel: View {
    let model: MatrixViewModel

    @State private var isPresentingPicker = false

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            grantButton

            explainer

            if model.isGrantBusy {
                inFlight
            }

            switch model.grantState {
            case .failed(let message):
                GrantFailurePanel(message: message)
            case .complete(let granted, let afterRelease):
                GrantResults(granted: granted, afterRelease: afterRelease)
            case .idle, .picking, .probing:
                EmptyView()
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Panel.background(scheme))
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(hasViolation ? OutcomeFamily.denial.color(in: scheme) : Hairline.color(scheme),
                        lineWidth: hasViolation ? 1.8 : 1)
        )
        .animation(.easeOut(duration: 0.22), value: model.grantStage)
    }

    private var hasViolation: Bool { !model.grantViolations.isEmpty }

    private var header: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            VStack(alignment: .leading, spacing: 1) {
                Text("DOCUMENT PICKER GRANT")
                    .font(.system(size: 11.5, weight: .bold, design: .monospaced))
                    .tracking(1.2)
                Text("does the grant reach further than the folder you pick?")
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            GrantStatusPill(model: model)
        }
    }

    /// Attached to this control's own modifier chain, because a third `.sheet`
    /// stacked onto one of the screen's existing sheets silently stops being
    /// presented.
    private var grantButton: some View {
        Button {
            model.beginPicking()
            isPresentingPicker = true
        } label: {
            GrantButtonLabel(isBusy: model.isGrantBusy)
        }
        .buttonStyle(.plain)
        .disabled(model.isGrantBusy)
        .accessibilityLabel("Grant access to a directory")
        .accessibilityHint("Opens Files so you can choose a folder. FSProbe then tests whether that grant reaches anything beyond the folder you chose.")
        .sheet(isPresented: $isPresentingPicker) {
            FolderPicker(
                isPresented: $isPresentingPicker,
                onPick: { url in
                    Task { @MainActor in model.grantSelected(url) }
                },
                onCancel: {
                    Task { @MainActor in model.pickerDidCancel() }
                }
            )
            .ignoresSafeArea()
        }
    }

    /// Shown whenever there is no result to read, so the control is never a
    /// button with no explanation attached to it and a failure never leaves the
    /// user without context.
    @ViewBuilder
    private var explainer: some View {
        switch model.grantState {
        case .idle, .failed:
            VStack(alignment: .leading, spacing: 5) {
                Text("Choose a folder in Files. FSProbe receives a security-scoped URL for it, then tests whether the grant reaches past it — the folder's parent, a `..` escape, a symlink pointing out of it, or a write into it — and then again after the scope is released.")
                    .font(.system(size: 10.5))
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                HairlineRule(axis: .horizontal)
                Text("The only writes are one synthetic file and one symlink, both inside the folder you pick, and both removed immediately.")
                    .font(.system(size: 9.5, design: .monospaced))
                    .foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        case .picking, .probing, .complete:
            EmptyView()
        }
    }

    private var inFlight: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text(inFlightLabel)
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .tracking(0.8)
                    .foregroundStyle(OutcomeFamily.other.color(in: scheme))
                    .fixedSize(horizontal: false, vertical: true)
            }
            ScanningBar()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(RowShade.alternate(scheme))
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Hairline.color(scheme), lineWidth: 1))
    }

    private var inFlightLabel: String {
        switch model.grantState {
        case .picking: return "PICKER OPEN — CHOOSE A FOLDER, OR CANCEL TO RETURN TO IDLE"
        case .probing: return "PROBING — SCOPE HELD, THEN RELEASED AND RETESTED"
        case .idle, .complete, .failed: return ""
        }
    }
}

/// The one control a first-time user has to find. High-contrast inverse fill,
/// so it reads as the primary action without adding a fifth hue to a palette
/// where green, red, grey and amber already carry data meaning.
private struct GrantButtonLabel: View {
    let isBusy: Bool

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        HStack(spacing: 10) {
            ZStack(alignment: .bottomTrailing) {
                Image(systemName: "folder.fill")
                    .font(.system(size: 15, weight: .semibold))
                    .frame(width: 30, height: 30)
                Image(systemName: isBusy ? "hourglass" : "plus.circle.fill")
                    .font(.system(size: 10, weight: .bold))
            }
            .frame(width: 30, height: 30)
            .background(RoundedRectangle(cornerRadius: 7).fill(ink.opacity(0.14)))

            VStack(alignment: .leading, spacing: 1) {
                Text(isBusy ? "GRANT IN FLIGHT" : "GRANT ACCESS TO A DIRECTORY")
                    .font(.system(size: 12.5, weight: .bold, design: .monospaced))
                    .tracking(0.8)
                    .fixedSize(horizontal: false, vertical: true)
                Text(isBusy ? "waiting for the picker, or for the probe" : "Pick a folder in Files")
                    .font(.system(size: 10))
                    .opacity(0.72)
            }

            Spacer(minLength: 6)

            Image(systemName: "chevron.right")
                .font(.system(size: 11, weight: .bold))
                .opacity(0.8)
        }
        .foregroundStyle(ink)
        .multilineTextAlignment(.leading)
        .padding(.horizontal, 12)
        .padding(.vertical, 11)
        .frame(maxWidth: .infinity)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(
                    LinearGradient(
                        colors: [faceTop, faceBottom],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
        )
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10).stroke(Hairline.color(scheme), lineWidth: 1)
        )
        .opacity(isBusy ? 0.6 : 1)
        .animation(.easeOut(duration: 0.15), value: isBusy)
    }

    private var faceTop: Color {
        scheme == .dark ? Color.white.opacity(0.96) : Color(red: 0.16, green: 0.18, blue: 0.24)
    }

    private var faceBottom: Color {
        scheme == .dark ? Color.white.opacity(0.80) : Color(red: 0.06, green: 0.07, blue: 0.11)
    }

    private var ink: Color {
        scheme == .dark ? Color(red: 0.05, green: 0.06, blue: 0.09) : Color.white
    }
}

private struct GrantStatusPill: View {
    let model: MatrixViewModel

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        HStack(spacing: 5) {
            OutcomeMark(family: family, shape: shape)
                .frame(width: 8, height: 8)
            Text(model.grantStatusLabel)
                .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                .tracking(1)
                .foregroundStyle(family.color(in: scheme))
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(Capsule().fill(Hairline.color(scheme)))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Grant status: \(model.grantStatusLabel)")
    }

    private var family: OutcomeFamily {
        switch model.grantState {
        case .idle: return .absent
        case .picking, .probing: return .other
        case .complete: return model.grantViolations.isEmpty ? .success : .denial
        case .failed: return .denial
        }
    }

    private var shape: MarkShape {
        switch model.grantState {
        case .idle: return .dashedRing
        case .picking: return .triangle
        case .probing: return .diamond
        case .complete: return model.grantViolations.isEmpty ? .disc : .breach
        case .failed: return .barred
        }
    }
}

// MARK: Grant results

private struct GrantResults: View {
    let granted: SecurityScopeProbe.Result
    let afterRelease: SecurityScopeProbe.Result

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            GrantRecordBlock(result: granted)

            if !violations.isEmpty {
                ViolationBanner(experiments: violations)
            }

            VStack(alignment: .leading, spacing: 8) {
                PanelLabel("SCOPE HELD — \(granted.experiments.count) EXPERIMENTS", tint: nil)
                ForEach(granted.experiments) { experiment in
                    ScopeExperimentCard(experiment: experiment)
                }
            }

            AfterReleaseGroup(result: afterRelease)

            VerdictLegend()
        }
    }

    /// Scope-held experiments first, then after-release, so the reading order
    /// matches the sequence the harness actually ran.
    private var violations: [SecurityScopeProbe.Experiment] {
        granted.experiments.filter { $0.isBoundaryViolation }
            + afterRelease.experiments.filter { $0.isBoundaryViolation }
    }
}

private struct GrantRecordBlock: View {
    let result: SecurityScopeProbe.Result

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            PanelLabel("GRANT RECORD", tint: nil)
            EvidenceLine(label: "granted", value: result.grantedPath, truncatesMiddle: true)
            EvidenceLine(label: "resolved", value: result.resolvedPath, truncatesMiddle: true)
            EvidenceLine(label: "scope", value: scopeText)
            HairlineRule(axis: .horizontal)
            HStack(spacing: 8) {
                Tally(shape: .disc, family: .success, count: result.count(of: .granted))
                Tally(shape: .blocked, family: .success, count: result.count(of: .held))
                if result.count(of: .notApplicable) > 0 {
                    Tally(shape: .dashedRing, family: .absent, count: result.count(of: .notApplicable))
                }
                if result.count(of: .grantFailed) > 0 {
                    Tally(shape: .barred, family: .other, count: result.count(of: .grantFailed))
                }
                if result.count(of: .failed) > 0 {
                    Tally(shape: .diamond, family: .other, count: result.count(of: .failed))
                }
                Spacer(minLength: 0)
                Text("\(result.observedCount)/\(result.experiments.count) observed")
                    .font(.system(size: 9.5, design: .monospaced))
                    .foregroundStyle(.tertiary)
            }
        }
    }

    private var scopeText: String {
        result.scopeActive
            ? "held for the duration of this battery"
            : "not held during this battery"
    }
}

/// Label, value, monospace, selectable. Long values truncate in the middle so
/// both ends of a path stay readable; the truncation is a rendering decision
/// only, so the selected and copied text is always the whole value.
private struct EvidenceLine: View {
    let label: String
    let value: String
    var truncatesMiddle: Bool = false

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            ScaledMono(text: label, base: 9, weight: .semibold, tracking: 0.8, colour: .secondary)
                .frame(width: 52, alignment: .leading)
            ScaledMono(
                text: value,
                base: truncatesMiddle ? 10.5 : 10,
                selectable: true,
                lineLimit: truncatesMiddle ? 2 : nil,
                truncation: truncatesMiddle ? .middle : .tail
            )
            Spacer(minLength: 0)
        }
        .contextMenu {
            Button {
                UIPasteboard.general.string = value
            } label: {
                Label("Copy full value", systemImage: "doc.on.doc")
            }
        }
    }
}

/// The finding, when there is one. Loud on purpose: this is the single result
/// the whole project exists to produce, so it gets the heaviest border on the
/// screen, its own silhouette, and the experiment ids spelled out.
private struct ViolationBanner: View {
    let experiments: [SecurityScopeProbe.Experiment]

    @Environment(\.colorScheme) private var scheme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var hasStruck = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 8) {
                OutcomeMark(family: .denial, shape: .breach)
                    .frame(width: 15, height: 15)
                    .scaleEffect(hasStruck ? 1 : 1.3)
                VStack(alignment: .leading, spacing: 1) {
                    Text("BOUNDARY VIOLATION")
                        .font(.system(size: 12, weight: .heavy, design: .monospaced))
                        .tracking(1.4)
                    Text("\(experiments.count) experiment\(experiments.count == 1 ? "" : "s") succeeded where the grant policy requires a refusal.")
                        .font(.system(size: 10))
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            .foregroundStyle(OutcomeFamily.denial.color(in: scheme))

            HairlineRule(axis: .horizontal)

            ForEach(experiments) { experiment in
                VStack(alignment: .leading, spacing: 2) {
                    ScaledMono(
                        text: experiment.id,
                        base: 11.5,
                        weight: .bold,
                        colour: OutcomeFamily.denial.color(in: scheme)
                    )
                    ScaledMono(text: experiment.interpretation.collapsed, base: 10.5, selectable: true)
                    ScaledMono(
                        text: "\(experiment.operation) · \(experiment.arguments)",
                        base: 9.5,
                        colour: .secondary,
                        selectable: true,
                        lineLimit: 2,
                        truncation: .middle
                    )
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(OutcomeFamily.denial.color(in: scheme).opacity(0.12))
        )
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(OutcomeFamily.denial.color(in: scheme), lineWidth: 2)
        )
        .onAppear {
            // One strike when the finding reaches the screen: the mark settles
            // from oversized to rest and stays there. No autoreversing repeat —
            // that would land it back at the oversized value and leave it there.
            guard !reduceMotion else { return }
            withAnimation(.easeOut(duration: 0.45)) {
                hasStruck = true
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(
            "Boundary violation. \(experiments.map(\.id).joined(separator: ", "))."
        )
    }
}

/// Everything that was measured once the scope was released. Set apart from
/// the held battery by a dashed frame, because the scope behind it is gone.
private struct AfterReleaseGroup: View {
    let result: SecurityScopeProbe.Result

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            PanelLabel("AFTER RELEASE", tint: nil)

            Text("stopAccessingSecurityScopedResource() was called. Every experiment below expects a denial, so a path that is still readable means the grant outlived its scope.")
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)

            EvidenceLine(label: "granted", value: result.grantedPath, truncatesMiddle: true)
            EvidenceLine(label: "resolved", value: result.resolvedPath, truncatesMiddle: true)

            ForEach(result.experiments) { experiment in
                ScopeExperimentCard(experiment: experiment)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12).fill(Panel.background(scheme).opacity(0.45)))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(Hairline.color(scheme), style: StrokeStyle(lineWidth: 1.2, dash: [5, 3]))
        )
    }
}

private struct ScopeExperimentCard: View {
    let experiment: SecurityScopeProbe.Experiment

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        let verdict = experiment.verdict
        let isViolation = experiment.isBoundaryViolation

        return VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top, spacing: 8) {
                OutcomeMark(family: verdict.family, shape: verdict.shape)
                    .frame(width: 11, height: 11)
                    .padding(.top, 2)
                VStack(alignment: .leading, spacing: 1) {
                    ScaledMono(text: experiment.id, base: 12, weight: .bold)
                    ScaledMono(text: experiment.operation, base: 9.5, colour: .secondary)
                }
                Spacer(minLength: 6)
                VStack(alignment: .trailing, spacing: 1) {
                    ScaledMono(
                        text: verdict.title,
                        base: 10.5,
                        weight: .bold,
                        tracking: 0.6,
                        colour: verdict.family.color(in: scheme)
                    )
                    // The core's own raw outcome, never replaced by the verdict.
                    ScaledMono(text: experiment.outcome.rawValue, base: 9.5, colour: .secondary)
                }
            }

            ScaledMono(text: experiment.interpretation.collapsed, base: 10.5, selectable: true)

            EvidenceLine(label: "expected", value: experiment.expected.collapsed)
            EvidenceLine(label: "mechanism", value: experiment.mechanism.collapsed)
            EvidenceLine(label: "argument", value: experiment.arguments, truncatesMiddle: true)
            EvidenceLine(label: "errno", value: errnoText)

            if isViolation {
                HStack(alignment: .top, spacing: 6) {
                    OutcomeMark(family: .denial, shape: .breach)
                        .frame(width: 8, height: 8)
                        .padding(.top, 1.5)
                    Text("BOUNDARY VIOLATION — this succeeded where the grant policy requires a refusal")
                        .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                        .tracking(0.6)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .foregroundStyle(OutcomeFamily.denial.color(in: scheme))
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(isViolation
                      ? OutcomeFamily.denial.color(in: scheme).opacity(0.10)
                      : Panel.background(scheme).opacity(0.55))
        )
        .overlay(alignment: .leading) {
            // A position cue as well as a hue cue: the violated cards carry a
            // rail down their leading edge that the others do not.
            if isViolation {
                UnevenRoundedRectangle(
                    topLeadingRadius: 10,
                    bottomLeadingRadius: 10,
                    style: .continuous
                )
                .fill(OutcomeFamily.denial.color(in: scheme))
                .frame(width: 3.5)
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(
                    isViolation ? OutcomeFamily.denial.color(in: scheme) : Hairline.color(scheme),
                    lineWidth: isViolation ? 1.8 : 1
                )
        )
        .accessibilityElement(children: .contain)
        .accessibilityLabel(accessibilityLabel)
    }

    /// Honest per outcome: "no errno" and "never attempted" are different facts.
    private var errnoText: String {
        if let name = experiment.errnoName, !name.isEmpty {
            return "\(name) (\(experiment.errnoNumber))"
        }
        switch experiment.outcome {
        case .permitted: return "none — the call returned success, so no errno was set"
        case .denied, .error: return experiment.errnoHeadline
        case .notApplicable: return "not attempted — the experiment's precondition failed"
        }
    }

    private var accessibilityLabel: String {
        let errno = errnoText
        return "\(experiment.id). \(experiment.operation). Outcome \(experiment.outcome.rawValue). \(errno). \(experiment.verdict.title). \(experiment.interpretation.collapsed)"
    }
}

/// A real failure, with the message exactly as it happened. Nothing is
/// summarised away, and nothing is invented to fill the gap.
private struct GrantFailurePanel: View {
    let message: String

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                OutcomeMark(family: .denial, shape: .barred)
                    .frame(width: 9, height: 9)
                PanelLabel("GRANT FAILED", tint: .denial)
            }
            ScaledMono(text: message, base: 10.5, selectable: true)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(OutcomeFamily.denial.color(in: scheme).opacity(0.10))
        )
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(OutcomeFamily.denial.color(in: scheme), lineWidth: 1.5)
        )
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Grant failed. \(message)")
    }
}

/// The verdict key. It states the rule explicitly, because this section breaks
/// the matrix's convention: here a denial is the passing outcome, so hue means
/// "was this expected" and the shape means "what happened".
private struct VerdictLegend: View {
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            PanelLabel("VERDICT KEY", tint: nil)
            Text("The shape carries the verdict. Colour only says whether that verdict was the one the grant policy predicts.")
                .font(.system(size: 9.5))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)

            LazyVGrid(
                columns: [GridItem(.adaptive(minimum: 200), spacing: 6, alignment: .leading)],
                alignment: .leading,
                spacing: 6
            ) {
                ForEach(ScopeVerdict.allCases, id: \.self) { verdict in
                    HStack(alignment: .top, spacing: 6) {
                        OutcomeMark(family: verdict.family, shape: verdict.shape)
                            .frame(width: 9, height: 9)
                            .padding(.top, 1.5)
                        VStack(alignment: .leading, spacing: 0) {
                            ScaledMono(
                                text: verdict.title,
                                base: 9.5,
                                weight: .bold,
                                colour: verdict.family.color(in: scheme)
                            )
                            Text(verdict.meaning)
                                .font(.system(size: 9.5))
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .accessibilityElement(children: .combine)
                }
            }
        }
    }
}

// MARK: Grant typesetting

/// Monospaced text at the instrument's optical size that still follows the
/// user's Dynamic Type setting. The fixed sizes used elsewhere on this screen
/// are chrome; the evidence in this section has to stay readable when the user
/// makes it bigger.
private struct ScaledMono: View {
    @ScaledMetric(relativeTo: .caption) private var scale: CGFloat = 1

    let text: String
    var base: CGFloat = 11
    var weight: Font.Weight = .regular
    var tracking: CGFloat = 0
    var colour: Color?
    var selectable: Bool = false
    var lineLimit: Int?
    var truncation: Text.TruncationMode = .tail

    var body: some View {
        Text(text)
            .font(.system(size: base * scale, weight: weight, design: .monospaced))
            .tracking(tracking)
            .multilineTextAlignment(.leading)
            .foregroundStyle(colour.map { AnyShapeStyle($0) } ?? AnyShapeStyle(Color.primary))
            .lineLimit(lineLimit)
            .truncationMode(truncation)
            .fixedSize(horizontal: false, vertical: true)
            .modifier(OptionalTextSelection(selectable: selectable))
    }
}

/// `textSelection` takes different types for enabled and disabled, so a ternary
/// cannot choose between them. This applies the right one without a branch in the
/// modifier chain.
private struct OptionalTextSelection: ViewModifier {
    let selectable: Bool

    func body(content: Content) -> some View {
        if selectable {
            content.textSelection(.enabled)
        } else {
            content.textSelection(.disabled)
        }
    }
}

/// The core writes several strings as multi-line literals. Collapsing the line
/// breaks keeps every word and drops only the layout the source file used.
private extension String {
    var collapsed: String {
        split(whereSeparator: { $0.isNewline })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .joined(separator: " ")
    }
}

// MARK: Write failures

private struct IssuePanel: View {
    let issues: [String]

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            PanelLabel("WRITE FAILURES", tint: .other)
            ForEach(Array(issues.enumerated()), id: \.offset) { _, issue in
                Text("· \(issue)")
                    .font(.system(size: 11, design: .monospaced))
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(12)
        .background(Panel.background(scheme))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(OutcomeFamily.other.color(in: scheme), lineWidth: 1)
        )
    }
}

// MARK: - Discrepancies

private struct DiscrepancyPanel: View {
    let discrepancies: [CapabilityMatrix.Discrepancy]
    let onSelect: (String) -> Void

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                PanelLabel("DISCREPANCIES", tint: .denial)
                Text("\(discrepancies.count)")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .foregroundStyle(OutcomeFamily.denial.color(in: scheme))
            }

            Text("Operations on the same path disagree about what is allowed. These are the questions worth chasing.")
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            ForEach(discrepancies) { discrepancy in
                Button {
                    onSelect(discrepancy.path)
                } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(middleTruncated(discrepancy.path, limit: 46))
                            .font(.system(size: 10.5, weight: .semibold, design: .monospaced))
                            .lineLimit(1)
                        Text(discrepancy.description)
                            .font(.system(size: 10))
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.leading)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .background(
                    RoundedRectangle(cornerRadius: 6)
                        .fill(OutcomeFamily.denial.color(in: scheme).opacity(0.10))
                )
                .accessibilityLabel("Discrepancy on \(discrepancy.path). \(discrepancy.description). Opens the detail.")
            }
        }
        .padding(12)
        .background(Panel.background(scheme))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(OutcomeFamily.denial.color(in: scheme), lineWidth: 1.5)
        )
    }
}

// MARK: - Matrix grid

private enum GridMetrics {
    static let pathColumnWidth: CGFloat = 150
    static let cellWidth: CGFloat = 52
    static let rowHeight: CGFloat = 60
    static let headerHeight: CGFloat = 26
    static var gridWidth: CGFloat { cellWidth * CGFloat(FSOperation.allCases.count) }
}

private struct MatrixSection: View {
    let title: String
    let caption: String
    let rows: [MatrixRowModel]
    let onSelect: (MatrixRowModel) -> Void

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeading(title: title, caption: caption)

            HStack(alignment: .top, spacing: 0) {
                // The leading path column is pinned: it stays readable while the
                // nine operation columns scroll underneath it.
                VStack(spacing: 0) {
                    PathHeaderCell()
                    ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                        PathCell(row: row, isAlternate: !index.isMultiple(of: 2)) {
                            onSelect(row)
                        }
                        HairlineRule(axis: .horizontal)
                    }
                }
                .frame(width: GridMetrics.pathColumnWidth)

                ScrollView(.horizontal) {
                    VStack(spacing: 0) {
                        OperationHeaderRow()
                        ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                            OperationRow(row: row, isAlternate: !index.isMultiple(of: 2)) {
                                onSelect(row)
                            }
                            HairlineRule(axis: .horizontal)
                        }
                    }
                }
                .scrollBounceBehavior(.basedOnSize, axes: .horizontal)
            }
            .background(Panel.background(scheme))
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Hairline.color(scheme), lineWidth: 1))
            .overlay {
                HStack(spacing: 0) {
                    Color.clear.frame(width: GridMetrics.pathColumnWidth, height: 1)
                    Rectangle().fill(Hairline.color(scheme)).frame(width: 0.5)
                }
            }
        }
    }
}

private struct SectionHeading: View {
    let title: String
    let caption: String

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.system(size: 11.5, weight: .bold, design: .monospaced))
                .tracking(0.8)
            Text(caption)
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Text("scroll sideways for all nine operations")
                .font(.system(size: 9, design: .monospaced))
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct PathHeaderCell: View {
    var body: some View {
        Text("PATH")
            .font(.system(size: 9, weight: .bold, design: .monospaced))
            .tracking(1.2)
            .foregroundStyle(.secondary)
            .padding(.leading, 10)
            .frame(width: GridMetrics.pathColumnWidth, height: GridMetrics.headerHeight, alignment: .leading)
    }
}

private struct OperationHeaderRow: View {
    var body: some View {
        HStack(spacing: 0) {
            ForEach(FSOperation.allCases, id: \.self) { operation in
                Text(operationLabel(operation))
                    .font(.system(size: 8.5, weight: .bold, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
                    .frame(width: GridMetrics.cellWidth, height: GridMetrics.headerHeight)
                    .accessibilityLabel("\(operation.rawValue). \(operation.explanation)")
            }
        }
        .frame(width: GridMetrics.gridWidth)
    }
}

private struct PathCell: View {
    let row: MatrixRowModel
    let isAlternate: Bool
    let action: () -> Void

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 4) {
                    if row.target.isBaseline {
                        Text("CTRL")
                            .font(.system(size: 7.5, weight: .heavy, design: .monospaced))
                            .padding(.horizontal, 3)
                            .padding(.vertical, 1)
                            .background(
                                Capsule().fill(OutcomeFamily.absent.color(in: scheme).opacity(0.22))
                            )
                    }
                    Text(row.target.label)
                        .font(.system(size: 10.5, weight: .semibold))
                        .lineLimit(1)
                }

                Text(middleTruncated(row.target.path, limit: 26))
                    .font(.system(size: 9.5, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)

                HStack(spacing: 7) {
                    Tally(shape: .disc, family: .success, count: row.granted)
                    Tally(shape: .blocked, family: .denial, count: row.denied)
                    Tally(shape: .dashedRing, family: .absent, count: row.absent)
                    if row.unrecorded > 0 {
                        Tally(shape: .unrecorded, family: .absent, count: row.unrecorded)
                    }
                }
            }
            .padding(.leading, 10)
            .frame(width: GridMetrics.pathColumnWidth, height: GridMetrics.rowHeight, alignment: .leading)
            .background(isAlternate ? RowShade.alternate(scheme) : Color.clear)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(
            "\(row.target.path). \(row.granted) granted, \(row.denied) denied, \(row.absent) absent. Opens the per-operation detail."
        )
    }
}

private struct Tally: View {
    let shape: MarkShape
    let family: OutcomeFamily
    let count: Int

    var body: some View {
        HStack(spacing: 2) {
            OutcomeMark(family: family, shape: shape)
                .frame(width: 6, height: 6)
            Text("\(count)")
                .font(.system(size: 9, weight: .medium, design: .monospaced))
                .foregroundStyle(count == 0 ? AnyShapeStyle(Color.secondary) : AnyShapeStyle(Color.primary))
        }
        .accessibilityHidden(true)
    }
}

private struct OperationRow: View {
    let row: MatrixRowModel
    let isAlternate: Bool
    let action: () -> Void

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        HStack(spacing: 0) {
            ForEach(FSOperation.allCases, id: \.self) { operation in
                Button(action: action) {
                    OutcomeCellView(
                        cell: row.cells[operation]
                            ?? MatrixViewModel.makeCell(operation: operation, result: nil),
                        path: row.target.path
                    )
                }
                .buttonStyle(.plain)
            }
        }
        .frame(width: GridMetrics.gridWidth)
        .background(isAlternate ? RowShade.alternate(scheme) : Color.clear)
    }
}

private struct OutcomeCellView: View {
    let cell: MatrixCell
    let path: String

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(spacing: 3) {
            OutcomeMark(family: cell.family, shape: cell.shape)
            Text(cell.code)
                .font(.system(size: 8.5, weight: .medium, design: .monospaced))
                .foregroundStyle(cell.isRecorded ? cell.family.color(in: scheme) : Color.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .frame(width: GridMetrics.cellWidth, height: GridMetrics.rowHeight)
        .contentShape(Rectangle())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilityLabel)
    }

    /// "/var/mobile readdir deniedEPERM EPERM 1"
    private var accessibilityLabel: String {
        guard cell.isRecorded else {
            return "\(path) \(operationLabel(cell.operation)) no result recorded"
        }
        var parts = [path, operationLabel(cell.operation), cell.outcomeName]
        if let name = cell.errnoName {
            parts.append(name)
            parts.append("\(cell.errnoNumber)")
        }
        return parts.joined(separator: " ")
    }
}

// MARK: - Marks

/// The non-colour half of the encoding: shape carries the meaning, hue
/// reinforces it. Neither is ever shown alone.
struct OutcomeMark: View {
    let family: OutcomeFamily
    let shape: MarkShape

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        let hue = family.color(in: scheme)
        switch shape {
        case .disc:
            Circle().fill(hue)
        case .blocked:
            RoundedRectangle(cornerRadius: 1.5)
                .fill(hue)
                .overlay {
                    Rectangle()
                        .fill(cutColour)
                        .frame(width: 1.6)
                        .rotationEffect(.degrees(45))
                }
                .clipShape(RoundedRectangle(cornerRadius: 1.5))
        case .barred:
            RoundedRectangle(cornerRadius: 1.5)
                .fill(hue)
                .overlay {
                    Rectangle()
                        .fill(cutColour)
                        .frame(width: 1.6)
                }
                .clipShape(RoundedRectangle(cornerRadius: 1.5))
        case .dashedRing:
            Circle().stroke(hue, style: StrokeStyle(lineWidth: 1.3, dash: [2, 1.6]))
        case .triangle:
            TriangleShape().fill(hue)
        case .diamond:
            DiamondShape().fill(hue)
        case .breach:
            // A stop sign. The silhouette appears nowhere else in the app, so
            // the one mark that means "this should not have been permitted" is
            // recognisable from its shape alone.
            OctagonShape()
                .fill(hue)
                .overlay {
                    Rectangle()
                        .fill(cutColour)
                        .frame(width: 1.6)
                        .rotationEffect(.degrees(45))
                }
                .clipShape(OctagonShape())
        case .unrecorded:
            RoundedRectangle(cornerRadius: 1.5)
                .stroke(hue.opacity(0.5), style: StrokeStyle(lineWidth: 1, dash: [1.5, 1.5]))
        }
    }

    private var cutColour: Color {
        scheme == .dark ? Color.black.opacity(0.85) : Color.white
    }
}

private struct TriangleShape: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        path.move(to: CGPoint(x: rect.midX, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY))
        path.addLine(to: CGPoint(x: rect.minX, y: rect.maxY))
        path.closeSubpath()
        return path
    }
}

private struct DiamondShape: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        path.move(to: CGPoint(x: rect.midX, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.midY))
        path.addLine(to: CGPoint(x: rect.midX, y: rect.maxY))
        path.addLine(to: CGPoint(x: rect.minX, y: rect.midY))
        path.closeSubpath()
        return path
    }
}

private struct OctagonShape: Shape {
    func path(in rect: CGRect) -> Path {
        // Corners cut at the regular-octagon ratio, so the mark keeps its
        // silhouette at the 9pt size it is used at in the matrix tallies.
        let cut = min(rect.width, rect.height) * 0.2929
        var path = Path()
        path.move(to: CGPoint(x: rect.minX + cut, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX - cut, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY + cut))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - cut))
        path.addLine(to: CGPoint(x: rect.maxX - cut, y: rect.maxY))
        path.addLine(to: CGPoint(x: rect.minX + cut, y: rect.maxY))
        path.addLine(to: CGPoint(x: rect.minX, y: rect.maxY - cut))
        path.addLine(to: CGPoint(x: rect.minX, y: rect.minY + cut))
        path.closeSubpath()
        return path
    }
}

// MARK: - Outcome strip + legend

private struct OutcomeStrip: View {
    var body: some View {
        LazyVGrid(
            columns: [GridItem(.adaptive(minimum: 148), spacing: 8, alignment: .leading)],
            alignment: .leading,
            spacing: 6
        ) {
            ForEach(legendOutcomes, id: \.self) { outcome in
                LegendChip(outcome: outcome, compact: true)
            }
            LegendChip(outcome: nil, compact: true)
        }
    }
}

private struct LegendChip: View {
    let outcome: ProbeOutcome?
    let compact: Bool

    @Environment(\.colorScheme) private var scheme

    var isFamily: OutcomeFamily { outcome.map { OutcomeFamily(from: $0) } ?? .absent }
    var markShape: MarkShape { outcome.map { isFamily.markShape(for: $0) } ?? .unrecorded }

    var body: some View {
        let family = isFamily
        let shape = markShape

        return HStack(spacing: 6) {
            OutcomeMark(family: family, shape: shape)
                .frame(width: 10, height: 10)
            VStack(alignment: .leading, spacing: 0) {
                Text(outcome?.rawValue ?? "not recorded")
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                if compact {
                    Text(family.title)
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(family.color(in: scheme))
                } else {
                    Text(outcome?.uiSummary ?? "The core produced no result for this operation.")
                        .font(.system(size: 9.5))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 8)
        .background(
            RoundedRectangle(cornerRadius: 7).fill(Hairline.color(scheme).opacity(0.6))
        )
    }
}

private struct LegendPanel: View {
    @Binding var isExpanded: Bool

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Button {
                withAnimation(.easeInOut(duration: 0.18)) { isExpanded.toggle() }
            } label: {
                HStack(spacing: 6) {
                    Text(isExpanded ? "LEGEND −" : "LEGEND +")
                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                        .tracking(1)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text(isExpanded ? "hide" : "outcomes and column keys")
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if isExpanded {
                VStack(alignment: .leading, spacing: 6) {
                    PanelLabel("OUTCOME", tint: nil)
                    ForEach(legendOutcomes, id: \.self) { outcome in
                        LegendChip(outcome: outcome, compact: false)
                    }
                    LegendChip(outcome: nil, compact: false)

                    HairlineRule(axis: .horizontal)

                    PanelLabel("COLUMNS", tint: nil)
                    ForEach(FSOperation.allCases, id: \.self) { operation in
                        HStack(alignment: .top, spacing: 8) {
                            Text(operationLabel(operation))
                                .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                                .foregroundStyle(OutcomeFamily.success.color(in: scheme))
                                .frame(width: 58, alignment: .leading)
                            VStack(alignment: .leading, spacing: 0) {
                                Text(operation.rawValue)
                                    .font(.system(size: 9.5, weight: .medium, design: .monospaced))
                                Text(operation.explanation)
                                    .font(.system(size: 9.5))
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        .padding(.vertical, 1)
                    }
                }
            }
        }
        .padding(12)
        .background(Panel.background(scheme))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Hairline.color(scheme), lineWidth: 1))
    }
}

// MARK: - Export panel

private struct ExportPanel: View {
    let model: MatrixViewModel

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            PanelLabel("REPORTS IN DOCUMENTS", tint: nil)

            if model.files.isEmpty {
                Text("No report files on disk.")
                    .font(.system(size: 10.5, design: .monospaced))
                    .foregroundStyle(.secondary)
            } else {
                ForEach(model.files) { file in
                    VStack(alignment: .leading, spacing: 1) {
                        Text(file.name)
                            .font(.system(size: 10.5, weight: .semibold, design: .monospaced))
                        Text(middleTruncated(file.url.path, limit: 52))
                            .font(.system(size: 9.5, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                        Text("\(formatBytes(file.byteCount)) · rewritten on every run")
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundStyle(.tertiary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                Text("Export sends both files to Files, AirDrop, or any other destination.")
                    .font(.system(size: 9.5))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(12)
        .background(Panel.background(scheme))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Hairline.color(scheme), lineWidth: 1))
    }
}

// MARK: - Shared chrome

struct PanelLabel: View {
    let text: String
    var tint: OutcomeFamily?

    /// Positional text with an optional tint, so call sites read as
    /// `PanelLabel("ERRNO", tint: .other)`.
    init(_ text: String, tint: OutcomeFamily? = nil) {
        self.text = text
        self.tint = tint
    }

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        Text(text)
            .font(.system(size: 9.5, weight: .bold, design: .monospaced))
            .tracking(1.2)
            .foregroundStyle(
                tint.map { AnyShapeStyle($0.color(in: scheme)) } ?? AnyShapeStyle(Color.secondary)
            )
    }
}

struct HairlineRule: View {
    let axis: Axis

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        Rectangle()
            .fill(Hairline.color(scheme))
            .frame(
                width: axis == .vertical ? 0.5 : nil,
                height: axis == .horizontal ? 0.5 : nil
            )
    }
}

// MARK: - Presentation vocabulary (shared with ResultDetailView)

/// Ordered outcome list. `ProbeOutcome` is not CaseIterable in FSProbeCore,
/// so the cases are enumerated here explicitly, in reporting order.
let legendOutcomes: [ProbeOutcome] = [
    .succeeded, .deniedEPERM, .deniedEACCES, .notFound, .notDirectory, .failedOther
]

extension OutcomeFamily {
    /// Four families, four hues. Absence is deliberately not red: a path that
    /// does not exist is a different fact from a path that is refused.
    func color(in scheme: ColorScheme) -> Color {
        switch (self, scheme) {
        case (.success, .dark): return Color(red: 0.30, green: 0.82, blue: 0.52)
        case (.success, _):     return Color(red: 0.05, green: 0.47, blue: 0.26)
        case (.denial, .dark):  return Color(red: 0.98, green: 0.45, blue: 0.43)
        case (.denial, _):      return Color(red: 0.72, green: 0.13, blue: 0.15)
        case (.absent, .dark):  return Color(red: 0.62, green: 0.68, blue: 0.78)
        case (.absent, _):      return Color(red: 0.40, green: 0.45, blue: 0.55)
        case (.other, .dark):   return Color(red: 0.96, green: 0.72, blue: 0.30)
        case (.other, _):       return Color(red: 0.62, green: 0.36, blue: 0.02)
        }
    }

    init(from outcome: ProbeOutcome) {
        switch outcome {
        case .succeeded: self = .success
        case .deniedEPERM, .deniedEACCES: self = .denial
        case .notFound: self = .absent
        case .notDirectory, .failedOther: self = .other
        }
    }

    /// Attribution → family. Deliberately the same four families as the outcome
    /// mapping, so the detail sheet and the matrix can never disagree about what
    /// a colour means:
    ///   - `documentedCapability` / `userGranted` are grants, so "granted".
    ///   - `sandboxEnforcement` / `posixPermissions` are refusals, so "denied".
    ///     Both denial mechanisms share a family, mirroring deniedEPERM and
    ///     deniedEACCES sharing one in the matrix.
    ///   - `pathAbsent` is an absent path, never a refusal.
    ///   - `configurationIssue` / `unexplained` are neither, so "other".
    init(from cause: AccessCause) {
        switch cause {
        case .documentedCapability, .userGranted: self = .success
        case .sandboxEnforcement, .posixPermissions: self = .denial
        case .pathAbsent: self = .absent
        case .configurationIssue, .unexplained: self = .other
        }
    }

    func markShape(for outcome: ProbeOutcome) -> MarkShape {
        switch outcome {
        case .succeeded: return .disc
        case .deniedEPERM: return .blocked
        case .deniedEACCES: return .barred
        case .notFound: return .dashedRing
        case .notDirectory: return .triangle
        case .failedOther: return .diamond
        }
    }
}

extension ProbeOutcome {
    /// Plain-language meaning, matching the outcome contract in FSProbeCore.
    var uiSummary: String {
        switch self {
        case .succeeded: return "The syscall completed successfully."
        case .notFound: return "The path does not exist (ENOENT). Absence, not denial."
        case .notDirectory: return "A path component is not a directory (ENOTDIR)."
        case .deniedEPERM: return "Denied by the platform sandbox (EPERM)."
        case .deniedEACCES: return "Denied by POSIX permission bits or ACLs (EACCES)."
        case .failedOther: return "Failed with some other errno."
        }
    }
}

extension AccessCause {
    /// Attribution meaning, matching the cause contract in FSProbeCore.
    var uiSummary: String {
        switch self {
        case .documentedCapability: return "Normal documented capability of an ordinary app."
        case .userGranted: return "Access granted through an explicit user action."
        case .sandboxEnforcement: return "Denial produced by the platform sandbox."
        case .posixPermissions: return "Denial produced by POSIX permission bits or ACLs."
        case .pathAbsent: return "The path simply does not exist on this system."
        case .configurationIssue: return "Probe or path configuration problem."
        case .unexplained: return "Not yet attributed — needs further investigation."
        }
    }
}

/// Short, fixed-width column header. The full raw value and the explanation
/// live in the legend and in the detail sheet.
func operationLabel(_ operation: FSOperation) -> String {
    switch operation {
    case .stat: return "lstat"
    case .statFollow: return "stat*"
    case .openDirectory: return "opendir"
    case .enumerate: return "readdir"
    case .readFile: return "read"
    case .createFile: return "create"
    case .writeFile: return "write"
    case .deleteFile: return "unlink"
    case .readLink: return "readlink"
    }
}

func middleTruncated(_ text: String, limit: Int) -> String {
    guard text.count > limit, limit >= 4 else { return text }
    let head = (limit - 1) / 2
    let tail = limit - 1 - head
    return String(text.prefix(head)) + "…" + String(text.suffix(tail))
}

func formatDuration(_ seconds: Double) -> String {
    guard seconds.isFinite, seconds >= 0 else { return "—" }
    return seconds < 1
        ? String(format: "%.0f ms", seconds * 1000)
        : String(format: "%.2f s", seconds)
}

func formatBytes(_ count: Int) -> String {
    if count < 1024 { return "\(count) B" }
    let kilobytes = Double(count) / 1024
    if kilobytes < 1024 { return String(format: "%.1f KB", kilobytes) }
    return String(format: "%.2f MB", kilobytes / 1024)
}

// MARK: - Background

/// A faint measuring grid: enough atmosphere to read as an instrument, never
/// enough to compete with the data.
struct InstrumentBackground: View {
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        ZStack {
            LinearGradient(
                colors: scheme == .dark
                    ? [Color(red: 0.06, green: 0.07, blue: 0.09), Color(red: 0.03, green: 0.04, blue: 0.05)]
                    : [Color(red: 0.97, green: 0.975, blue: 0.98), Color(red: 0.92, green: 0.93, blue: 0.95)],
                startPoint: .top,
                endPoint: .bottom
            )
            MeasuringGrid(scheme: scheme)
        }
        .ignoresSafeArea()
    }
}

private struct MeasuringGrid: View {
    let scheme: ColorScheme

    var body: some View {
        Canvas { context, size in
            let step: CGFloat = 18
            let lineColor = scheme == .dark ? Color.white.opacity(0.05) : Color.black.opacity(0.05)
            var path = Path()
            var x: CGFloat = 0
            while x <= size.width {
                path.move(to: CGPoint(x: x, y: 0))
                path.addLine(to: CGPoint(x: x, y: size.height))
                x += step
            }
            var y: CGFloat = 0
            while y <= size.height {
                path.move(to: CGPoint(x: 0, y: y))
                path.addLine(to: CGPoint(x: size.width, y: y))
                y += step
            }
            context.stroke(path, with: .color(lineColor), lineWidth: 0.5)
        }
    }
}

enum Hairline {
    static func color(_ scheme: ColorScheme) -> Color {
        scheme == .dark ? Color.white.opacity(0.14) : Color.black.opacity(0.14)
    }
}

enum Panel {
    static func background(_ scheme: ColorScheme) -> Color {
        scheme == .dark ? Color.white.opacity(0.05) : Color.white.opacity(0.82)
    }
}

enum RowShade {
    static func alternate(_ scheme: ColorScheme) -> Color {
        scheme == .dark ? Color.white.opacity(0.035) : Color.black.opacity(0.03)
    }
}

// MARK: - Share

/// Multi-item share, so *both* report files reach Files or AirDrop in one
/// action. SwiftUI's ShareLink only carries a single item.
struct ShareSheet: UIViewControllerRepresentable {
    let activityItems: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: activityItems, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

// MARK: - Folder picker

/// The document picker, in folder mode.
///
/// `.folder` is the whole point of this control: granting a directory rather
/// than a file is what makes the parent, sibling and `..` experiments mean
/// anything. `asCopy: false` is equally deliberate — a copy would land in the
/// app's own inbox and carry no security scope at all, which is the one thing
/// this flow exists to test.
///
/// No usage-description string is needed: `UIDocumentPickerViewController` is a
/// user-mediated pick, not a permission-gated API, and the app builds with
/// `GENERATE_INFOPLIST_FILE = YES` so there is no plist to add one to anyway.
///
/// The sheet does not dismiss itself when hosted inside a SwiftUI sheet, so the
/// coordinator writes `isPresented` back to close it on both paths.
struct FolderPicker: UIViewControllerRepresentable {
    @Binding var isPresented: Bool
    let onPick: (URL) -> Void
    let onCancel: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(isPresented: $isPresented, onPick: onPick, onCancel: onCancel)
    }

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(
            forOpeningContentTypes: [.folder],
            asCopy: false
        )
        picker.delegate = context.coordinator
        picker.allowsMultipleSelection = false
        return picker
    }

    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {
        context.coordinator.isPresented = $isPresented
    }

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        var isPresented: Binding<Bool>
        private let onPick: (URL) -> Void
        private let onCancel: () -> Void

        init(isPresented: Binding<Bool>, onPick: @escaping (URL) -> Void, onCancel: @escaping () -> Void) {
            self.isPresented = isPresented
            self.onPick = onPick
            self.onCancel = onCancel
        }

        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            // An empty selection is not a pick and not a failure: there was
            // nothing to grant, so it returns to idle.
            guard let url = urls.first else {
                isPresented.wrappedValue = false
                onCancel()
                return
            }
            isPresented.wrappedValue = false
            onPick(url)
        }

        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
            isPresented.wrappedValue = false
            onCancel()
        }
    }
}