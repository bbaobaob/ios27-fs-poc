//
//  MatrixView.swift
//  FSProbe (App) — the whole app.
//
//  Two buttons and a log pane.
//
//    RUN          runs the full probe battery (every experiment, runBoundary
//                 experiments included) and rewrites both report files.
//    EXPORT LOG   hands matrix.json and matrix.txt to the share sheet, so they
//                 can be sent to Files, AirDrop or anywhere else.
//    THE LOG      shows matrix.txt exactly as it was written — the file, not a
//                 second rendering of the same data.
//
//  Saving needs no button: every run writes both files into the app's Documents
//  directory, which lives under /var/mobile/Containers on iOS. Nothing outside
//  the container is writable — the sandbox denies it with EPERM — so the save
//  path is stated on screen rather than assumed.
//

#if canImport(FSProbeCore)
// FSProbeCore is a separate module when this app is built as a SwiftPM package
// (the xtool path). The generated Xcode project compiles the probe engine into
// the same target, where it is not a module and the import is skipped.
import FSProbeCore
#endif

import SwiftUI
import UIKit

// MARK: - Screen

struct MatrixView: View {

    let model: MatrixViewModel

    @State private var isExporting = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 12) {
                RunHeader(model: model)

                ControlRow(model: model, isExporting: $isExporting)

                if !model.issues.isEmpty {
                    IssuePanel(issues: model.issues)
                }

                LogPane(text: model.reportText, isRunning: model.phase == .running)
            }
            .padding(.horizontal, 14)
            .padding(.top, 10)
            .padding(.bottom, 10)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .background(InstrumentBackground())
            .navigationTitle("FSProbe")
            .navigationBarTitleDisplayMode(.inline)
            // On the screen's own modifier chain: stacking two .sheet modifiers
            // on one view silently disables the first. This is the only sheet
            // the app has now.
            .sheet(isPresented: $isExporting) {
                ShareSheet(activityItems: model.files.map(\.url))
            }
        }
        .task {
            // The battery runs itself on launch, so the reports are on disk and
            // on screen before anyone presses anything.
            await model.runIfNeeded()
        }
    }
}

// MARK: - Header

private struct RunHeader: View {
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
                } else {
                    MetaLine(label: "platform", value: "not yet captured")
                }
                MetaLine(label: "run", value: runSummary)
                MetaLine(label: "saved", value: savedSummary)
                MetaLine(label: "path", value: model.writtenDirectory ?? "nothing written yet")
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Panel.background(scheme))
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Hairline.color(scheme), lineWidth: 1))
    }

    private var runSummary: String {
        switch model.phase {
        case .idle:
            return "not started"
        case .running:
            return "#\(model.runCount) · probing \(model.targets.count) targets × \(FSOperation.allCases.count) operations"
        case .complete:
            return "#\(model.runCount) · \(formatDuration(model.duration)) · \(model.resultCount) results"
        }
    }

    /// Real byte counts from the files that were actually written. No sizes are
    /// shown for a file that failed to write; the failure is in the issue panel
    /// below instead.
    private var savedSummary: String {
        guard !model.files.isEmpty else {
            return model.phase == .complete ? "nothing written" : "—"
        }
        return model.files
            .map { "\($0.name) \(formatBytes($0.byteCount))" }
            .joined(separator: " · ")
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
                .foregroundStyle(.primary)
                .textSelection(.enabled)
                .lineLimit(2)
                .truncationMode(.middle)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct StatusPill: View {
    let phase: MatrixViewModel.Phase
    let scheme: ColorScheme

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var isRunning: Bool { phase == .running }

    var body: some View {
        HStack(spacing: 5) {
            Circle()
                .fill(tint)
                .frame(width: 7, height: 7)
                .scaleEffect(isRunning ? 1.35 : 1)
                .opacity(isRunning ? 0.55 : 1)
                // The looping animation is attached only while the probe is in
                // flight; when it finishes the default animation returns the dot
                // to rest instead of leaving it stuck mid-pulse.
                .animation(
                    isRunning && !reduceMotion
                        ? .easeInOut(duration: 0.9).repeatForever(autoreverses: true)
                        : .default,
                    value: isRunning
                )
            Text(label)
                .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                .tracking(1)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(Capsule().fill(Hairline.color(scheme)))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Run status: \(label)")
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

// MARK: - Controls

private struct ControlRow: View {
    let model: MatrixViewModel
    @Binding var isExporting: Bool

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(spacing: 8) {
            HStack(spacing: 10) {
                Button {
                    Task { await model.run() }
                } label: {
                    Label(model.phase == .idle ? "Run" : "Run again", systemImage: "play.fill")
                        .font(.system(size: 13, weight: .semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 9)
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.phase == .running)
                .accessibilityHint("Runs every probe experiment and rewrites matrix.json and matrix.txt in Documents.")

                Button {
                    isExporting = true
                } label: {
                    Label("Export log", systemImage: "square.and.arrow.up")
                        .font(.system(size: 13, weight: .semibold))
                        .padding(.vertical, 9)
                }
                .buttonStyle(.bordered)
                .disabled(!model.canExport)
                .accessibilityHint("Sends matrix.json and matrix.txt to Files, AirDrop, or any other destination.")
            }

            if model.phase == .running {
                RunningIndicator()
            } else if !model.canExport && model.phase == .complete {
                Text("No report files were written. See the write failures above.")
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
                Text("PROBING — EVERY EXPERIMENT")
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

/// Indeterminate sweep. The running state is shown explicitly — the log never
/// implies completion by showing an empty pane.
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

// MARK: - Write failures

/// Shown only when a real write failed. The message is whatever the OS said,
/// never a paraphrase.
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
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Panel.background(scheme))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(OutcomeFamily.other.color(in: scheme), lineWidth: 1)
        )
    }
}

// MARK: - Log pane

/// matrix.txt on screen, verbatim.
///
/// Rendered line by line in a lazy stack rather than as one `Text`: the report
/// runs to thousands of lines once every battery is included, and a lazy stack
/// only lays out what is on screen, so a long report stays scrollable. Each line
/// is selectable, and the blank ones keep their row so the report's own spacing
/// survives.
private struct LogPane: View {
    let text: String
    let isRunning: Bool

    @Environment(\.colorScheme) private var scheme

    private var lines: [String] {
        text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    }

    var body: some View {
        // Split once per render: the report is long, and re-splitting it for the
        // header, the pane and the accessibility label would triple the cost.
        let lines = self.lines
        let isEmpty = lines.isEmpty

        return VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 6) {
                PanelLabel("MATRIX.TXT", tint: nil)
                Spacer(minLength: 6)
                Text(isEmpty ? "empty" : "\(lines.count) lines")
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            HairlineRule(axis: .horizontal)

            if isEmpty {
                placeholder
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 1) {
                        ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                            Text(line.isEmpty ? " " : line)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundStyle(Color.primary.opacity(0.88))
                                .textSelection(.enabled)
                                .lineLimit(nil)
                                .fixedSize(horizontal: false, vertical: true)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.top, 10)
                    .padding(.bottom, 14)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(terminal)
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12).stroke(Hairline.color(scheme), lineWidth: 1)
        )
        // A status rail down the leading edge, so the pane's state is readable
        // without reading the text inside it.
        .overlay(alignment: .leading) {
            UnevenRoundedRectangle(
                topLeadingRadius: 12,
                bottomLeadingRadius: 12,
                style: .continuous
            )
            .fill(rail(isEmpty: isEmpty))
            .frame(width: 2.5)
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(isEmpty ? "No report yet. Press Run." : "Report, \(lines.count) lines")
    }

    /// Near-black in dark mode, paper-white in light mode: the log always reads
    /// as a terminal, and the surrounding chrome never competes with it.
    private var terminal: Color {
        scheme == .dark
            ? Color(red: 0.035, green: 0.042, blue: 0.055)
            : Color(red: 0.975, green: 0.982, blue: 0.992)
    }

    private func rail(isEmpty: Bool) -> Color {
        isEmpty
            ? OutcomeFamily.absent.color(in: scheme).opacity(0.5)
            : OutcomeFamily.success.color(in: scheme).opacity(0.85)
    }

    private var placeholder: some View {
        VStack(spacing: 6) {
            Text(isRunning ? "RUNNING THE PROBES…" : "NO REPORT YET")
                .font(.system(size: 11, weight: .bold, design: .monospaced))
                .tracking(1.2)
                .foregroundStyle(isRunning
                                 ? OutcomeFamily.other.color(in: scheme)
                                 : Color.secondary)
            Text(isRunning
                 ? "Every probe is running. The report appears here as soon as it lands in Documents."
                 : "Press Run. The report is written to Documents and shown here.")
                .font(.system(size: 10.5))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(.horizontal, 24)
        .padding(.vertical, 28)
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

// MARK: - Presentation vocabulary

/// Colour family a state belongs to. Four families, four hues. Absence is
/// deliberately not denial: nothing captured yet is not the same fact as a
/// refusal.
enum OutcomeFamily: String, Sendable {
    case success
    case denial
    case absent
    case other

    /// Four families, four hues, and the light and dark ramps are tuned
    /// separately so the accent never falls into the background on either.
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
/// enough to compete with the report.
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