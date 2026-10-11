//
//  ResultDetailView.swift
//  FSProbe (App) — per-target evidence sheet.
//
//  Everything the matrix cell had to compress is shown here in full: the exact
//  path, the rationale, every operation, the exact errno name/number/strerror
//  text, the evidence the core captured, and the attribution.
//

#if canImport(FSProbeCore)
// FSProbeCore is a separate module when this app is built as a SwiftPM package
// (the xtool path). The generated Xcode project compiles the probe engine into
// the same target, where it is not a module and the import is skipped.
import FSProbeCore
#endif

import SwiftUI

struct ResultDetailView: View {

    let target: FSTarget
    let matrix: CapabilityMatrix

    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    identityBlock
                    rationaleBlock

                    if !localDiscrepancies.isEmpty {
                        discrepancyBlock
                    }

                    PanelLabel("OPERATIONS — \(FSOperation.allCases.count)", tint: nil)

                    ForEach(FSOperation.allCases, id: \.self) { operation in
                        OperationResultCard(
                            operation: operation,
                            result: results[operation]
                        )
                    }
                }
                .padding(.horizontal, 14)
                .padding(.top, 10)
                .padding(.bottom, 30)
            }
            .background(InstrumentBackground())
            .navigationTitle(target.label)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Close") { dismiss() }
                }
            }
        }
    }

    // MARK: Derived data

    private var results: [FSOperation: ProbeResult] {
        matrix.results(for: target.path)
    }

    private var localDiscrepancies: [CapabilityMatrix.Discrepancy] {
        matrix.discrepancies().filter { $0.path == target.path }
    }

    // MARK: Blocks

    private var identityBlock: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                Text(target.isBaseline ? "BASELINE" : "INVESTIGATION")
                    .font(.system(size: 9, weight: .heavy, design: .monospaced))
                    .tracking(1)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(
                        Capsule().fill(
                            (target.isBaseline ? OutcomeFamily.absent : OutcomeFamily.other)
                                .color(in: scheme).opacity(0.20)
                        )
                    )
                Text("\(recordedCount)/\(FSOperation.allCases.count) recorded")
                    .font(.system(size: 9.5, design: .monospaced))
                    .foregroundStyle(.secondary)
            }

            Text(target.path)
                .font(.system(size: 13, weight: .medium, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)

            Text(target.label)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Panel.background(scheme))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Hairline.color(scheme), lineWidth: 1))
    }

    private var recordedCount: Int {
        FSOperation.allCases.filter { results[$0] != nil }.count
    }

    private var rationaleBlock: some View {
        VStack(alignment: .leading, spacing: 4) {
            PanelLabel("RATIONALE", tint: nil)
            Text(target.rationale)
                .font(.system(size: 11.5))
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Panel.background(scheme))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Hairline.color(scheme), lineWidth: 1))
    }

    private var discrepancyBlock: some View {
        VStack(alignment: .leading, spacing: 6) {
            PanelLabel("DISCREPANCIES ON THIS PATH", tint: .denial)
            ForEach(localDiscrepancies) { discrepancy in
                Text("· \(discrepancy.description)")
                    .font(.system(size: 11, design: .monospaced))
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(OutcomeFamily.denial.color(in: scheme).opacity(0.10))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(OutcomeFamily.denial.color(in: scheme), lineWidth: 1.5)
        )
    }
}

// MARK: - One operation

private struct OperationResultCard: View {

    let operation: FSOperation
    let result: ProbeResult?

    @Environment(\.colorScheme) private var scheme

    var body: some View {
        let family = result.map { OutcomeFamily(from: $0.outcome) } ?? .absent
        let shape = result.map { family.markShape(for: $0.outcome) } ?? .unrecorded

        return VStack(alignment: .leading, spacing: 7) {
            HStack(alignment: .top, spacing: 8) {
                Text(operation.rawValue)
                    .font(.system(size: 12, weight: .bold, design: .monospaced))
                Spacer(minLength: 8)
                HStack(spacing: 5) {
                    OutcomeMark(family: family, shape: shape)
                        .frame(width: 9, height: 9)
                    Text(result?.outcome.rawValue ?? "not recorded")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundStyle(result == nil ? Color.secondary : family.color(in: scheme))
                }
            }

            Text(operation.explanation)
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if let result {
                Text(result.outcome.uiSummary)
                    .font(.system(size: 10.5))
                    .fixedSize(horizontal: false, vertical: true)
                errnoBlock(result)
                causeBlock(result)
                if !evidenceRows(result.evidence).isEmpty {
                    evidenceBlock(result.evidence)
                }
                if let note = result.note {
                    noteBlock(note)
                }
            } else {
                Text("No result was recorded for this operation on this path.")
                    .font(.system(size: 10.5, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Panel.background(scheme))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Hairline.color(scheme), lineWidth: 1))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(operation.rawValue). \(operation.explanation). \(accessibilityOutcome)")
    }

    private var accessibilityOutcome: String {
        guard let result else { return "No result recorded." }
        var parts = [result.outcome.rawValue]
        if let name = result.errnoName { parts.append("\(name) \(result.errnoNumber)") }
        parts.append("attributed to \(result.cause.rawValue)")
        return parts.joined(separator: ", ")
    }

    private func errnoBlock(_ result: ProbeResult) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            PanelLabel("ERRNO", tint: nil)
            if result.outcome == .succeeded {
                Text("0 — no error")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(OutcomeFamily.success.color(in: scheme))
            } else {
                Text(errnoHeadline(result))
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                if let description = result.errnoDescription {
                    Text(description)
                        .font(.system(size: 10.5, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Text("No strerror() text was recorded for this errno.")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(OutcomeFamily.other.color(in: scheme))
                }
            }
        }
    }

    private func errnoHeadline(_ result: ProbeResult) -> String {
        if let name = result.errnoName, !name.isEmpty {
            return "\(name) (\(result.errnoNumber))"
        }
        return "errno \(result.errnoNumber) (no symbolic name recorded)"
    }

    private func causeBlock(_ result: ProbeResult) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            PanelLabel("ATTRIBUTION", tint: OutcomeFamily(from: result.cause))
            Text(result.cause.rawValue)
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .foregroundStyle(OutcomeFamily(from: result.cause).color(in: scheme))
            Text(result.cause.uiSummary)
                .font(.system(size: 10.5))
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func evidenceBlock(_ evidence: ProbeEvidence) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            PanelLabel("EVIDENCE", tint: nil)
            ForEach(evidenceRows(evidence)) { entry in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(entry.label)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .frame(width: 108, alignment: .leading)
                    Text(entry.value)
                        .font(.system(size: 10.5, design: .monospaced))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                }
            }
        }
    }

    private func noteBlock(_ note: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            PanelLabel("NOTE", tint: .other)
            Text(note)
                .font(.system(size: 10.5))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - Evidence flattening

/// Only the fields that actually carry a value are shown; an absent field is
/// omitted rather than rendered as a blank or a zero.
private struct EvidenceEntry: Identifiable {
    let id: String
    let label: String
    let value: String
}

private func evidenceRows(_ evidence: ProbeEvidence) -> [EvidenceEntry] {
    var rows: [EvidenceEntry] = []

    if let entryCount = evidence.entryCount {
        rows.append(EvidenceEntry(id: "entryCount", label: "entries", value: "\(entryCount)"))
    }
    if let names = evidence.sampleEntryNames, !names.isEmpty {
        rows.append(EvidenceEntry(id: "sampleNames", label: "sample names", value: names.joined(separator: ", ")))
    }
    if let bytesRead = evidence.bytesRead {
        rows.append(EvidenceEntry(id: "bytesRead", label: "bytes read", value: "\(bytesRead)"))
    }
    if let bytesWritten = evidence.bytesWritten {
        rows.append(EvidenceEntry(id: "bytesWritten", label: "bytes written", value: "\(bytesWritten)"))
    }
    if let matched = evidence.readBackMatched {
        rows.append(EvidenceEntry(id: "readBack", label: "read-back matched", value: matched ? "yes" : "no"))
    }
    if let linkTarget = evidence.linkTarget {
        rows.append(EvidenceEntry(id: "linkTarget", label: "link target", value: linkTarget))
    }
    if let size = evidence.statSize {
        rows.append(EvidenceEntry(id: "statSize", label: "stat size", value: "\(size) bytes"))
    }
    if let mode = evidence.statModeOctal {
        rows.append(EvidenceEntry(id: "statMode", label: "stat mode", value: "0o\(mode)"))
    }
    if let isDirectory = evidence.statIsDirectory {
        rows.append(EvidenceEntry(id: "isDirectory", label: "is directory", value: isDirectory ? "yes" : "no"))
    }

    return rows
}