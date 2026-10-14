import XCTest
@testable import FSProbeCore

/// Tests for the foreign-memory probe.
///
/// The Mach calls are Darwin-only, so the verification host withholds every read.
/// What these tests establish is that the data itself is never part of the result
/// — only the fact of the read and its size — and that a withheld read is never a
/// violation.
final class ForeignMemoryProbeTests: XCTestCase {

    func testOnlyPermittedIsAViolation() {
        let cases: [(ForeignMemoryProbe.Outcome, Bool)] = [
            (.permitted, true), (.deniedByPolicy, false),
            (.deniedByValidity, false), (.noTaskPort, false),
            (.controlFailed, false), (.symbolUnavailable, false), (.notAttempted, false)
        ]
        for (outcome, shouldFlag) in cases {
            let item = ForeignMemoryProbe.Read(
                id: "case", mechanism: "m", operation: "o", target: "t",
                expected: "e", expectedDenied: true, outcome: outcome,
                returnValue: nil, errorName: nil, bytesRead: nil,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertEqual(item.isBoundaryViolation, shouldFlag,
                           "\(outcome) must \(shouldFlag ? "" : "not ") be a violation")
        }
    }

    func testTheDataItselfIsNeverPartOfTheResult() {
        // This reads memory, so the discipline matters: the result records only
        // whether the read was permitted and how many bytes came back. A test
        // asserting that is the cheapest place to keep it honest.
        let result = ForeignMemoryProbe.probe()
        for item in result.reads {
            // bytesRead is a count, never contents.
            if let bytes = item.bytesRead {
                XCTAssertGreaterThan(bytes, 0)
                XCTAssertLessThanOrEqual(bytes, 4096,
                                         "only one page is ever requested")
            }
            // The interpretation must not embed any memory contents.
            XCTAssertFalse(item.interpretation.contains("0x"),
                           "\(item.id) appears to embed memory contents")
        }
    }

    func testTheSelfControlLeadsWhereTheAPIExists() {
        let result = ForeignMemoryProbe.probe()
        XCTAssertFalse(result.reads.isEmpty)
        if MachShim.available {
            XCTAssertEqual(result.reads.first?.id, "mach-vm-read-self",
                           "the first read must be the self control")
            XCTAssertFalse(result.reads.first?.isBoundaryViolation ?? true,
                           "the self control must never be a violation")
            XCTAssertFalse(result.reads.first?.expectedDenied ?? true,
                           "the self control must not expect denial")
        } else {
            XCTAssertEqual(result.reads.first?.outcome, .symbolUnavailable)
            XCTAssertTrue(result.violations.isEmpty)
        }
    }

    func testNoViolationWhereNothingWasMeasured() {
        let result = ForeignMemoryProbe.probe()
        for item in result.reads {
            if item.isBoundaryViolation {
                XCTAssertEqual(item.outcome, .permitted)
                XCTAssertFalse(item.interpretation.isEmpty)
            }
            if item.outcome == .noTaskPort || item.outcome == .controlFailed {
                XCTAssertFalse(item.isBoundaryViolation)
            }
        }
        XCTAssertTrue(result.violations.allSatisfy { $0.outcome == .permitted })
    }

    func testViolationListMatchesPerReadFlags() {
        let result = ForeignMemoryProbe.probe()
        let flagged = Set(result.reads.filter { $0.isBoundaryViolation }.map { $0.id })
        let listed = Set(result.violations.map { $0.id })
        XCTAssertEqual(flagged, listed, "the violation list must match the flags")
    }

    func testReportRendersTheForeignMemorySection() {
        let matrix = CapabilityMatrix(
            results: [],
            environment: CapabilityMatrix.EnvironmentRecord(
                osVersion: "test", osBuild: "test", deviceModel: "test"
            ),
            foreignMemory: ForeignMemoryProbe.probe()
        )
        let text = ReportExporter.text(matrix, targets: [])
        XCTAssertTrue(text.contains("Can an ordinary app read another process's memory?"),
                      "the report must render the foreign-memory section")
        // The launchd rung appears only when the self-control succeeded, because
        // the foreign reads are gated behind it. On the verification host the Mach
        // API is absent so the whole experiment is withheld with a single rung,
        // and that rung still names launchd as the intended target. Asserting the
        // target's presence unconditionally would encode one platform's shape as
        // the rule.
        XCTAssertTrue(text.contains("launchd"),
                      "the target must be identifiable in whatever rung ran")
    }
}
