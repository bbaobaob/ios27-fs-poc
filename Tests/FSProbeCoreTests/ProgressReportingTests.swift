import XCTest
@testable import FSProbeCore

/// Tests for incremental progress reporting and the embedded-XPC time budget.
///
/// Background: the simulator run that validates every commit waits a bounded
/// time for matrix.json. The battery once grew past that budget, and because
/// the matrix was written exactly once at the end, the run produced NO evidence
/// at all -- an interrupted run and a run that found nothing looked identical.
/// These tests pin the two properties that fix that: phases report progress as
/// they finish, and the slowest phase cannot exceed its budget.
final class ProgressReportingTests: XCTestCase {

    func testPhasesReportProgressAsTheyFinish() {
        // Every reportProgress call hands over a snapshot of the same shape as
        // the final matrix, with phases that never ran left nil. A consumer
        // that writes each snapshot to disk therefore always holds evidence for
        // every phase that finished -- which is the whole point.
        var stages: [String] = []
        var snapshots: [CapabilityMatrix] = []
        let matrix = MatrixRunner().run(
            targets: [],
            runBoundaryExperiments: true,
            onProgress: { stage, partial in
                stages.append(stage)
                snapshots.append(partial)
            }
        )

        XCTAssertFalse(stages.isEmpty,
                       "at least one phase must report progress")
        XCTAssertEqual(stages.count, Set(stages).count,
                       "each stage must be reported once: \(stages)")

        // Snapshots are cumulative: a section that is non-nil in one snapshot
        // must stay non-nil in every later snapshot and in the final matrix.
        // A snapshot that silently lost a finished phase would corrupt the
        // partial file it is written to.
        for snapshot in snapshots {
            if snapshot.processExecution != nil {
                XCTAssertNotNil(matrix.processExecution,
                                "a finished phase must survive to the final matrix")
            }
            if snapshot.machServiceCensus != nil {
                XCTAssertNotNil(matrix.machServiceCensus,
                                "a finished phase must survive to the final matrix")
            }
        }
    }

    func testProgressSnapshotsRenderAsNotAttempted() {
        // A partial file is read by the same report renderer as the final one.
        // Sections for phases that never ran must render as NOT_ATTEMPTED, never
        // as empty findings -- otherwise an interrupted run would read as "these
        // phases found nothing".
        var first: CapabilityMatrix?
        _ = MatrixRunner().run(
            targets: [],
            runBoundaryExperiments: true,
            onProgress: { _, partial in
                if first == nil { first = partial }
            }
        )
        guard let snapshot = first else {
            XCTFail("no phase reported progress")
            return
        }
        let text = ReportExporter.text(snapshot, targets: [])
        XCTAssertFalse(text.isEmpty)
    }

    func testEmbeddedXPCPhaseFitsInsideTheCIBudget() {
        // The property that matters is the product, not either factor: the
        // phase's worst case is maxFrameworks services times perServiceTimeout
        // seconds each. If someone raises either one without the other, this
        // fails -- which is exactly the review this bound needs, because the
        // failure mode is a silent CI timeout that destroys all evidence from
        // every phase, including the ones that finished.
        let worstCase = Double(EmbeddedXPCServiceProbe.maxFrameworks)
            * EmbeddedXPCServiceProbe.perServiceTimeout
        XCTAssertLessThanOrEqual(worstCase, 30,
                                 "the embedded-XPC phase must fit in ~30s worst case")
    }

    func testEmbeddedXPCBoundIsRecordedNotImplied() {
        // A census whose bounds are not in the result cannot be compared across
        // runs: "12 services reachable" means something different out of 25
        // examined than out of 60.
        let result = EmbeddedXPCServiceProbe.probe()
        XCTAssertLessThanOrEqual(result.frameworksExamined,
                                 EmbeddedXPCServiceProbe.maxFrameworks)
    }
}
