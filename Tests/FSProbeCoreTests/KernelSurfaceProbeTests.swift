import XCTest
@testable import FSProbeCore

/// Tests for the three probes that pushed past the census: IOKit user-client
/// OPEN (the census only enumerated names), kernel objects reached without the
/// filesystem, and the classic escape primitives.
///
/// All three are Darwin-only, so on the verification host they report
/// unattempted. What these tests pin is the discipline each depends on:
///
///   - an opened user client is reachable attack surface, never a finding;
///   - a permitted answer from setuid(0) or a snapshot revert is a candidate
///     that must be reproduced on device, never a confirmed violation;
///   - every group runs its control first and unconditionally, so a result
///     with no control in it reads as impossible rather than empty.
///
/// The classification tables matter as much as the flags: `EPERM` is a sandbox
/// denial, `EACCES` is POSIX/SIP, `EXDEV` is cross-volume and not attributable.
/// Collapsing any of those into "denied" would launder a measurement into a
/// conclusion the kernel never made.
final class KernelSurfaceProbeTests: XCTestCase {

    // MARK: - IOKitUserClientOpenProbe

    func testOpeningAUserClientIsNeverAFinding() {
        // The census rule extended one step further: if VISIBILITY is not a
        // finding, then neither is OPENING. An app that opens a user client
        // has reached attack surface; the finding would be the driver doing
        // something dangerous for an unidentified caller, which this probe
        // deliberately does not test (no external method is called).
        let cases: [IOKitUserClientOpenProbe.Outcome] = [
            .opened, .refused, .empty, .symbolUnavailable, .notAttempted
        ]
        for outcome in cases {
            let entry = IOKitUserClientOpenProbe.Entry(
                id: "case", serviceName: "AppleFoo", operation: "IOServiceOpen",
                outcome: outcome, kernReturn: 0, openedConnect: false,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertFalse(entry.isBoundaryViolation,
                           "\(outcome) must never be a violation")
        }
    }

    func testTheControlLeadsAndDoesNotExpectServices() {
        // A class that cannot exist must match nothing. That is what makes a
        // populated root walk meaningful rather than ambiguous.
        let result = IOKitUserClientOpenProbe.probe()
        XCTAssertFalse(result.entries.isEmpty)
        XCTAssertEqual(result.entries.first?.id, "iokit-open-control",
                       "the first entry must be the nonexistent-class control")
        XCTAssertNotEqual(result.entries.first?.outcome, .opened,
                          "the control must never report an opened user client")
    }

    func testUserClientViolationsAreAlwaysEmpty() {
        let result = IOKitUserClientOpenProbe.probe()
        XCTAssertTrue(result.violations.isEmpty,
                      "no user-client open is ever a violation by itself")
    }

    func testOpensAreBounded() {
        // A walk that opens every service on a large registry could stall the
        // whole matrix. The bound is a safety property, so it is pinned.
        XCTAssertEqual(IOKitUserClientOpenProbe.maxServices, 40)
    }

    // MARK: - KernelObjectSurfaceProbe

    func testPermittedIsNeverAFinding() {
        let cases: [KernelObjectSurfaceProbe.Outcome] = [
            .permitted, .denied, .notFound, .otherError, .notAttempted, .symbolUnavailable
        ]
        for outcome in cases {
            let entry = KernelObjectSurfaceProbe.Entry(
                id: "case", group: "socket families", operation: "socket(AF_SYSTEM)",
                target: "AF_SYSTEM", outcome: outcome, errnoName: nil,
                returnedValue: nil, observed: "obs", interpretation: "interp"
            )
            XCTAssertFalse(entry.isBoundaryViolation,
                           "\(outcome) must never be a violation")
        }
    }

    func testKernelObjectGroupsRunTheirControls() {
        // Three groups, three controls, all first-in-group. A group whose
        // control is missing is a group whose refusals cannot be read.
        let result = KernelObjectSurfaceProbe.probe()
        for id in ["posix-ipc-control", "socket-control", "device-control"] {
            XCTAssertTrue(result.entries.contains { $0.id == id },
                          "\(id) must always be present")
        }
    }

    func testControlGroupsDoNotExpectDenial() {
        // The POSIX-IPC and device controls use paths that cannot exist, so
        // their expected answer is ENOENT -- not a refusal. A control that
        // "expects denial" would be calibrated against the wrong baseline.
        let result = KernelObjectSurfaceProbe.probe()
        let ipcControl = result.entries.first { $0.id == "posix-ipc-control" }
        XCTAssertNotEqual(ipcControl?.outcome, .denied,
                          "a nonexistent-object control must not read as a denial")
        let deviceControl = result.entries.first { $0.id == "device-control" }
        XCTAssertNotEqual(deviceControl?.outcome, .denied,
                          "a nonexistent-device control must not read as a denial")
    }

    func testKernelObjectViolationsAreAlwaysEmpty() {
        let result = KernelObjectSurfaceProbe.probe()
        XCTAssertTrue(result.violations.isEmpty)
        XCTAssertTrue(result.violationsAlwaysEmpty)
    }

    func testTheThreeGroupsAreAllPresent() {
        let result = KernelObjectSurfaceProbe.probe()
        let groups = Set(result.entries.map { $0.group })
        XCTAssertEqual(groups.count, 3,
                       "POSIX IPC, socket families, and device files must all run")
    }

    // MARK: - PrivilegeAndSnapshotProbe

    func testAPermittedEscapePrimitiveIsNeverAConfirmedFinding() {
        // This is the sharpest discipline in the project. `setuid(0)`
        // succeeding, or `fs_snapshot_revert` answering ENOENT instead of
        // EPERM, would be extraordinary -- and is still not a finding here,
        // because a finding requires reproduction on a stock iOS 27.0 device
        // with the exact build, entitlements, and signing config recorded.
        // Calling it a violation from a simulator run is how false findings
        // are manufactured.
        let cases: [PrivilegeAndSnapshotProbe.Outcome] = [
            .permitted, .denied, .notFound, .otherError, .notAttempted, .symbolUnavailable
        ]
        for outcome in cases {
            let entry = PrivilegeAndSnapshotProbe.Entry(
                id: "case", group: "privilege", operation: "setuid(0)",
                target: "uid 0", outcome: outcome, errnoName: nil,
                returnedValue: nil, observed: "obs", interpretation: "interp"
            )
            XCTAssertFalse(entry.isBoundaryViolation,
                           "\(outcome) must never be a violation")
        }
    }

    func testEscapePrimitiveGroupsRunTheirControls() {
        // On Darwin each group runs its own positive control first; on a host
        // without Darwin the same five groups are still recorded, one
        // not-attempted placeholder each. What is pinned is that no group is
        // silently absent -- a group missing from the result would read as
        // "tested and found nothing" when it was never tested at all.
        let result = PrivilegeAndSnapshotProbe.probe()
        let groups = Set(result.entries.map { $0.group })
        for expected in [
            "privilege", "apfs-snapshot", "extended-attribute",
            "rename-exchange", "cross-process-fd"
        ] {
            XCTAssertTrue(groups.contains(expected),
                          "the \(expected) group must always be present")
        }
        #if canImport(Darwin)
        for id in [
            "priv-control-setuid-own",
            "xattr-control-create",
            "rename-control-swap-in-container",
            "fd-control-own-pid"
        ] {
            XCTAssertTrue(result.entries.contains { $0.id == id },
                          "\(id) must always be present on Darwin")
        }
        #endif
    }

    func testTheSelfTargetedControlMustNotExpectDenial() {
        // setuid(getuid()) is a no-op set to the caller's own uid and must
        // succeed. If it does not, every set*id(0) refusal in the group is
        // uninterpretable -- which the probe threads through as INCONCLUSIVE.
        #if canImport(Darwin)
        let result = PrivilegeAndSnapshotProbe.probe()
        let control = result.entries.first { $0.id == "priv-control-setuid-own" }
        XCTAssertNotNil(control, "the own-uid control must be recorded on Darwin")
        XCTAssertNotEqual(control?.outcome, .denied,
                          "setting the caller's own uid must not read as a denial")
        #else
        // Without Darwin there is no uid to set, so the control cannot run at
        // all. The placeholder is still recorded rather than omitted.
        let result = PrivilegeAndSnapshotProbe.probe()
        XCTAssertFalse(result.entries.isEmpty)
        #endif
    }

    func testEscapePrimitiveViolationsAreAlwaysEmpty() {
        let result = PrivilegeAndSnapshotProbe.probe()
        XCTAssertTrue(result.violations.isEmpty)
        XCTAssertTrue(result.violationsAlwaysEmpty)
    }

    func testTheFiveGroupsAreAllPresent() {
        let result = PrivilegeAndSnapshotProbe.probe()
        XCTAssertGreaterThanOrEqual(Set(result.entries.map { $0.group }).count, 5,
                                    "privilege, snapshots, xattrs, rename, fds")
    }

    // MARK: - The discipline the three probes share

    func testNoProbeConvertsAReturnValueIntoAViolation() {
        // The single rule that keeps this project honest, checked across all
        // three probes at once: an API returning without error is never, by
        // itself, a demonstrated boundary violation.
        let all: [[Any]] = [
            IOKitUserClientOpenProbe.probe().entries.map { $0.isBoundaryViolation },
            KernelObjectSurfaceProbe.probe().entries.map { $0.isBoundaryViolation },
            PrivilegeAndSnapshotProbe.probe().entries.map { $0.isBoundaryViolation }
        ]
        for group in all {
            for flagged in group {
                XCTAssertEqual(flagged as? Bool, false)
            }
        }
    }

    func testEveryResultCarriesItsControl() {
        // A result with no control in it must be impossible. If any of the
        // three probes ever returns an empty entry list, that is a bug, not a
        // clean run.
        XCTAssertFalse(IOKitUserClientOpenProbe.probe().entries.isEmpty)
        XCTAssertFalse(KernelObjectSurfaceProbe.probe().entries.isEmpty)
        XCTAssertFalse(PrivilegeAndSnapshotProbe.probe().entries.isEmpty)
    }
}
