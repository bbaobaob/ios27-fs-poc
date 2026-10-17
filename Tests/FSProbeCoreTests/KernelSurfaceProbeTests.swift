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

    // MARK: - KqueueProcessWatchProbe

    func testKqueueRegistrationIsNeverAFinding() {
        let cases: [KqueueProcessWatchProbe.Outcome] = [
            .registered, .refused, .notFound, .otherError, .notAttempted, .symbolUnavailable
        ]
        for outcome in cases {
            let entry = KqueueProcessWatchProbe.Entry(
                id: "case", group: "cross-process exit watch (EVFILT_PROC)",
                operation: "kevent(EVFILT_PROC, EV_ADD, NOTE_EXIT)",
                target: "pid 1", outcome: outcome, errnoName: nil,
                returnedValue: nil, observed: "obs", interpretation: "interp"
            )
            XCTAssertFalse(entry.isBoundaryViolation,
                           "\(outcome) must never be a violation")
        }
    }

    func testKqueueControlLeads() {
        // A kevent on the caller's own pid must succeed; that is what makes a
        // refusal on launchd interpretable rather than ambiguous.
        let result = KqueueProcessWatchProbe.probe()
        XCTAssertFalse(result.entries.isEmpty)
        #if canImport(Darwin)
        XCTAssertEqual(result.entries.first?.id, "kq-proc-control-kqueue",
                       "the first entry must be the kqueue() control")
        XCTAssertTrue(result.entries.contains { $0.id == "kq-proc-control-self" },
                      "the own-pid kevent control must be present on Darwin")
        XCTAssertNotEqual(
            result.entries.first { $0.id == "kq-proc-control-self" }?.outcome,
            .refused,
            "a kevent on the caller's own pid must not read as a refusal"
        )
        #else
        // Without Darwin there is no kqueue to open and no pid to watch; the
        // control is still recorded as a placeholder rather than omitted.
        XCTAssertTrue(result.entries.contains { $0.id.hasPrefix("kq-proc-") },
                      "the process-exit control must still be recorded")
        #endif
    }

    func testKqueueViolationsAreAlwaysEmpty() {
        let result = KqueueProcessWatchProbe.probe()
        XCTAssertTrue(result.violations.isEmpty)
        XCTAssertTrue(result.violationsAlwaysEmpty)
    }

    // MARK: - SymlinkAndRaceProbe

    func testSymlinkCreationIsNeverAFinding() {
        // The sharpest discipline in this file: creating a symlink that NAMES
        // an unreachable path is not following one. Calling it a violation
        // would spend the project's credibility on a shape that has not been
        // demonstrated.
        let cases: [SymlinkAndRaceProbe.Outcome] = [
            .permitted, .denied, .loop, .notFound, .otherError, .notAttempted, .symbolUnavailable
        ]
        for outcome in cases {
            let entry = SymlinkAndRaceProbe.Entry(
                id: "case", group: "symlink race, measured not exploited",
                operation: "symlink(/etc/passwd, link)", target: "/etc/passwd",
                outcome: outcome, errnoName: nil, returnedValue: nil,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertFalse(entry.isBoundaryViolation,
                           "\(outcome) must never be a violation")
        }
    }

    func testSymlinkControlLeads() {
        // An in-container linkat must succeed, or every cross-container
        // refusal below it is inconclusive.
        let result = SymlinkAndRaceProbe.probe()
        XCTAssertFalse(result.entries.isEmpty)
        #if canImport(Darwin)
        XCTAssertTrue(result.entries.contains { $0.id == "at-control-linkat-in-container" },
                      "the in-container linkat control must be present on Darwin")
        XCTAssertTrue(result.entries.contains { $0.id == "nofollow-control-create" },
                      "the O_NOFOLLOW positive control must be present on Darwin")
        #else
        // Without Darwin the groups are recorded as placeholders instead.
        XCTAssertEqual(Set(result.entries.map { $0.group }).count, 3)
        #endif
    }

    func testSymlinkViolationsAreAlwaysEmpty() {
        let result = SymlinkAndRaceProbe.probe()
        XCTAssertTrue(result.violations.isEmpty)
        XCTAssertTrue(result.violationsAlwaysEmpty)
    }

    // MARK: - SandboxExtensionProbe

    func testAMintedTokenIsNotAConfirmedFinding() {
        // This is the one place the project could most easily overclaim. A
        // token minted for /etc/passwd would be extraordinary -- and it is
        // still not a finding from a simulator or CI host, because those are
        // macOS processes under a different sandbox. The interpretation prose
        // says what it would mean; the flag stays false.
        let cases: [SandboxExtensionProbe.Outcome] = [
            .issued, .denied, .notFound, .otherError, .notAttempted, .symbolUnavailable
        ]
        for outcome in cases {
            let entry = SandboxExtensionProbe.Entry(
                id: "case", group: "issuing for a path outside the container",
                operation: "sandbox_extension_issue_file(self, /etc/passwd, 0, &handle)",
                target: "/etc/passwd", outcome: outcome, errnoName: nil,
                returnedValue: nil, observed: "obs", interpretation: "interp"
            )
            XCTAssertFalse(entry.isBoundaryViolation,
                           "\(outcome) must never be a violation")
        }
    }

    func testExtensionControlLeads() {
        // Issuing for the app's own file is the positive control: if it
        // returns NULL, every refusal below is indistinguishable from the
        // machinery not running, and the probe is required to SAY so rather
        // than let the group read as a clean result. On the macOS CI runner
        // the app carries no sandbox-extension entitlement, so the control
        // legitimately answers denied -- which is exactly the case this test
        // pins, because a control that fails and is not labelled as failed is
        // how an inconclusive group gets read as a negative finding.
        let result = SandboxExtensionProbe.probe()
        XCTAssertFalse(result.entries.isEmpty)
        #if canImport(Darwin)
        guard let control = result.entries.first(where: { $0.id == "extension-own-issue" }) else {
            XCTFail("the own-file issuance control must be present on Darwin")
            return
        }
        XCTAssertNotEqual(control.outcome, .symbolUnavailable,
                          "the issuance symbol must resolve on Darwin")
        if control.outcome == .denied {
            XCTAssertTrue(
                control.interpretation.contains("CONTROL FAILED"),
                """
                a control that produced no token must be labelled as failed, \
                not silently left to read as a refusal by the boundary
                """
            )
        } else {
            XCTAssertEqual(control.outcome, .issued)
        }
        #else
        XCTAssertEqual(Set(result.entries.map { $0.group }).count, 3)
        #endif
    }

    func testExtensionViolationsAreAlwaysEmpty() {
        let result = SandboxExtensionProbe.probe()
        XCTAssertTrue(result.violations.isEmpty)
        XCTAssertTrue(result.violationsAlwaysEmpty)
    }

    // MARK: - The discipline the three probes share

    func testNoKqueueSymlinkOrExtensionProbeClaimsAViolation() {
        // The single rule that keeps this project honest, checked across all
        // three probes at once: an API returning without error is never, by
        // itself, a demonstrated boundary violation.
        let all: [[Any]] = [
            KqueueProcessWatchProbe.probe().entries.map { $0.isBoundaryViolation },
            SymlinkAndRaceProbe.probe().entries.map { $0.isBoundaryViolation },
            SandboxExtensionProbe.probe().entries.map { $0.isBoundaryViolation }
        ]
        for group in all {
            for flagged in group {
                XCTAssertEqual(flagged as? Bool, false)
            }
        }
    }

    func testEveryRaceAndExtensionResultCarriesItsControl() {
        // A result with no control in it must be impossible. If any of the
        // three probes ever returns an empty entry list, that is a bug, not a
        // clean run.
        XCTAssertFalse(KqueueProcessWatchProbe.probe().entries.isEmpty)
        XCTAssertFalse(SymlinkAndRaceProbe.probe().entries.isEmpty)
        XCTAssertFalse(SandboxExtensionProbe.probe().entries.isEmpty)
    }

    // MARK: - FsGetPathProbe

    func testAPathObtainedByNumberIsNotAConfirmedFinding() {
        // The one question in the project that supplies no path at all. If it
        // answers for an object the app never opened, the app has learned a
        // name it was forbidden to speak -- and that is still not a finding
        // from a simulator or CI host, because those are macOS processes under
        // a different sandbox.
        let cases: [FsGetPathProbe.Outcome] = [
            .answered, .denied, .notFound, .otherError, .notAttempted, .symbolUnavailable
        ]
        for outcome in cases {
            let entry = FsGetPathProbe.Entry(
                id: "case", group: "objects the app has no path to",
                operation: "fsgetpath(buf, 1024, volume, object)",
                target: "object 2 on the app's own volume",
                outcome: outcome, errnoName: nil, returnedValue: nil,
                observed: "obs", interpretation: "interp"
            )
            XCTAssertFalse(entry.isBoundaryViolation,
                           "\(outcome) must never be a violation")
        }
    }

    func testFsGetPathControlLeads() {
        // The control must return the path the app created, addressed by the
        // (volume, object) pair read out of that same file. Without it, a
        // refusal on a foreign object says only that fsgetpath is unavailable.
        let result = FsGetPathProbe.probe()
        XCTAssertFalse(result.entries.isEmpty)
        #if canImport(Darwin)
        guard let control = result.entries.first(
            where: { $0.id == "fsgetpath-control-own-object" }
        ) else {
            XCTFail("the own-object control must be present on Darwin")
            return
        }
        XCTAssertNotEqual(control.outcome, .symbolUnavailable,
                          "fsgetpath must resolve on Darwin")
        if control.outcome != .answered {
            XCTAssertTrue(
                control.interpretation.contains("CONTROL FAILED"),
                """
                a control that produced no path must be labelled as failed, \
                not silently left to read as a refusal by the boundary
                """
            )
        }
        #else
        XCTAssertEqual(Set(result.entries.map { $0.group }).count, 3)
        #endif
    }

    func testFsGetPathViolationsAreAlwaysEmpty() {
        let result = FsGetPathProbe.probe()
        XCTAssertTrue(result.violations.isEmpty)
        XCTAssertTrue(result.violationsAlwaysEmpty)
    }

    func testForeignProbesAreBounded() {
        // Each foreign object id is a syscall, and the interesting answer is
        // whether ANY is answered, not how many there are. The bound is a
        // safety property, so it is pinned.
        XCTAssertEqual(FsGetPathProbe.maxForeignProbes, 24)
    }
}
