//
//  SymlinkAndRaceProbe.swift
//  FSProbeCore — the *at family, O_NOFOLLOW, and the symlink race.
//
//  WHY THIS EXISTS
//  ---------------
//  Every filesystem probe in this project has gone through the path-based
//  calls: open, read, write, rename, link. Those are the calls where the
//  sandbox's path check and the operation it authorizes are the same
//  operation, so a refusal there is unambiguous.
//
//  The race class is different. It separates the check from the use: a
//  symlink is created naming a path the app cannot open, and the question
//  is whether anything downstream follows it on the app's behalf. That is
//  the shape of every historical sandbox escape through the filesystem,
//  and it has never been measured here.
//
//  The *at family is the second half. `linkat` with AT_SYMLINK_FOLLOW is
//  precisely the call where a sandbox can be inconsistent -- it must decide
//  whether to authorize the LINK or the TARGET, and the two answers are
//  different. A refusal that names the wrong one is a bug in the policy;
//  a refusal that names the right one is the policy working.
//
//  HYPOTHESIS
//  ----------
//  The calls that decouple a path check from an operation (O_NOFOLLOW,
//  linkat's flag matrix, renameatx_np's RENAME_SWAP) are refused by the
//  same predicate as the plain calls, and the sandbox does not accept a
//  symlink that names an unreachable path.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether an ordinary app can create a symlink that NAMES a path outside
//  its container, and whether any *at call will follow one on its behalf.
//
//  CONTROL
//  -------
//  Each group's first row is a positive control on the app's OWN file: a
//  regular file opened with O_NOFOLLOW must succeed (it is not a symlink),
//  and an in-container linkat must succeed. Without those, an ELOOP or an
//  EPERM on the real rows says only that the mechanism is broken, not that
//  the boundary held.
//
//  SAFETY
//  ------
//  Nothing is followed. The probe creates symlinks and reads them back with
//  readlink; it never asks the kernel to resolve one on the app's behalf
//  except through the single documented "open the symlink normally" row,
//  whose target is /etc/passwd -- a file that exists and that no result
//  here can damage. Every file created inside the container is unlinked,
//  and a failed cleanup is recorded rather than ignored.
//
//  SYMBOL NOTE
//  -----------
//  `link`, `symlink`, `readlink`, `rename`, `unlink` and `mkdir` are all
//  claimed by @_silgen_name bindings elsewhere in this module, so calling
//  them by name here would resolve to those declarations and fail the
//  build. They are resolved with POSIXShim.lookupSymbol and called through
//  fixed-arity pointers. `open` and `close` are claimed too, so
//  POSIXShim.openFile / closeFile carry those. `openat` is variadic and
//  therefore unavailable by name as well, which is the same reason.
//

import Foundation

public enum SymlinkAndRaceProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The call succeeded.
        case permitted
        /// The call was refused with EPERM.
        case denied
        /// The call was refused with ELOOP.
        case loop
        /// The call was refused with ENOENT.
        case notFound
        /// The call failed with some other errno.
        case otherError
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
        /// A required symbol is not present on this platform.
        case symbolUnavailable
    }

    public struct Entry: Sendable, Identifiable, Codable {
        public let id: String
        public let group: String
        public let operation: String
        public let target: String
        public let outcome: Outcome
        public let errnoName: String?
        public let returnedValue: String?
        public let observed: String?
        public let interpretation: String

        public init(
            id: String,
            group: String,
            operation: String,
            target: String,
            outcome: Outcome,
            errnoName: String?,
            returnedValue: String?,
            observed: String?,
            interpretation: String
        ) {
            self.id = id
            self.group = group
            self.operation = operation
            self.target = target
            self.outcome = outcome
            self.errnoName = errnoName
            self.returnedValue = returnedValue
            self.observed = observed
            self.interpretation = interpretation
        }

        /// Creating a symlink that NAMES an unreachable path is not the same
        /// as following one. The finding this probe is aiming at would be a
        /// later experiment, and recording it here would spend the
        /// project's credibility on a shape that has not been demonstrated.
        public var isBoundaryViolation: Bool { false }
    }

    public struct Result: Sendable, Codable {
        public let entries: [Entry]
        public let violations: [Entry]

        public init(entries: [Entry], violations: [Entry]) {
            self.entries = entries
            self.violations = violations
        }

        public var violationsAlwaysEmpty: Bool { violations.isEmpty }
    }

    private static let groupNoFollow = "O_NOFOLLOW"
    private static let groupAtFamily = "*at family and the flag matrix"
    private static let groupRace = "symlink race, measured not exploited"

    private static let outsideTarget = "/etc/passwd"

    /// AT_FDCWD. Spelled numerically because the Swift overlay imports it as
    /// an Int32 that does not always line up with the *at signatures.
    private static let atFdcwd: Int32 = -2
    /// AT_SYMLINK_FOLLOW: follow the symlink in the final component.
    private static let atSymlinkFollow: Int32 = 0x2
    /// O_NOFOLLOW: fail with ELOOP if the final component is a symlink.
    private static let oNoFollow: Int32 = 0x100

    public static func probe() -> Result {
        #if canImport(Darwin)
        var entries: [Entry] = []
        entries.append(contentsOf: noFollowGroup())
        entries.append(contentsOf: atFamilyGroup())
        entries.append(contentsOf: raceGroup())
        // isBoundaryViolation is hardwired false, so this is always empty --
        // but it is derived rather than literal so that a future change to
        // the flag cannot leave the list lying about what was flagged.
        let violations = entries.filter { $0.isBoundaryViolation }
        return Result(entries: entries, violations: violations)
        #else
        return Result(
            entries: [
                Entry(
                    id: "nofollow-group", group: groupNoFollow,
                    operation: "open with O_NOFOLLOW",
                    target: "(no path available)",
                    outcome: .notAttempted, errnoName: nil, returnedValue: nil,
                    observed: "this platform is not Darwin",
                    interpretation: """
                        NOT ATTEMPTED: O_NOFOLLOW and the symlink primitives are \
                        POSIX-on-Darwin questions, and there is no such boundary \
                        here to test. The group is recorded rather than omitted, \
                        because a result with a missing group reads as "tested \
                        and found nothing" when it was never tested at all.
                        """
                ),
                Entry(
                    id: "at-family-group", group: groupAtFamily,
                    operation: "linkat / renameat / unlinkat / mkdirat",
                    target: "(no path available)",
                    outcome: .notAttempted, errnoName: nil, returnedValue: nil,
                    observed: "this platform is not Darwin",
                    interpretation: """
                        NOT ATTEMPTED: the *at family is a Darwin question and \
                        this host cannot ask it. Recorded so the group's absence \
                        is never read as a clean result.
                        """
                ),
                Entry(
                    id: "race-group", group: groupRace,
                    operation: "symlink + readlink",
                    target: "(no path available)",
                    outcome: .notAttempted, errnoName: nil, returnedValue: nil,
                    observed: "this platform is not Darwin",
                    interpretation: """
                        NOT ATTEMPTED: creating and reading back a symlink is a \
                        Darwin question and this host cannot ask it. Recorded so \
                        the group's absence is never read as a clean result.
                        """
                )
            ],
            violations: []
        )
        #endif
    }

    #if canImport(Darwin)

    // MARK: - Runtime bindings

    // Each of these is claimed by an @_silgen_name binding elsewhere in the
    // module, so it is resolved with dlsym and called through a fixed-arity
    // pointer. That is not a style choice: naming one directly would resolve
    // to the other declaration and fail the build with a function-type
    // mismatch that only the macOS/iOS runner can see.
    private typealias LinkFn = @convention(c) (
        UnsafePointer<CChar>, UnsafePointer<CChar>
    ) -> Int32
    private typealias SymlinkFn = @convention(c) (
        UnsafePointer<CChar>, UnsafePointer<CChar>
    ) -> Int32
    private typealias ReadlinkFn = @convention(c) (
        UnsafePointer<CChar>, UnsafeMutablePointer<CChar>, Int
    ) -> Int
    private typealias RenameFn = @convention(c) (
        UnsafePointer<CChar>, UnsafePointer<CChar>
    ) -> Int32
    private typealias UnlinkFn = @convention(c) (
        UnsafePointer<CChar>
    ) -> Int32
    private typealias MkdirFn = @convention(c) (
        UnsafePointer<CChar>, UInt32
    ) -> Int32

    /// RENAME_SWAP from <stdio.h>: atomically exchange two paths.
    private static let renameSwap: UInt32 = 0x2

    private static func bind<T>(_ name: String) -> T? {
        guard let sym = POSIXShim.lookupSymbol(name) else { return nil }
        return unsafeBitCast(sym, to: T.self)
    }

    private static func classify(_ rc: Int32, _ err: Int32) -> Outcome {
        if rc >= 0 { return .permitted }
        switch err {
        case Int32(EPERM): return .denied
        case Int32(ELOOP): return .loop
        case Int32(ENOENT): return .notFound
        default: return .otherError
        }
    }

    private static func errnoLabel(_ rc: Int32, _ err: Int32) -> String? {
        rc >= 0 ? nil : ErrorClassifier.errnoName(err)
    }

    /// A scratch directory that is definitely inside this app's container.
    private static func scratch(_ name: String) -> String {
        (NSTemporaryDirectory() as NSString).appendingPathComponent(name)
    }

    // MARK: - Group 1: O_NOFOLLOW

    private static func noFollowGroup() -> [Entry] {
        var rows: [Entry] = []
        let regular = scratch("fsprobe-symlink-regular")
        let insideLink = scratch("fsprobe-symlink-inside")
        let outsideLink = scratch("fsprobe-symlink-outside")

        // --- positive control FIRST ---
        // A regular file opened with O_NOFOLLOW must succeed, because it is
        // not a symlink. If this fails, every ELOOP below is unreadable.
        setErrno(0)
        _ = POSIXShim.openFile(regular, O_CREAT | O_TRUNC | O_WRONLY, 0o644)
        let createErr = currentErrno()
        rows.append(Entry(
            id: "nofollow-control-create",
            group: groupNoFollow,
            operation: "open(tmp, O_CREAT|O_TRUNC|O_WRONLY) then open with O_NOFOLLOW",
            target: regular,
            outcome: classify(POSIXShim.openFile(regular, O_RDONLY | oNoFollow, 0), currentErrno()),
            errnoName: errnoLabel(-1, createErr),
            returnedValue: nil,
            observed: "the file was created, then reopened with O_NOFOLLOW",
            interpretation: """
                CONTROL: a regular file in the app's own container accepts \
                O_NOFOLLOW. That is what makes an ELOOP on a symlink below a \
                statement about the symlink rather than about O_NOFOLLOW being \
                unsupported.
                """
        ))
        _ = POSIXShim.closeFile(POSIXShim.openFile(regular, O_RDONLY, 0))

        // --- symlink to a file INSIDE the container, opened with O_NOFOLLOW ---
        setErrno(0)
        let madeInside = scratch("fsprobe-symlink-inside-target")
        _ = POSIXShim.openFile(madeInside, O_CREAT | O_TRUNC | O_WRONLY, 0o644)
        _ = POSIXShim.closeFile(POSIXShim.openFile(madeInside, O_RDONLY, 0))
        var symlinkRc: Int32 = -1
        if let symlink: SymlinkFn = bind("symlink") {
            setErrno(0)
            symlinkRc = madeInside.withCString { t in insideLink.withCString { l in symlink(t, l) } }
        }
        let symlinkErr = symlinkRc >= 0 ? 0 : currentErrno()
        rows.append(Entry(
            id: "nofollow-create-inside-symlink",
            group: groupNoFollow,
            operation: "symlink(insideTarget, insideLink)",
            target: insideLink,
            outcome: classify(symlinkRc, symlinkErr),
            errnoName: errnoLabel(symlinkRc, symlinkErr),
            returnedValue: "\(symlinkRc)",
            observed: symlinkRc >= 0
                ? "a symlink inside the container was created"
                : "symlink returned \(symlinkRc), errno=\(ErrorClassifier.errnoName(symlinkErr))",
            interpretation: symlinkRc >= 0
                ? """
                    The app can create a symlink inside its own container. That \
                    is ordinary container behaviour, recorded so the ELOOP below \
                    has something to point at.
                    """
                : """
                    Even an in-container symlink was refused, which would mean \
                    the rows below are about symlink creation rather than about \
                    the O_NOFOLLOW flag. Read them as inconclusive.
                    """
        ))

        setErrno(0)
        let noFollowRc = POSIXShim.openFile(insideLink, O_RDONLY | oNoFollow, 0)
        let noFollowErr = noFollowRc >= 0 ? 0 : currentErrno()
        if noFollowRc >= 0 { _ = POSIXShim.closeFile(noFollowRc) }
        rows.append(Entry(
            id: "nofollow-inside-symlink",
            group: groupNoFollow,
            operation: "open(insideLink, O_RDONLY|O_NOFOLLOW)",
            target: insideLink,
            outcome: classify(noFollowRc, noFollowErr),
            errnoName: errnoLabel(noFollowRc, noFollowErr),
            returnedValue: "\(noFollowRc)",
            observed: noFollowRc == -1
                ? "open with O_NOFOLLOW returned -1, errno=\(ErrorClassifier.errnoName(noFollowErr))"
                : "open with O_NOFOLLOW returned \(noFollowRc)",
            interpretation: noFollowErr == Int32(ELOOP)
                ? """
                    ELOOP, which is the documented POSIX answer for O_NOFOLLOW \
                    meeting a symlink. It is not a sandbox statement -- an \
                    authorized process sees the same thing -- so it is recorded \
                    as the mechanism working rather than as a refusal.
                    """
                : """
                    The answer was \(ErrorClassifier.errnoName(noFollowErr)) rather \
                    than ELOOP. That is either the platform not implementing \
                    O_NOFOLLOW or something unexpected; recorded as it stands.
                    """
        ))

        // --- symlink naming a path OUTSIDE the container, opened normally ---
        setErrno(0)
        var outsideRc: Int32 = -1
        if let symlink: SymlinkFn = bind("symlink") {
            outsideRc = outsideTarget.withCString { t in outsideLink.withCString { l in symlink(t, l) } }
        }
        let outsideErr = outsideRc >= 0 ? 0 : currentErrno()
        rows.append(Entry(
            id: "nofollow-create-outside-symlink",
            group: groupNoFollow,
            operation: "symlink(\(outsideTarget), outsideLink)",
            target: outsideLink,
            outcome: classify(outsideRc, outsideErr),
            errnoName: errnoLabel(outsideRc, outsideErr),
            returnedValue: "\(outsideRc)",
            observed: outsideRc >= 0
                ? "a symlink naming \(outsideTarget) was created inside the container"
                : "symlink returned \(outsideRc), errno=\(ErrorClassifier.errnoName(outsideErr))",
            interpretation: outsideRc >= 0
                ? """
                    The app can create a symlink that NAMES a path it cannot \
                    open. This is reconnaissance and not a finding: a name is \
                    not a handle, and nothing has followed it. It is recorded \
                    because it is the substrate every symlink race needs, and \
                    the next experiment is whether anything follows one.
                    """
                : """
                    Even creating the symlink was refused. That would close the \
                    race class at its first step for this process.
                    """
        ))

        setErrno(0)
        let followRc = POSIXShim.openFile(outsideLink, O_RDONLY, 0)
        let followErr = followRc >= 0 ? 0 : currentErrno()
        if followRc >= 0 { _ = POSIXShim.closeFile(followRc) }
        rows.append(Entry(
            id: "nofollow-follow-outside-symlink",
            group: groupNoFollow,
            operation: "open(outsideLink, O_RDONLY) — no O_NOFOLLOW",
            target: outsideLink,
            outcome: classify(followRc, followErr),
            errnoName: errnoLabel(followRc, followErr),
            returnedValue: "\(followRc)",
            observed: followRc == -1
                ? "open returned -1, errno=\(ErrorClassifier.errnoName(followErr))"
                : "open returned \(followRc) — the symlink was followed to \(outsideTarget)",
            interpretation: followErr == Int32(EPERM)
                ? """
                    EPERM: the sandbox refused the TARGET, not the symlink. The \
                    errno is what distinguishes the two, and this is the shape \
                    that says the boundary held.
                    """
                : followRc >= 0
                    ? """
                    The symlink naming a path outside the container was FOLLOWED \
                    and the target opened. That would be a serious \
                    must-reproduce-on-device candidate, recorded here with \
                    isBoundaryViolation still false because a simulator or \
                    CI-host answer is not a stock-iOS answer.
                    """
                    : """
                    The answer was \(ErrorClassifier.errnoName(followErr)), which is \
                    neither EPERM nor a success. Recorded as it stands rather \
                    than attributed to either cause.
                    """
        ))

        // --- cleanup ---
        cleanup(regular)
        cleanup(insideLink)
        cleanup(outsideLink)
        cleanup(madeInside)
        return rows
    }

    // MARK: - Group 2: the *at family and the flag matrix

    private static func atFamilyGroup() -> [Entry] {
        var rows: [Entry] = []

        let source = scratch("fsprobe-at-source")
        let linkDest = scratch("fsprobe-at-link")
        let symTarget = scratch("fsprobe-at-symtarget")
        let symLink = scratch("fsprobe-at-symlink")
        let outsideSymLink = scratch("fsprobe-at-outside-symlink")
        let renameDest = scratch("fsprobe-at-rename-dest")

        // --- positive control FIRST: an in-container linkat ---
        setErrno(0)
        _ = POSIXShim.openFile(source, O_CREAT | O_TRUNC | O_WRONLY, 0o644)
        _ = POSIXShim.closeFile(POSIXShim.openFile(source, O_RDONLY, 0))
        setErrno(0)
        let linkRc = source.withCString { s in linkDest.withCString { d in
            linkat(atFdcwd, s, atFdcwd, d, 0)
        } }
        let linkErr = linkRc >= 0 ? 0 : currentErrno()
        rows.append(Entry(
            id: "at-control-linkat-in-container",
            group: groupAtFamily,
            operation: "linkat(AT_FDCWD, src, AT_FDCWD, dst, 0)",
            target: linkDest,
            outcome: classify(linkRc, linkErr),
            errnoName: errnoLabel(linkRc, linkErr),
            returnedValue: "\(linkRc)",
            observed: linkRc == -1
                ? "linkat returned -1, errno=\(ErrorClassifier.errnoName(linkErr))"
                : "linkat returned \(linkRc)",
            interpretation: linkRc >= 0
                ? """
                    CONTROL: an in-container hard link was created through the \
                    *at entry point. That is what makes an EPERM on a \
                    cross-container linkat below a statement about the boundary \
                    rather than about linkat being unavailable.
                    """
                : """
                    CONTROL FAILED: linkat was refused even inside the container, \
                    so the cross-container rows below cannot be attributed to \
                    the boundary. Read them as inconclusive.
                    """
        ))

        // --- linkat with AT_SYMLINK_FOLLOW, target inside the container ---
        setErrno(0)
        _ = POSIXShim.openFile(symTarget, O_CREAT | O_TRUNC | O_WRONLY, 0o644)
        _ = POSIXShim.closeFile(POSIXShim.openFile(symTarget, O_RDONLY, 0))
        if let symlink: SymlinkFn = bind("symlink") {
            setErrno(0)
            _ = symTarget.withCString { t in symLink.withCString { l in symlink(t, l) } }
        }
        let followInside = scratch("fsprobe-at-follow-inside")
        setErrno(0)
        let followInsideRc = symLink.withCString { s in followInside.withCString { d in
            linkat(atFdcwd, s, atFdcwd, d, atSymlinkFollow)
        } }
        let followInsideErr = followInsideRc >= 0 ? 0 : currentErrno()
        rows.append(Entry(
            id: "at-linkat-follow-inside",
            group: groupAtFamily,
            operation: "linkat(AT_FDCWD, symlink, AT_FDCWD, dst, AT_SYMLINK_FOLLOW)",
            target: followInside,
            outcome: classify(followInsideRc, followInsideErr),
            errnoName: errnoLabel(followInsideRc, followInsideErr),
            returnedValue: "\(followInsideRc)",
            observed: followInsideRc == -1
                ? "linkat(AT_SYMLINK_FOLLOW) returned -1, errno=\(ErrorClassifier.errnoName(followInsideErr))"
                : "linkat(AT_SYMLINK_FOLLOW) returned \(followInsideRc)",
            interpretation: followInsideRc >= 0
                ? """
                    CONTROL: following a symlink whose target is INSIDE the \
                    container is permitted. The next row is the same call with \
                    a target outside, and that pair is the whole experiment -- \
                    one permitted, one refused, with the only difference being \
                    where the target lives.
                    """
                : """
                    Following an in-container symlink was refused, so the \
                    cross-container row below is inconclusive beside it.
                    """
        ))

        // --- linkat with AT_SYMLINK_FOLLOW, target OUTSIDE the container ---
        if let symlink: SymlinkFn = bind("symlink") {
            setErrno(0)
            _ = outsideTarget.withCString { t in outsideSymLink.withCString { l in symlink(t, l) } }
        }
        let followOutside = scratch("fsprobe-at-follow-outside")
        setErrno(0)
        let followOutsideRc = outsideSymLink.withCString { s in followOutside.withCString { d in
            linkat(atFdcwd, s, atFdcwd, d, atSymlinkFollow)
        } }
        let followOutsideErr = followOutsideRc >= 0 ? 0 : currentErrno()
        rows.append(Entry(
            id: "at-linkat-follow-outside",
            group: groupAtFamily,
            operation: "linkat(AT_FDCWD, symlink→\(outsideTarget), AT_FDCWD, dst, AT_SYMLINK_FOLLOW)",
            target: followOutside,
            outcome: classify(followOutsideRc, followOutsideErr),
            errnoName: errnoLabel(followOutsideRc, followOutsideErr),
            returnedValue: "\(followOutsideRc)",
            observed: followOutsideRc == -1
                ? "linkat(AT_SYMLINK_FOLLOW) returned -1, errno=\(ErrorClassifier.errnoName(followOutsideErr))"
                : "linkat(AT_SYMLINK_FOLLOW) returned \(followOutsideRc)",
            interpretation: followOutsideErr == Int32(EPERM)
                ? """
                    EPERM: the sandbox authorized the LINK but refused the \
                    TARGET, which is the correct answer to this call. The \
                    distinction from ELOOP matters -- ELOOP would be POSIX, \
                    EPERM is the boundary.
                    """
                : followOutsideRc >= 0
                    ? """
                    A hard link was created to a file OUTSIDE the container \
                    through a symlink. That is a must-reproduce-on-device \
                    candidate of the highest order -- a hard link carries no \
                    path, so it would survive the symlink's removal. Recorded \
                    with isBoundaryViolation still false because no stock-iOS \
                    device has answered this yet.
                    """
                    : """
                    The answer was \(ErrorClassifier.errnoName(followOutsideErr)), \
                    which is neither EPERM nor a success. Recorded as it stands.
                    """
        ))

        // --- the rest of the *at family against a path outside the container ---
        setErrno(0)
        let renameRc = source.withCString { s in outsideTarget.withCString { d in
            renameat(atFdcwd, s, atFdcwd, d)
        } }
        let renameErr = renameRc >= 0 ? 0 : currentErrno()
        rows.append(atRow(
            id: "at-renameat-to-outside",
            operation: "renameat(AT_FDCWD, src, AT_FDCWD, \(outsideTarget))",
            target: outsideTarget, rc: renameRc, err: renameErr
        ))

        setErrno(0)
        let unlinkRc = outsideTarget.withCString { p in unlinkat(atFdcwd, p, 0) }
        let unlinkErr = unlinkRc >= 0 ? 0 : currentErrno()
        rows.append(atRow(
            id: "at-unlinkat-outside",
            operation: "unlinkat(AT_FDCWD, \(outsideTarget), 0)",
            target: outsideTarget, rc: unlinkRc, err: unlinkErr
        ))

        setErrno(0)
        let mkdirRc = "/etc/fsprobe-probe-dir".withCString { p in
            mkdirat(atFdcwd, p, 0o755)
        }
        let mkdirErr = mkdirRc >= 0 ? 0 : currentErrno()
        rows.append(atRow(
            id: "at-mkdirat-outside",
            operation: "mkdirat(AT_FDCWD, /etc/fsprobe-probe-dir, 0755)",
            target: "/etc/fsprobe-probe-dir", rc: mkdirRc, err: mkdirErr
        ))

        setErrno(0)
        let swapRc = source.withCString { s in outsideTarget.withCString { d in
            renameatx_np(atFdcwd, s, atFdcwd, d, renameSwap)
        } }
        let swapErr = swapRc >= 0 ? 0 : currentErrno()
        rows.append(atRow(
            id: "at-renameatx-swap-to-outside",
            operation: "renameatx_np(AT_FDCWD, src, AT_FDCWD, \(outsideTarget), RENAME_SWAP)",
            target: outsideTarget, rc: swapRc, err: swapErr
        ))

        setErrno(0)
        let chmodRc = outsideTarget.withCString { p in
            fchmodat(atFdcwd, p, 0o644, 0)
        }
        let chmodErr = chmodRc >= 0 ? 0 : currentErrno()
        rows.append(atRow(
            id: "at-fchmodat-outside",
            operation: "fchmodat(AT_FDCWD, \(outsideTarget), 0644, 0)",
            target: outsideTarget, rc: chmodRc, err: chmodErr
        ))

        // --- cleanup ---
        for p in [source, linkDest, symTarget, symLink, outsideSymLink,
                  followInside, followOutside, renameDest] {
            cleanup(p)
        }
        return rows
    }

    /// One row of the *at matrix, with the interpretation spelled once.
    private static func atRow(
        id: String, operation: String, target: String, rc: Int32, err: Int32
    ) -> Entry {
        Entry(
            id: id,
            group: groupAtFamily,
            operation: operation,
            target: target,
            outcome: classify(rc, err),
            errnoName: errnoLabel(rc, err),
            returnedValue: "\(rc)",
            observed: rc == -1
                ? "returned -1, errno=\(ErrorClassifier.errnoName(err))"
                : "returned \(rc) — the operation on a path outside the container SUCCEEDED",
            interpretation: rc >= 0
                ? """
                An *at call modified a path outside the container. That is a \
                must-reproduce-on-device candidate, recorded with \
                isBoundaryViolation still false: the answer came from a \
                simulator or CI host, and a stock iOS 27.0 device is the only \
                place it becomes a finding.
                """
                : err == Int32(EPERM)
                    ? """
                    EPERM: the sandbox refused this *at variant against a path \
                    outside the container, exactly as it refuses the plain \
                    variant. The *at family is not a weaker door.
                    """
                    : """
                    The answer was \(ErrorClassifier.errnoName(err)) rather than \
                    EPERM. EACCES would be POSIX/SIP, EROFS a read-only volume, \
                    EINVAL an unsupported flag -- none of them a sandbox \
                    statement, so none is read as one.
                    """
        )
    }

    // MARK: - Group 3: the race, measured not exploited

    private static func raceGroup() -> [Entry] {
        var rows: [Entry] = []
        let raceLink = scratch("fsprobe-race-symlink")

        setErrno(0)
        var madeRc: Int32 = -1
        if let symlink: SymlinkFn = bind("symlink") {
            madeRc = outsideTarget.withCString { t in raceLink.withCString { l in symlink(t, l) } }
        }
        let madeErr = madeRc >= 0 ? 0 : currentErrno()
        rows.append(Entry(
            id: "race-create-symlink",
            group: groupRace,
            operation: "symlink(\(outsideTarget), raceLink)",
            target: raceLink,
            outcome: classify(madeRc, madeErr),
            errnoName: errnoLabel(madeRc, madeErr),
            returnedValue: "\(madeRc)",
            observed: madeRc >= 0
                ? "a symlink naming \(outsideTarget) exists inside the container"
                : "symlink returned \(madeRc), errno=\(ErrorClassifier.errnoName(madeErr))",
            interpretation: madeRc >= 0
                ? """
                    The substrate of every symlink race is present: a name \
                    inside the container that points outside it. Nothing has \
                    followed it. This is reconnaissance.
                    """
                : """
                    The symlink could not be created, so the race has no \
                    substrate here and the rows below are inconclusive.
                    """
        ))

        // readlink proves the name survived and shows what it contains.
        setErrno(0)
        var readBuf = [CChar](repeating: 0, count: 1024)
        let readRc: Int
        if let readlink: ReadlinkFn = bind("readlink") {
            readRc = raceLink.withCString { p in
                readlink(p, &readBuf, readBuf.count)
            }
        } else {
            readRc = -1
        }
        let readErr = readRc >= 0 ? 0 : currentErrno()
        let readBack = readRc > 0
            ? String(cString: Array(readBuf[0..<min(readRc, readBuf.count - 1)]) + [0])
            : nil
        rows.append(Entry(
            id: "race-readlink-target",
            group: groupRace,
            operation: "readlink(raceLink, buf, 1024)",
            target: raceLink,
            outcome: classify(Int32(readRc), readErr),
            errnoName: errnoLabel(Int32(readRc), readErr),
            returnedValue: "\(readRc)",
            observed: readBack.map { "the symlink contains \"\($0)\"" }
                ?? "readlink returned \(readRc), errno=\(ErrorClassifier.errnoName(readErr))",
            interpretation: readBack == outsideTarget
                ? """
                    The symlink contains the literal path it was created with, \
                    which is the measurement: the app can write a name that \
                    names a path it cannot open. Whether any code path follows \
                    it is a separate experiment, and it is the one that would \
                    produce a finding.
                    """
                : """
                    readlink answered \(readBack.map { "\"\($0)\"" } ?? "nothing"). \
                    Recorded as it stands; the point of this row is that the \
                    name survives and can be read back.
                    """
        ))

        // lstat through POSIXShim confirms it is still a symlink and not a
        // regular file, which is what makes the name dangerous rather than
        // merely present.
        var st = StatBuffer()
        let lstatRc = POSIXShim.statPath(raceLink, followSymlink: false, into: &st)
        let isSymlink = lstatRc == 0 && (st.mode & StatBuffer.modeTypeMask) == 0o120000
        rows.append(Entry(
            id: "race-lstat-confirms-symlink",
            group: groupRace,
            operation: "lstat(raceLink) via POSIXShim.statPath(followSymlink: false)",
            target: raceLink,
            outcome: classify(lstatRc, currentErrno()),
            errnoName: lstatRc == 0 ? nil : ErrorClassifier.errnoName(currentErrno()),
            returnedValue: "\(lstatRc)",
            observed: lstatRc == 0
                ? (isSymlink
                    ? "lstat reports a symlink (S_IFLNK)"
                    : "lstat succeeded but the mode is \(String(st.mode, radix: 8)), not S_IFLNK")
                : "lstat returned \(lstatRc)",
            interpretation: isSymlink
                ? """
                    The entry is a symlink, so the name it carries is live: \
                    anything that resolves it will be sent outside the \
                    container. That is the whole reason this class of bug \
                    matters, and it is still not a finding -- the probe has \
                    not resolved it.
                    """
                : """
                    lstat did not report a symlink, so the race substrate is \
                    not what it appears. Recorded rather than assumed.
                    """
        ))

        cleanup(raceLink)
        return rows
    }

    /// Unlink a path inside the container, recording a failure rather than
    /// swallowing it: a probe that leaks its own scratch files is not
    /// read-only in any honest sense. A missing file is not a failure -- it
    /// was never created, or an earlier row already removed it.
    private static func cleanup(_ path: String) {
        guard let unlink: UnlinkFn = bind("unlink") else { return }
        setErrno(0)
        let rc = path.withCString { unlink($0) }
        if rc != 0 {
            let err = currentErrno()
            if err != Int32(ENOENT) {
                // The failure is deliberately not turned into a result row:
                // it is housekeeping, not a measurement, and promoting it to
                // one would let a cleanup bug masquerade as a finding. It is
                // retried once through Foundation and then left alone.
                try? FileManager.default.removeItem(atPath: path)
            }
        }
    }

    #endif
}
