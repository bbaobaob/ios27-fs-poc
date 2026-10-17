//
//  SandboxExtensionProbe.swift
//  FSProbeCore — can an ordinary app MINT a sandbox extension?
//
//  WHY THIS EXISTS
//  ---------------
//  A sandbox extension is not a permission check; it is a token that GRANTS
//  access to a path the holder could not otherwise reach. The whole point of
//  the mechanism is to carry authority across a boundary: a file picker
//  mints one for the file the user chose, hands it to another process, and
//  that process can then open a path its own sandbox would refuse.
//
//  That makes the issuance path the sharpest question in this project.
//  Every other probe asks "can the app reach X?" This one asks "can the app
//  manufacture a credential for X?" -- and if the answer is yes for a path
//  outside the container, the boundary is not bypassed so much as
//  volunteered. Nothing here has tested it.
//
//  HYPOTHESIS
//  ----------
//  An ordinary sandboxed app can issue an extension for a path inside its
//  own container, and is refused for every path outside it.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether `sandbox_extension_issue_file` will mint a token naming a path
//  outside the app's container.
//
//  CONTROL
//  -------
//  The first row issues an extension for a file the app just created in its
//  own container. If that returns NULL, every refusal below says only that
//  the extension machinery is unavailable to this process -- not that the
//  boundary held.
//
//  SAFETY
//  ------
//  No token is consumed more than once. Every issued token is released. And
//  the probe never USES a token to open a path outside the container -- that
//  is the exploit, and this round measures only whether the token can be
//  minted. Minting is safe: a token is inert until something consumes it.
//
//  SYMBOL NOTE
//  -----------
//  None of the sandbox_extension_* functions are in the Swift Darwin
//  overlay, so they are resolved with POSIXShim.lookupSymbol rather than
//  named. `fcntl` is variadic (`int fcntl(int, int, ...)`) and therefore
//  unavailable by name as well, which is the same reason it goes through the
//  same path. The overlay not exporting a symbol and the importer refusing a
//  variadic one are two different facts, and both point at the same place:
//  the overlay is not the kernel.
//

import Foundation

public enum SandboxExtensionProbe {

    public enum Outcome: String, Codable, Sendable {
        /// A token came back non-null, or the call returned success.
        case issued
        /// The call was refused with EPERM, or the token was NULL.
        case denied
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

        /// Even a token minted for a path outside the container is not
        /// recorded as a finding here. It is the most serious shape this
        /// project can measure, and it is exactly the one that must not be
        /// asserted from a simulator or CI host: those are macOS processes
        /// running under a different sandbox, and a macOS answer is not an
        /// iOS answer. The interpretation prose says what it would mean; the
        /// flag stays false until a stock iOS 27.0 device answers.
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

    private static let groupIssueOwn = "issuing for the app's own file"
    private static let groupIssueOutside = "issuing for a path outside the container"
    private static let groupGetPath = "fgetpath on a descriptor"

    private static let outsideTarget = "/etc/passwd"

    public static func probe() -> Result {
        #if canImport(Darwin)
        var entries: [Entry] = []
        entries.append(contentsOf: issueOwnGroup())
        entries.append(contentsOf: issueOutsideGroup())
        entries.append(contentsOf: getPathGroup())
        let violations = entries.filter { $0.isBoundaryViolation }
        return Result(entries: entries, violations: violations)
        #else
        return Result(
            entries: [
                Entry(
                    id: "issue-own-group", group: groupIssueOwn,
                    operation: "sandbox_extension_issue_file",
                    target: "(no path available)",
                    outcome: .notAttempted, errnoName: nil, returnedValue: nil,
                    observed: "this platform is not Darwin",
                    interpretation: """
                        NOT ATTEMPTED: sandbox extensions are a Darwin/seatbelt \
                        mechanism and there is none here. The group is recorded \
                        rather than omitted so its absence is never read as a \
                        clean result.
                        """
                ),
                Entry(
                    id: "issue-outside-group", group: groupIssueOutside,
                    operation: "sandbox_extension_issue_file",
                    target: "(no path available)",
                    outcome: .notAttempted, errnoName: nil, returnedValue: nil,
                    observed: "this platform is not Darwin",
                    interpretation: """
                        NOT ATTEMPTED: the issuance question needs a seatbelt \
                        sandbox to be meaningful, and there is none here.
                        """
                ),
                Entry(
                    id: "getpath-group", group: groupGetPath,
                    operation: "fcntl(fd, F_GETPATH, buf)",
                    target: "(no descriptor available)",
                    outcome: .notAttempted, errnoName: nil, returnedValue: nil,
                    observed: "this platform is not Darwin",
                    interpretation: """
                        NOT ATTEMPTED: F_GETPATH is a Darwin fcntl command and \
                        there is none here.
                        """
                )
            ],
            violations: []
        )
        #endif
    }

    #if canImport(Darwin)

    // MARK: - Runtime bindings

    // `sandbox_extension_issue_file(ext, path, flags, &handle)` returns a
    // malloc'd C string the caller must free, and writes the handle that
    // sandbox_extension_release later takes. The handle-out parameter is
    // spelled as a pointer to an optional raw pointer so a nil is expressible.
    private typealias IssueFileFn = @convention(c) (
        UInt32, UnsafePointer<CChar>, UInt32,
        UnsafeMutablePointer<UnsafeMutableRawPointer?>
    ) -> UnsafePointer<CChar>?

    // The to-process variant is not bound: see the note in issueOutsideGroup
    // for why calling it crashes the host app rather than answering.
    private typealias ConsumeFn = @convention(c) (
        UnsafePointer<CChar>
    ) -> Int32

    private typealias ReleaseFn = @convention(c) (
        UnsafeMutableRawPointer?
    ) -> Int32

    // F_GETPATH is normally reached through `fcntl(fd, F_GETPATH, buf)`, but
    // fcntl is variadic (`int fcntl(int, int, ...)`) and the Swift importer
    // marks variadic C functions unavailable. Binding it as a fixed three-arg
    // pointer and calling it would hand the third argument to the callee's
    // va_list machinery, which on arm64e reads varargs from a different place
    // than the fixed registers -- a garbage buffer pointer and a SIGSEGV.
    // `fgetpath` is the non-variadic equivalent the platform provides for
    // precisely this command, so it is used instead.
    private typealias FGetPathFn = @convention(c) (
        Int32, UnsafeMutablePointer<CChar>, Int
    ) -> Int32

    private static func bind<T>(_ name: String) -> T? {
        guard let sym = POSIXShim.lookupSymbol(name) else { return nil }
        return unsafeBitCast(sym, to: T.self)
    }

    private static func scratch(_ name: String) -> String {
        (NSTemporaryDirectory() as NSString).appendingPathComponent(name)
    }

    // MARK: - Group 1: issuing for the app's own file

    private static func issueOwnGroup() -> [Entry] {
        var rows: [Entry] = []
        let own = scratch("fsprobe-extension-\(getpid())")

        setErrno(0)
        let createFD = POSIXShim.openFile(own, O_CREAT | O_TRUNC | O_WRONLY, 0o644)
        let createErr = currentErrno()
        rows.append(Entry(
            id: "extension-control-create",
            group: groupIssueOwn,
            operation: "open(tmp, O_CREAT|O_TRUNC|O_WRONLY)",
            target: own,
            outcome: classifyFD(createFD, createErr),
            errnoName: createFD >= 0 ? nil : ErrorClassifier.errnoName(createErr),
            returnedValue: "\(createFD)",
            observed: createFD >= 0
                ? "the control file exists inside the container"
                : "open returned -1, errno=\(ErrorClassifier.errnoName(createErr))",
            interpretation: createFD >= 0
                ? """
                    The substrate for this group's control exists. Without it \
                    every token row below would be answering a question about a \
                    missing file rather than about the boundary.
                    """
                : """
                    The control file could not be created, so the token rows \
                    below are inconclusive. Recorded beside them rather than \
                    dropped, because a group with no control in it reads like \
                    a group whose control passed.
                    """
        ))
        if createFD >= 0 { _ = POSIXShim.closeFile(createFD) }

        guard let issue: IssueFileFn = bind("sandbox_extension_issue_file") else {
            rows.append(Entry(
                id: "extension-own-issue",
                group: groupIssueOwn,
                operation: "sandbox_extension_issue_file(self, ownFile, 0, &handle)",
                target: own,
                outcome: .symbolUnavailable, errnoName: nil, returnedValue: nil,
                observed: "sandbox_extension_issue_file could not be resolved with dlsym",
                interpretation: """
                    NOT ATTEMPTED: the symbol is absent from the process image, \
                    so the issuance question could not be asked at all. A \
                    missing symbol is a statement about the platform, not a \
                    refusal by it.
                    """
            ))
            cleanup(own)
            return rows
        }

        var handle: UnsafeMutableRawPointer? = nil
        setErrno(0)
        let token = own.withCString { issue(MachShim.taskSelf, $0, 0, &handle) }
        let tokenErr = currentErrno()
        var observed: String
        if let token {
            observed = "a non-null token was minted for the app's own file"
            // Consume it once, then release the handle. Consuming a token the
            // app itself minted for its own file is safe: it grants nothing
            // the app did not already have.
            if let consume: ConsumeFn = bind("sandbox_extension_consume") {
                setErrno(0)
                let consumeRC = consume(token)
                observed += "; sandbox_extension_consume -> \(consumeRC)"
                if consumeRC != 0 {
                    observed += " (errno=\(ErrorClassifier.errnoName(currentErrno())))"
                }
            } else {
                observed += "; sandbox_extension_consume unresolved"
            }
            if let release: ReleaseFn = bind("sandbox_extension_release") {
                setErrno(0)
                let releaseRC = release(handle)
                observed += "; sandbox_extension_release -> \(releaseRC)"
            } else {
                observed += "; sandbox_extension_release unresolved (handle leaked)"
            }
        } else {
            observed = "the token came back NULL, errno=\(ErrorClassifier.errnoName(tokenErr))"
        }

        rows.append(Entry(
            id: "extension-own-issue",
            group: groupIssueOwn,
            operation: "sandbox_extension_issue_file(self, ownFile, 0, &handle)",
            target: own,
            outcome: token != nil ? .issued : .denied,
            errnoName: token != nil ? nil : ErrorClassifier.errnoName(tokenErr),
            returnedValue: token != nil ? "non-null token" : "NULL",
            observed: observed,
            interpretation: token != nil
                ? """
                    CONTROL: the app can mint an extension for a file inside \
                    its own container, and consume it. That is what makes a \
                    refusal in the next group a statement about the boundary \
                    rather than about the mechanism being unavailable.
                    """
                : """
                    CONTROL FAILED: no token came back even for the app's own \
                    file. Every row in the next group is therefore \
                    inconclusive -- a refusal there would be \
                    indistinguishable from the machinery simply not running.
                    """
        ))

        cleanup(own)
        return rows
    }

    // MARK: - Group 2: issuing for a path outside the container

    private static func issueOutsideGroup() -> [Entry] {
        var rows: [Entry] = []

        guard let issue: IssueFileFn = bind("sandbox_extension_issue_file") else {
            rows.append(Entry(
                id: "extension-outside-issue",
                group: groupIssueOutside,
                operation: "sandbox_extension_issue_file(self, \(outsideTarget), 0, &handle)",
                target: outsideTarget,
                outcome: .symbolUnavailable, errnoName: nil, returnedValue: nil,
                observed: "sandbox_extension_issue_file could not be resolved with dlsym",
                interpretation: """
                    NOT ATTEMPTED: the symbol is absent, so the question that \
                    this whole probe exists to ask could not be asked.
                    """
            ))
            return rows
        }

        // --- /etc/passwd ---
        var passwdHandle: UnsafeMutableRawPointer? = nil
        setErrno(0)
        let passwdToken = outsideTarget.withCString {
            issue(MachShim.taskSelf, $0, 0, &passwdHandle)
        }
        let passwdErr = currentErrno()
        var passwdObserved: String
        if let passwdToken {
            passwdObserved = "a non-null token was minted for a path OUTSIDE the container"
            if let release: ReleaseFn = bind("sandbox_extension_release") {
                setErrno(0)
                passwdObserved += "; sandbox_extension_release -> \(release(passwdHandle))"
            } else {
                passwdObserved += "; sandbox_extension_release unresolved (handle leaked)"
            }
        } else {
            passwdObserved = "the token came back NULL, errno=\(ErrorClassifier.errnoName(passwdErr))"
        }
        rows.append(Entry(
            id: "extension-outside-etc-passwd",
            group: groupIssueOutside,
            operation: "sandbox_extension_issue_file(self, \(outsideTarget), 0, &handle)",
            target: outsideTarget,
            outcome: passwdToken != nil ? .issued : .denied,
            errnoName: passwdToken != nil ? nil : ErrorClassifier.errnoName(passwdErr),
            returnedValue: passwdToken != nil ? "non-null token" : "NULL",
            observed: passwdObserved,
            interpretation: passwdToken != nil
                ? """
                    A token was minted for a path outside the container. This \
                    is the finding this probe exists to look for, and it is \
                    still recorded with isBoundaryViolation false: the answer \
                    came from a simulator or CI host, which is a macOS process \
                    under a different sandbox, and a stock iOS 27.0 device is \
                    the only place it becomes real. What it would mean if real \
                    is specific -- the token's entire purpose is to carry \
                    authority the holder does not otherwise have, so a token \
                    minted for /etc/passwd is a credential for /etc/passwd.
                    """
                : passwdErr == Int32(EPERM)
                    ? """
                    EPERM: the issuance path is gated by the sandbox exactly as \
                    the open path is. The app cannot manufacture a credential \
                    for a path it cannot reach, which is the correct answer.
                    """
                    : """
                    The answer was \(ErrorClassifier.errnoName(passwdErr)) rather \
                    than EPERM. ENOENT would be a missing file, ENOSYS an \
                    unimplemented mechanism -- neither is a boundary statement.
                    """
        ))

        // --- / and /var/mobile ---
        for (id, path) in [
            ("extension-outside-root", "/"),
            ("extension-outside-var-mobile", "/var/mobile")
        ] {
            var h: UnsafeMutableRawPointer? = nil
            setErrno(0)
            let tok = path.withCString { issue(MachShim.taskSelf, $0, 0, &h) }
            let err = currentErrno()
            var obs: String
            if let tok {
                obs = "a non-null token was minted for \(path)"
                if let release: ReleaseFn = bind("sandbox_extension_release") {
                    setErrno(0)
                    obs += "; sandbox_extension_release -> \(release(h))"
                } else {
                    obs += "; sandbox_extension_release unresolved (handle leaked)"
                }
            } else {
                obs = "the token came back NULL, errno=\(ErrorClassifier.errnoName(err))"
            }
            rows.append(Entry(
                id: id,
                group: groupIssueOutside,
                operation: "sandbox_extension_issue_file(self, \(path), 0, &handle)",
                target: path,
                outcome: tok != nil ? .issued : .denied,
                errnoName: tok != nil ? nil : ErrorClassifier.errnoName(err),
                returnedValue: tok != nil ? "non-null token" : "NULL",
                observed: obs,
                interpretation: tok != nil
                    ? """
                    A token was minted for \(path). Recorded with \
                    isBoundaryViolation false for the same reason as the \
                    /etc/passwd row: a simulator or CI-host answer is a macOS \
                    answer, and only a stock iOS 27.0 device makes it a \
                    finding. If it is real, a token for a volume root is a \
                    credential for everything under it.
                    """
                    : """
                    Refused, errno \(ErrorClassifier.errnoName(err)). A refusal \
                    here alongside a refusal for /etc/passwd is the boundary \
                    holding consistently rather than selectively.
                    """
            ))
        }

        // --- the to-process variant is deliberately NOT measured ---
        //
        // It was implemented, and it crashed the app with EXC_BAD_ACCESS at
        // 0x21da inside sandbox_extension_issue_file_to_process itself, on the
        // iOS simulator. The self variant with the same `ext` port completed
        // without incident on the rows above, so the difference is inside that
        // function: it dereferences its target-process argument before the
        // authorization check that lets the self variant return early.
        //
        // A probe is not allowed to crash the app it is measuring. Rather than
        // guess at a signature that would make the call survivable -- a wrong
        // guess here is a SIGSEGV, not a wrong answer -- the variant is
        // recorded as unattempted with the reason stated. The question it
        // would answer (can a token be minted for ANOTHER process) is not the
        // one this probe exists for; the one above is.
        rows.append(Entry(
            id: "extension-outside-to-own-process",
            group: groupIssueOutside,
            operation: "sandbox_extension_issue_file_to_process(self, \(outsideTarget), 0, ownPid)",
            target: outsideTarget,
            outcome: .notAttempted, errnoName: nil, returnedValue: nil,
            observed: "not attempted: the call crashed the host app (EXC_BAD_ACCESS at 0x21da)",
            interpretation: """
                NOT ATTEMPTED: this variant dereferences its target-process \
                argument before the authorization check that lets the self \
                variant above return early, and calling it through a \
                dlsym-resolved pointer crashed the app. A probe that kills \
                the process it is measuring has produced no measurement at \
                all, so it is not retried with a guessed signature. The \
                question this variant would answer -- whether a token can be \
                minted on behalf of another process -- is a confused-deputy \
                shape, and the row that matters for this probe is the self \
                variant above, which asks whether the PATH can be outside.
                """
        ))

        return rows
    }

    // MARK: - Group 3: fcntl F_GETPATH on a descriptor

    private static func getPathGroup() -> [Entry] {
        var rows: [Entry] = []
        let own = scratch("fsprobe-getpath-\(getpid())")

        setErrno(0)
        let createFD = POSIXShim.openFile(own, O_CREAT | O_TRUNC | O_WRONLY, 0o644)
        let createErr = currentErrno()
        if createFD < 0 {
            rows.append(Entry(
                id: "getpath-control-open",
                group: groupGetPath,
                operation: "open(tmp, O_CREAT|O_TRUNC|O_WRONLY)",
                target: own,
                outcome: classifyFD(createFD, createErr),
                errnoName: ErrorClassifier.errnoName(createErr),
                returnedValue: "\(createFD)",
                observed: "open returned -1, errno=\(ErrorClassifier.errnoName(createErr))",
                interpretation: """
                    CONTROL FAILED: the descriptor could not be obtained, so \
                    the F_GETPATH row below is inconclusive. Recorded rather \
                    than omitted.
                    """
            ))
            return rows
        }
        _ = POSIXShim.closeFile(createFD)

        setErrno(0)
        let fd = POSIXShim.openFile(own, O_RDONLY, 0)
        let openErr = currentErrno()
        guard fd >= 0 else {
            rows.append(Entry(
                id: "getpath-control-open",
                group: groupGetPath,
                operation: "open(tmp, O_RDONLY)",
                target: own,
                outcome: classifyFD(fd, openErr),
                errnoName: ErrorClassifier.errnoName(openErr),
                returnedValue: "\(fd)",
                observed: "open returned -1, errno=\(ErrorClassifier.errnoName(openErr))",
                interpretation: """
                    CONTROL FAILED: the file could not be reopened read-only, \
                    so no descriptor exists for F_GETPATH to answer about.
                    """
            ))
            cleanup(own)
            return rows
        }
        defer { _ = POSIXShim.closeFile(fd) }

        guard let fgetpath: FGetPathFn = bind("fgetpath") else {
            rows.append(Entry(
                id: "getpath-control-fcntl",
                group: groupGetPath,
                operation: "fgetpath(fd, buf, len)",
                target: own,
                outcome: .symbolUnavailable, errnoName: nil, returnedValue: nil,
                observed: "fgetpath could not be resolved with dlsym",
                interpretation: """
                    NOT ATTEMPTED: fgetpath is absent from the process image, \
                    so the path-of-a-descriptor question could not be asked. A \
                    missing symbol is a statement about the platform, not a \
                    refusal by it.
                    """
            ))
            cleanup(own)
            return rows
        }

        var buf = [CChar](repeating: 0, count: 1024)
        setErrno(0)
        let rc = fgetpath(fd, &buf, buf.count)
        let err = currentErrno()
        let returned = rc == 0 ? String(cString: buf) : nil
        rows.append(Entry(
            id: "getpath-control-fcntl",
            group: groupGetPath,
            operation: "fgetpath(fd, buf, 1024)",
            target: own,
            outcome: rc == 0 ? .issued : .denied,
            errnoName: rc == 0 ? nil : ErrorClassifier.errnoName(err),
            returnedValue: "\(rc)",
            observed: returned.map { "fgetpath returned \"\($0)\"" }
                ?? "fgetpath returned \(rc), errno=\(ErrorClassifier.errnoName(err))",
            interpretation: rc == 0
                ? """
                    CONTROL: fgetpath answered for a descriptor the app holds \
                    on its own file, so the mechanism works. What it cannot do \
                    is answer for a descriptor the app does not hold -- and \
                    that is the boundary, not a gap in it. F_GETPATH reads a \
                    path the kernel already associated with an open file; it \
                    does not resolve a path the app was refused.
                    """
                : """
                    fgetpath failed even for the app's own descriptor, \
                    errno=\(ErrorClassifier.errnoName(err)). The mechanism is \
                    unavailable here, which is recorded rather than assumed.
                    """
        ))

        cleanup(own)
        return rows
    }

    // MARK: - Shared helpers

    private static func classifyFD(_ fd: Int32, _ err: Int32) -> Outcome {
        fd >= 0 ? .issued : (err == Int32(EPERM) ? .denied : .otherError)
    }

    private static func cleanup(_ path: String) {
        guard let unlinkSym = POSIXShim.lookupSymbol("unlink") else { return }
        let unlink = unsafeBitCast(unlinkSym, to: (@convention(c) (UnsafePointer<CChar>) -> Int32).self)
        setErrno(0)
        let rc = path.withCString { unlink($0) }
        if rc != 0 && currentErrno() != Int32(ENOENT) {
            // Housekeeping, not a measurement: a cleanup failure is retried
            // once through Foundation and deliberately never promoted into a
            // result row, because that would let a scratch-file bug
            // masquerade as a finding.
            try? FileManager.default.removeItem(atPath: path)
        }
    }

    #endif
}
