//
//  ProcessExecutionProbe.swift
//  FSProbeCore — can an ordinary app run a system binary?
//
//  HYPOTHESIS
//  ----------
//  Nineteen modules have tested what an ordinary app can reach, read, and write.
//  None has tested the most consequential thing of all: whether it can RUN
//  something.
//
//  If a sandboxed app can execute a system binary, the sandbox is finished. Every
//  containment rule this project has measured assumes the process is the one the
//  platform launched, with the container it was given. A spawned binary inherits
//  the caller's credentials and sandbox, so this is not an escape by itself — but
//  it is the primitive every other escalation needs, because it turns a read bug
//  into a write bug and a write bug into code execution.
//
//  Three mechanisms are tested, because they are three code paths:
//
//    posix_spawn()   the modern spawn path, with file actions and attributes
//    execve()        the raw path, replacing the calling image
//    system()/popen() the libc wrappers, which spawn a shell
//
//  BOUNDARY UNDER TEST
//  -------------------
//  The `process-exec` / `file-exec` sandbox operation, which is a separate
//  predicate from every file-read and file-write operation tested so far.
//
//  CONTROL
//  -------
//  A path that does not exist. The expected answer is ENOENT, and that is what
//  makes a refusal interpretable: ENOENT means the lookup ran and found nothing,
//  while EPERM means the policy refused it. Without that distinction a refusal
//  on a real binary could be either.
//
//  There is deliberately no positive control. An ordinary iOS app cannot execute
//  even its own bundled binary without an entitlement, so there is no known-good
//  spawn to compare against, and inventing one would be guessing.
//
//  SAFETY
//  ------
//  The command executed is `true` — it does nothing, exits zero, and touches
//  nothing. No shell is given any input, no file is named, no environment
//  variable carries anything. The child is reaped immediately. This is the
//  minimum that answers the question, and it is deliberately not more.
//

import Foundation

public enum ProcessExecutionProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The child was created and ran.
        case permitted
        /// The call was refused with EPERM.
        case denied
        /// The call failed with ENOENT, meaning the path was not there.
        case notFound
        /// The call failed for another recorded reason.
        case otherError
        /// The symbol is not present on this platform.
        case symbolUnavailable
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Spawn: Sendable, Identifiable, Codable {
        public let id: String
        /// The mechanism under test.
        public let mechanism: String
        /// The libc call exercised.
        public let operation: String
        /// The concrete arguments, so the experiment is reproducible.
        public let arguments: String
        /// What the expected policy predicts.
        public let expected: String
        /// True when success would be a boundary violation.
        public let expectedDenied: Bool
        public let outcome: Outcome
        /// The errno from the call, captured immediately afterwards.
        public let errnoName: String?
        /// The return value as the platform reported it.
        public let returnValue: String?
        /// What was observed.
        public let observed: String?
        /// What the observation means.
        public let interpretation: String

        public init(
            id: String,
            mechanism: String,
            operation: String,
            arguments: String,
            expected: String,
            expectedDenied: Bool,
            outcome: Outcome,
            errnoName: String?,
            returnValue: String?,
            observed: String?,
            interpretation: String
        ) {
            self.id = id
            self.mechanism = mechanism
            self.operation = operation
            self.arguments = arguments
            self.expected = expected
            self.expectedDenied = expectedDenied
            self.outcome = outcome
            self.errnoName = errnoName
            self.returnValue = returnValue
            self.observed = observed
            self.interpretation = interpretation
        }

        public var isBoundaryViolation: Bool {
            outcome == .permitted && expectedDenied
        }
    }

    public struct Result: Sendable, Codable {
        public let spawns: [Spawn]
        public let violations: [Spawn]

        public init(spawns: [Spawn], violations: [Spawn]) {
            self.spawns = spawns
            self.violations = violations
        }
    }

    /// The command executed. `true` does nothing, exits zero, touches nothing.
    private static let harmlessCommand = "true"

    /// A path that cannot exist. Its expected answer is ENOENT, which is what
    /// makes a refusal on a real path interpretable.
    private static let nonexistentPath = "/usr/bin/fsprobe-nonexistent-binary"

    /// System binaries that exist on both iOS and macOS. `/bin/sh` is the
    /// consequential one: a shell is a general execution primitive.
    private static let systemBinaries: [(path: String, why: String)] = [
        ("/bin/sh", "a shell, which is a general execution primitive"),
        ("/usr/bin/true", "a trivial system binary"),
        ("/bin/ls", "a system utility that reads directories"),
    ]

    public static func probe() -> Result {
        var spawns: [Spawn] = []

        // Control first: a path that does not exist.
        spawns.append(posixSpawnCase(
            id: "posix-spawn-nonexistent-control",
            path: nonexistentPath,
            arguments: "\(nonexistentPath) (control)",
            why: """
                CONTROL: a path that cannot exist. Its expected answer is ENOENT, \
                and that is what makes a refusal on a real binary interpretable -- \
                ENOENT means the lookup ran and found nothing, EPERM means the \
                policy refused it.
                """,
            expectedDenied: false
        ))

        for entry in systemBinaries {
            spawns.append(posixSpawnCase(
                id: "posix-spawn-\(entry.path)",
                path: entry.path,
                arguments: entry.path,
                why: """
                    A system binary: \(entry.why). Executing it would give an \
                    ordinary app the ability to run code the platform shipped.
                    """,
                expectedDenied: true
            ))
        }

        // The libc wrappers, which are separate code paths from posix_spawn.
        spawns.append(systemCase())
        spawns.append(popenCase())

        let violations = spawns.filter { $0.isBoundaryViolation }
        return Result(spawns: spawns, violations: violations)
    }

    // MARK: - Cases

    private static func posixSpawnCase(
        id: String,
        path: String,
        arguments: String,
        why: String,
        expectedDenied: Bool
    ) -> Spawn {
        let operation = "posix_spawn(path, argv, NULL, NULL)"
        let mechanism = """
            \(why) The `process-exec` sandbox operation is a separate predicate \
            from every file-read and file-write operation tested so far, and it \
            has never been tested here.
            """

        setErrno(0)
        let rc = runPosixSpawn(path)
        let err = currentErrno()

        return classify(
            id: id, mechanism: mechanism, operation: operation,
            arguments: arguments, rc: rc, err: err,
            expectedDenied: expectedDenied,
            expected: expectedDenied
                ? "Denied with EPERM. An ordinary app must not execute system binaries."
                : "ENOENT. The path does not exist, which calibrates the refusal.",
            permittedMeaning: """
                A system binary was spawned. An ordinary app can execute code the \
                platform shipped, which is the primitive every other escalation \
                needs: it turns a read bug into a write bug and a write bug into \
                code execution.
                """,
            deniedMeaning: """
                Refused with EPERM. Executing a system binary is denied by policy, \
                and the control below confirms the refusal is not merely a missing \
                path.
                """,
            notFoundMeaning: """
                The path was not there. This is the control's expected answer and \
                it is what makes a refusal on a real binary interpretable.
                """
        )
    }

    private static func systemCase() -> Spawn {
        let id = "system-true"
        let operation = "system(\(harmlessCommand))"
        let mechanism = """
            The libc `system()` wrapper, which spawns a shell to run a command. A \
            separate code path from posix_spawn, and never tested.
            """
        let arguments = harmlessCommand

        setErrno(0)
        let rc = runSystem(harmlessCommand)
        let err = currentErrno()

        return classify(
            id: id, mechanism: mechanism, operation: operation,
            arguments: arguments, rc: rc, err: err,
            expectedDenied: true,
            expected: "Denied with EPERM, or a non-zero status.",
            permittedMeaning: """
                system() ran a command through a shell. A shell is a general \
                execution primitive, so this is the same finding as spawning one \
                directly.
                """,
            deniedMeaning: """
                Refused. The shell path is denied too.
                """,
            notFoundMeaning: """
                The shell itself was not found, which would be surprising on this \
                platform and worth recording.
                """
        )
    }

    private static func popenCase() -> Spawn {
        let id = "popen-true"
        let operation = "popen(\(harmlessCommand), \"r\")"
        let mechanism = """
            The libc `popen()` wrapper, which spawns a shell and returns a pipe to \
            it. A separate code path again, and never tested.
            """
        let arguments = "\(harmlessCommand), r"

        setErrno(0)
        let stream = runPopen(harmlessCommand)
        let err = currentErrno()

        if let stream {
            // Reap it immediately: the command does nothing and the pipe is closed.
            #if canImport(Darwin)
            _ = cPclose(stream)
            #endif
            return Spawn(
                id: id, mechanism: mechanism, operation: operation,
                arguments: arguments,
                expected: "Denied with EPERM.",
                expectedDenied: true,
                outcome: .permitted,
                errnoName: nil,
                returnValue: "a stream was returned",
                observed: "a pipe to a spawned shell was obtained",
                interpretation: """
                    popen() spawned a shell and returned a pipe to it. A shell with \
                    a readable pipe is both an execution primitive and a channel \
                    for its output, which is the same finding as spawning one \
                    directly.
                    """
            )
        }

        // A nil stream with a zero errno must never read as permitted: the
        // classifier treats (rc == -1, err == 0) as success, which is correct for
        // a call that returns -1 on failure with errno set, but popen returns a
        // POINTER, not an int -- nil with no errno means "no stream and no
        // reason", which is unanswered, not permitted. The sentinel keeps the
        // two cases apart.
        if err == 0 {
            return Spawn(
                id: id, mechanism: mechanism, operation: operation,
                arguments: arguments,
                expected: "Denied with EPERM.",
                expectedDenied: true,
                outcome: .otherError,
                errnoName: nil,
                returnValue: "nil stream, errno 0",
                observed: "no stream was returned and no errno was set",
                interpretation: """
                    No pipe was obtained and the platform gave no reason, so \
                    nothing is claimed about the boundary either way.
                    """
            )
        }
        return classify(
            id: id, mechanism: mechanism, operation: operation,
            arguments: arguments, rc: -1, err: err,
            expectedDenied: true,
            expected: "Denied with EPERM.",
            permittedMeaning: "A pipe to a spawned shell was obtained.",
            deniedMeaning: """
                Refused. The popen path is denied too.
                """,
            notFoundMeaning: """
                The shell was not found, which would be surprising on this platform.
                """
        )
    }

    // MARK: - Raw calls

    private static func runPosixSpawn(_ path: String) -> Int {
        #if canImport(Darwin)
        var pid: Int32 = 0
        // argv is NULL-terminated and the first element is the program name.
        let argv: [UnsafeMutablePointer<CChar>?] = [
            strdup(path), strdup(harmlessCommand), nil
        ]
        defer {
            for element in argv where element != nil { free(element) }
        }
        let environment = [UnsafeMutablePointer<CChar>?](repeating: nil, count: 1)
        let rc = path.withCString { programPath in
            posix_spawn(&pid, programPath, nil, nil, argv, environment)
        }
        return Int(rc)
        #else
        setErrno(ENOSYS)
        return -1
        #endif
    }

    // `system` is bound by name for the same reason `popen` is: the SDK marks it
    // unavailable with the note that process spawning is unavailable on iOS. That
    // note is evidence about the SDK; the question here is about the kernel, and
    // only the kernel can answer it.
    #if canImport(Darwin)
    @_silgen_name("system")
    private static func cSystem(_ command: UnsafePointer<CChar>) -> Int32
    #endif

    private static func runSystem(_ command: String) -> Int {
        #if canImport(Darwin)
        return Int(command.withCString { cSystem($0) })
        #else
        setErrno(ENOSYS)
        return -1
        #endif
    }

    // popen and pclose are bound by name rather than called through the import,
    // because the Swift import marks them unavailable with the note "On iOS,
    // process spawning is unavailable". That note is itself evidence -- Apple
    // closed this path in the SDK -- but an unavailable API is not the same as an
    // absent symbol, which is the distinction this whole project turns on. Binding
    // by name resolves the real symbol in the runtime and lets the experiment
    // measure what the kernel does rather than what the header allows.
    //
    // The FILE* that popen returns is handled as an opaque pointer, because FILE
    // is not a type Swift exposes on every platform this builds for.
    #if canImport(Darwin)
    @_silgen_name("popen")
    private static func cPopen(
        _ command: UnsafePointer<CChar>, _ mode: UnsafePointer<CChar>
    ) -> OpaquePointer?

    @_silgen_name("pclose")
    private static func cPclose(_ stream: OpaquePointer?) -> Int32
    #endif

    private static func runPopen(_ command: String) -> OpaquePointer? {
        #if canImport(Darwin)
        return command.withCString { commandPath in
            "r".withCString { mode in
                cPopen(commandPath, mode)
            }
        }
        #else
        return nil
        #endif
    }

    // MARK: - Classification

    /// Turn a return code and errno into the outcome that matters.
    ///
    /// ENOENT and EPERM mean different things and must not be collapsed: one says
    /// the lookup ran and found nothing, the other says the policy refused it.
    private static func classify(
        id: String,
        mechanism: String,
        operation: String,
        arguments: String,
        rc: Int,
        err: Int32,
        expectedDenied: Bool,
        expected: String,
        permittedMeaning: String,
        deniedMeaning: String,
        notFoundMeaning: String
    ) -> Spawn {
        let outcome: Outcome
        switch err {
        case 0:
            // system() returns a status rather than setting errno; a zero status
            // means the command ran and succeeded.
            outcome = (rc == 0 || rc == -1) ? .permitted : .otherError
        case Int32(ENOENT):
            outcome = .notFound
        case Int32(EPERM):
            outcome = .denied
        case Int32(EACCES):
            outcome = .denied
        default:
            outcome = .otherError
        }

        let errnoName = outcome == .permitted ? nil : ErrorClassifier.errnoName(err)

        let interpretation: String
        switch outcome {
        case .permitted: interpretation = permittedMeaning
        case .denied: interpretation = deniedMeaning
        case .notFound: interpretation = notFoundMeaning
        case .otherError:
            interpretation = """
                Failed for a recorded reason other than a policy denial, so nothing \
                is claimed about the boundary.
                """
        default:
            interpretation = "No measurement was made."
        }

        return Spawn(
            id: id, mechanism: mechanism, operation: operation,
            arguments: arguments, expected: expected,
            expectedDenied: expectedDenied,
            outcome: outcome,
            errnoName: errnoName,
            returnValue: "\(rc)",
            observed: outcome == .permitted
                ? "the child ran and exited"
                : "failed with \(errnoName ?? "an unknown errno")",
            interpretation: interpretation
        )
    }
}
