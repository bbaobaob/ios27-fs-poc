//
//  SandboxProfileSpawnProbe.swift
//  FSProbeCore — attaching a different sandbox profile to a child process.
//
//  WHY THIS EXISTS
//  ---------------
//  CVE-2026-20628, documented publicly at wts.dev/posts/sandbox-spawnattrs-escape/,
//  is the most relevant published mechanism this project has not tested.
//
//  The mechanism: `posix_spawnattr_setmacpolicyinfo_np()` lets a process attach a
//  binary blob to the Sandbox MAC policy for a child it is about to spawn. The
//  blob names a BUILT-IN sandbox profile. The child's profile was applied
//  *instead of* the parent's, so a sandboxed parent could name a profile that
//  permits more than its own -- for example "no-network", which allows filesystem
//  access the caller lacks.
//
//  The reason it worked is the part that matters: a child normally inherits the
//  parent's profile, and the built-in-profile field overrode that without any
//  comparison of whether the child's profile was more permissive than the
//  parent's.
//
//  Apple's fix was a blanket denial: sandboxed processes can no longer name a
//  built-in profile, except with `com.apple.private.security.sandbox-spawnattrs`.
//
//  THIS IS NOT ASSUMED PATCHED. The advisory covers 26.3 and earlier majors. iOS
//  27.0 is a later release, so it very likely carries the fix -- but "very likely"
//  is not a measurement, and the whole point of this project is that the
//  measurement is what counts. A blanket denial is also a blunt instrument: it
//  can be incomplete in ways that only show up on the platform it was tested on
//  least, and the original researcher could only reliably exploit on macOS.
//
//  HYPOTHESIS
//  ----------
//  `posix_spawnattr_setmacpolicyinfo_np` accepts a built-in profile name from an
//  ordinary sandboxed app, and a child spawned with it holds permissions the
//  parent lacks.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether a sandboxed process can name the sandbox profile of a process it
//  spawns, and thereby choose a more permissive one than its own.
//
//  SAFETY
//  ------
//  Step one only sets the attribute and never spawns anything -- it asks the
//  kernel whether the name is accepted, and nothing is executed. Step two, which
//  runs only if step one succeeds, spawns `/bin/sh -c true`: a command that does
//  nothing, exits zero, touches nothing, and is given no input and no file to
//  name. The child is reaped immediately.
//

import Foundation

public enum SandboxProfileSpawnProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The attribute was accepted, or the child ran.
        case permitted
        /// The attribute was refused, or the child was refused.
        case denied
        /// The symbol is not present on this platform.
        case symbolUnavailable
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Attempt: Sendable, Identifiable, Codable {
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
        public let attempts: [Attempt]
        public let violations: [Attempt]

        public init(attempts: [Attempt], violations: [Attempt]) {
            self.attempts = attempts
            self.violations = violations
        }
    }

    /// Built-in profile names to try.
    ///
    /// "no-network" is the one from the published writeup: it permits filesystem
    /// access the caller lacks, which is exactly what makes the bug consequential.
    /// The others are plausible built-in names tried for completeness; a name the
    /// platform does not know produces EINVAL, which is recorded rather than
    /// guessed at.
    /// Exposed so a test can assert the profile from the published writeup is in
    /// the list, which is what makes the experiment test that mechanism rather
    /// than a guess.
    public static let profileNames = [
        "no-network",
        "no-write",
        "no-sandbox",
    ]

    /// The profile names, joined once so no string literal contains a double
    /// quote inside an interpolation.
    private static var profileNameList: String {
        profileNames.joined(separator: ", ")
    }

    public static func probe() -> Result {
        #if canImport(Darwin)
        guard setMacPolicyInfoAvailable else {
            return Result(
                attempts: [Attempt(
                    id: "setmacpolicyinfo",
                    mechanism: """
                        CVE-2026-20628: naming a built-in sandbox profile for a \
                        child. The symbol is not present on this platform, so the \
                        experiment was never attempted.
                        """,
                    operation: "posix_spawnattr_setmacpolicyinfo_np(attr, name, len)",
                    arguments: "profile names: \(profileNameList)",
                    expected: "Denied. A sandboxed process must not choose its child's profile.",
                    expectedDenied: true,
                    outcome: .symbolUnavailable,
                    errnoName: nil, returnValue: nil,
                    observed: nil,
                    interpretation: """
                        NOT ATTEMPTED: the symbol could not be resolved, so no \
                        measurement was made. This is a statement about the platform, \
                        not a denial.
                        """
                )],
                violations: []
            )
        }

        var attempts: [Attempt] = []

        // Step one: does the kernel accept a profile name at all? Nothing is
        // spawned, so this is safe to run unconditionally.
        for name in profileNames {
            attempts.append(setAttributeCase(name))
        }

        // Step two, only if step one succeeded for any name: spawn a child with
        // that profile and see whether the spawn is permitted.
        let accepted = profileNames.filter { name in
            attempts.contains { $0.id == "setmacpolicyinfo-\(name)" && $0.outcome == .permitted }
        }
        if let first = accepted.first {
            attempts.append(spawnWithProfileCase(first))
        } else {
            attempts.append(Attempt(
                id: "spawn-with-profile",
                mechanism: """
                    Spawning a child under a built-in profile the caller named. \
                    Gated behind step one: if no name was accepted, there is nothing \
                    to spawn with and this step would be meaningless.
                    """,
                operation: "posix_spawn(\"/bin/sh\", argv, NULL, &attr, NULL, NULL)",
                arguments: "no accepted profile name",
                expected: "Denied.",
                expectedDenied: true,
                outcome: .notAttempted,
                errnoName: nil, returnValue: nil,
                observed: "no profile name was accepted",
                interpretation: """
                    NOT ATTEMPTED: no built-in profile name was accepted, so there \
                    was nothing to spawn a child with. This is the expected shape on \
                    a platform carrying the fix.
                    """
            ))
        }

        let violations = attempts.filter { $0.isBoundaryViolation }
        return Result(attempts: attempts, violations: violations)
        #else
        return Result(
            attempts: [Attempt(
                id: "setmacpolicyinfo",
                mechanism: """
                    CVE-2026-20628: naming a built-in sandbox profile for a child.
                    """,
                operation: "posix_spawnattr_setmacpolicyinfo_np(attr, name, len)",
                arguments: "profile names: \(profileNameList)",
                expected: "Denied. A sandboxed process must not choose its child's profile.",
                expectedDenied: true,
                outcome: .symbolUnavailable,
                errnoName: nil, returnValue: nil,
                observed: nil,
                interpretation: """
                    NOT ATTEMPTED: this is a Darwin API and is not present on this \
                    platform.
                    """
            )],
            violations: []
        )
        #endif
    }

    #if canImport(Darwin)

    /// True when the function resolves in this runtime.
    private static var setMacPolicyInfoAvailable: Bool {
        POSIXShim.lookupSymbol("posix_spawnattr_setmacpolicyinfo_np") != nil
    }

    // The spawn-attribute lifecycle is bound by name rather than called through
    // the import. `posix_spawnattr_t` is `void *`, so the C signature is
    // `int posix_spawnattr_init(void **)`, and Swift's imported form of that is
    // not a form this file can spell portably: the same call failed to compile
    // on the iOS SDK and would have failed again on any SDK that imports the
    // type differently. Naming the parameter explicitly removes the question.
    // Pointer representations are ABI-identical, so the binding is exact.
    @_silgen_name("posix_spawnattr_init")
    private static func cSpawnAttrInit(
        _ attribute: UnsafeMutablePointer<UnsafeMutableRawPointer?>
    ) -> Int32

    @_silgen_name("posix_spawnattr_destroy")
    private static func cSpawnAttrDestroy(
        _ attribute: UnsafeMutablePointer<UnsafeMutableRawPointer?>
    ) -> Int32

    // posix_spawnattr_t is `void *`, so in Swift it is an UnsafeMutableRawPointer
    // and the C signature's `posix_spawnattr_t *attr` is a pointer to that. The
    // second parameter is `const void *`, which takes a raw pointer directly.
    private typealias SetMacPolicyInfoFn = @convention(c) (
        UnsafeMutablePointer<UnsafeMutableRawPointer?>, UnsafeRawPointer, Int
    ) -> Int32

    private static func resolveSetMacPolicyInfo() -> SetMacPolicyInfoFn? {
        guard let sym = POSIXShim.lookupSymbol("posix_spawnattr_setmacpolicyinfo_np") else {
            return nil
        }
        return unsafeBitCast(sym, to: SetMacPolicyInfoFn.self)
    }

    /// Ask the kernel whether it accepts a built-in profile name for a child.
    ///
    /// This only sets an attribute on a spawnattr. Nothing is spawned, so the step
    /// is safe to run unconditionally and answers the question directly.
    private static func setAttributeCase(_ name: String) -> Attempt {
        let id = "setmacpolicyinfo-\(name)"
        let operation = "posix_spawnattr_setmacpolicyinfo_np(attr, \"\(name)\", len)"
        let mechanism = """
            CVE-2026-20628: naming a built-in sandbox profile for a child. The \
            child would receive that profile INSTEAD OF the parent's, so a \
            sandboxed parent could name a more permissive one.
            """

        guard let setter = resolveSetMacPolicyInfo() else {
            return Attempt(
                id: id, mechanism: mechanism, operation: operation,
                arguments: name,
                expected: "Denied.",
                expectedDenied: true,
                outcome: .symbolUnavailable,
                errnoName: nil, returnValue: nil,
                observed: nil,
                interpretation: "NOT ATTEMPTED: the symbol is not present."
            )
        }

        // A real, initialised spawnattr. It has to come from posix_spawnattr_init
        // rather than a zeroed buffer: the library owns the struct it points at,
        // and handing it uninitialised memory would be undefined behaviour that
        // could crash instead of answering the question.
        // The storage is declared at the C type -- `void *` -- rather than at
        // whatever Swift imports `posix_spawnattr_t` to be, because Swift will not
        // convert an UnsafeMutableRawPointer into a typed pointer. Declaring it the
        // way the header does is the only spelling that does not depend on how this
        // SDK happened to import the typedef.
        var attributeStorage: UnsafeMutableRawPointer?
        let initRC = cSpawnAttrInit(&attributeStorage)
        guard initRC == 0 else {
            return Attempt(
                id: id, mechanism: mechanism, operation: operation,
                arguments: name,
                expected: "Denied.",
                expectedDenied: true,
                outcome: .notAttempted,
                errnoName: nil, returnValue: "init rc=\(initRC)",
                observed: "the spawn attributes could not be initialised",
                interpretation: """
                    NOT ATTEMPTED: the spawn attributes could not be initialised, \
                    so there was no attribute to set a profile on.
                    """
            )
        }
        defer { _ = cSpawnAttrDestroy(&attributeStorage) }

        // The setter is a posix_spawnattr function, which returns the error
        // number instead of setting errno -- the same convention as posix_spawn
        // itself. Reading errno here would report success's leftover zero for a
        // call that had actually been refused.
        setErrno(0)
        let rc = name.withCString { cName in
            setter(&attributeStorage, cName, strlen(cName))
        }
        let err = rc == 0 ? currentErrno() : rc

        let permitted = rc == 0
        return Attempt(
            id: id, mechanism: mechanism, operation: operation,
            arguments: name,
            expected: """
                Denied with EPERM. A sandboxed process must not choose its child's \
                sandbox profile.
                """,
            expectedDenied: true,
            outcome: permitted ? .permitted : .denied,
            errnoName: permitted ? nil : ErrorClassifier.errnoName(err),
            returnValue: "\(rc)",
            observed: permitted
                ? "the profile name was accepted"
                : "refused with \(ErrorClassifier.errnoName(err))",
            interpretation: permitted
                ? """
                The kernel accepted a built-in profile name from an ordinary \
                sandboxed app. That is the primitive CVE-2026-20628 described: the \
                child's profile can be named rather than inherited. The follow-up \
                is to spawn a child with it and observe what it can reach.
                """
                : """
                Refused. The blanket denial described in Apple's fix holds on this \
                platform, so a sandboxed process cannot name its child's profile.
                """
        )
    }

    /// Spawn a child under a profile name the kernel accepted.
    private static func spawnWithProfileCase(_ name: String) -> Attempt {
        let id = "spawn-with-profile"
        let operation = "posix_spawn(\"/bin/sh\", [\"sh\", \"-c\", \"true\"], NULL, &attr, NULL, NULL)"
        let mechanism = """
            Spawning a child under a built-in profile the caller named. If the \
            spawn is permitted, the child holds a profile the caller chose rather \
            than one it inherited.
            """

        guard let setter = resolveSetMacPolicyInfo() else {
            return Attempt(
                id: id, mechanism: mechanism, operation: operation,
                arguments: name,
                expected: "Denied.",
                expectedDenied: true,
                outcome: .symbolUnavailable,
                errnoName: nil, returnValue: nil,
                observed: nil,
                interpretation: "NOT ATTEMPTED: the symbol is not present."
            )
        }

        var attributeStorage: UnsafeMutableRawPointer?
        let initRC = cSpawnAttrInit(&attributeStorage)
        guard initRC == 0 else {
            return Attempt(
                id: id, mechanism: mechanism, operation: operation,
                arguments: name,
                expected: "Denied.",
                expectedDenied: true,
                outcome: .notAttempted,
                errnoName: nil, returnValue: "init rc=\(initRC)",
                observed: "the spawn attributes could not be initialised",
                interpretation: """
                    NOT ATTEMPTED: the spawn attributes could not be initialised, \
                    so there was no attribute to set a profile on.
                    """
            )
        }
        defer { _ = cSpawnAttrDestroy(&attributeStorage) }

        let setRC = name.withCString { cName in
            setter(&attributeStorage, cName, strlen(cName))
        }
        guard setRC == 0 else {
            return Attempt(
                id: id, mechanism: mechanism, operation: operation,
                arguments: name,
                expected: "Denied.",
                expectedDenied: true,
                outcome: .notAttempted,
                errnoName: nil, returnValue: "setattr rc=\(setRC)",
                observed: "the attribute could not be set on this attempt",
                interpretation: """
                    NOT ATTEMPTED: the profile name was accepted in the previous \
                    step but not on this one, so the spawn was not attempted.
                    """
            )
        }

        var pid: Int32 = 0
        let argv: [UnsafeMutablePointer<CChar>?] = [
            strdup("/bin/sh"), strdup("-c"), strdup("true"), nil
        ]
        defer {
            for element in argv where element != nil { free(element) }
        }

        // argv and envp are both `char *const []`, which Swift cannot infer from a
        // literal, so the empty environment is named explicitly rather than passed
        // as a bare nil.
        let environment = [UnsafeMutablePointer<CChar>?](repeating: nil, count: 1)

        // posix_spawn declares its attributes as `const posix_spawnattr_t *`, so
        // the storage is re-typed as a const pointer to the same pointee. Note
        // that this SDK imports `posix_spawnattr_t` as an OPTIONAL raw pointer --
        // an observation from a compiler error, not an assumption -- so the pointee
        // here is optional to match. Re-pointing the memory would have produced a
        // pointer of the wrong type that still looked correct.
        guard attributeStorage != nil else {
            return Attempt(
                id: id, mechanism: mechanism, operation: operation,
                arguments: name,
                expected: "Denied.",
                expectedDenied: true,
                outcome: .notAttempted,
                errnoName: nil, returnValue: "the attribute was nil after init",
                observed: "the spawn attributes carried no pointer",
                interpretation: """
                    NOT ATTEMPTED: the spawn attributes reported success but \
                    carried no pointer, so there was nothing to spawn with.
                    """
            )
        }
        // The import wants `UnsafePointer<UnsafeMutableRawPointer?>?` for the
        // attributes, which is exactly the C type: posix_spawnattr_t is `void *`
        // imported as an optional raw pointer. The address is taken inside
        // withUnsafePointer so the storage and the conversion are the same
        // expression -- there is no separate converted variable that could drift
        // out of step with the storage it was made from.
        var storage = attributeStorage

        // posix_spawn returns the error number; errno is untouched. See the
        // note in ProcessExecutionProbe for why reading errno here misreports
        // every refusal.
        setErrno(0)
        let spawnRC: Int32 = "/bin/sh".withCString { programPath in
            withUnsafePointer(to: &storage) { attributePointer in
                posix_spawn(&pid, programPath, nil, attributePointer, argv, environment)
            }
        }
        let rc = Int(spawnRC)
        let err = spawnRC == 0 ? currentErrno() : spawnRC

        if rc == 0 {
            // Reap it immediately: the command does nothing and exits zero.
            var status: Int32 = 0
            waitpid(pid, &status, 0)
            return Attempt(
                id: id, mechanism: mechanism, operation: operation,
                arguments: name,
                expected: "Denied.",
                expectedDenied: true,
                outcome: .permitted,
                errnoName: nil, returnValue: "rc=0, pid=\(pid)",
                observed: "a child was spawned under profile \"\(name)\"",
                interpretation: """
                    A child was spawned under a built-in profile the caller named. \
                    That is the primitive CVE-2026-20628 described, and the next \
                    step is to observe what the child can reach that the parent \
                    cannot -- which is the actual security effect and what turns \
                    this from a curiosity into a violation.
                    """
            )
        }

        return Attempt(
            id: id, mechanism: mechanism, operation: operation,
            arguments: name,
            expected: "Denied.",
            expectedDenied: true,
            outcome: .denied,
            errnoName: ErrorClassifier.errnoName(err),
            returnValue: "\(rc)",
            observed: "the spawn was refused with \(ErrorClassifier.errnoName(err))",
            interpretation: """
                Refused. The attribute was accepted but the spawn was not, which \
                means the kernel accepted the name and then refused to act on it. \
                That is a weaker fix than a blanket denial and is worth recording \
                precisely, because it is a different shape from the documented one.
                """
        )
    }

    #endif
}
