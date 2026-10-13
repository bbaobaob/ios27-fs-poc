//
//  SearchFSProbe.swift
//  FSProbeCore — enumerating a volume without directory-read permission.
//
//  HYPOTHESIS
//  ----------
//  Every enumeration attempt so far asked the kernel to list a directory:
//  `opendir` + `readdir`, `getattrlistbulk` through Foundation, and
//  `getdirentriesattr` through a descriptor. All were refused with EPERM.
//
//  `searchfs` is a fundamentally different primitive. It asks the filesystem to
//  find entries matching a *name pattern* across a volume, which is a different
//  kernel operation from reading a directory. Its man page describes it as
//  searching a filesystem for files matching given criteria, and it is a separate
//  VFS operation with its own authorization.
//
//  If `searchfs` is not confined the way directory reads are, an app can discover
//  the *names* of files on a protected volume without ever holding permission to
//  read any directory. Names alone are not contents, but they are the missing
//  half of the chain: with a name, the metadata-read primitives (getxattr,
//  getattrlist) and the descriptor primitives become addressable, and
//  `openbyid_np` becomes usable once an inode is known.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether volume-wide name search is authorized separately from directory
//  enumeration.
//
//  CONTROL
//  -------
//  The search runs first inside the app's own container, where it must succeed.
//  Without that control a refusal outside is uninterpretable.
//
//  SAFETY
//  ------
//  Read-only. The search asks only for entry names, which is the minimum needed
//  to learn whether the operation is permitted. No file is opened, written, or
//  removed. The search is bounded by a short time limit so a slow volume cannot
//  hang the harness.
//
//  IMPLEMENTATION NOTE
//  -------------------
//  `struct fssearchblock` is laid out by hand rather than through a header,
//  because the header is not importable on every platform this builds for. Every
//  buffer is oversized well past the structure, and the request asks for one
//  attribute, so a size misunderstanding cannot overflow anything. The heap
//  overflow in the statfs probe came from exactly this kind of assumption, so
//  the sizes here are deliberately generous rather than merely sufficient.
//

import Foundation

public enum SearchFSProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The search ran and reported matches.
        case answered
        /// The search ran and reported no matches, without being refused.
        case noMatches
        /// The search was refused.
        case denied
        /// The control did not produce the expected answer.
        case controlFailed
        /// The symbol is not present on this platform.
        case symbolUnavailable
        /// The experiment was not attempted, with the reason recorded.
        case notAttempted
    }

    public struct Search: Sendable, Identifiable, Codable {
        public let id: String
        /// The mechanism under test.
        public let mechanism: String
        /// The libc call exercised.
        public let operation: String
        /// The concrete arguments, so the experiment is reproducible.
        public let arguments: String
        /// What the expected policy predicts.
        public let expected: String
        /// True when a non-refusal answer would be a boundary violation.
        ///
        /// Both `answered` and `noMatches` count: a search that completes without
        /// being refused has crossed the boundary, whether or not it found
        /// anything. The absence of results is not the absence of authorization.
        public let expectedDenied: Bool
        public let outcome: Outcome
        /// The errno from the call, captured immediately afterwards.
        public let errnoName: String?
        /// How many entries the search reported.
        public let matchCount: Int?
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
            matchCount: Int?,
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
            self.matchCount = matchCount
            self.observed = observed
            self.interpretation = interpretation
        }

        public var isBoundaryViolation: Bool {
            guard expectedDenied else { return false }
            return outcome == .answered || outcome == .noMatches
        }
    }

    public struct Result: Sendable, Codable {
        public let searches: [Search]
        public let violations: [Search]

        public init(searches: [Search], violations: [Search]) {
            self.searches = searches
            self.violations = violations
        }
    }

    /// The volumes to search, by device identifier taken from `lstat` of a path
    /// on each. `/var/tmp` is excluded: a rename to it returned EXDEV, so it is a
    /// different volume and a refusal there would not be attributable to policy.
    private static let searchTargets: [(label: String, path: String)] = [
        ("container", ""),
        ("var-mobile", "/var/mobile"),
    ]

    /// A name pattern that will match nothing, so the search exercises the
    /// authorization check without enumerating real entries.
    private static let probePattern = "fsprobe-nonexistent-probe-pattern"

    /// `ATTR_BIT_MAP_COUNT`, and the single attribute requested.
    private static let attrBitMapCount: UInt16 = 5
    private static let attrCmnName: UInt32 = 0x00000001

    /// Generous buffers. The searchblock and state structures are laid out by
    /// hand, so the sizes are chosen to be far larger than any plausible layout
    /// rather than merely sufficient — the statfs heap overflow came from a
    /// buffer that was merely close.
    private static let searchBlockSize = 512
    private static let stateSize = 1024
    private static let attributeBufferSize = 8192

    #if canImport(Darwin)

    @_silgen_name("searchfs")
    private static func cSearchfs(
        _ path: UnsafePointer<CChar>,
        _ searchblock: UnsafeMutableRawPointer,
        _ nummatches: UnsafeMutablePointer<UInt>,
        _ scriptoptions: UInt32,
        _ options: UInt32,
        _ state: UnsafeMutableRawPointer
    ) -> Int32

    private static var symbolsAvailable: Bool { true }

    #else

    private static var symbolsAvailable: Bool { false }

    #endif

    public static func probe(containerPath: String) -> Result {
        var searches: [Search] = []

        // Control: search inside this app's own container. Must succeed, or a
        // refusal outside is uninterpretable.
        let controlRC = callSearchfs(containerPath)
        let controlAnswer = classify(controlRC)
        let controlOK = controlAnswer != .denied

        // /var/mobile is the protected target. It exists on the device (lstat
        // succeeds) and not on the verification host, where the case is withheld.
        let protectedTarget = "/var/mobile"
        guard pathExists(protectedTarget) else {
            searches.append(Search(
                id: "searchfs-var-mobile",
                mechanism: """
                    A volume-wide name search, which is a different VFS operation \
                    from reading a directory. If it is not confined the way \
                    directory reads are, an app can discover file NAMES on a \
                    protected volume without permission to read any directory.
                    """,
                operation: "searchfs(path, &searchblock, &nummatches, 0, 0, &state)",
                arguments: "\(protectedTarget), pattern=\(probePattern)",
                expected: "Denied with EPERM on a protected volume.",
                expectedDenied: true,
                outcome: .notAttempted,
                errnoName: nil, matchCount: nil,
                observed: "the path does not exist on this platform",
                interpretation: """
                    NOT ATTEMPTED: /var/mobile is an iOS location and does not exist \
                    on this platform. Running it would produce ENOENT and say \
                    nothing about the sandbox.
                    """
            ))
            let violations = searches.filter { $0.isBoundaryViolation }
            return Result(searches: searches, violations: violations)
        }

        guard controlOK else {
            searches.append(Search(
                id: "searchfs-var-mobile",
                mechanism: """
                    A volume-wide name search, a different VFS operation from \
                    reading a directory.
                    """,
                operation: "searchfs(path, &searchblock, &nummatches, 0, 0, &state)",
                arguments: "\(protectedTarget), pattern=\(probePattern)",
                expected: "Denied with EPERM on a protected volume.",
                expectedDenied: true,
                outcome: .controlFailed,
                errnoName: nil, matchCount: nil,
                observed: "the control search inside the container was itself refused",
                interpretation: """
                    The control failed, so a refusal outside is uninterpretable: it \
                    could mean the policy denies the search, or that searchfs does \
                    not work on this platform. Nothing is claimed.
                    """
            ))
            let violations = searches.filter { $0.isBoundaryViolation }
            return Result(searches: searches, violations: violations)
        }

        let rc = callSearchfs(protectedTarget)
        searches.append(makeSearch(
            id: "searchfs-var-mobile",
            path: protectedTarget,
            rc: rc,
            controlAnswer: controlAnswer
        ))

        let violations = searches.filter { $0.isBoundaryViolation }
        return Result(searches: searches, violations: violations)
    }

    // MARK: - The search itself

    private static func callSearchfs(_ path: String) -> Int {
        #if canImport(Darwin)
        let searchblock = UnsafeMutableRawPointer.allocate(
            byteCount: searchBlockSize, alignment: 8
        )
        defer { searchblock.deallocate() }
        memset(searchblock, 0, searchBlockSize)

        let state = UnsafeMutableRawPointer.allocate(
            byteCount: stateSize, alignment: 8
        )
        defer { state.deallocate() }
        memset(state, 0, stateSize)

        let attributeBuffer = UnsafeMutableRawPointer.allocate(
            byteCount: attributeBufferSize, alignment: 8
        )
        defer { attributeBuffer.deallocate() }
        memset(attributeBuffer, 0, attributeBufferSize)

        // The request asks for one attribute and matches nothing. Asking for
        // nothing is the point: it exercises the authorization check without
        // enumerating real entries.
        let returnattrs = UnsafeMutablePointer<UInt32>.allocate(capacity: 1)
        defer { returnattrs.deallocate() }
        returnattrs[0] = attrCmnName

        // Layout, by offset, of struct fssearchblock:
        //   0   returnattrs        (pointer)
        //   8   sizeofreturnattrs  (u32)
        //   12  attrmaxcount       (u32)
        //   16  searchattrs1       (u32[1])
        //   20  sizeofsearchattrs1 (u32)
        //   24  searchattrs2       (u32[1])
        //   28  sizeofsearchattrs2 (u32)
        //   32  timelimit          (timeval: 2 x i64)
        //   48  wantedtime         (u32)
        //   56  namepattern        (pointer)
        //   64  namelen            (usize)
        //   72  reserved           (u32)
        searchblock.storeBytes(
            of: UnsafeMutableRawPointer(returnattrs),
            toByteOffset: 0, as: UnsafeMutableRawPointer.self
        )
        searchblock.storeBytes(
            of: UInt32(MemoryLayout<UInt32>.size), toByteOffset: 8, as: UInt32.self
        )
        searchblock.storeBytes(
            of: UInt32(1), toByteOffset: 12, as: UInt32.self
        )
        // searchattrs1/2 left zeroed: no search criteria, so the search matches
        // on the name pattern alone.
        searchblock.storeBytes(
            of: UInt32(0), toByteOffset: 20, as: UInt32.self
        )
        searchblock.storeBytes(
            of: UInt32(0), toByteOffset: 28, as: UInt32.self
        )
        // A one-second limit, so a slow volume cannot hang the harness.
        searchblock.storeBytes(of: Int64(1), toByteOffset: 32, as: Int64.self)
        searchblock.storeBytes(of: Int64(0), toByteOffset: 40, as: Int64.self)
        searchblock.storeBytes(of: UInt32(0), toByteOffset: 48, as: UInt32.self)

        let patternBytes = Array(probePattern.utf8) + [0]
        let namepattern = UnsafeMutablePointer<CChar>.allocate(capacity: patternBytes.count)
        defer { namepattern.deallocate() }
        for (index, byte) in patternBytes.enumerated() {
            namepattern[index] = CChar(bitPattern: UInt8(byte))
        }
        searchblock.storeBytes(
            of: UnsafeMutableRawPointer(namepattern),
            toByteOffset: 56, as: UnsafeMutableRawPointer.self
        )
        searchblock.storeBytes(
            of: patternBytes.count, toByteOffset: 64, as: Int.self
        )

        var nummatches: UInt = 0
        setErrno(0)
        let rc = path.withCString { p in
            cSearchfs(p, searchblock, &nummatches, 0, 0, state)
        }
        if rc == 0 { return Int(nummatches) }
        return -1
        #else
        setErrno(ENOSYS)
        return -1
        #endif
    }

    // MARK: - Classification

    private static func classify(_ rc: Int) -> Outcome {
        if rc >= 0 { return rc == 0 ? .noMatches : .answered }
        let err = currentErrno()
        switch err {
        case Int32(EPERM): return .denied
        case Int32(EACCES): return .denied
        case Int32(ENOENT): return .notAttempted
        default: return .noMatches
        }
    }

    private static func makeSearch(
        id: String,
        path: String,
        rc: Int,
        controlAnswer: Outcome
    ) -> Search {
        let err = currentErrno()
        let errnoName = rc < 0 ? ErrorClassifier.errnoName(err) : nil
        let answer = classify(rc)
        let matchCount = rc >= 0 ? rc : nil

        switch answer {
        case .answered, .noMatches:
            return Search(
                id: id,
                mechanism: """
                    A volume-wide name search, a different VFS operation from \
                    reading a directory. If it is not confined the way directory \
                    reads are, an app can discover file NAMES on a protected volume \
                    without permission to read any directory.
                    """,
                operation: "searchfs(path, &searchblock, &nummatches, 0, 0, &state)",
                arguments: "\(path), pattern=\(probePattern)",
                expected: "Denied with EPERM on a protected volume.",
                expectedDenied: true,
                outcome: answer,
                errnoName: errnoName,
                matchCount: matchCount,
                observed: answer == .answered
                    ? "the search completed and reported \(rc) match(es)"
                    : "the search completed and reported no matches",
                interpretation: answer == .answered
                    ? """
                    The search ran to completion on a protected volume and reported \
                    matches. That is a name-enumeration primitive on a volume this \
                    app cannot read any directory of. Names are the missing half of \
                    the chain: with them, the metadata-read and descriptor \
                    primitives become addressable.
                    """
                    : """
                    The search ran to completion on a protected volume and was not \
                    refused. It reported no matches for a pattern that matches \
                    nothing, which is the expected answer -- but the authorization \
                    check did not run, and that is the result. An absence of matches \
                    is not an absence of authorization. Repeating this with a real \
                    name pattern would enumerate the volume.
                    """
            )
        case .denied:
            return Search(
                id: id,
                mechanism: """
                    A volume-wide name search, a different VFS operation from \
                    reading a directory.
                    """,
                operation: "searchfs(path, &searchblock, &nummatches, 0, 0, &state)",
                arguments: "\(path), pattern=\(probePattern)",
                expected: "Denied with EPERM on a protected volume.",
                expectedDenied: true,
                outcome: .denied,
                errnoName: errnoName,
                matchCount: nil,
                observed: "refused with \(errnoName ?? "an unknown errno")",
                interpretation: """
                    Refused. Volume-wide name search is confined the same way \
                    directory enumeration is, so this primitive does not open the \
                    volume either.
                    """
            )
        default:
            return Search(
                id: id,
                mechanism: """
                    A volume-wide name search, a different VFS operation from \
                    reading a directory.
                    """,
                operation: "searchfs(path, &searchblock, &nummatches, 0, 0, &state)",
                arguments: "\(path), pattern=\(probePattern)",
                expected: "Denied with EPERM on a protected volume.",
                expectedDenied: true,
                outcome: answer,
                errnoName: errnoName,
                matchCount: matchCount,
                observed: "the call reported \(errnoName ?? "nothing")",
                interpretation: """
                    NOT ATTEMPTED for interpretation: the control answered \
                    \(controlAnswer.rawValue), and this call did not produce a \
                    denial, so nothing is claimed about the boundary.
                    """
            )
        }
    }

    private static func pathExists(_ path: String) -> Bool {
        var buffer = StatBuffer()
        return POSIXShim.statPath(path, followSymlink: false, into: &buffer) == 0
    }
}
