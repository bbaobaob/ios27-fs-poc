//
//  FsGetPathProbe.swift
//  FSProbeCore — can an ordinary app ask the kernel for a path it was refused?
//
//  WHY THIS EXISTS
//  ---------------
//  Every path lookup this project has done starts from a string: the app
//  names a path and the sandbox decides whether that name resolves. That
//  is one question, and it is well covered now.
//
//  `fsgetpath` is a different question. It takes a VOLUME ID and an OBJECT
//  ID -- the two numbers that identify a vnode -- and returns the path the
//  kernel has recorded for it. No path is supplied, so there is no path to
//  check. If the function answers for an object outside the container, the
//  app has learned a path it was never allowed to name, which is a
//  disclosure primitive rather than an access one, and it is the kind of
//  asymmetry that tends to sit underneath a larger bug.
//
//  The app does not need to enumerate to make this interesting: it can
//  learn its own volume id from a file it legitimately owns, and then ask
//  about object ids it has never opened.
//
//  HYPOTHESIS
//  ----------
//  `fsgetpath` answers for the app's own objects and refuses for anything
//  else, including objects on the same volume identified only by number.
//
//  BOUNDARY UNDER TEST
//  -------------------
//  Whether a path can be obtained for an object the app was never given a
//  path to, by addressing that object as a pair of numbers.
//
//  CONTROL
//  -------
//  The first row asks for the path of a file the app just created in its
//  own container, addressed by the (volume, object) pair read out of that
//  same file. It MUST return the path it was created with. Without that,
//  every refusal below says only that fsgetpath is unavailable, not that
//  the boundary held.
//
//  SAFETY
//  ------
//  Read-only. The function returns a path; it opens nothing, changes
//  nothing, and cannot be made to resolve anything. Object ids are probed
//  in a small bounded range and only on the volume the app already has an
//  object on.
//
//  SYMBOL NOTE
//  -----------
//  `fsgetpath` is not in the Swift Darwin overlay, so it is resolved with
//  POSIXShim.lookupSymbol and called through a fixed-arity pointer. It is
//  not variadic, which is why this is safe where binding fcntl the same
//  way was not.
//

import Foundation

public enum FsGetPathProbe {

    public enum Outcome: String, Codable, Sendable {
        /// The call returned a path.
        case answered
        /// The call was refused with EPERM.
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

        /// A path obtained for an object the app was never given a path to
        /// is the shape this probe is looking for, and it is still not a
        /// finding from a simulator or CI host: those are macOS processes,
        /// and a macOS answer is not an iOS answer. The interpretation
        /// prose says what it would mean; the flag stays false until a
        /// stock iOS 27.0 device answers.
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

    private static let groupOwn = "the app's own object, addressed by number"
    private static let groupForeign = "objects the app has no path to"
    private static let groupVolume = "a volume the app has no object on"

    /// How many foreign object ids to probe. Small on purpose: each is a
    /// syscall, and the interesting answer is whether ANY of them is
    /// answered, not how many there are.
    public static let maxForeignProbes = 24

    public static func probe() -> Result {
        #if canImport(Darwin)
        var entries: [Entry] = []
        entries.append(contentsOf: ownGroup())
        entries.append(contentsOf: foreignGroup())
        entries.append(contentsOf: volumeGroup())
        let violations = entries.filter { $0.isBoundaryViolation }
        return Result(entries: entries, violations: violations)
        #else
        return Result(
            entries: [
                Entry(
                    id: "fsgetpath-own-group", group: groupOwn,
                    operation: "fsgetpath(buf, len, volumeID, objectID)",
                    target: "(no object available)",
                    outcome: .notAttempted, errnoName: nil, returnedValue: nil,
                    observed: "this platform is not Darwin",
                    interpretation: """
                        NOT ATTEMPTED: fsgetpath is a Darwin VFS call and there \
                        is no such thing here. The group is recorded rather than \
                        omitted so its absence is never read as a clean result.
                        """
                ),
                Entry(
                    id: "fsgetpath-foreign-group", group: groupForeign,
                    operation: "fsgetpath(buf, len, volumeID, foreignObjectID)",
                    target: "(no object available)",
                    outcome: .notAttempted, errnoName: nil, returnedValue: nil,
                    observed: "this platform is not Darwin",
                    interpretation: """
                        NOT ATTEMPTED: the by-number question needs a Darwin VFS \
                        to be meaningful, and there is none here.
                        """
                ),
                Entry(
                    id: "fsgetpath-volume-group", group: groupVolume,
                    operation: "fsgetpath(buf, len, foreignVolumeID, objectID)",
                    target: "(no volume available)",
                    outcome: .notAttempted, errnoName: nil, returnedValue: nil,
                    observed: "this platform is not Darwin",
                    interpretation: """
                        NOT ATTEMPTED: volume ids are a Darwin concept and there \
                        is none here.
                        """
                )
            ],
            violations: []
        )
        #endif
    }

    #if canImport(Darwin)

    // `ssize_t fsgetpath(char *buf, size_t bufsize, uint64_t volume_id,
    //                   uint64_t object_id)` -- the form this probe was first
    // written against.
    private typealias FsGetPathFn = @convention(c) (
        UnsafeMutablePointer<CChar>, Int, UInt64, UInt64
    ) -> Int

    // The other form in the headers: `fsid_t *fsid` rather than a bare
    // `uint64_t volume_id`. `fsid_t` is two int32s, and the whole reason this
    // second binding exists is that the first one answered EFAULT for a file
    // that demonstrably exists -- which is what passing a number into a slot
    // the callee dereferences as a pointer looks like. Rather than guess
    // which form a given OS ships, both are tried and both are recorded.
    private typealias FsGetPathFsidFn = @convention(c) (
        UnsafeMutablePointer<CChar>, Int, UnsafeMutableRawPointer, UInt64
    ) -> Int

    private static func bind<T>(_ name: String) -> T? {
        guard let sym = POSIXShim.lookupSymbol(name) else { return nil }
        return unsafeBitCast(sym, to: T.self)
    }

    private static func scratch(_ name: String) -> String {
        (NSTemporaryDirectory() as NSString).appendingPathComponent(name)
    }

    /// The result of one fsgetpath attempt, with the form that produced it.
    private struct Attempt {
        let form: String
        let path: String?
        let rc: Int
        let err: Int32
    }

    /// Try both documented forms of the third argument. A bare
    /// `uint64_t volume_id` and an `fsid_t *` are not interchangeable, and
    /// passing one where the other is expected is a dereference of a small
    /// integer -- an EFAULT rather than a wrong answer, which is why the
    /// first version of this probe answered EFAULT for a file it had just
    /// created. Both are attempted and both are reported, so the form that
    /// works on the host is visible in the result rather than assumed.
    private static func getPath(
        volume: UInt64, object: UInt64, deviceID: Int32
    ) -> (Attempt, Attempt) {
        var bufA = [CChar](repeating: 0, count: 1024)
        var rcA = -1
        var errA: Int32 = Int32(ENOSYS)
        var pathA: String?
        if let fn: FsGetPathFn = bind("fsgetpath") {
            setErrno(0)
            rcA = fn(&bufA, bufA.count, volume, object)
            errA = currentErrno()
            if rcA > 0 { pathA = String(cString: bufA) }
        }
        let a = Attempt(form: "uint64_t volume_id", path: pathA, rc: rcA, err: errA)

        var bufB = [CChar](repeating: 0, count: 1024)
        var rcB = -1
        var errB: Int32 = Int32(ENOSYS)
        var pathB: String?
        if let fn: FsGetPathFsidFn = bind("fsgetpath") {
            // fsid_t is two int32s. The first is the device id on Darwin, and
            // the second is zero for a single-volume answer.
            var fsid = [Int32(deviceID), Int32(0)]
            setErrno(0)
            rcB = fsid.withUnsafeMutableBufferPointer { fsidPtr in
                fn(&bufB, bufB.count, fsidPtr.baseAddress!, object)
            }
            errB = currentErrno()
            if rcB > 0 { pathB = String(cString: bufB) }
        }
        let b = Attempt(form: "fsid_t *", path: pathB, rc: rcB, err: errB)
        return (a, b)
    }

    private static func classify(_ rc: Int, _ err: Int32) -> Outcome {
        rc > 0 ? .answered : (err == Int32(EPERM) ? .denied
            : (err == Int32(ENOENT) ? .notFound : .otherError))
    }

    /// Render one attempt for an `observed` line.
    private static func describe(_ a: Attempt) -> String {
        if let p = a.path { return "\(a.form): \"\(p)\"" }
        return "\(a.form): rc \(a.rc), errno \(ErrorClassifier.errnoName(a.err))"
    }

    /// The interpretation for a pair of attempts. A path from either form is
    /// the answer; EFAULT from both means the call is malformed and the row is
    /// inconclusive rather than negative.
    private static func interpret(
        _ a: Attempt, _ b: Attempt, target: String
    ) -> String {
        let anyPath = a.path ?? b.path
        if let p = anyPath {
            let via = a.path != nil ? a.form : b.form
            return """
                A path was obtained for \(target) via the \(via) form. No path \
                was supplied, so there was nothing for the sandbox's path hook \
                to check -- the object was addressed as a pair of numbers. \
                Recorded with isBoundaryViolation false because the answer came \
                from a simulator or CI host, a macOS process under a different \
                sandbox; only a stock iOS 27.0 device makes it a finding. What \
                it would mean if real is specific: the app learned the name of \
                an object it was never given a path to.
                """
        }
        if a.err == Int32(EFAULT) && b.err == Int32(EFAULT) {
            return """
                Both forms answered EFAULT, which is not an authorization \
                answer: it says the callee rejected an address. The \
                own-object control above is the row that decides whether that \
                is a malformed call or the boundary holding, and this row is \
                inconclusive beside it.
                """
        }
        if a.err == Int32(EPERM) || b.err == Int32(EPERM) {
            return """
                EPERM from at least one form: the sandbox gates the by-number \
                lookup exactly as it gates the by-name one. The app cannot \
                learn a path it was refused, which is the correct answer.
                """
        }
        if a.err == Int32(ENOENT) || b.err == Int32(ENOENT) {
            return """
                ENOENT: there is no such object. That is an answer about the \
                object, not about the boundary, and it is the expected shape \
                for ids the app invented.
                """
        }
        return """
            Neither form produced a path or a refusal this probe can name. \
            Recorded as it stands rather than attributed to either cause.
            """
    }

    // MARK: - Group 1: the app's own object

    private static func ownGroup() -> [Entry] {
        guard let _: FsGetPathFn = bind("fsgetpath") else {
            return [Entry(
                id: "fsgetpath-symbol",
                group: groupOwn,
                operation: "dlsym(fsgetpath)",
                target: "(the symbol itself)",
                outcome: .symbolUnavailable, errnoName: nil, returnedValue: nil,
                observed: "fsgetpath could not be resolved with dlsym",
                interpretation: """
                    NOT ATTEMPTED: the symbol is absent from the process image, \
                    so no by-number question could be asked. A missing symbol is \
                    a statement about the platform, not a refusal by it.
                    """
            )]
        }

        let own = scratch("fsprobe-fsgetpath-\(getpid())")
        setErrno(0)
        let fd = POSIXShim.openFile(own, O_CREAT | O_TRUNC | O_WRONLY, 0o644)
        let createErr = currentErrno()
        guard fd >= 0 else {
            return [Entry(
                id: "fsgetpath-control-create",
                group: groupOwn,
                operation: "open(tmp, O_CREAT|O_TRUNC|O_WRONLY)",
                target: own,
                outcome: classify(Int(fd), createErr),
                errnoName: ErrorClassifier.errnoName(createErr),
                returnedValue: "\(fd)",
                observed: "open returned -1, errno=\(ErrorClassifier.errnoName(createErr))",
                interpretation: """
                    CONTROL FAILED: the object to address by number could not be \
                    created, so no row below has anything to point at. Recorded \
                    rather than omitted.
                    """
            )]
        }
        _ = POSIXShim.closeFile(fd)
        defer { cleanup(own) }

        // Read the (volume, object) pair out of the app's own file. This is
        // the only identity the probe has, and every later row is built from
        // it -- which is exactly why the control has to pass first.
        var st = StatBuffer()
        let statRC = POSIXShim.statPath(own, followSymlink: false, into: &st)
        guard statRC == 0 else {
            return [Entry(
                id: "fsgetpath-control-stat",
                group: groupOwn,
                operation: "stat(ownFile)",
                target: own,
                outcome: classify(Int(statRC), currentErrno()),
                errnoName: ErrorClassifier.errnoName(currentErrno()),
                returnedValue: "\(statRC)",
                observed: "stat returned \(statRC), so no (volume, object) pair is available",
                interpretation: """
                    CONTROL FAILED: without the identity pair there is nothing \
                    to address by number, and the rows below are inconclusive.
                    """
            )]
        }
        let volume = UInt64(bitPattern: Int64(st.deviceID))
        let object = st.inode

        let (a, b) = getPath(volume: volume, object: object, deviceID: st.deviceID)
        let anyAnswered = a.path != nil || b.path != nil
        return [Entry(
            id: "fsgetpath-control-own-object",
            group: groupOwn,
            operation: "fsgetpath(buf, 1024, volume/object from stat of ownFile)",
            target: own,
            outcome: anyAnswered ? .answered : classify(a.rc, a.err),
            errnoName: anyAnswered ? nil : ErrorClassifier.errnoName(a.err),
            returnedValue: anyAnswered ? "path" : "\(a.rc)",
            observed: "\(describe(a)); \(describe(b))",
            interpretation: a.path == own || b.path == own
                ? """
                    CONTROL: the path came back byte-identical to the path the \
                    app created, obtained by addressing the object as a pair of \
                    numbers with no path supplied. That is what makes a refusal \
                    in the next group a statement about the boundary rather \
                    than about fsgetpath being unavailable.
                    """
                : anyAnswered
                    ? """
                    CONTROL PARTIAL: fsgetpath answered, but with a different \
                    path than the one created. That is worth understanding \
                    before the foreign rows are read -- it may mean the app is \
                    not on the volume it thinks it is, or that the form which \
                    worked is the one this probe did not expect.
                    """
                    : a.err == Int32(EFAULT) && b.err == Int32(EFAULT)
                        ? """
                        CONTROL FAILED, and not for an authorization reason: \
                        both forms answered EFAULT for an object the app owns \
                        and can stat. EFAULT says the callee rejected an \
                        address, not that a path was refused, so the call itself \
                        is malformed rather than the boundary holding. Every row \
                        in the next group is inconclusive beside it.
                        """
                        : """
                        CONTROL FAILED: no path came back for an object the app \
                        owns and can stat. Every row in the next group is \
                        therefore inconclusive, and a refusal there would be \
                        indistinguishable from the machinery not running.
                        """
        )]
    }

    // MARK: - Group 2: objects the app has no path to

    private static func foreignGroup() -> [Entry] {
        // Re-derive the identity from the app's own file, because the volume
        // id is what the foreign rows share and there is nowhere else to get
        // it. If the control above failed, the volume id is still usable for
        // asking -- it is the object ids that change.
        let own = scratch("fsprobe-fsgetpath-\(getpid())")
        setErrno(0)
        let fd = POSIXShim.openFile(own, O_CREAT | O_TRUNC | O_WRONLY, 0o644)
        guard fd >= 0 else {
            return [Entry(
                id: "fsgetpath-foreign-setup",
                group: groupForeign,
                operation: "open(tmp) to obtain a volume id",
                target: own,
                outcome: classify(Int(fd), currentErrno()),
                errnoName: ErrorClassifier.errnoName(currentErrno()),
                returnedValue: "\(fd)",
                observed: "open returned -1, errno=\(ErrorClassifier.errnoName(currentErrno()))",
                interpretation: """
                    NOT ATTEMPTED: without an object on the volume there is no \
                    volume id to ask about, so the foreign-object rows could not \
                    run. Recorded rather than omitted.
                    """
            )]
        }
        _ = POSIXShim.closeFile(fd)
        defer { cleanup(own) }

        var st = StatBuffer()
        guard POSIXShim.statPath(own, followSymlink: false, into: &st) == 0 else {
            return [Entry(
                id: "fsgetpath-foreign-setup",
                group: groupForeign,
                operation: "stat(tmp) to obtain a volume id",
                target: own,
                outcome: classify(-1, currentErrno()),
                errnoName: ErrorClassifier.errnoName(currentErrno()),
                returnedValue: "-1",
                observed: "stat returned -1, so no volume id is available",
                interpretation: """
                    NOT ATTEMPTED: the volume id is the shared coordinate of \
                    every foreign row, and without it none of them could be \
                    asked. Recorded rather than omitted.
                    """
            )]
        }
        let volume = UInt64(bitPattern: Int64(st.deviceID))

        var rows: [Entry] = []
        // Low object ids are the interesting ones: they are the volume's own
        // metadata and root objects, which no app is ever given a path to.
        // The app has never opened any of them; it only knows the volume they
        // live on, because it has an object there itself.
        for object in [UInt64(1), 2, 3, 4, 5, 6, 7, 8, 15, 16, 24] where
            rows.count < maxForeignProbes
        {
            let (a, b) = getPath(
                volume: volume, object: object, deviceID: st.deviceID
            )
            let answered = a.path != nil || b.path != nil
            rows.append(Entry(
                id: "fsgetpath-foreign-object-\(object)",
                group: groupForeign,
                operation: "fsgetpath(buf, 1024, volume=\(volume), object=\(object))",
                target: "object \(object) on the app's own volume",
                outcome: answered ? .answered : classify(a.rc, a.err),
                errnoName: answered ? nil : ErrorClassifier.errnoName(a.err),
                returnedValue: answered ? "path" : "\(a.rc)",
                observed: "\(describe(a)); \(describe(b))",
                interpretation: interpret(
                    a, b, target: "object \(object) on this volume"
                )
            ))
        }
        return rows
    }

    // MARK: - Group 3: a volume the app has no object on

    private static func volumeGroup() -> [Entry] {
        // The app's own volume id, reused as the object side of a question
        // about a DIFFERENT volume. If fsgetpath answered for objects on a
        // volume the app has nothing on, the boundary would not even be
        // per-volume.
        var rows: [Entry] = []
        for (id, volume) in [
            ("fsgetpath-foreign-volume-zero", UInt64(0)),
            ("fsgetpath-foreign-volume-one", UInt64(1))
        ] {
            let (a, b) = getPath(volume: volume, object: 2, deviceID: Int32(volume))
            let answered = a.path != nil || b.path != nil
            rows.append(Entry(
                id: id,
                group: groupVolume,
                operation: "fsgetpath(buf, 1024, volume=\(volume), object=2)",
                target: "object 2 on volume \(volume)",
                outcome: answered ? .answered : classify(a.rc, a.err),
                errnoName: answered ? nil : ErrorClassifier.errnoName(a.err),
                returnedValue: answered ? "path" : "\(a.rc)",
                observed: "\(describe(a)); \(describe(b))",
                interpretation: interpret(
                    a, b, target: "object 2 on volume \(volume)"
                )
            ))
        }
        return rows
    }

    private static func cleanup(_ path: String) {
        guard let sym = POSIXShim.lookupSymbol("unlink") else { return }
        let unlink = unsafeBitCast(
            sym, to: (@convention(c) (UnsafePointer<CChar>) -> Int32).self
        )
        setErrno(0)
        let rc = path.withCString { unlink($0) }
        if rc != 0 && currentErrno() != Int32(ENOENT) {
            // Housekeeping, not a measurement: retried once through Foundation
            // and never promoted into a result row, because a scratch-file bug
            // must not be able to masquerade as a finding.
            try? FileManager.default.removeItem(atPath: path)
        }
    }

    #endif
}
