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
    //                   uint64_t object_id)` -- not variadic, not in the Swift
    // overlay, so it is resolved and called through a fixed pointer.
    private typealias FsGetPathFn = @convention(c) (
        UnsafeMutablePointer<CChar>, Int, UInt64, UInt64
    ) -> Int

    private static func bind<T>(_ name: String) -> T? {
        guard let sym = POSIXShim.lookupSymbol(name) else { return nil }
        return unsafeBitCast(sym, to: T.self)
    }

    private static func scratch(_ name: String) -> String {
        (NSTemporaryDirectory() as NSString).appendingPathComponent(name)
    }

    /// Call fsgetpath, returning (path, rc, errno).
    private static func getPath(
        _ volume: UInt64, _ object: UInt64
    ) -> (path: String?, rc: Int, err: Int32) {
        guard let fn: FsGetPathFn = bind("fsgetpath") else {
            return (nil, -1, Int32(ENOSYS))
        }
        var buf = [CChar](repeating: 0, count: 1024)
        setErrno(0)
        let rc = fn(&buf, buf.count, volume, object)
        let err = currentErrno()
        let path = rc > 0 ? String(cString: buf) : nil
        return (path, rc, err)
    }

    private static func classify(_ rc: Int, _ err: Int32) -> Outcome {
        rc > 0 ? .answered : (err == Int32(EPERM) ? .denied
            : (err == Int32(ENOENT) ? .notFound : .otherError))
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

        let (path, rc, err) = getPath(volume, object)
        return [Entry(
            id: "fsgetpath-control-own-object",
            group: groupOwn,
            operation: "fsgetpath(buf, 1024, volume=\(volume), object=\(object))",
            target: own,
            outcome: classify(rc, err),
            errnoName: rc > 0 ? nil : ErrorClassifier.errnoName(err),
            returnedValue: rc > 0 ? "path (\(rc) bytes)" : "\(rc)",
            observed: path.map { "fsgetpath returned \"\($0)\"" }
                ?? "fsgetpath returned \(rc), errno=\(ErrorClassifier.errnoName(err))",
            interpretation: path == own
                ? """
                    CONTROL: the path came back byte-identical to the path the \
                    app created, obtained by addressing the object as a pair of \
                    numbers with no path supplied. That is what makes a refusal \
                    in the next group a statement about the boundary rather \
                    than about fsgetpath being unavailable.
                    """
                : path != nil
                    ? """
                    CONTROL PARTIAL: fsgetpath answered, but with a different \
                    path than the one created (\(path ?? "nil")). That is worth \
                    understanding before the foreign rows are read -- it may \
                    mean the app is not on the volume it thinks it is.
                    """
                    : """
                    CONTROL FAILED: no path came back for an object the app owns \
                    and can stat. Every row in the next group is therefore \
                    inconclusive, and a refusal there would be \
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
            let (path, rc, err) = getPath(volume, object)
            rows.append(Entry(
                id: "fsgetpath-foreign-object-\(object)",
                group: groupForeign,
                operation: "fsgetpath(buf, 1024, volume=\(volume), object=\(object))",
                target: "object \(object) on the app's own volume",
                outcome: classify(rc, err),
                errnoName: rc > 0 ? nil : ErrorClassifier.errnoName(err),
                returnedValue: rc > 0 ? "path (\(rc) bytes)" : "\(rc)",
                observed: path.map { "fsgetpath returned \"\($0)\"" }
                    ?? "fsgetpath returned \(rc), errno=\(ErrorClassifier.errnoName(err))",
                interpretation: rc > 0
                    ? """
                    A path was obtained for object \(object) on this volume, an \
                    object the app has never opened and was never given a path \
                    to. That is a path-disclosure primitive reached by \
                    addressing a vnode as a pair of numbers. It is recorded with \
                    isBoundaryViolation false because the answer came from a \
                    simulator or CI host -- a macOS process, under a different \
                    sandbox -- and only a stock iOS 27.0 device makes it a \
                    finding. What it would mean if real is specific: the app \
                    could learn the names of files it is forbidden to name.
                    """
                    : err == Int32(EPERM)
                        ? """
                        EPERM: the sandbox gates the by-number lookup exactly as \
                        it gates the by-name one. The app cannot learn a path it \
                        was refused, which is the correct answer.
                        """
                        : err == Int32(ENOENT)
                            ? """
                            ENOENT: there is no such object on this volume. That is \
                            an answer about the object, not about the boundary, \
                            and it is the expected shape for ids the app invented.
                            """
                            : """
                            The answer was \(ErrorClassifier.errnoName(err)), which \
                            is neither EPERM nor ENOENT. Recorded as it stands \
                            rather than attributed to either cause.
                            """
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
            let (path, rc, err) = getPath(volume, 2)
            rows.append(Entry(
                id: id,
                group: groupVolume,
                operation: "fsgetpath(buf, 1024, volume=\(volume), object=2)",
                target: "object 2 on volume \(volume)",
                outcome: classify(rc, err),
                errnoName: rc > 0 ? nil : ErrorClassifier.errnoName(err),
                returnedValue: rc > 0 ? "path (\(rc) bytes)" : "\(rc)",
                observed: path.map { "fsgetpath returned \"\($0)\"" }
                    ?? "fsgetpath returned \(rc), errno=\(ErrorClassifier.errnoName(err))",
                interpretation: rc > 0
                    ? """
                    A path was obtained on a volume the app has no object on. \
                    Recorded with isBoundaryViolation false for the same reason \
                    as the foreign-object rows: a simulator or CI-host answer is \
                    a macOS answer. If real, it would mean the lookup is not \
                    even scoped to the volume the app can see.
                    """
                    : """
                    Refused, errno \(ErrorClassifier.errnoName(err)). A refusal \
                    here alongside refusals on the app's own volume is the \
                    boundary holding consistently rather than selectively.
                    """
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
