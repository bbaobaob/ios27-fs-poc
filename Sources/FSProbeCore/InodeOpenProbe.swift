//
//  InodeOpenProbe.swift
//  FSProbeCore — open a vnode by inode, bypassing path resolution entirely.
//
//  HYPOTHESIS
//  ----------
//  Every path-based experiment so far has been refused, and the research
//  establishes why: the seatbelt lookup hook runs per component on the *resolved*
//  vnode, so `..`, symlinks, and dirfd-relative paths are all authorized normally.
//  That conclusion rests on one assumption — that the caller must traverse a path.
//
//  `openbyid_np()` does not traverse a path. It opens a vnode by filesystem id and
//  inode number:
//
//      fsid_t   fsid  = {st.st_dev, 0};
//      uint64_t objid = st.st_ino;
//      int fd = openbyid_np(&fsid, (fsobj_id_t *)&objid, flags);
//
//  The kernel resolves the object directly. If policy is enforced only in the
//  namei/lookup path, an inode-based open would never be checked — and we already
//  hold the (st_dev, st_ino) pairs, because `lstat()` succeeds on every /var/
//  directory the sandbox refuses to open.
//
//  EXPECTED RESULT
//  ---------------
//  Denied. The header for this call states the caller is "subject to ... checks
//  like a regular open", and Apple's own tests exercise it under a sandbox policy.
//
//  A contrary result would be a genuine boundary violation: an ordinary app
//  reading or enumerating a directory outside its container by inode, with no path
//  traversal involved.
//
//  SAFETY
//  ------
//  The first attempt uses O_EVTONLY, which requests authorization without granting
//  read or write access — it cannot modify anything. Only if that succeeds is a
//  read attempted, and only on directories the sandbox already refuses by path.
//

import Foundation

public enum InodeOpenProbe {

    // Darwin fcntl.h values, named distinctly to avoid colliding with whatever
    // the platform module happens to import.
    private static let kO_RDONLY: Int32 = 0x0000
    private static let kO_WRONLY: Int32 = 0x0001
    private static let kO_EVTONLY: Int32 = 0x2000
    private static let kO_DIRECTORY: Int32 = 0x100000

    public struct Attempt: Sendable, Codable {
        /// The path whose (fsid, inode) pair was used.
        public let path: String
        /// st_dev, the filesystem id.
        public let deviceID: Int32
        /// st_ino, the object id.
        public let inode: UInt64
        /// Whether lstat supplied the identifiers.
        public let identifiersAvailable: Bool
        /// Result of opening by inode with O_EVTONLY.
        public let evtonlyErrnoName: String?
        /// Result of opening by inode with O_RDONLY.
        public let readonlyErrnoName: String?
        /// Result of opening by inode with O_RDONLY|O_DIRECTORY.
        public let directoryErrnoName: String?
        /// Number of entries enumerated through the inode-opened descriptor, when
        /// the directory open succeeded.
        public let enumeratedEntries: Int?
        /// Sample entry names, when enumeration succeeded.
        public let sampleEntryNames: [String]?
        /// What the path-based open returned, for comparison.
        public let pathOpenErrnoName: String?
        /// What the path-based enumeration returned, for comparison.
        public let pathEnumerationErrnoName: String?

        public init(
            path: String,
            deviceID: Int32,
            inode: UInt64,
            identifiersAvailable: Bool,
            evtonlyErrnoName: String?,
            readonlyErrnoName: String?,
            directoryErrnoName: String?,
            enumeratedEntries: Int?,
            sampleEntryNames: [String]?,
            pathOpenErrnoName: String?,
            pathEnumerationErrnoName: String?
        ) {
            self.path = path
            self.deviceID = deviceID
            self.inode = inode
            self.identifiersAvailable = identifiersAvailable
            self.evtonlyErrnoName = evtonlyErrnoName
            self.readonlyErrnoName = readonlyErrnoName
            self.directoryErrnoName = directoryErrnoName
            self.enumeratedEntries = enumeratedEntries
            self.sampleEntryNames = sampleEntryNames
            self.pathOpenErrnoName = pathOpenErrnoName
            self.pathEnumerationErrnoName = pathEnumerationErrnoName
        }

        /// True when an inode-based open succeeded where the path-based one did
        /// not. This is the condition that would indicate a policy gap.
        public var inodeOpenSucceededWherePathFailed: Bool {
            (evtonlyErrnoName == nil || readonlyErrnoName == nil || directoryErrnoName == nil)
                && (pathOpenErrnoName != nil || pathEnumerationErrnoName != nil)
        }

        /// True when a directory outside the container was enumerated through an
        /// inode-opened descriptor.
        public var enumeratedByInode: Bool {
            (enumeratedEntries ?? 0) > 0 && pathEnumerationErrnoName != nil
        }
    }

    public struct Result: Sendable, Codable {
        public let attempts: [Attempt]
        /// Whether the `openbyid_np` symbol was available at all.
        public let symbolAvailable: Bool
        /// Attempts where the inode open succeeded but the path open did not.
        public let violations: [Attempt]

        public init(attempts: [Attempt], symbolAvailable: Bool, violations: [Attempt]) {
            self.attempts = attempts
            self.symbolAvailable = symbolAvailable
            self.violations = violations
        }
    }

    /// Run the inode-open battery against `paths`.
    ///
    /// Each path must be one the process can `lstat` but not open by path — which
    /// is exactly the /var/ set established by the earlier runs. A path that opens
    /// normally by path is a poor test, so the path-based result is recorded for
    /// comparison and the comparison drives the verdict.
    public static func probe(paths: [String]) -> Result {
        guard let openByID = resolveOpenByID() else {
            return Result(attempts: [], symbolAvailable: false, violations: [])
        }

        var attempts: [Attempt] = []
        for path in paths {
            attempts.append(attempt(path: path, openByID: openByID))
        }

        let violations = attempts.filter { $0.inodeOpenSucceededWherePathFailed }
        return Result(attempts: attempts, symbolAvailable: true, violations: violations)
    }

    /// The /var/ paths the device run established as lstat-able but not openable.
    public static func defaultTargets() -> [String] {
        [
            "/var",
            "/private/var",
            "/var/mobile",
            "/var/mobile/Library",
            "/var/mobile/Library/Preferences",
            "/var/mobile/Containers",
            "/var/mobile/Containers/Data/Application",
            "/var/mobile/Containers/Shared/AppGroup",
            "/var/tmp"
        ]
    }

    // MARK: - Internals

    private typealias OpenByIDFn = @convention(c) (
        UnsafePointer<Int32>, UnsafePointer<UInt64>, Int32
    ) -> Int32

    /// Resolve `openbyid_np` at runtime so the build never fails if the symbol is
    /// absent from the platform's libSystem.
    private static func resolveOpenByID() -> OpenByIDFn? {
        guard let sym = POSIXShim.lookupSymbol("openbyid_np") else { return nil }
        return unsafeBitCast(sym, to: OpenByIDFn.self)
    }

    private static func attempt(path: String, openByID: OpenByIDFn) -> Attempt {
        // Identifiers from lstat.
        var buffer = StatBuffer()
        let statRC = POSIXShim.statPath(path, followSymlink: false, into: &buffer)
        guard statRC == 0 else {
            return Attempt(
                path: path, deviceID: 0, inode: 0, identifiersAvailable: false,
                evtonlyErrnoName: nil, readonlyErrnoName: nil,
                directoryErrnoName: nil, enumeratedEntries: nil,
                sampleEntryNames: nil, pathOpenErrnoName: nil,
                pathEnumerationErrnoName: nil
            )
        }

        let deviceID = buffer.deviceID
        let inode = buffer.inode

        // Path-based comparison: what does a normal open return for this path?
        let pathFD = POSIXShim.openFile(path, kO_RDONLY, 0)
        let pathOpenErrnoName: String?
        if pathFD >= 0 {
            POSIXShim.closeFile(pathFD)
            pathOpenErrnoName = nil
        } else {
            pathOpenErrnoName = ErrorClassifier.errnoName(currentErrno())
        }

        var pathEnumerationErrnoName: String?
        if let dir = POSIXShim.openDir(path) {
            POSIXShim.closeDir(dir)
        } else {
            pathEnumerationErrnoName = ErrorClassifier.errnoName(currentErrno())
        }

        // The inode-based attempts.
        var fsid: [Int32] = [deviceID, 0]
        var objid: UInt64 = inode

        let evtonlyFD = openByID(&fsid, &objid, kO_EVTONLY)
        let evtonlyErrnoName: String?
        if evtonlyFD >= 0 {
            POSIXShim.closeFile(evtonlyFD)
            evtonlyErrnoName = nil
        } else {
            evtonlyErrnoName = ErrorClassifier.errnoName(currentErrno())
        }

        let readonlyFD = openByID(&fsid, &objid, kO_RDONLY)
        let readonlyErrnoName: String?
        if readonlyFD >= 0 {
            POSIXShim.closeFile(readonlyFD)
            readonlyErrnoName = nil
        } else {
            readonlyErrnoName = ErrorClassifier.errnoName(currentErrno())
        }

        // The prize: open the directory by inode and enumerate it.
        var directoryErrnoName: String?
        var enumeratedEntries: Int?
        var sampleEntryNames: [String]?
        let directoryFD = openByID(&fsid, &objid, kO_RDONLY | kO_DIRECTORY)
        if directoryFD >= 0 {
            directoryErrnoName = nil
            if let dir = POSIXShim.openDirFromFD(directoryFD) {
                var names: [String] = []
                var count = 0
                setErrno(0)
                while POSIXShim.nextEntry(dir) != nil {
                    count += 1
                    if let name = POSIXShim.nextEntryName(dir), name != "." && name != "..",
                       names.count < 10 {
                        names.append(name)
                    }
                    setErrno(0)
                }
                POSIXShim.closeDir(dir)
                enumeratedEntries = count
                sampleEntryNames = names.isEmpty ? nil : names
            } else {
                // fdopendir consumed the descriptor on failure; nothing to close.
                directoryErrnoName = ErrorClassifier.errnoName(currentErrno())
            }
        } else {
            directoryErrnoName = ErrorClassifier.errnoName(currentErrno())
        }

        return Attempt(
            path: path,
            deviceID: deviceID,
            inode: inode,
            identifiersAvailable: true,
            evtonlyErrnoName: evtonlyErrnoName,
            readonlyErrnoName: readonlyErrnoName,
            directoryErrnoName: directoryErrnoName,
            enumeratedEntries: enumeratedEntries,
            sampleEntryNames: sampleEntryNames,
            pathOpenErrnoName: pathOpenErrnoName,
            pathEnumerationErrnoName: pathEnumerationErrnoName
        )
    }
}
