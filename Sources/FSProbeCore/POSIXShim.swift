//
//  POSIXShim.swift
//  FSProbeCore — uniform POSIX surface used by the probe engine.
//
//  The probe engine calls only these wrappers. On Darwin they are thin
//  pass-throughs to the platform libc (POSIXShim+Darwin.swift); on non-Darwin
//  verification hosts they bind to the same C symbols
//  (POSIXShim+Compat.swift). Exactly one implementation is compiled per
//  platform, and neither alters what the engine measures.
//
//  API (all return -1/0 conventions identical to POSIX, with errno set):
//    openFile(_:_:_:)            -> open(path, flags, mode)
//    closeFile(_:)               -> close(fd)
//    readFD(_:_:_:)              -> read(fd, buf, count)
//    writeFD(_:_:_:)             -> write(fd, buf, count)
//    openDir(_:)                 -> opendir(path)
//    nextEntry(_:)               -> readdir(dir)
//    closeDir(_:)                -> closedir(dir)
//    statPath(_:followSymlink:into:) -> stat()/lstat()
//    readLink(_:into:capacity:)  -> readlink(path, buf, capacity)
//    unlinkFile(_:)              -> unlink(path)
//    linkFile(_:_:)              -> link(source, destination)
//    renameFile(_:_:)            -> rename(source, destination)
//    fileSize(atPath:)           -> st_size via stat()
//

import Foundation

/// Minimal stat result: only the fields the capability matrix records.
public struct StatBuffer: Sendable {
    /// `S_IFMT` — the file-type bits of st_mode.
    public static let modeTypeMask: UInt32 = 0o170000
    /// `S_IFDIR` — directory file type.
    public static let modeDirectory: UInt32 = 0o040000

    public var size: Int64 = 0
    /// Full st_mode value (file type + permission bits).
    public var mode: UInt32 = 0
    public init() {}
}

public enum POSIXShim {}
