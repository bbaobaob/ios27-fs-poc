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
//    read(_:_:_:)                -> read(fd, buf, count)
//    write(_:_:_:)               -> write(fd, buf, count)
//    openDir(_:)                 -> opendir(path)
//    nextEntry(_:)               -> readdir(dir)
//    closeDir(_:)                -> closedir(dir)
//    statPath(_:followSymlink:into:) -> stat()/lstat()
//    readLink(_:into:capacity:)  -> readlink(path, buf, capacity)
//    unlinkFile(_:)              -> unlink(path)
//

import Foundation

/// Minimal stat result: only the fields the capability matrix records.
public struct StatBuffer: Sendable {
    public var size: Int64 = 0
    /// Full st_mode value (file type + permission bits).
    public var mode: UInt32 = 0
    public init() {}
}

public enum POSIXShim {}
