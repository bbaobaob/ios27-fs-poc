//
//  ErrnoAccess.swift
//  FSProbeCore — portable access to the thread-local errno.
//
//  On Darwin (iOS/macOS, the actual target) `errno` is the standard macro and
//  is both readable and writable. Other platforms expose the same value through
//  a function; this shim keeps the rest of the harness platform-independent so
//  the probe logic can be compile-verified outside Darwin too.
//

import Foundation

/// Read the current thread's errno.
@inline(__always)
func currentErrno() -> Int32 {
#if canImport(Darwin)
    return errno
#else
    return Int32(__errno().pointee)
#endif
}

/// Set the current thread's errno.
@inline(__always)
func setErrno(_ value: Int32) {
#if canImport(Darwin)
    errno = value
#else
    __errno().pointee = Int32(value)
#endif
}

/// Portable existence check. Uses `fileExists` rather than `access(F_OK)` so
/// the same source compiles on Darwin and non-Darwin verification hosts.
func pathExists(_ path: String) -> Bool {
    FileManager.default.fileExists(atPath: path)
}
