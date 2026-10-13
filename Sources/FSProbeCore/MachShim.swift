//
//  MachShim.swift
//  FSProbeCore — the single place the Mach and libproc APIs are bound.
//
//  WHY THIS FILE EXISTS
//  --------------------
//  `@_silgen_name` binds a symbol to a Swift declaration, and the Swift compiler
//  treats the resulting function as a method of the enclosing type. Two different
//  enums that both declare `@_silgen_name("mach_port_deallocate")` therefore share
//  ONE implementation while declaring different signatures, and the build fails
//  with "function type mismatch, declared as ... but used as ...".
//
//  That is exactly what happened: CrossProcessProbe, AlternateLookupProbe, and
//  RemainingPrimitivesProbe each bound the Mach error and port-deallocation
//  functions independently. The fix is structural — bind every Mach and libproc
//  symbol once, here, and have every module call through this shim.
//
//  The same reasoning applies to the libproc functions, which is why they live
//  here too even though only one module currently uses them.
//
//  Each binding is gated to Darwin, where the symbols exist. The verification host
//  gets stubs that report the symbol as absent, so a module can ask
//  `MachShim.available` and withhold its experiment rather than fabricating a
//  result.
//

import Foundation

#if canImport(Darwin)
import Darwin
/// The Mach port type, spelled portably so this file compiles everywhere.
public typealias MachPort = mach_port_t
#else
/// A stand-in for the verification host, where Mach does not exist.
public typealias MachPort = UInt32
#endif

/// The single binding point for the Mach task/port and libproc APIs.
public enum MachShim {

    /// True when the platform provides these APIs.
    public static var available: Bool {
        #if canImport(Darwin)
        return true
        #else
        return false
        #endif
    }

    // MARK: - Task and port primitives

    /// `mach_task_self_` — this task's own port.
    public static var taskSelf: MachPort {
        #if canImport(Darwin)
        return mach_task_self_
        #else
        return 0
        #endif
    }

    /// `mach_host_self()` — a host port, the strongest Mach primitive.
    public static func hostSelf() -> MachPort {
        #if canImport(Darwin)
        return mach_host_self()
        #else
        return 0
        #endif
    }

    /// `mach_port_deallocate(task, name)`.
    @discardableResult
    public static func deallocatePort(_ task: MachPort, _ name: MachPort) -> Int32 {
        #if canImport(Darwin)
        return mach_port_deallocate(task, name)
        #else
        return -1
        #endif
    }

    /// `task_get_bootstrap_port(task, &port)`.
    ///
    /// Bound by name because these two live in libSystem's bootstrap.h rather
    /// than in the Darwin module, so they are not visible to a plain import.
    /// They are bound HERE, once, which is the entire purpose of this file.
    #if canImport(Darwin)
    @_silgen_name("task_get_bootstrap_port")
    private static func cTaskGetBootstrapPort(
        _ task: MachPort, _ port: UnsafeMutablePointer<MachPort>
    ) -> Int32

    @_silgen_name("bootstrap_look_up")
    private static func cBootstrapLookUp(
        _ bp: MachPort, _ name: UnsafePointer<CChar>,
        _ sp: UnsafeMutablePointer<MachPort>
    ) -> Int32
    #endif

    public static func taskGetBootstrapPort(
        _ task: MachPort, _ port: UnsafeMutablePointer<MachPort>
    ) -> Int32 {
        #if canImport(Darwin)
        return cTaskGetBootstrapPort(task, port)
        #else
        return -1
        #endif
    }

    /// `bootstrap_look_up(bp, name, &sp)`.
    public static func bootstrapLookUp(
        _ bootstrapPort: MachPort,
        _ serviceName: UnsafePointer<CChar>,
        _ servicePort: UnsafeMutablePointer<MachPort>
    ) -> Int32 {
        #if canImport(Darwin)
        return cBootstrapLookUp(bootstrapPort, serviceName, servicePort)
        #else
        return -1
        #endif
    }

    /// `task_for_pid(target, pid, &task)`.
    public static func taskForPid(
        _ target: MachPort, _ pid: Int32, _ task: UnsafeMutablePointer<MachPort>
    ) -> Int32 {
        #if canImport(Darwin)
        return task_for_pid(target, pid, task)
        #else
        return -1
        #endif
    }

    /// `mach_error_string(kr)` — the platform's own name for a kern_return_t.
    public static func machErrorString(_ kr: Int32) -> String {
        #if canImport(Darwin)
        guard let ptr = mach_error_string(mach_error_t(kr)) else {
            return "kern_return_t \(kr)"
        }
        return String(cString: ptr)
        #else
        return "kern_return_t \(kr)"
        #endif
    }

    // MARK: - libproc primitives

    /// `proc_pidpath(pid, buffer, size)` — a process's executable path.
    public static func procPidPath(
        _ pid: Int32, _ buffer: UnsafeMutableRawPointer, _ size: UInt32
    ) -> Int32 {
        #if canImport(Darwin)
        return proc_pidpath(pid, buffer, size)
        #else
        return -1
        #endif
    }

    /// `proc_listallpids(buffer, size)` — the process table.
    public static func procListAllPids(
        _ buffer: UnsafeMutableRawPointer?, _ size: Int32
    ) -> Int32 {
        #if canImport(Darwin)
        return proc_listallpids(buffer, size)
        #else
        return -1
        #endif
    }
}
