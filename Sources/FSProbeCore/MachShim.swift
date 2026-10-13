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

    /// `task_get_bootstrap_port(task, &port)` and `bootstrap_look_up(bp, name, &sp)`.
    ///
    /// These are resolved at runtime rather than linked. The link failed on macOS
    /// with "Undefined symbols for architecture arm64: _task_get_bootstrap_port":
    /// the symbol is not present in the macOS libSystem that the runner links
    /// against, and binding it by name therefore breaks the build on a platform
    /// where the experiment cannot run anyway.
    ///
    /// Resolving at runtime is the honest answer here, and it matches what the
    /// clonefile and openbyid_np experiments already do for the same reason: the
    /// symbol is an iOS research target, its presence is itself a fact worth
    /// recording, and a platform without it must report the experiment as
    /// unattempted rather than failing to build.
    private typealias TaskGetBootstrapPortFn = @convention(c) (
        MachPort, UnsafeMutablePointer<MachPort>
    ) -> Int32

    private typealias BootstrapLookUpFn = @convention(c) (
        MachPort, UnsafePointer<CChar>, UnsafeMutablePointer<MachPort>
    ) -> Int32

    private static var taskGetBootstrapPortFn: TaskGetBootstrapPortFn? {
        guard let sym = POSIXShim.lookupSymbol("task_get_bootstrap_port") else { return nil }
        return unsafeBitCast(sym, to: TaskGetBootstrapPortFn.self)
    }

    private static var bootstrapLookUpFn: BootstrapLookUpFn? {
        guard let sym = POSIXShim.lookupSymbol("bootstrap_look_up") else { return nil }
        return unsafeBitCast(sym, to: BootstrapLookUpFn.self)
    }

    /// True when both bootstrap symbols resolved, which is what makes the
    /// alternate-lookup experiment runnable at all.
    public static var bootstrapAPIAvailable: Bool {
        taskGetBootstrapPortFn != nil && bootstrapLookUpFn != nil
    }

    public static func taskGetBootstrapPort(
        _ task: MachPort, _ port: UnsafeMutablePointer<MachPort>
    ) -> Int32 {
        guard let fn = taskGetBootstrapPortFn else { return -1 }
        return fn(task, port)
    }

    /// `bootstrap_look_up(bp, name, &sp)`.
    public static func bootstrapLookUp(
        _ bootstrapPort: MachPort,
        _ serviceName: UnsafePointer<CChar>,
        _ servicePort: UnsafeMutablePointer<MachPort>
    ) -> Int32 {
        guard let fn = bootstrapLookUpFn else { return -1 }
        return fn(bootstrapPort, serviceName, servicePort)
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

    /// `task_get_special_port(task, which, &port)` — a named special port.
    ///
    /// Bound by name: it lives in the Mach headers, which are not visible to a
    /// plain `import Darwin` on the iOS SDK.
    #if canImport(Darwin)
    @_silgen_name("task_get_special_port")
    private static func cTaskGetSpecialPort(
        _ task: MachPort, _ which: Int32, _ port: UnsafeMutablePointer<MachPort>
    ) -> Int32

    @_silgen_name("task_threads")
    private static func cTaskThreads(
        _ task: MachPort, _ list: UnsafeMutablePointer<MachPort>,
        _ count: UnsafeMutablePointer<Int32>
    ) -> Int32

    @_silgen_name("task_info")
    private static func cTaskInfo(
        _ task: MachPort, _ flavor: Int32,
        _ info: UnsafeMutableRawPointer, _ count: UnsafeMutablePointer<UInt32>
    ) -> Int32
    #endif

    public static func taskGetSpecialPort(
        _ task: MachPort, _ which: Int32, _ port: UnsafeMutablePointer<MachPort>
    ) -> Int32 {
        #if canImport(Darwin)
        return cTaskGetSpecialPort(task, which, port)
        #else
        return -1
        #endif
    }

    /// `task_threads(task, &list, &count)` — the threads of a task.
    public static func taskThreads(
        _ task: MachPort, _ list: UnsafeMutablePointer<MachPort>,
        _ count: UnsafeMutablePointer<Int32>
    ) -> Int32 {
        #if canImport(Darwin)
        return cTaskThreads(task, list, count)
        #else
        return -1
        #endif
    }

    /// `task_info(task, flavor, &info, &count)` — information about a task.
    public static func taskInfo(
        _ task: MachPort, _ flavor: Int32,
        _ info: UnsafeMutableRawPointer, _ count: UnsafeMutablePointer<UInt32>
    ) -> Int32 {
        #if canImport(Darwin)
        return cTaskInfo(task, flavor, info, count)
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

    /// `proc_pidpath(pid, buffer, size)` — a process's executable path, and
    /// `proc_listallpids(buffer, size)` — the process table.
    ///
    /// Bound by name because libproc.h is not visible to a plain `import Darwin`
    /// on the iOS SDK: the symbols resolve on macOS through the Darwin module but
    /// not on iOS, where the header is not imported. Binding them here, once, is
    /// what keeps this working on the platform the research actually targets.
    #if canImport(Darwin)
    @_silgen_name("proc_pidpath")
    private static func cProcPidPath(
        _ pid: Int32, _ buffer: UnsafeMutableRawPointer, _ size: UInt32
    ) -> Int32

    @_silgen_name("proc_listallpids")
    private static func cProcListAllPids(
        _ buffer: UnsafeMutableRawPointer?, _ size: Int32
    ) -> Int32
    #endif

    public static func procPidPath(
        _ pid: Int32, _ buffer: UnsafeMutableRawPointer, _ size: UInt32
    ) -> Int32 {
        #if canImport(Darwin)
        return cProcPidPath(pid, buffer, size)
        #else
        return -1
        #endif
    }

    /// `proc_listallpids(buffer, size)` — the process table.
    public static func procListAllPids(
        _ buffer: UnsafeMutableRawPointer?, _ size: Int32
    ) -> Int32 {
        #if canImport(Darwin)
        return cProcListAllPids(buffer, size)
        #else
        return -1
        #endif
    }
}
