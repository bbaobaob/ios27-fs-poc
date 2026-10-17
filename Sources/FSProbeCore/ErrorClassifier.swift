//
//  ErrorClassifier.swift
//  FSProbeCore — maps observed errno values to outcomes and access causes.
//
//  The distinction between EPERM and EACCES matters on iOS: the seatbelt
//  sandbox denies with EPERM, while POSIX permission bits deny with EACCES.
//  Conflating them would hide the authorization boundary being investigated.
//

import Foundation

public enum ErrorClassifier {

    /// Symbolic name for an errno value, using the Darwin/Glibc tables.
    public static func errnoName(_ code: Int32) -> String {
        switch code {
        case Int32(EPERM): return "EPERM"
        case Int32(ENOENT): return "ENOENT"
        case Int32(ESRCH): return "ESRCH"
        case Int32(EINTR): return "EINTR"
        case Int32(EIO): return "EIO"
        case Int32(ENXIO): return "ENXIO"
        case Int32(E2BIG): return "E2BIG"
        case Int32(ENOEXEC): return "ENOEXEC"
        case Int32(EBADF): return "EBADF"
        case Int32(ECHILD): return "ECHILD"
        case Int32(EAGAIN): return "EAGAIN"
        case Int32(ENOMEM): return "ENOMEM"
        case Int32(EACCES): return "EACCES"
        case Int32(EFAULT): return "EFAULT"
        case Int32(EBUSY): return "EBUSY"
        case Int32(EEXIST): return "EEXIST"
        case Int32(EXDEV): return "EXDEV"
        case Int32(ENODEV): return "ENODEV"
        case Int32(ENOTDIR): return "ENOTDIR"
        case Int32(EISDIR): return "EISDIR"
        case Int32(EINVAL): return "EINVAL"
        case Int32(ENFILE): return "ENFILE"
        case Int32(EMFILE): return "EMFILE"
        case Int32(ENOTTY): return "ENOTTY"
        case Int32(EFBIG): return "EFBIG"
        case Int32(ENOSPC): return "ENOSPC"
        case Int32(ESPIPE): return "ESPIPE"
        case Int32(EROFS): return "EROFS"
        case Int32(EMLINK): return "EMLINK"
        case Int32(EPIPE): return "EPIPE"
        case Int32(EDEADLK): return "EDEADLK"
        case Int32(ENAMETOOLONG): return "ENAMETOOLONG"
        case Int32(ELOOP): return "ELOOP"
        case Int32(EOVERFLOW): return "EOVERFLOW"
        // The first of the two below is not academic. `socket(AF_UNSPEC, ...)`
        // answers EAFNOSUPPORT, which is what the socket-family control is
        // *supposed* to see -- and an unnamed errno rendered it as "errno(47)",
        // i.e. as an anomaly rather than as the control's expected answer.
        //
        // ENOATTR is spelled numerically because <sys/errno.h> defines it
        // conditionally and the Swift Darwin module does not export it at all,
        // so `Int32(ENOATTR)` does not compile. Its value on Darwin is 93 and
        // it is what getxattr answers for a name that does not exist -- the
        // extended-attribute equivalent of ENOENT. Without a name that answer
        // read as "errno(93)" and looked like a boundary question instead of
        // the absence of one attribute.
        case Int32(EAFNOSUPPORT): return "EAFNOSUPPORT"
        #if canImport(Darwin)
        case 93: return "ENOATTR"
        #endif
        default: return "errno(\(code))"
        }
    }

    /// Classify an errno into a coarse outcome.
    public static func outcome(for code: Int32) -> ProbeOutcome {
        switch code {
        case 0: return .succeeded
        case Int32(ENOENT): return .notFound
        case Int32(ENOTDIR): return .notDirectory
        case Int32(EISDIR): return .isDirectory
        case Int32(EPERM): return .deniedEPERM
        case Int32(EACCES): return .deniedEACCES
        default: return .failedOther
        }
    }

    /// Attribute an outcome to an access cause.
    ///
    /// - Parameter pathExisted: whether a prior existence check found the path.
    ///   A denial on a path that does not exist is not a security observation.
    public static func cause(outcome: ProbeOutcome, pathExisted: Bool) -> AccessCause {
        switch outcome {
        case .succeeded:
            return .documentedCapability
        case .notFound, .notDirectory:
            return .pathAbsent
        case .isDirectory:
            // EISDIR is the documented POSIX answer to reading a directory: it
            // happens for an authorized process too, so it is neither a denial
            // nor an unexplained anomaly. The read-back layer knows from
            // `ProbeEvidence.statIsDirectory` when the target really is one.
            return .documentedCapability
        case .deniedEPERM:
            // On iOS, EPERM from the sandbox is the seatbelt denial signature.
            return .sandboxEnforcement
        case .deniedEACCES:
            return .posixPermissions
        case .notAttempted:
            // Nothing ran, so nothing was observed.
            return .configurationIssue
        case .failedOther:
            return pathExisted ? .unexplained : .pathAbsent
        }
    }

    /// Exact strerror() text for an errno, so reports never show a generic message.
    public static func description(for code: Int32) -> String {
        String(cString: strerror(code))
    }
}
