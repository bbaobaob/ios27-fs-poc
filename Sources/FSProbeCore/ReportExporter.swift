//
//  ReportExporter.swift
//  FSProbeCore — deterministic JSON and plain-text export of the capability matrix.
//

import Foundation

public enum ReportExporter {

    /// Encode the matrix as pretty-printed JSON with sorted keys.
    public static func json(_ matrix: CapabilityMatrix) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let payload = MatrixPayload(matrix: matrix)
        return try encoder.encode(payload)
    }

    /// Render a fixed-width plain-text table for terminal/report use.
    public static func text(_ matrix: CapabilityMatrix, targets: [FSTarget]) -> String {
        var lines: [String] = []
        lines.append("FSProbe capability matrix")
        lines.append("platform: \(matrix.environment.osName) \(matrix.environment.osVersion)")
        lines.append("build:    \(matrix.environment.osBuild)")
        lines.append("device:   \(matrix.environment.deviceModel)")
        lines.append("process:  \(matrix.environment.processPath)")
        lines.append("captured: \(matrix.environment.timestampUTC)")
        lines.append("")

        let ops = FSOperation.allCases
        let rows = matrix.rows(targets: targets)

        // Each cell is "outcome errno": the outcome says what kind of result it
        // was, the errno says exactly which failure was observed. A cell with no
        // result is rendered as the explicit not-attempted outcome rather than a
        // dash, so a missing measurement can never be read as a passing one.
        let table: [[FSOperation: String]] = rows.map { row in
            var cells: [FSOperation: String] = [:]
            for op in ops {
                guard let outcome = row.cells[op] else {
                    cells[op] = ProbeOutcome.notAttempted.rawValue
                    continue
                }
                if let errno = row.errnoNames[op] {
                    cells[op] = "\(outcome.rawValue) \(errno)"
                } else {
                    cells[op] = outcome.rawValue
                }
            }
            return cells
        }

        let pathWidth = max(28, (targets.map { $0.path.count }.max() ?? 28))
        // Wide enough for the widest cell this run produced, so an errno is
        // never cut off by the column it is printed in.
        let cellWidth = max(12, table.flatMap { $0.values }.map { $0.count }.max() ?? 12)
        var header = "path".padding(toLength: pathWidth, withPad: " ", startingAt: 0)
        for op in ops {
            header += " " + op.rawValue.padding(toLength: cellWidth, withPad: " ", startingAt: 0)
        }
        lines.append(header)
        lines.append(String(repeating: "-", count: header.count))

        for (index, row) in rows.enumerated() {
            var line = row.path.padding(toLength: pathWidth, withPad: " ", startingAt: 0)
            for op in ops {
                let cell = table[index][op] ?? ProbeOutcome.notAttempted.rawValue
                line += " " + cell.padding(toLength: cellWidth, withPad: " ", startingAt: 0)
            }
            lines.append(line)
        }

        if !matrix.ancestors.isEmpty {
            lines.append("")
            lines.append("Ancestor ascent (read-only: lstat / opendir / readdir):")
            for step in matrix.ancestors {
                let detail = step.fullyVisible
                    ? "visible"
                    : "lstat=\(step.lstat.rawValue) opendir=\(step.openDirectory.rawValue) readdir=\(step.enumerate.rawValue)"
                let entries = step.entryCount.map { " (\($0) entries)" } ?? ""
                let errno = step.errnoName.map { " [\($0)]" } ?? ""
                lines.append("  \(step.depth) \(step.path) — \(detail)\(entries)\(errno)")
                if let reason = step.stopReason {
                    lines.append("      stopped: \(reason)")
                }
            }
            if let boundary = AncestorProbe.boundary(in: matrix.ancestors) {
                lines.append("  boundary: first not-fully-visible ancestor is depth \(boundary.depth) (\(boundary.path))")
            }
        }

        if let profile = matrix.sandboxProfile {
            lines.append("")
            lines.append("Sandbox profile (read from the app's own container metadata):")
            lines.append("  readable:        \(profile.readable)")
            lines.append("  metadata size:   \(profile.metadataSizeBytes.map { "\($0) bytes" } ?? "unknown")")
            lines.append("  identifier:      \(profile.metadataIdentifier ?? "unknown")")
            lines.append("  metadata keys:   \(profile.metadataKeys.joined(separator: ", "))")
            lines.append("  MCMMetadataInfo: \(profile.infoKeys.joined(separator: ", "))")
            lines.append("  has profile:     \(profile.hasSandboxProfileData)")
            if let bytes = profile.sandboxProfileBytes {
                lines.append("  profile size:    \(bytes) bytes")
            }
            if let digest = profile.sandboxProfileSHA256 {
                lines.append("  profile sha256:  \(digest)")
            }
            lines.append("  parses as plist: \(profile.profileParsesAsPlist)")
            if !profile.profileTopLevelKeys.isEmpty {
                lines.append("  profile keys:    \(profile.profileTopLevelKeys.joined(separator: ", "))")
            }
            if let errno = profile.readErrnoName {
                lines.append("  read errno:      \(errno)")
            }
            lines.append("  writable:        \(profile.writable)")
            if let errno = profile.writeErrnoName {
                lines.append("  write errno:     \(errno)")
            }
            lines.append("  note:            \(profile.note)")
        }

        if let cw = matrix.containerWrite {
            lines.append("")
            lines.append("Container write boundary (synthetic file, verified, removed):")
            lines.append("  container: \(cw.containerPath)")
            for entry in cw.entries {
                // The verdict names the state that was actually observed: a
                // refusal, a write that could not be verified, or a probe that
                // never reached the syscall. A recorded errno is what separates
                // "denied" from "not probed".
                let verdict: String
                if entry.writable {
                    verdict = "WRITABLE"
                } else if entry.createErrnoName != nil {
                    verdict = entry.enumerable ? "read-only" : "denied"
                } else if entry.writeErrnoName != nil || entry.readBackErrnoName != nil
                            || entry.readBackMatched != nil {
                    verdict = "wrote, not verified"
                } else {
                    verdict = "not probed"
                }
                let mode = entry.modeOctal.map { " mode=\($0)" } ?? ""
                let count = entry.entryCount.map { " entries=\($0)" } ?? ""
                lines.append("  \(entry.depth) \(entry.path) — \(verdict)\(mode)\(count)")

                // Every field the probe recorded is printed, not just the one
                // that produced the verdict: which errno, whether the read-back
                // matched, and whether the synthetic file could be removed again.
                var evidence: [String] = []
                if let errno = entry.createErrnoName { evidence.append("create errno: \(errno)") }
                if let errno = entry.writeErrnoName { evidence.append("write errno: \(errno)") }
                if let errno = entry.readBackErrnoName { evidence.append("read-back errno: \(errno)") }
                if let matched = entry.readBackMatched { evidence.append("read-back matched: \(matched)") }
                evidence.append("removed: \(entry.removable)")
                lines.append("      \(evidence.joined(separator: ", "))")
            }
            lines.append("  writable:                \(cw.writablePaths.joined(separator: ", "))")
            lines.append("  readable but not writable: \(cw.readableButNotWritablePaths.joined(separator: ", "))")
            if !cw.inconclusivePaths.isEmpty {
                lines.append("  inconclusive:            \(cw.inconclusivePaths.joined(separator: ", "))")
            }
        }

        if let clone = matrix.clone {
            lines.append("")
            lines.append("APFS clone across the boundary (a copy by inode):")
            if !clone.candidateSources.isEmpty {
                lines.append("  sources tried: \(clone.candidateSources.joined(separator: ", "))")
            }
            for experiment in clone.experiments {
                let flag = experiment.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(experiment.outcome.rawValue)] \(experiment.id)\(flag)")
                lines.append("      \(experiment.operation)  args: \(experiment.arguments)")
                if let errno = experiment.errnoName {
                    lines.append("      errno: \(errno) (\(experiment.errnoNumber))")
                }
                if let bytes = experiment.clonedBytes {
                    lines.append("      cloned: \(bytes) bytes, sha256 \(experiment.clonedSHA256 ?? "unknown")")
                }
                lines.append("      result: \(experiment.interpretation)")
            }
            if !clone.violations.isEmpty {
                lines.append("  VIOLATIONS: \(clone.violations.map { $0.id }.joined(separator: ", "))")
            } else {
                lines.append("  no clone succeeded across the boundary")
            }
        }

        // The XPC section is printed only when the experiments that produce it
        // were requested. Printing it unconditionally would state a conclusion
        // about service reachability for runs that never asked the question.
        if matrix.xpcServices != nil || matrix.fileCoordinator != nil {
            lines.append("")
            lines.append("XPC service reachability:")
            if let services = matrix.xpcServices, !services.isEmpty {
                for service in services {
                    lines.append("  \(service.serviceName): \(service.reachability.rawValue)"
                                 + " (\(service.responseMilliseconds.map { "\($0)ms" } ?? "no response"))")
                    if let reason = service.refusalReason { lines.append("      \(reason)") }
                }
            } else {
                lines.append("  NOT_ATTEMPTED: no mach service was opened, named, or probed.")
                lines.append("  \(XPCProbe.serviceCandidates().count) candidate services were "
                    + "identified and recorded as the attack surface; none could be probed.")
            }
            lines.append("  reason (an SDK availability fact, not a measurement): "
                + XPCProbe.xpcUnavailableReason)
        }

        if let coordinator = matrix.fileCoordinator {
            lines.append("")
            lines.append("NSFileCoordinator as a confused deputy:")
            for experiment in coordinator.experiments {
                let flag = experiment.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(experiment.outcome.rawValue)] \(experiment.id)\(flag)")
                lines.append("      \(experiment.operation)  args: \(experiment.arguments)")
                if let domain = experiment.errorDomain {
                    lines.append("      error: \(domain) \(experiment.errorCode ?? 0)")
                }
                lines.append("      result: \(experiment.interpretation)")
            }
            if !coordinator.violations.isEmpty {
                lines.append("  VIOLATIONS: \(coordinator.violations.map { $0.id }.joined(separator: ", "))")
            } else if coordinator.experiments.isEmpty {
                lines.append("  NOT_ATTEMPTED: no coordination experiment ran on this platform.")
            } else {
                lines.append("  no coordination succeeded where the policy predicts refusal")
            }
        }

        // Mach-lookup reachability. This is the experiment that converts the
        // earlier "an app cannot open a mach service by name" claim from an SDK
        // inference into a measurement, by resolving the connection factory at
        // runtime and then actually attempting each lookup.
        if let machServices = matrix.machServices {
            lines.append("")
            lines.append("Mach service reachability (connection factory resolved at runtime):")
            let resolved = machServices.filter { $0.symbolResolved }.count
            lines.append("  connection factory resolved in \(resolved) of \(machServices.count) attempts"
                + " (symbol presence is not a permission)")
            // The negative control calibrates what a refusal looks like, so it is
            // called out explicitly rather than buried in the list.
            if let control = machServices.first(where: { $0.serviceName.contains("nonexistent") }) {
                lines.append("  negative control (\(control.serviceName)): \(control.reachability.rawValue)")
                if let reason = control.refusalReason {
                    lines.append("      \(reason)")
                }
            }
            for service in machServices where !service.serviceName.contains("nonexistent") {
                let timing = service.responseMilliseconds.map { " \($0)ms" } ?? ""
                lines.append("  [\(service.reachability.rawValue)] \(service.serviceName)\(timing)")
                if let reason = service.refusalReason {
                    lines.append("      \(reason)")
                }
            }
            let answered = machServices.filter { $0.reachability == .reachable }.count
            lines.append("  \(answered) candidate(s) answered a connection carrying no protocol")
            lines.append("  note: reachability is reconnaissance, not a finding. A finding")
            lines.append("        requires an effect the caller was not authorized to produce.")
        }

        if let introspection = matrix.processIntrospection {
            lines.append("")
            lines.append("Cross-process introspection:")
            if introspection.attempts.isEmpty {
                lines.append("  NOT_ATTEMPTED: the process introspection APIs are not present"
                    + " on this platform, so no attempt was made.")
            } else {
                let controlNote = introspection.controlSucceeded
                    ? "the self-targeting control succeeded, so the results below are interpretable"
                    : "the self-targeting control FAILED, so every result below is INCONCLUSIVE:"
                        + " a refusal here means the API is unusable, not that the policy denies it"
                lines.append("  \(controlNote)")
                for attempt in introspection.attempts {
                    let marker = attempt.isControl ? " [control]" : ""
                    lines.append("  [\(attempt.outcome.rawValue)] \(attempt.operation) -> \(attempt.target)\(marker)")
                    if let rv = attempt.returnValue { lines.append("      return: \(rv)") }
                    if let err = attempt.errorName { lines.append("      error: \(err)") }
                    if let observed = attempt.observed { lines.append("      observed: \(observed)") }
                    lines.append("      result: \(attempt.interpretation)")
                }
                if !introspection.violations.isEmpty {
                    lines.append("  VIOLATIONS: \(introspection.violations.map { $0.id }.joined(separator: ", "))")
                } else if introspection.controlSucceeded {
                    lines.append("  no cross-process operation succeeded where the policy predicts refusal")
                } else {
                    lines.append("  INCONCLUSIVE: the control did not succeed, so no denial can be claimed")
                }
            }
        }

        if let deputy = matrix.preferenceDeputy {            lines.append("")
            lines.append("cfprefsd as a confused deputy (UserDefaults suite resolution):")
            for experiment in deputy.experiments {
                let flag = experiment.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(experiment.outcome.rawValue)] \(experiment.id)\(flag)")
                lines.append("      \(experiment.operation)  args: \(experiment.arguments)")
                if let observed = experiment.observed {
                    lines.append("      observed: \(observed)")
                }
                lines.append("      result: \(experiment.interpretation)")
            }
            if !deputy.violations.isEmpty {
                lines.append("  VIOLATIONS: \(deputy.violations.map { $0.id }.joined(separator: ", "))")
            } else if deputy.experiments.isEmpty {
                lines.append("  NOT_ATTEMPTED: no preference experiment ran.")
            } else {
                lines.append("  every write landed inside this container, as the policy predicts")
            }
        }

        if let classes = matrix.operationClasses {
            lines.append("")
            lines.append("Untested sandbox operation classes:")
            for experiment in classes.experiments {
                let flag = experiment.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(experiment.outcome.rawValue)] \(experiment.id)\(flag)")
                lines.append("      \(experiment.operation)  args: \(experiment.arguments)")
                if let errno = experiment.errnoName {
                    lines.append("      errno: \(errno)")
                }
                if let observed = experiment.observed {
                    lines.append("      observed: \(observed)")
                }
                lines.append("      result: \(experiment.interpretation)")
            }
            if !classes.violations.isEmpty {
                lines.append("  VIOLATIONS: \(classes.violations.map { $0.id }.joined(separator: ", "))")
            } else if classes.experiments.isEmpty {
                lines.append("  NOT_ATTEMPTED: no operation-class experiment ran.")
            } else {
                lines.append("  no operation class succeeded where the policy predicts refusal")
            }
        }

        if let metadata = matrix.metadataReads {
            lines.append("")
            lines.append("Read primitives that do not open the file:")
            for experiment in metadata.experiments {
                let flag = experiment.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(experiment.outcome.rawValue)] \(experiment.id)\(flag)")
                lines.append("      \(experiment.operation)  args: \(experiment.arguments)")
                if let errno = experiment.errnoName {
                    lines.append("      errno: \(errno)")
                }
                lines.append("      observed: \(experiment.observed ?? "no answer")")
                lines.append("      result: \(experiment.interpretation)")
            }
            if !metadata.violations.isEmpty {
                lines.append("  VIOLATIONS: \(metadata.violations.map { $0.id }.joined(separator: ", "))")
            } else if metadata.experiments.isEmpty {
                lines.append("  NOT_ATTEMPTED: no metadata-read experiment ran.")
            } else {
                lines.append("  every read primitive was refused where the policy predicts refusal")
            }
        }

        if let descriptors = matrix.descriptorPrimitives {
            lines.append("")
            lines.append("Primitives reachable through a descriptor:")
            for step in descriptors.steps {
                let flag = step.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(step.outcome.rawValue)] \(step.id)\(flag)")
                lines.append("      \(step.operation)  args: \(step.arguments)")
                if let errno = step.errnoName {
                    lines.append("      errno: \(errno)")
                }
                if let count = step.entryCount {
                    lines.append("      entries: \(count)")
                }
                lines.append("      observed: \(step.observed ?? "no answer")")
                lines.append("      result: \(step.interpretation)")
            }
            if !descriptors.violations.isEmpty {
                lines.append("  VIOLATIONS: \(descriptors.violations.map { $0.id }.joined(separator: ", "))")
            } else if descriptors.steps.isEmpty {
                lines.append("  NOT_ATTEMPTED: no descriptor experiment ran.")
            } else {
                lines.append("  no descriptor primitive succeeded where the policy predicts refusal")
            }
        }

        if let surface = matrix.foundationSurface {
            lines.append("")
            lines.append("The same boundary through Foundation rather than libc:")
            for item in surface.cases {
                let flag = item.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(item.outcome.rawValue)] \(item.id)\(flag)")
                lines.append("      \(item.operation)  args: \(item.arguments)")
                if let errno = item.errnoName {
                    lines.append("      errno: \(errno)")
                }
                lines.append("      observed: \(item.observed ?? "no answer")")
                lines.append("      result: \(item.interpretation)")
            }
            if !surface.violations.isEmpty {
                lines.append("  VIOLATIONS: \(surface.violations.map { $0.id }.joined(separator: ", "))")
            } else if surface.cases.isEmpty {
                lines.append("  NOT_ATTEMPTED: no Foundation-surface case ran.")
            } else {
                lines.append("  no Foundation API reported access the direct calls refused")
            }
        }

        if let lookups = matrix.alternateLookups {
            lines.append("")
            lines.append("Mach service lookup by a path other than the XPC factory:")
            lines.append("  bootstrap port available: \(lookups.bootstrapPortAvailable)")
            for item in lookups.lookups {
                let flag = item.isBoundaryViolation ? "  <-- BYPASS" : ""
                let xpc = item.xpcOutcome.map { "XPC: \($0)" } ?? "XPC: unknown"
                lines.append("  [\(item.outcome.rawValue)] \(item.serviceName)  (\(xpc))\(flag)")
                if let rv = item.returnValue { lines.append("      return: \(rv)") }
                if let err = item.errorName { lines.append("      error: \(err)") }
                lines.append("      result: \(item.interpretation)")
            }
            if !lookups.violations.isEmpty {
                lines.append("  BYPASSES: \(lookups.violations.map { $0.serviceName }.joined(separator: ", "))")
            } else if !lookups.bootstrapPortAvailable {
                lines.append("  NOT_ATTEMPTED: no bootstrap port, so nothing was measured")
            } else {
                lines.append("  no service resolved here that the XPC path refused")
            }
        }

        if let remaining = matrix.remainingPrimitives {
            lines.append("")
            lines.append("Primitives never tried before:")
            for item in remaining.cases {
                let flag = item.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(item.outcome.rawValue)] \(item.id)\(flag)")
                lines.append("      \(item.operation)  args: \(item.arguments)")
                if let rv = item.returnValue { lines.append("      return: \(rv)") }
                if let err = item.errorName { lines.append("      error: \(err)") }
                lines.append("      observed: \(item.observed ?? "no answer")")
                lines.append("      result: \(item.interpretation)")
            }
            if !remaining.violations.isEmpty {
                lines.append("  VIOLATIONS: \(remaining.violations.map { $0.id }.joined(separator: ", "))")
            } else if remaining.cases.isEmpty {
                lines.append("  NOT_ATTEMPTED: no remaining-primitive case ran.")
            } else {
                lines.append("  no remaining primitive answered where the policy predicts refusal")
            }
        }

        if let search = matrix.searchFS {
            lines.append("")
            lines.append("Volume-wide name search (searchfs):")
            for item in search.searches {
                let flag = item.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(item.outcome.rawValue)] \(item.id)\(flag)")
                lines.append("      \(item.operation)  args: \(item.arguments)")
                if let errno = item.errnoName { lines.append("      errno: \(errno)") }
                if let count = item.matchCount { lines.append("      matches: \(count)") }
                lines.append("      observed: \(item.observed ?? "no answer")")
                lines.append("      result: \(item.interpretation)")
            }
            if !search.violations.isEmpty {
                lines.append("  VIOLATIONS: \(search.violations.map { $0.id }.joined(separator: ", "))")
            } else if search.searches.isEmpty {
                lines.append("  NOT_ATTEMPTED: no searchfs experiment ran.")
            } else {
                lines.append("  the volume-wide search was refused, as the policy predicts")
            }
        }

        if let ladder = matrix.machPrivilege {
            lines.append("")
            lines.append("The Mach privilege ladder:")
            for rung in ladder.rungs {
                let flag = rung.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(rung.outcome.rawValue)] \(rung.id)\(flag)")
                lines.append("      \(rung.operation)  args: \(rung.arguments)")
                if let rv = rung.returnValue { lines.append("      return: \(rv)") }
                if let err = rung.errorName { lines.append("      error: \(err)") }
                lines.append("      observed: \(rung.observed ?? "no answer")")
                lines.append("      result: \(rung.interpretation)")
            }
            if !ladder.violations.isEmpty {
                lines.append("  VIOLATIONS: \(ladder.violations.map { $0.id }.joined(separator: ", "))")
            } else if ladder.rungs.isEmpty {
                lines.append("  NOT_ATTEMPTED: no Mach-privilege rung ran.")
            } else {
                lines.append("  no rung of the privilege ladder was reachable")
            }
        }

        if let replies = matrix.xpcReplies {
            lines.append("")
            lines.append("Do the reachable services actually answer a message?")
            for item in replies.probes {
                let flag = item.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(item.reply.rawValue)] \(item.serviceName)"
                    + "  (lookup: \(item.lookupOutcome))\(flag)")
                if let ms = item.responseMilliseconds {
                    lines.append("      response: \(ms)ms")
                }
                if let reason = item.interruptionReason {
                    lines.append("      reason: \(reason)")
                }
                if let shape = item.replyShape {
                    lines.append("      reply shape: \(shape)")
                }
                lines.append("      observed: \(item.observed ?? "no answer")")
                lines.append("      result: \(item.interpretation)")
            }
            if !replies.violations.isEmpty {
                lines.append("  VIOLATIONS: \(replies.violations.map { $0.serviceName }.joined(separator: ", "))")
            } else if replies.probes.isEmpty {
                lines.append("  NOT_ATTEMPTED: no reply probe ran.")
            } else {
                lines.append("  no service replied to a caller it had not identified")
            }
        }

        if let ipc = matrix.ipcSurface {
            lines.append("")
            lines.append("IPC surface reachable from an ordinary app:")
            for item in ipc.mechanisms {
                let flag = item.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(item.outcome.rawValue)] \(item.id)\(flag)")
                lines.append("      \(item.operation)  args: \(item.arguments)")
                lines.append("      observed: \(item.observed ?? "no answer")")
                lines.append("      result: \(item.interpretation)")
            }
            if !ipc.violations.isEmpty {
                lines.append("  VIOLATIONS: \(ipc.violations.map { $0.id }.joined(separator: ", "))")
            } else if ipc.mechanisms.isEmpty {
                lines.append("  NOT_ATTEMPTED: no IPC mechanism ran.")
            } else {
                lines.append("  no IPC mechanism reached a name the lookup paths refused")
            }
        }

        if let host = matrix.hostPort {
            lines.append("")
            lines.append("Is an obtainable host port actually usable?")
            lines.append("  host port obtained: \(host.hostPortObtained)")
            lines.append("  host port is impotent (every use refused with a validity error): \(host.hostPortIsImpotent)")
            for rung in host.rungs {
                let flag = rung.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(rung.outcome.rawValue)] \(rung.id)\(flag)")
                lines.append("      \(rung.operation)")
                if let rv = rung.returnValue { lines.append("      return: \(rv)") }
                if let err = rung.errorName { lines.append("      error: \(err)") }
                lines.append("      observed: \(rung.observed ?? "no answer")")
                lines.append("      result: \(rung.interpretation)")
            }
            if !host.violations.isEmpty {
                lines.append("  VIOLATIONS: \(host.violations.map { $0.id }.joined(separator: ", "))")
            } else if host.hostPortObtained && host.hostPortIsImpotent {
                lines.append("  the host port is obtainable but grants nothing: the earlier violation was an artifact")
            } else if !host.hostPortObtained {
                lines.append("  no host port was obtained")
            } else {
                lines.append("  the host port was refused by policy on every use")
            }
        }

        if let psets = matrix.processorSets {
            lines.append("")
            lines.append("Can an ordinary app enumerate every task on the device?")
            for rung in psets.rungs {
                let flag = rung.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(rung.outcome.rawValue)] \(rung.id)\(flag)")
                lines.append("      \(rung.operation)")
                if let rv = rung.returnValue { lines.append("      return: \(rv)") }
                if let err = rung.errorName { lines.append("      error: \(err)") }
                if let count = rung.taskCount { lines.append("      tasks: \(count)") }
                lines.append("      observed: \(rung.observed ?? "no answer")")
                lines.append("      result: \(rung.interpretation)")
            }
            if !psets.violations.isEmpty {
                lines.append("  VIOLATIONS: \(psets.violations.map { $0.id }.joined(separator: ", "))")
            } else if psets.rungs.isEmpty {
                lines.append("  NOT_ATTEMPTED: no processor-set rung ran.")
            } else {
                lines.append("  no processor set yielded a task list")
            }
        }

        if let memory = matrix.foreignMemory {
            lines.append("")
            lines.append("Can an ordinary app read another process's memory?")
            for item in memory.reads {
                let flag = item.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(item.outcome.rawValue)] \(item.id)  -> \(item.target)\(flag)")
                lines.append("      \(item.operation)")
                if let rv = item.returnValue { lines.append("      return: \(rv)") }
                if let err = item.errorName { lines.append("      error: \(err)") }
                if let bytes = item.bytesRead { lines.append("      bytes: \(bytes)") }
                lines.append("      observed: \(item.observed ?? "no answer")")
                lines.append("      result: \(item.interpretation)")
            }
            if !memory.violations.isEmpty {
                lines.append("  VIOLATIONS: \(memory.violations.map { $0.id }.joined(separator: ", "))")
            } else if memory.reads.isEmpty {
                lines.append("  NOT_ATTEMPTED: no memory read ran.")
            } else {
                lines.append("  no foreign memory was readable")
            }
        }

        if let io = matrix.inodeOpen {
            lines.append("")
            lines.append("Open-by-inode (openbyid_np: no path traversal at all):")
            lines.append("  symbol available: \(io.symbolAvailable)")
            if !io.symbolAvailable {
                lines.append("  openbyid_np is not present on this platform, so the experiment could not run.")
            }
            for attempt in io.attempts {
                let flag = attempt.enumeratedByInode ? "  <-- ENUMERATED BY INODE" : ""
                lines.append("  \(attempt.path)")
                // A nil errno means the open succeeded *only* when the attempt was
                // actually made. Without identifiers there is nothing to report,
                // and printing "ok" there would present a missing measurement as a
                // successful one.
                func inodeResult(_ errnoName: String?) -> String {
                    guard attempt.identifiersAvailable else { return "not attempted" }
                    return errnoName ?? "ok"
                }
                func pathResult(_ errnoName: String?) -> String {
                    errnoName ?? "ok"
                }
                lines.append("      inode: dev=\(attempt.deviceID) ino=\(attempt.inode)")
                lines.append("      by inode:  evtonly=\(inodeResult(attempt.evtonlyErrnoName)) "
                    + "readonly=\(inodeResult(attempt.readonlyErrnoName)) "
                    + "directory=\(inodeResult(attempt.directoryErrnoName))")
                lines.append("      by path:   open=\(pathResult(attempt.pathOpenErrnoName)) "
                    + "enumerate=\(pathResult(attempt.pathEnumerationErrnoName))")
                if let count = attempt.enumeratedEntries {
                    lines.append("      enumerated \(count) entries by inode\(flag)")
                    if let names = attempt.sampleEntryNames, !names.isEmpty {
                        lines.append("      sample: \(names.joined(separator: ", "))")
                    }
                }
                if attempt.inodeOpenSucceededWherePathFailed {
                    lines.append("      VERDICT: inode open succeeded where the path open was refused.")
                }
            }
            if !io.violations.isEmpty {
                lines.append("  VIOLATIONS: \(io.violations.map { $0.path }.joined(separator: ", "))")
            } else {
                lines.append("  no inode-based open succeeded where the path-based one was refused")
            }
        }

        for (label, scope) in [("while the scope is held", matrix.securityScope),
                               ("after the scope was released", matrix.securityScopeAfterRelease)] {
            guard let scope else { continue }
            lines.append("")
            lines.append("User-granted scope (\(label)):")
            lines.append("  granted:  \(scope.grantedPath)")
            lines.append("  resolved: \(scope.resolvedPath)")
            lines.append("  active:   \(scope.scopeActive)")
            for experiment in scope.experiments {
                let flag = experiment.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(experiment.outcome.rawValue)] \(experiment.id)\(flag)")
                lines.append("      \(experiment.operation)  args: \(experiment.arguments)")
                if let errno = experiment.errnoName {
                    lines.append("      errno: \(errno) (\(experiment.errnoNumber))")
                }
                lines.append("      result: \(experiment.interpretation)")
            }
            if !scope.violations.isEmpty {
                lines.append("  VIOLATIONS: \(scope.violations.map { $0.id }.joined(separator: ", "))")
            } else {
                lines.append("  no experiment succeeded where the grant should have refused it")
            }
        }

        if !matrix.boundaryExperiments.isEmpty {
            lines.append("")
            lines.append("Boundary-mechanism experiments:")
            for experiment in matrix.boundaryExperiments {
                let flag = experiment.isBoundaryViolation ? "  <-- BOUNDARY VIOLATION" : ""
                lines.append("  [\(experiment.outcome.rawValue)] \(experiment.id)\(flag)")
                lines.append("      mechanism: \(experiment.mechanism)")
                lines.append("      operation: \(experiment.operation)  args: \(experiment.arguments)")
                lines.append("      expected:  \(experiment.expected)")
                if let errno = experiment.errnoName {
                    lines.append("      errno:     \(errno) (\(experiment.errnoNumber))")
                }
                lines.append("      result:    \(experiment.interpretation)")
            }
        }

        lines.append("")
        lines.append("Discrepancies:")
        let discrepancies = matrix.discrepancies()
        if discrepancies.isEmpty {
            lines.append("  none")
        } else {
            for d in discrepancies {
                lines.append("  - [\(d.path)] \(d.description)")
            }
        }
        return lines.joined(separator: "\n") + "\n"
    }

    /// JSON payload shape. Kept explicit so the format is stable across versions.
    private struct MatrixPayload: Encodable {
        let schema: String
        let environment: CapabilityMatrix.EnvironmentRecord
        let results: [ProbeResult]
        let ancestors: [AncestorStep]
        let boundaryExperiments: [CrossBoundaryProbe.Experiment]
        let sandboxProfile: SandboxProfileProbe.Result?
        let containerWrite: ContainerWriteProbe.Result?
        let inodeOpen: InodeOpenProbe.Result?
        let securityScope: SecurityScopeProbe.Result?
        let clone: CloneProbe.Result?
        let xpcServices: [XPCProbe.ServiceProbe]?
        let fileCoordinator: XPCProbe.CoordinatorResult?
        let securityScopeAfterRelease: SecurityScopeProbe.Result?
        let machServices: [CrossProcessProbe.MachServiceProbe]?
        let processIntrospection: CrossProcessProbe.IntrospectionReport?
        let preferenceDeputy: PreferenceDeputyProbe.Result?
        let operationClasses: FileOperationClassProbe.Result?
        let metadataReads: MetadataReadProbe.Result?
        let descriptorPrimitives: DescriptorPrimitiveProbe.Result?
        let foundationSurface: FoundationSurfaceProbe.Result?
        let alternateLookups: AlternateLookupProbe.Result?
        let remainingPrimitives: RemainingPrimitivesProbe.Result?
        let searchFS: SearchFSProbe.Result?
        let machPrivilege: MachPrivilegeProbe.Result?
        let xpcReplies: XPCReplyProbe.Result?
        let ipcSurface: IPCSurfaceProbe.Result?
        let hostPort: HostPortProbe.Result?
        let processorSets: ProcessorSetProbe.Result?
        let foreignMemory: ForeignMemoryProbe.Result?

        init(matrix: CapabilityMatrix) {
            self.schema = "fsprobe.capability-matrix.v9"
            self.environment = matrix.environment
            self.results = matrix.results
            self.ancestors = matrix.ancestors
            self.boundaryExperiments = matrix.boundaryExperiments
            self.sandboxProfile = matrix.sandboxProfile
            self.containerWrite = matrix.containerWrite
            self.inodeOpen = matrix.inodeOpen
            self.securityScope = matrix.securityScope
            self.securityScopeAfterRelease = matrix.securityScopeAfterRelease
            self.clone = matrix.clone
            self.xpcServices = matrix.xpcServices
            self.fileCoordinator = matrix.fileCoordinator
            self.machServices = matrix.machServices
            self.processIntrospection = matrix.processIntrospection
            self.preferenceDeputy = matrix.preferenceDeputy
            self.operationClasses = matrix.operationClasses
            self.metadataReads = matrix.metadataReads
            self.descriptorPrimitives = matrix.descriptorPrimitives
            self.foundationSurface = matrix.foundationSurface
            self.alternateLookups = matrix.alternateLookups
            self.remainingPrimitives = matrix.remainingPrimitives
            self.searchFS = matrix.searchFS
            self.machPrivilege = matrix.machPrivilege
            self.xpcReplies = matrix.xpcReplies
            self.ipcSurface = matrix.ipcSurface
            self.hostPort = matrix.hostPort
            self.processorSets = matrix.processorSets
            self.foreignMemory = matrix.foreignMemory
        }
    }
}
