#!/usr/bin/env python3
"""Generate FSProbe.xcodeproj for the iOS app target.

The repository is a SwiftPM package (library + tests + CLI). SwiftPM cannot
produce iOS app bundles, so the iOS app needs an Xcode project. Rather than
committing a hand-maintained .pbxproj — which drifts silently and is effectively
unreviewable — the project is generated from the source tree by this script and
the generated output is committed alongside it.

Run from the repository root:

    python3 scripts/generate_xcode_project.py

Layout produced:

    FSProbe (iOS app)  <- Sources/FSProbeCore/*.swift + Sources/App/*.swift

A single app target compiles the probe library and the UI together. The module
boundary between them lives in the SwiftPM package (FSProbeCore is a real
library target there, which is what the tests and the CLI import); the app
target is a thin shell around the same sources. A two-target Xcode project
(library + app, with a target dependency) was attempted first and is recorded
in docs/attribution.md as a known limitation.

Sources/fsprobe-cli is deliberately excluded: it is the command-line runner used
by CI, not part of the app.

The generator validates its own output (balanced delimiters, resolvable object
references, no duplicate build settings, quoted values that need quoting) and
exits non-zero rather than writing a project Xcode cannot open.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROJECT_DIR = ROOT / "FSProbe.xcodeproj"
PBXPROJ = PROJECT_DIR / "project.pbxproj"

DEPLOYMENT_TARGET = "17.0"
BUNDLE_ID = "com.bbaobaob.fsprobe"
APP_TARGET = "FSProbe"

CORE_DIR = ROOT / "Sources" / "FSProbeCore"
APP_DIR = ROOT / "Sources" / "App"


def uid(seed: str) -> str:
    """Deterministic 24-hex-uppercase Xcode object identifier."""
    return hashlib.md5(seed.encode()).hexdigest()[:24].upper()


# Characters permitted in an unquoted old-style plist value. Anything outside
# this set — notably '+', as in POSIXShim+Compat.swift — must be quoted, or the
# whole project fails to parse with "missing semicolon in dictionary".
SAFE_BARE = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./$-")


def plist_value(value: str) -> str:
    """Quote a value only when it is not safe as a bare token."""
    if value and all(ch in SAFE_BARE for ch in value):
        return value
    return '"' + value.replace('"', '\\"') + '"'


def collect(directory: Path) -> list[str]:
    if not directory.is_dir():
        return []
    return sorted(str(p.relative_to(ROOT)) for p in directory.rglob("*.swift"))


PROJECT_SETTINGS = [
    ("ALWAYS_SEARCH_USER_PATHS", "NO"),
    ("CLANG_ENABLE_MODULES", "YES"),
    ("ENABLE_USER_SCRIPT_SANDBOXING", "YES"),
    ("CLANG_ENABLE_OBJC_WEAK", "YES"),
    ("CLANG_WARN_BOOL_CONVERSION", "YES"),
    ("CLANG_WARN_CONSTANT_CONVERSION", "YES"),
    ("CLANG_WARN_EMPTY_BODY", "YES"),
    ("CLANG_WARN_ENUM_CONVERSION", "YES"),
    ("CLANG_WARN_INFINITE_RECURSION", "YES"),
    ("CLANG_WARN_INT_CONVERSION", "YES"),
    ("CLANG_WARN_NON_LITERAL_NULL_CONVERSION", "YES"),
    ("CLANG_WARN_OBJC_IMPLICIT_RETAIN_SELF", "YES"),
    ("CLANG_WARN_OBJC_LITERAL_CONVERSION", "YES"),
    ("CLANG_WARN_QUOTED_INCLUDE_IN_FRAMEWORK_HEADER", "YES"),
    ("CLANG_WARN_RANGE_LOOP_ANALYSIS", "YES"),
    ("CLANG_WARN_STRICT_PROTOTYPES", "YES"),
    ("CLANG_WARN_SUSPICIOUS_MOVE", "YES"),
    ("CLANG_WARN_UNREACHABLE_CODE", "YES"),
    ("CLANG_WARN__DUPLICATE_METHOD_MATCH", "YES"),
    ("COPY_PHASE_STRIP", "NO"),
    ("ENABLE_STRICT_OBJC_MSGSEND", "NO"),
    ("GCC_C_LANGUAGE_STANDARD", "gnu17"),
    ("GCC_DYNAMIC_NO_PIC", "NO"),
    ("GCC_NO_COMMON_BLOCKS", "YES"),
    ("GCC_WARN_64_TO_32_BIT_CONVERSION", "YES"),
    ("GCC_WARN_ABOUT_RETURN_TYPE", "YES_ERROR"),
    ("GCC_WARN_UNDECLARED_SELECTOR", "YES"),
    ("GCC_WARN_UNINITIALIZED_AUTOS", "YES_AGGRESSIVE"),
    ("GCC_WARN_UNUSED_FUNCTION", "YES"),
    ("GCC_WARN_UNUSED_VARIABLE", "YES"),
    ("IPHONEOS_DEPLOYMENT_TARGET", DEPLOYMENT_TARGET),
    ("SDKROOT", "iphoneos"),
]

DEBUG_EXTRA = [
    ("ENABLE_TESTABILITY", "YES"),
    ("GCC_OPTIMIZATION_LEVEL", "0"),
    ("GCC_PREPROCESSOR_DEFINITIONS", '("DEBUG=1","$(inherited)")'),
    ("ONLY_ACTIVE_ARCH", "YES"),
    ("SWIFT_ACTIVE_COMPILATION_CONDITIONS", "DEBUG"),
    ("SWIFT_OPTIMIZATION_LEVEL", '"-Onone"'),
]

RELEASE_EXTRA = [
    ("DEBUG_INFORMATION_FORMAT", '"dwarf-with-dsym"'),
    ("ENABLE_NS_ASSERTIONS", "NO"),
    ("GCC_OPTIMIZATION_LEVEL", "s"),
    ("SWIFT_COMPILATION_MODE", "wholemodule"),
    ("SWIFT_OPTIMIZATION_LEVEL", '"-O"'),
    ("VALIDATE_PRODUCT", "YES"),
]

APP_SETTINGS = [
    ("CODE_SIGN_STYLE", "Automatic"),
    ("CODE_SIGNING_ALLOWED", "NO"),
    ("CURRENT_PROJECT_VERSION", "1"),
    ("GENERATE_INFOPLIST_FILE", "YES"),
    ("INFOPLIST_KEY_UIApplicationSceneManifest_Generation", "YES"),
    ("INFOPLIST_KEY_UILaunchScreen_Generation", "YES"),
    ("INFOPLIST_KEY_UISupportedInterfaceOrientations_iPhone",
     '"UIInterfaceOrientationPortrait UIInterfaceOrientationLandscapeLeft UIInterfaceOrientationLandscapeRight"'),
    ("IPHONEOS_DEPLOYMENT_TARGET", DEPLOYMENT_TARGET),
    ("LD_RUNPATH_SEARCH_PATHS", '("$(inherited)","@executable_path/Frameworks")'),
    ("MARKETING_VERSION", "1.0"),
    ("PRODUCT_BUNDLE_IDENTIFIER", BUNDLE_ID),
    ("PRODUCT_NAME", '"$(TARGET_NAME)"'),
    ("SDKROOT", "iphoneos"),
    ("SWIFT_VERSION", "5.0"),
    ("TARGETED_DEVICE_FAMILY", "1"),
]


def main() -> int:
    core_files = collect(CORE_DIR)
    app_files = collect(APP_DIR)

    if not core_files:
        print("error: Sources/FSProbeCore contains no .swift files", file=sys.stderr)
        return 1
    if not app_files:
        print("error: Sources/App contains no .swift files", file=sys.stderr)
        return 1

    all_files = core_files + app_files

    ids: dict[str, str] = {
        "project": uid("PBXProject"),
        "mainGroup": uid("PBXGroup:main"),
        "productsGroup": uid("PBXGroup:products"),
        "sourcesGroup": uid("PBXGroup:sources"),
        "target": uid("PBXNativeTarget:" + APP_TARGET),
        "sourcesPhase": uid("PBXSourcesBuildPhase:" + APP_TARGET),
        "frameworksPhase": uid("PBXFrameworksBuildPhase:" + APP_TARGET),
        "resourcesPhase": uid("PBXResourcesBuildPhase:" + APP_TARGET),
        "targetConfigList": uid("XCConfigurationList:" + APP_TARGET),
        "projectConfigList": uid("XCConfigurationList:project"),
        "projectDebug": uid("XCBuildConfiguration:project:Debug"),
        "projectRelease": uid("XCBuildConfiguration:project:Release"),
        "targetDebug": uid("XCBuildConfiguration:" + APP_TARGET + ":Debug"),
        "targetRelease": uid("XCBuildConfiguration:" + APP_TARGET + ":Release"),
        "appProduct": uid("PBXFileReference:" + APP_TARGET + ".app"),
    }
    for f in all_files:
        ids[f"file:{f}"] = uid(f"PBXFileReference:{f}")
        ids[f"build:{f}"] = uid(f"PBXBuildFile:{f}")

    lines: list[str] = []
    w = lines.append

    w("// !$*UTF8*$!")
    w("{")
    w("\tarchiveVersion = 1;")
    w("\tclasses = {")
    w("\t};")
    w("\tobjectVersion = 56;")
    w("\tobjects = {")
    w("")

    # ------------------------------------------------------ PBXBuildFile
    w("/* Begin PBXBuildFile section */")
    for f in all_files:
        base = os.path.basename(f)
        w(f"\t\t{ids[f'build:{f}']} /* {base} in Sources */ = "
          f"{{isa = PBXBuildFile; fileRef = {ids[f'file:{f}']} /* {base} */; }};")
    w("/* End PBXBuildFile section */")
    w("")

    # --------------------------------------------------- PBXFileReference
    w("/* Begin PBXFileReference section */")
    w(f"\t\t{ids['appProduct']} /* {APP_TARGET}.app */ = "
      f"{{isa = PBXFileReference; explicitFileType = wrapper.application; "
      f"includeInIndex = 0; path = {plist_value(APP_TARGET + '.app')}; "
      f"sourceTree = BUILT_PRODUCTS_DIR; }};")
    for f in all_files:
        rel = os.path.relpath(f, "Sources")
        w(f"\t\t{ids[f'file:{f}']} /* {rel} */ = "
          f"{{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; "
          f"path = {plist_value(rel)}; sourceTree = \"<group>\"; }};")
    w("/* End PBXFileReference section */")
    w("")

    # ---------------------------------------------- PBXFrameworksBuildPhase
    w("/* Begin PBXFrameworksBuildPhase section */")
    w(f"\t\t{ids['frameworksPhase']} /* Frameworks */ = {{")
    w("\t\t\tisa = PBXFrameworksBuildPhase;")
    w("\t\t\tbuildActionMask = 2147483647;")
    w("\t\t\tfiles = (")
    w("\t\t\t);")
    w("\t\t\trunOnlyForDeploymentPostprocessing = 0;")
    w("\t\t};")
    w("/* End PBXFrameworksBuildPhase section */")
    w("")

    # --------------------------------------------------------- PBXGroup
    w("/* Begin PBXGroup section */")
    w(f"\t\t{ids['sourcesGroup']} /* Sources */ = {{")
    w("\t\t\tisa = PBXGroup;")
    w("\t\t\tchildren = (")
    for f in all_files:
        w(f"\t\t\t\t{ids[f'file:{f}']} /* {os.path.relpath(f, 'Sources')} */,")
    w("\t\t\t);")
    w(f"\t\t\tpath = {plist_value('Sources')};")
    w("\t\t\tsourceTree = \"<group>\";")
    w("\t\t};")
    w(f"\t\t{ids['productsGroup']} /* Products */ = {{")
    w("\t\t\tisa = PBXGroup;")
    w("\t\t\tchildren = (")
    w(f"\t\t\t\t{ids['appProduct']} /* {APP_TARGET}.app */,")
    w("\t\t\t);")
    w(f"\t\t\tname = {plist_value('Products')};")
    w("\t\t\tsourceTree = \"<group>\";")
    w("\t\t};")
    w(f"\t\t{ids['mainGroup']} = {{")
    w("\t\t\tisa = PBXGroup;")
    w("\t\t\tchildren = (")
    w(f"\t\t\t\t{ids['sourcesGroup']} /* Sources */,")
    w(f"\t\t\t\t{ids['productsGroup']} /* Products */,")
    w("\t\t\t);")
    w("\t\t\tsourceTree = \"<group>\";")
    w("\t\t};")
    w("/* End PBXGroup section */")
    w("")

    # ------------------------------------------------------ PBXNativeTarget
    w("/* Begin PBXNativeTarget section */")
    w(f"\t\t{ids['target']} /* {APP_TARGET} */ = {{")
    w("\t\t\tisa = PBXNativeTarget;")
    w(f"\t\t\tbuildConfigurationList = {ids['targetConfigList']} "
      f"/* Build configuration list for PBXNativeTarget \"{APP_TARGET}\" */;")
    w("\t\t\tbuildPhases = (")
    w(f"\t\t\t\t{ids['sourcesPhase']} /* Sources */,")
    w(f"\t\t\t\t{ids['frameworksPhase']} /* Frameworks */,")
    w(f"\t\t\t\t{ids['resourcesPhase']} /* Resources */,")
    w("\t\t\t);")
    w("\t\t\tbuildRules = (")
    w("\t\t\t);")
    w("\t\t\tdependencies = (")
    w("\t\t\t);")
    w(f"\t\t\tname = {plist_value(APP_TARGET)};")
    w(f"\t\t\tproductName = {plist_value(APP_TARGET)};")
    w(f"\t\t\tproductReference = {ids['appProduct']} /* {APP_TARGET}.app */;")
    w("\t\t\tproductType = \"com.apple.product-type.application\";")
    w("\t\t};")
    w("/* End PBXNativeTarget section */")
    w("")

    # ----------------------------------------------------------- PBXProject
    w("/* Begin PBXProject section */")
    w(f"\t\t{ids['project']} /* Project object */ = {{")
    w("\t\t\tisa = PBXProject;")
    w("\t\t\tattributes = {")
    w("\t\t\t\tBuildIndependentTargetsInParallel = 1;")
    w("\t\t\t\tLastSwiftUpdateCheck = 1640;")
    w("\t\t\t\tLastUpgradeCheck = 1640;")
    w("\t\t\t\tTargetAttributes = {")
    w(f"\t\t\t\t\t{ids['target']} = {{")
    w("\t\t\t\t\t\tCreatedOnToolsVersion = 16.4;")
    w("\t\t\t\t\t};")
    w("\t\t\t\t};")
    w("\t\t\t};")
    w(f"\t\t\tbuildConfigurationList = {ids['projectConfigList']} "
      f"/* Build configuration list for PBXProject \"{APP_TARGET}\" */;")
    w("\t\t\tcompatibilityVersion = \"Xcode 14.0\";")
    w("\t\t\tdevelopmentRegion = en;")
    w("\t\t\thasScannedForEncodings = 0;")
    w("\t\t\tknownRegions = (")
    w("\t\t\t\ten,")
    w("\t\t\t\tBase,")
    w("\t\t\t);")
    w(f"\t\t\tmainGroup = {ids['mainGroup']};")
    w(f"\t\t\tproductRefGroup = {ids['productsGroup']} /* Products */;")
    w("\t\t\tprojectDirPath = \"\";")
    w("\t\t\tprojectRoot = \"\";")
    w("\t\t\ttargets = (")
    w(f"\t\t\t\t{ids['target']} /* {APP_TARGET} */,")
    w("\t\t\t);")
    w("\t\t};")
    w("/* End PBXProject section */")
    w("")

    # ------------------------------------------------ PBXResourcesBuildPhase
    w("/* Begin PBXResourcesBuildPhase section */")
    w(f"\t\t{ids['resourcesPhase']} /* Resources */ = {{")
    w("\t\t\tisa = PBXResourcesBuildPhase;")
    w("\t\t\tbuildActionMask = 2147483647;")
    w("\t\t\tfiles = (")
    w("\t\t\t);")
    w("\t\t\trunOnlyForDeploymentPostprocessing = 0;")
    w("\t\t};")
    w("/* End PBXResourcesBuildPhase section */")
    w("")

    # -------------------------------------------------- PBXSourcesBuildPhase
    w("/* Begin PBXSourcesBuildPhase section */")
    w(f"\t\t{ids['sourcesPhase']} /* Sources */ = {{")
    w("\t\t\tisa = PBXSourcesBuildPhase;")
    w("\t\t\tbuildActionMask = 2147483647;")
    w("\t\t\tfiles = (")
    for f in all_files:
        w(f"\t\t\t\t{ids[f'build:{f}']} /* {os.path.basename(f)} in Sources */,")
    w("\t\t\t);")
    w("\t\t\trunOnlyForDeploymentPostprocessing = 0;")
    w("\t\t};")
    w("/* End PBXSourcesBuildPhase section */")
    w("")

    # ------------------------------------------------- XCBuildConfiguration
    w("/* Begin XCBuildConfiguration section */")

    def emit_config(config_id: str, display: str, entries: list[tuple[str, str]]) -> None:
        w(f"\t\t{config_id} /* {display} */ = {{")
        w("\t\t\tisa = XCBuildConfiguration;")
        w("\t\t\tbuildSettings = {")
        for key, value in entries:
            w(f"\t\t\t\t{key} = {value};")
        w("\t\t\t};")
        w(f"\t\t\tname = {plist_value(display)};")
        w("\t\t};")

    emit_config(ids["projectDebug"], "Debug", PROJECT_SETTINGS + DEBUG_EXTRA)
    emit_config(ids["projectRelease"], "Release", PROJECT_SETTINGS + RELEASE_EXTRA)
    emit_config(ids["targetDebug"], "Debug", APP_SETTINGS)
    emit_config(ids["targetRelease"], "Release", APP_SETTINGS)
    w("/* End XCBuildConfiguration section */")
    w("")

    # ------------------------------------------------- XCConfigurationList
    w("/* Begin XCConfigurationList section */")
    for name, list_id, children in [
        ("PBXProject", ids["projectConfigList"],
         [("Debug", ids["projectDebug"]), ("Release", ids["projectRelease"])]),
        (f'PBXNativeTarget "{APP_TARGET}"', ids["targetConfigList"],
         [("Debug", ids["targetDebug"]), ("Release", ids["targetRelease"])]),
    ]:
        w(f"\t\t{list_id} /* Build configuration list for {name} */ = {{")
        w("\t\t\tisa = XCConfigurationList;")
        w("\t\t\tbuildConfigurations = (")
        for display, c in children:
            w(f"\t\t\t\t{c} /* {display} */,")
        w("\t\t\t);")
        w("\t\t\tdefaultConfigurationIsVisible = 0;")
        w("\t\t\tdefaultConfigurationName = Release;")
        w("\t\t};")
    w("/* End XCConfigurationList section */")
    w("")

    w("\t};")
    w(f"\trootObject = {ids['project']} /* Project object */;")
    w("}")

    content = "\n".join(lines) + "\n"
    problems = validate(content)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1

    PROJECT_DIR.mkdir(parents=True, exist_ok=True)
    PBXPROJ.write_text(content, encoding="utf-8")

    print(f"wrote {PBXPROJ.relative_to(ROOT)}")
    print(f"  target:  {APP_TARGET} ({BUNDLE_ID})")
    print(f"  sources: {len(core_files)} probe library + {len(app_files)} app "
          f"= {len(all_files)} file(s)")
    print("  validated: balanced delimiters, resolvable references, "
          "no duplicate settings")
    return 0


def validate(content: str) -> list[str]:
    """Structural checks that catch the failure modes which produce a project
    Xcode refuses to open."""
    problems: list[str] = []

    if content.count("{") != content.count("}"):
        problems.append("unbalanced braces")
    if content.count("(") != content.count(")"):
        problems.append("unbalanced parentheses")
    if not content.startswith("// !$*UTF8*$!"):
        problems.append("missing UTF8 plist header")

    defined = set(re.findall(r"^\s*([0-9A-F]{24})\s*(?:/\*.*?\*/)?\s*=", content, re.M))
    referenced = set(re.findall(r"=\s*([0-9A-F]{24})", content)) | set(
        re.findall(r"\b([0-9A-F]{24})\s*/\*", content)
    )
    missing = referenced - defined
    if missing:
        problems.append(f"object references without a definition: {sorted(missing)}")

    for block in re.findall(r"buildSettings = \{(.*?)\n\t\t\t\};", content, re.S):
        keys = re.findall(r"^\s{4}([A-Za-z0-9_]+)\s*=", block, re.M)
        duplicates = {k for k in keys if keys.count(k) > 1}
        if duplicates:
            problems.append(f"duplicate build setting(s): {sorted(duplicates)}")

    # Any unquoted value containing a character outside the safe bare-token set
    # makes the old-style parser abandon the file. Object-definition lines
    # ("<24-hex> /* comment */ = {") are skipped: they are not assignments.
    for match in re.finditer(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;\n]+);", content, re.M):
        key, value = match.group(1), match.group(2).strip()
        # Strip a trailing comment: "ID /* comment */" is a valid value.
        value = re.sub(r"\s*/\*.*?\*/\s*$", "", value).strip()
        if value.startswith('"') or value.startswith("(") or value.startswith("{"):
            continue
        if value and not all(ch in SAFE_BARE for ch in value):
            problems.append(f"{key}: unquoted value with unsafe characters: {value}")

    return problems


if __name__ == "__main__":
    raise SystemExit(main())
