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

    FSProbeCore (static library)  <- Sources/FSProbeCore/*.swift
    FSProbe      (iOS app)        <- Sources/App/*.swift, links FSProbeCore

The app therefore imports FSProbeCore as a real module, exactly as it does under
SwiftPM, and the probe logic stays separate from the UI. Sources/fsprobe-cli is
deliberately excluded: it is the command-line runner used by CI, not part of the
app.

The generator validates its own output (balanced delimiters, resolvable object
references, no duplicate build settings) and exits non-zero rather than writing
a project Xcode cannot open.
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

CORE_DIR = ROOT / "Sources" / "FSProbeCore"
APP_DIR = ROOT / "Sources" / "App"

LIB_TARGET = "FSProbeCore"
LIB_PRODUCT = "libFSProbeCore.a"
APP_TARGET = "FSProbe"


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


# ---------------------------------------------------------------------------
# Build settings
# ---------------------------------------------------------------------------

PROJECT_SETTINGS_DEBUG = [
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
    ("ENABLE_TESTABILITY", "YES"),
    ("GCC_C_LANGUAGE_STANDARD", "gnu17"),
    ("GCC_DYNAMIC_NO_PIC", "NO"),
    ("GCC_NO_COMMON_BLOCKS", "YES"),
    ("GCC_OPTIMIZATION_LEVEL", "0"),
    ("GCC_PREPROCESSOR_DEFINITIONS", '("DEBUG=1","$(inherited)")'),
    ("GCC_WARN_64_TO_32_BIT_CONVERSION", "YES"),
    ("GCC_WARN_ABOUT_RETURN_TYPE", "YES_ERROR"),
    ("GCC_WARN_UNDECLARED_SELECTOR", "YES"),
    ("GCC_WARN_UNINITIALIZED_AUTOS", "YES_AGGRESSIVE"),
    ("GCC_WARN_UNUSED_FUNCTION", "YES"),
    ("GCC_WARN_UNUSED_VARIABLE", "YES"),
    ("IPHONEOS_DEPLOYMENT_TARGET", DEPLOYMENT_TARGET),
    ("SDKROOT", "iphoneos"),
    ("SWIFT_ACTIVE_COMPILATION_CONDITIONS", "DEBUG"),
    ("SWIFT_OPTIMIZATION_LEVEL", '"-Onone"'),
]

PROJECT_SETTINGS_RELEASE = [
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
    ("DEBUG_INFORMATION_FORMAT", '"dwarf-with-dsym"'),
    ("ENABLE_NS_ASSERTIONS", "NO"),
    ("GCC_C_LANGUAGE_STANDARD", "gnu17"),
    ("GCC_DYNAMIC_NO_PIC", "NO"),
    ("GCC_NO_COMMON_BLOCKS", "YES"),
    ("GCC_OPTIMIZATION_LEVEL", "s"),
    ("GCC_WARN_64_TO_32_BIT_CONVERSION", "YES"),
    ("GCC_WARN_ABOUT_RETURN_TYPE", "YES_ERROR"),
    ("GCC_WARN_UNDECLARED_SELECTOR", "YES"),
    ("GCC_WARN_UNINITIALIZED_AUTOS", "YES_AGGRESSIVE"),
    ("GCC_WARN_UNUSED_FUNCTION", "YES"),
    ("GCC_WARN_UNUSED_VARIABLE", "YES"),
    ("IPHONEOS_DEPLOYMENT_TARGET", DEPLOYMENT_TARGET),
    ("SDKROOT", "iphoneos"),
    ("SWIFT_COMPILATION_MODE", "wholemodule"),
    ("SWIFT_OPTIMIZATION_LEVEL", '"-O"'),
    ("VALIDATE_PRODUCT", "YES"),
]

LIB_SETTINGS = [
    ("CODE_SIGNING_ALLOWED", "NO"),
    ("DEFINES_MODULE", "YES"),
    ("IPHONEOS_DEPLOYMENT_TARGET", DEPLOYMENT_TARGET),
    ("MACH_O_TYPE", "staticlib"),
    ("PRODUCT_MODULE_NAME", LIB_TARGET),
    ("PRODUCT_NAME", '"$(TARGET_NAME)"'),
    ("SDKROOT", "iphoneos"),
    ("SKIP_INSTALL", "YES"),
    ("SWIFT_VERSION", "5.0"),
    ("SWIFT_EMIT_LOC_STRINGS", "NO"),
]

APP_SETTINGS = [
    ("ASSETCATALOG_COMPILER_APPICON_NAME", "AppIcon"),
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

    # ------------------------------------------------------------------ ids
    ids: dict[str, str] = {
        "project": uid("PBXProject"),
        "mainGroup": uid("PBXGroup:main"),
        "productsGroup": uid("PBXGroup:products"),
        "sourcesGroup": uid("PBXGroup:sources"),
        "libTarget": uid("PBXNativeTarget:" + LIB_TARGET),
        "appTarget": uid("PBXNativeTarget:" + APP_TARGET),
        "libSourcesPhase": uid("PBXSourcesBuildPhase:" + LIB_TARGET),
        "libFrameworksPhase": uid("PBXFrameworksBuildPhase:" + LIB_TARGET),
        "libConfigList": uid("XCConfigurationList:" + LIB_TARGET),
        "appSourcesPhase": uid("PBXSourcesBuildPhase:" + APP_TARGET),
        "appFrameworksPhase": uid("PBXFrameworksBuildPhase:" + APP_TARGET),
        "appResourcesPhase": uid("PBXResourcesBuildPhase:" + APP_TARGET),
        "appConfigList": uid("XCConfigurationList:" + APP_TARGET),
        "projectConfigList": uid("XCConfigurationList:project"),
        "projectDebug": uid("XCBuildConfiguration:project:Debug"),
        "projectRelease": uid("XCBuildConfiguration:project:Release"),
        "libDebug": uid("XCBuildConfiguration:" + LIB_TARGET + ":Debug"),
        "libRelease": uid("XCBuildConfiguration:" + LIB_TARGET + ":Release"),
        "appDebug": uid("XCBuildConfiguration:" + APP_TARGET + ":Debug"),
        "appRelease": uid("XCBuildConfiguration:" + APP_TARGET + ":Release"),
        "dependency": uid("PBXTargetDependency:" + APP_TARGET + "->" + LIB_TARGET),
        "proxy": uid("PBXContainerItemProxy:" + APP_TARGET + "->" + LIB_TARGET),
        "libProductRef": uid("PBXFileReference:" + LIB_PRODUCT),
        "appProductRef": uid("PBXFileReference:" + APP_TARGET + ".app"),
        "libProductBuild": uid("PBXBuildFile:product:" + LIB_PRODUCT),
    }
    for f in core_files:
        ids[f"file:{f}"] = uid(f"PBXFileReference:{f}")
        ids[f"build:{f}"] = uid(f"PBXBuildFile:{f}")
    for f in app_files:
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
    for f in core_files:
        w(f"\t\t{ids[f'build:{f}']} /* {os.path.basename(f)} in Sources */ = "
          f"{{isa = PBXBuildFile; fileRef = {ids[f'file:{f}']} /* {os.path.basename(f)} */; }};")
    for f in app_files:
        w(f"\t\t{ids[f'build:{f}']} /* {os.path.basename(f)} in Sources */ = "
          f"{{isa = PBXBuildFile; fileRef = {ids[f'file:{f}']} /* {os.path.basename(f)} */; }};")
    w(f"\t\t{ids['libProductBuild']} /* {LIB_PRODUCT} in Frameworks */ = "
      f"{{isa = PBXBuildFile; productRef = {ids['libProductRef']} /* {LIB_PRODUCT} */; }};")
    w("/* End PBXBuildFile section */")
    w("")

    # -------------------------------------------------- PBXContainerItemProxy
    w("/* Begin PBXContainerItemProxy section */")
    w(f"\t\t{ids['proxy']} /* PBXContainerItemProxy */ = {{")
    w("\t\t\tisa = PBXContainerItemProxy;")
    w(f"\t\t\tcontainerPortal = {ids['project']} /* Project object */;")
    w("\t\t\tproxyType = 1;")
    w(f"\t\t\tremoteGlobalIDString = {ids['libTarget']};")
    w("\t\t\tremoteInfo = " + LIB_TARGET + ";")
    w("\t\t};")
    w("/* End PBXContainerItemProxy section */")
    w("")

    # --------------------------------------------------- PBXFileReference
    w("/* Begin PBXFileReference section */")
    w(f"\t\t{ids['appProductRef']} /* {APP_TARGET}.app */ = "
      f"{{isa = PBXFileReference; explicitFileType = wrapper.application; "
      f"includeInIndex = 0; path = {plist_value(APP_TARGET + '.app')}; "
      f"sourceTree = BUILT_PRODUCTS_DIR; }};")
    w(f"\t\t{ids['libProductRef']} /* {LIB_PRODUCT} */ = "
      f"{{isa = PBXFileReference; explicitFileType = archive.ar; "
      f"includeInIndex = 0; path = {plist_value(LIB_PRODUCT)}; "
      f"sourceTree = BUILT_PRODUCTS_DIR; }};")
    for f in core_files + app_files:
        rel = os.path.relpath(f, "Sources")
        w(f"\t\t{ids[f'file:{f}']} /* {rel} */ = "
          f"{{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; "
          f"path = {plist_value(rel)}; sourceTree = \"<group>\"; }};")
    w("/* End PBXFileReference section */")
    w("")

    # ---------------------------------------------- PBXFrameworksBuildPhase
    w("/* Begin PBXFrameworksBuildPhase section */")
    w(f"\t\t{ids['appFrameworksPhase']} /* Frameworks */ = {{")
    w("\t\t\tisa = PBXFrameworksBuildPhase;")
    w("\t\t\tbuildActionMask = 2147483647;")
    w("\t\t\tfiles = (")
    w(f"\t\t\t\t{ids['libProductBuild']} /* {LIB_PRODUCT} in Frameworks */,")
    w("\t\t\t);")
    w("\t\t\trunOnlyForDeploymentPostprocessing = 0;")
    w("\t\t};")
    w(f"\t\t{ids['libFrameworksPhase']} /* Frameworks */ = {{")
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
    for f in core_files + app_files:
        w(f"\t\t\t\t{ids[f'file:{f}']} /* {os.path.relpath(f, 'Sources')} */,")
    w("\t\t\t);")
    w(f"\t\t\tpath = {plist_value('Sources')};")
    w("\t\t\tsourceTree = \"<group>\";")
    w("\t\t};")
    w(f"\t\t{ids['productsGroup']} /* Products */ = {{")
    w("\t\t\tisa = PBXGroup;")
    w("\t\t\tchildren = (")
    w(f"\t\t\t\t{ids['appProductRef']} /* {APP_TARGET}.app */,")
    w(f"\t\t\t\t{ids['libProductRef']} /* {LIB_PRODUCT} */,")
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
    w(f"\t\t{ids['libTarget']} /* {LIB_TARGET} */ = {{")
    w("\t\t\tisa = PBXNativeTarget;")
    w(f"\t\t\tbuildConfigurationList = {ids['libConfigList']} "
      f"/* Build configuration list for PBXNativeTarget \"{LIB_TARGET}\" */;")
    w("\t\t\tbuildPhases = (")
    w(f"\t\t\t\t{ids['libSourcesPhase']} /* Sources */,")
    w(f"\t\t\t\t{ids['libFrameworksPhase']} /* Frameworks */,")
    w("\t\t\t);")
    w("\t\t\tbuildRules = (")
    w("\t\t\t);")
    w("\t\t\tdependencies = (")
    w("\t\t\t);")
    w(f"\t\t\tname = {plist_value(LIB_TARGET)};")
    w(f"\t\t\tproductName = {plist_value(LIB_TARGET)};")
    w(f"\t\t\tproductReference = {ids['libProductRef']} /* {LIB_PRODUCT} */;")
    w("\t\t\tproductType = \"com.apple.product-type.library.static\";")
    w("\t\t};")
    w(f"\t\t{ids['appTarget']} /* {APP_TARGET} */ = {{")
    w("\t\t\tisa = PBXNativeTarget;")
    w(f"\t\t\tbuildConfigurationList = {ids['appConfigList']} "
      f"/* Build configuration list for PBXNativeTarget \"{APP_TARGET}\" */;")
    w("\t\t\tbuildPhases = (")
    w(f"\t\t\t\t{ids['appSourcesPhase']} /* Sources */,")
    w(f"\t\t\t\t{ids['appFrameworksPhase']} /* Frameworks */,")
    w(f"\t\t\t\t{ids['appResourcesPhase']} /* Resources */,")
    w("\t\t\t);")
    w("\t\t\tbuildRules = (")
    w("\t\t\t);")
    w("\t\t\tdependencies = (")
    w(f"\t\t\t\t{ids['dependency']} /* PBXTargetDependency */,")
    w("\t\t\t);")
    w(f"\t\t\tname = {plist_value(APP_TARGET)};")
    w(f"\t\t\tproductName = {plist_value(APP_TARGET)};")
    w(f"\t\t\tproductReference = {ids['appProductRef']} /* {APP_TARGET}.app */;")
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
    w(f"\t\t\t\t\t{ids['appTarget']} = {{")
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
    w(f"\t\t\t\t{ids['libTarget']} /* {LIB_TARGET} */,")
    w(f"\t\t\t\t{ids['appTarget']} /* {APP_TARGET} */,")
    w("\t\t\t);")
    w("\t\t};")
    w("/* End PBXProject section */")
    w("")

    # ------------------------------------------------ PBXResourcesBuildPhase
    w("/* Begin PBXResourcesBuildPhase section */")
    w(f"\t\t{ids['appResourcesPhase']} /* Resources */ = {{")
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
    for name, phase_id, files in [
        (LIB_TARGET, ids["libSourcesPhase"], core_files),
        (APP_TARGET, ids["appSourcesPhase"], app_files),
    ]:
        w(f"\t\t{phase_id} /* Sources */ = {{")
        w("\t\t\tisa = PBXSourcesBuildPhase;")
        w("\t\t\tbuildActionMask = 2147483647;")
        w("\t\t\tfiles = (")
        for f in files:
            w(f"\t\t\t\t{ids[f'build:{f}']} /* {os.path.basename(f)} in Sources */,")
        w("\t\t\t);")
        w("\t\t\trunOnlyForDeploymentPostprocessing = 0;")
        w("\t\t};")
    w("/* End PBXSourcesBuildPhase section */")
    w("")

    # ------------------------------------------------- PBXTargetDependency
    w("/* Begin PBXTargetDependency section */")
    w(f"\t\t{ids['dependency']} /* PBXTargetDependency */ = {{")
    w("\t\t\tisa = PBXTargetDependency;")
    w(f"\t\t\ttarget = {ids['libTarget']} /* {LIB_TARGET} */;")
    w(f"\t\t\ttargetProxy = {ids['proxy']} /* PBXContainerItemProxy */;")
    w("\t\t};")
    w("/* End PBXTargetDependency section */")
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

    emit_config(ids["projectDebug"], "Debug", PROJECT_SETTINGS_DEBUG)
    emit_config(ids["projectRelease"], "Release", PROJECT_SETTINGS_RELEASE)
    emit_config(ids["libDebug"], "Debug", LIB_SETTINGS)
    emit_config(ids["libRelease"], "Release", LIB_SETTINGS)
    emit_config(ids["appDebug"], "Debug", APP_SETTINGS)
    emit_config(ids["appRelease"], "Release", APP_SETTINGS)
    w("/* End XCBuildConfiguration section */")
    w("")

    # ------------------------------------------------- XCConfigurationList
    w("/* Begin XCConfigurationList section */")
    config_lists = [
        ("PBXProject", ids["projectConfigList"],
         [("Debug", ids["projectDebug"]), ("Release", ids["projectRelease"])]),
        (f'PBXNativeTarget "{LIB_TARGET}"', ids["libConfigList"],
         [("Debug", ids["libDebug"]), ("Release", ids["libRelease"])]),
        (f'PBXNativeTarget "{APP_TARGET}"', ids["appConfigList"],
         [("Debug", ids["appDebug"]), ("Release", ids["appRelease"])]),
    ]
    for name, list_id, children in config_lists:
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
    print(f"  {LIB_TARGET}: static library, {len(core_files)} source file(s)")
    print(f"  {APP_TARGET}: iOS app ({BUNDLE_ID}), {len(app_files)} source file(s), links {LIB_TARGET}")
    print("  validated: balanced delimiters, resolvable references, no duplicate settings")
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

    # Duplicate keys inside one buildSettings block silently drop settings and
    # have historically produced unreadable projects.
    for block in re.findall(r"buildSettings = \{(.*?)\n\t\t\t\};", content, re.S):
        keys = re.findall(r"^\s{4}([A-Za-z0-9_]+)\s*=", block, re.M)
        duplicates = {k for k in keys if keys.count(k) > 1}
        if duplicates:
            problems.append(f"duplicate build setting(s): {sorted(duplicates)}")

    return problems


if __name__ == "__main__":
    raise SystemExit(main())
