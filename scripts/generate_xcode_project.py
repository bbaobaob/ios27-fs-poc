#!/usr/bin/env python3
"""Generate FSProbe.xcodeproj for the iOS app target.

The repository is a SwiftPM package for the probe library plus a plain iOS app
target. SwiftPM cannot produce iOS app bundles, so the app needs an Xcode
project. Rather than committing a hand-maintained .pbxproj (which drifts and is
impossible to review), the project is generated from the source tree by this
script and the output is committed.

Run from the repository root:

    python3 scripts/generate_xcode_project.py

The generated project compiles every file in Sources/FSProbeCore and
Sources/App into a single app target. Sources/fsprobe-cli is deliberately
excluded: it is the command-line runner for CI, not part of the app.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROJECT_DIR = ROOT / "FSProbe.xcodeproj"
PBXPROJ = PROJECT_DIR / "project.pbxproj"

APP_TARGET = "FSProbe"
BUNDLE_ID = "com.bbaobaob.fsprobe"
DEPLOYMENT_TARGET = "17.0"

CORE_DIR = ROOT / "Sources" / "FSProbeCore"
APP_DIR = ROOT / "Sources" / "App"


def uid(seed: str) -> str:
    """Deterministic 24-hex-uppercase Xcode object identifier."""
    return hashlib.md5(seed.encode()).hexdigest()[:24].upper()


def collect(directory: Path) -> list[str]:
    if not directory.is_dir():
        return []
    return sorted(
        str(p.relative_to(ROOT))
        for p in directory.rglob("*.swift")
    )


def main() -> int:
    core_files = collect(CORE_DIR)
    app_files = collect(APP_DIR)

    if not core_files or not app_files:
        print("error: expected Sources/FSProbeCore and Sources/App to contain .swift files",
              file=sys.stderr)
        return 1

    all_files = core_files + app_files

    # Object identifiers -----------------------------------------------------
    ids = {
        "project": uid("PBXProject"),
        "mainGroup": uid("PBXGroup:main"),
        "productsGroup": uid("PBXGroup:products"),
        "sourcesGroup": uid("PBXGroup:sources"),
        "appProduct": uid("PBXFileReference:app"),
        "target": uid("PBXNativeTarget"),
        "sourcesPhase": uid("PBXSourcesBuildPhase"),
        "frameworksPhase": uid("PBXFrameworksBuildPhase"),
        "resourcesPhase": uid("PBXResourcesBuildPhase"),
        "projectConfigList": uid("XCConfigurationList:project"),
        "targetConfigList": uid("XCConfigurationList:target"),
        "projectDebug": uid("XCBuildConfiguration:project:Debug"),
        "projectRelease": uid("XCBuildConfiguration:project:Release"),
        "targetDebug": uid("XCBuildConfiguration:target:Debug"),
        "targetRelease": uid("XCBuildConfiguration:target:Release"),
    }
    for f in all_files:
        ids[f"fileRef:{f}"] = uid(f"PBXFileReference:{f}")
        ids[f"buildFile:{f}"] = uid(f"PBXBuildFile:{f}")

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

    # PBXBuildFile -----------------------------------------------------------
    w("/* Begin PBXBuildFile section */")
    for f in all_files:
        w(f"\t\t{ids[f'buildFile:{f}']} /* {os.path.basename(f)} in Sources */ = "
          f"{{isa = PBXBuildFile; fileRef = {ids[f'fileRef:{f}']} /* {os.path.basename(f)} */; }};")
    w("/* End PBXBuildFile section */")
    w("")

    # PBXFileReference -------------------------------------------------------
    w("/* Begin PBXFileReference section */")
    w(f"\t\t{ids['appProduct']} /* {APP_TARGET}.app */ = "
      f"{{isa = PBXFileReference; explicitFileType = wrapper.application; "
      f"includeInIndex = 0; path = {APP_TARGET}.app; sourceTree = BUILT_PRODUCTS_DIR; }};")
    for f in all_files:
        # Paths are relative to the Sources group (which declares path = Sources).
        rel = os.path.relpath(f, "Sources")
        w(f"\t\t{ids[f'fileRef:{f}']} /* {rel} */ = "
          f"{{isa = PBXFileReference; lastKnownFileType = sourcecode.swift; "
          f"path = {rel}; sourceTree = \"<group>\"; }};")
    w("/* End PBXFileReference section */")
    w("")

    # PBXFrameworksBuildPhase ------------------------------------------------
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

    # PBXGroup ---------------------------------------------------------------
    w("/* Begin PBXGroup section */")
    w(f"\t\t{ids['sourcesGroup']} /* Sources */ = {{")
    w("\t\t\tisa = PBXGroup;")
    w("\t\t\tchildren = (")
    for f in all_files:
        w(f"\t\t\t\t{ids[f'fileRef:{f}']} /* {f} */,")
    w("\t\t\t);")
    w("\t\t\tpath = Sources;")
    w("\t\t\tsourceTree = \"<group>\";")
    w("\t\t};")

    w(f"\t\t{ids['productsGroup']} /* Products */ = {{")
    w("\t\t\tisa = PBXGroup;")
    w("\t\t\tchildren = (")
    w(f"\t\t\t\t{ids['appProduct']} /* {APP_TARGET}.app */,")
    w("\t\t\t);")
    w("\t\t\tname = Products;")
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

    # PBXNativeTarget --------------------------------------------------------
    w("/* Begin PBXNativeTarget section */")
    w(f"\t\t{ids['target']} /* {APP_TARGET} */ = {{")
    w("\t\t\tisa = PBXNativeTarget;")
    w(f"\t\t\tbuildConfigurationList = {ids['targetConfigList']} /* Build configuration list for PBXNativeTarget \"{APP_TARGET}\" */;")
    w("\t\t\tbuildPhases = (")
    w(f"\t\t\t\t{ids['sourcesPhase']} /* Sources */,")
    w(f"\t\t\t\t{ids['frameworksPhase']} /* Frameworks */,")
    w(f"\t\t\t\t{ids['resourcesPhase']} /* Resources */,")
    w("\t\t\t);")
    w("\t\t\tbuildRules = (")
    w("\t\t\t);")
    w("\t\t\tdependencies = (")
    w("\t\t\t);")
    w(f"\t\t\tname = {APP_TARGET};")
    w(f"\t\t\tproductName = {APP_TARGET};")
    w(f"\t\t\tproductReference = {ids['appProduct']} /* {APP_TARGET}.app */;")
    w("\t\t\tproductType = \"com.apple.product-type.application\";")
    w("\t\t};")
    w("/* End PBXNativeTarget section */")
    w("")

    # PBXProject -------------------------------------------------------------
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
    w(f"\t\t\tbuildConfigurationList = {ids['projectConfigList']} /* Build configuration list for PBXProject \"{APP_TARGET}\" */;")
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

    # PBXResourcesBuildPhase -------------------------------------------------
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

    # PBXSourcesBuildPhase ---------------------------------------------------
    w("/* Begin PBXSourcesBuildPhase section */")
    w(f"\t\t{ids['sourcesPhase']} /* Sources */ = {{")
    w("\t\t\tisa = PBXSourcesBuildPhase;")
    w("\t\t\tbuildActionMask = 2147483647;")
    w("\t\t\tfiles = (")
    for f in all_files:
        w(f"\t\t\t\t{ids[f'buildFile:{f}']} /* {os.path.basename(f)} in Sources */,")
    w("\t\t\t);")
    w("\t\t\trunOnlyForDeploymentPostprocessing = 0;")
    w("\t\t};")
    w("/* End PBXSourcesBuildPhase section */")
    w("")

    # XCBuildConfiguration ---------------------------------------------------
    def settings_block(indent: str, entries: list[tuple[str, str]]) -> None:
        for key, value in entries:
            if value == "":
                w(f"{indent}{key} = \"\";")
            else:
                w(f"{indent}{key} = {value};")

    project_common = [
        ("ALWAYS_SEARCH_USER_PATHS", "NO"),
        ("CLANG_ENABLE_MODULES", "YES"),
        ("ENABLE_USER_SCRIPT_SANDBOXING", "YES"),
        ("ENABLE_STRICT_OBJC_MSGSEND", "NO"),
        ("CLANG_ANALYZER_NONNULL", "YES"),
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
        ("ENABLE_TESTABILITY", "NO"),
        ("GCC_C_LANGUAGE_STANDARD", "gnu17"),
        ("GCC_DYNAMIC_NO_PIC", "NO"),
        ("GCC_NO_COMMON_BLOCKS", "YES"),
        ("GCC_OPTIMIZATION_LEVEL", "0"),
        ("GCC_PREPROCESSOR_DEFINITIONS", "(\"DEBUG=1\",\"$(inherited)\")"),
        ("GCC_WARN_64_TO_32_BIT_CONVERSION", "YES"),
        ("GCC_WARN_ABOUT_RETURN_TYPE", "YES_ERROR"),
        ("GCC_WARN_UNDECLARED_SELECTOR", "YES"),
        ("GCC_WARN_UNINITIALIZED_AUTOS", "YES_AGGRESSIVE"),
        ("GCC_WARN_UNUSED_FUNCTION", "YES"),
        ("GCC_WARN_UNUSED_VARIABLE", "YES"),
        ("MACOSX_DEPLOYMENT_TARGET", "14.0"),
        ("MTL_ENABLE_DEBUG_INFO", "INCLUDE_SOURCE"),
        ("ONLY_ACTIVE_ARCH", "YES"),
        ("SDKROOT", "iphoneos"),
        ("SWIFT_ACTIVE_COMPILATION_CONDITIONS", "DEBUG"),
        ("SWIFT_OPTIMIZATION_LEVEL", "\"-Onone\""),
    ]

    target_common = [
        ("CODE_SIGN_STYLE", "Automatic"),
        ("CODE_SIGNING_ALLOWED", "NO"),
        ("CURRENT_PROJECT_VERSION", "1"),
        ("GENERATE_INFOPLIST_FILE", "YES"),
        ("INFOPLIST_KEY_UIApplicationSceneManifest_Generation", "YES"),
        ("INFOPLIST_KEY_UILaunchScreen_Generation", "YES"),
        ("INFOPLIST_KEY_UISupportedInterfaceOrientations_iPhone", "\"UIInterfaceOrientationPortrait UIInterfaceOrientationLandscapeLeft UIInterfaceOrientationLandscapeRight\""),
        ("IPHONEOS_DEPLOYMENT_TARGET", DEPLOYMENT_TARGET),
        ("LD_RUNPATH_SEARCH_PATHS", "(\"$(inherited)\",\"@executable_path/Frameworks\")"),
        ("MARKETING_VERSION", "1.0"),
        ("PRODUCT_BUNDLE_IDENTIFIER", BUNDLE_ID),
        ("PRODUCT_NAME", "\"$(TARGET_NAME)\""),
        ("SWIFT_VERSION", "5.0"),
        ("TARGETED_DEVICE_FAMILY", "1"),
        ("IPHONEOS_DEPLOYMENT_TARGET", DEPLOYMENT_TARGET),
    ]

    w("/* Begin XCBuildConfiguration section */")
    for name, config_id, is_debug in [
        ("Debug", ids["projectDebug"], True),
        ("Release", ids["projectRelease"], False),
    ]:
        entries = list(project_common)
        if not is_debug:
            entries = [
                (k, v) for k, v in entries
                if k not in {"GCC_PREPROCESSOR_DEFINITIONS", "GCC_OPTIMIZATION_LEVEL",
                             "SWIFT_OPTIMIZATION_LEVEL", "SWIFT_ACTIVE_COMPILATION_CONDITIONS",
                             "ONLY_ACTIVE_ARCH", "ENABLE_TESTABILITY", "MTL_ENABLE_DEBUG_INFO"}
            ]
            entries += [
                ("DEBUG_INFORMATION_FORMAT", "\"dwarf-with-dsym\""),
                ("ENABLE_NS_ASSERTIONS", "NO"),
                ("GCC_OPTIMIZATION_LEVEL", "s"),
                ("SWIFT_COMPILATION_MODE", "wholemodule"),
                ("SWIFT_OPTIMIZATION_LEVEL", "\"-O\""),
                ("VALIDATE_PRODUCT", "YES"),
            ]
        w(f"\t\t{config_id} /* {name} */ = {{")
        w("\t\t\tisa = XCBuildConfiguration;")
        w("\t\t\tbuildSettings = {")
        settings_block("\t\t\t\t", entries)
        w("\t\t\t};")
        w(f"\t\t\tname = {name};")
        w("\t\t};")

    for name, config_id in [("Debug", ids["targetDebug"]), ("Release", ids["targetRelease"])]:
        w(f"\t\t{config_id} /* {name} */ = {{")
        w("\t\t\tisa = XCBuildConfiguration;")
        w("\t\t\tbuildSettings = {")
        settings_block("\t\t\t\t", target_common)
        w("\t\t\t};")
        w(f"\t\t\tname = {name};")
        w("\t\t};")
    w("/* End XCBuildConfiguration section */")
    w("")

    # XCConfigurationList ----------------------------------------------------
    w("/* Begin XCConfigurationList section */")
    config_lists = [
        ("PBXProject", ids["projectConfigList"],
         [("Debug", ids["projectDebug"]), ("Release", ids["projectRelease"])]),
        (f"PBXNativeTarget \"{APP_TARGET}\"", ids["targetConfigList"],
         [("Debug", ids["targetDebug"]), ("Release", ids["targetRelease"])]),
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

    PROJECT_DIR.mkdir(parents=True, exist_ok=True)
    PBXPROJ.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"wrote {PBXPROJ.relative_to(ROOT)}")
    print(f"  target:    {APP_TARGET} ({BUNDLE_ID})")
    print(f"  sources:   {len(core_files)} core + {len(app_files)} app = {len(all_files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
