# RE Engine Universal

Aegis universal debug runtime project for Capcom **RE Engine** targets.

## What It Does

1. Allocates a console on DLL load.
2. Enumerates loaded modules and PE exports.
3. Detects RE Engine targets generically from runtime metadata/TDB evidence, with known process names such as `re2.exe`, `re8GEDemo.exe`, `dmc5.exe`, `mhrise.exe`, and Capcom Arcade Stadium executables used only as fast-path hints.
4. Starts the internal ImGui overlay. Press `F4` to toggle the menu.
5. Dumps the generic module/export SDK.
6. Scans loaded RE-family PE images for `via.*` and `app.*` metadata strings and writes a no-offset RE type SDK.
7. Scans process memory for validated RE `TDB` metadata headers, then decodes type definitions, field offsets, method definitions, direct native function pointers, and rejected candidates.
8. Builds a hook-candidate registry from discoverable PE exports plus validated direct TDB method pointers.
9. Runs an internal TDB-backed world walker that discovers singleton getter roots and module/global object pointers from inside the DLL, then walks validated object fields into component snapshots.
10. Draws internal-walker or provider-backed 2D boxes, 3D boxes, labels, and lines for live components.

## Important Limits

Retail RE Engine games are usually monolithic EXEs. This DLL does not hardcode RVAs and does not blindly walk arbitrary object memory. The TDB backend provides type names, field offsets, method names, direct method pointers, and runtime type/vtable validation data for titles/layouts that validate at runtime. The internal world walker uses that data to find and traverse live object graphs without requiring an external root provider.

## Outputs

Files are written to `%TEMP%`:

```text
REEngine_Universal_Report.txt
REEngine_Universal_Trace.txt
REEngine_Universal_Log.txt
REEngine_Universal_Modules.csv
REEngine_Universal_MatchedExports.csv
REEngine_Universal_SDK.json
REEngine_Universal_SDK.h
REEngine_Universal_SDKMap.csv
REEngine_Universal_SDKValidation.json
REEngine_Universal_RETypeSDK.json
REEngine_Universal_RETypeSDK.h
REEngine_Universal_RETypeSDK.csv
REEngine_Universal_MetadataBackend.log
REEngine_Universal_Metadata.json
REEngine_Universal_Metadata.csv
REEngine_Universal_WorldWalker.json
REEngine_Universal_Resolver.json
```

## Build

```powershell
& "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe" ".\AegisREEngineUniversal.sln" /m /p:Configuration=Release /p:Platform=x64 /v:minimal
```

Output:

```text
build\x64\Release\AegisREEngineUniversal.dll
```

## Live Component Providers

The DLL now has an internal TDB-backed world walker enabled by default. It discovers roots from validated singleton `get_Instance` method candidates and module/global object pointer slots, validates every object pointer against decoded TDB class-info addresses, and walks fields with fixed caps on roots, objects, field reads, and depth. The older `AegisRE_RegisterComponentProvider` API remains available for compatibility, but it is not required for the internal path.

## Metadata Backend

The exported `AegisRE_ScanMetadataBackend`, `AegisRE_GetMetadataStats`, `AegisRE_GetMetadataTypeInfo`, `AegisRE_GetMetadataFieldInfo`, and `AegisRE_GetMetadataMethodInfo` APIs expose the validated TDB data. The JSON/CSV writers mirror the same data to disk and log every accepted/rejected TDB candidate to the console, universal log, and metadata backend log.

## Internal World Walker

Use `AegisRE_RunInternalWorldScan`, `AegisRE_GetWorldWalkerStats`, and `AegisRE_WriteWorldWalkerReport` for internal walker diagnostics. The ImGui menu also has an `RE World` tab for forcing scans and exporting the current root/component report.
