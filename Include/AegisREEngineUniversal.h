#pragma once

#include "AegisUniversalRuntime.h"

#if defined(_MSC_VER)
#define AEGIS_RE_CALL __stdcall
#else
#define AEGIS_RE_CALL
#endif

enum AegisREMatrixFlags : std::uint32_t
{
    AegisREMatrix_Auto = 0,
    AegisREMatrix_RowMajor = 1u << 0,
    AegisREMatrix_ColumnMajor = 1u << 1,
    AegisREMatrix_D3DDepth = 1u << 2,
    AegisREMatrix_OpenGLDepth = 1u << 3,
    AegisREMatrix_YFlip = 1u << 4
};

enum AegisREComponentFlags : std::uint32_t
{
    AegisREComponent_None = 0,
    AegisREComponent_Component = 1u << 0,
    AegisREComponent_GameObject = 1u << 1,
    AegisREComponent_Transform = 1u << 2,
    AegisREComponent_Camera = 1u << 3,
    AegisREComponent_Player = 1u << 4,
    AegisREComponent_Npc = 1u << 5,
    AegisREComponent_Ai = 1u << 6,
    AegisREComponent_Enemy = 1u << 7,
    AegisREComponent_Entity = 1u << 8,
    AegisREComponent_Visible = 1u << 9,
    AegisREComponent_LikelyTarget = 1u << 10,
    AegisREComponent_TypeCatalog = 1u << 11,
    AegisREComponent_LiveSnapshot = 1u << 12
};

enum AegisRETypeFlags : std::uint32_t
{
    AegisREType_None = 0,
    AegisREType_Via = 1u << 0,
    AegisREType_App = 1u << 1,
    AegisREType_Component = 1u << 2,
    AegisREType_GameObject = 1u << 3,
    AegisREType_Transform = 1u << 4,
    AegisREType_Camera = 1u << 5,
    AegisREType_Player = 1u << 6,
    AegisREType_Npc = 1u << 7,
    AegisREType_Ai = 1u << 8,
    AegisREType_Enemy = 1u << 9,
    AegisREType_Entity = 1u << 10,
    AegisREType_Utf16 = 1u << 11,
    AegisREType_Ascii = 1u << 12,
    AegisREType_LikelyTarget = 1u << 13
};

enum AegisREHookCandidateFlags : std::uint32_t
{
    AegisREHookCandidate_None = 0,
    AegisREHookCandidate_Export = 1u << 0,
    AegisREHookCandidate_MainModule = 1u << 1,
    AegisREHookCandidate_SideModule = 1u << 2,
    AegisREHookCandidate_Renderer = 1u << 3,
    AegisREHookCandidate_Audio = 1u << 4,
    AegisREHookCandidate_MetadataOnly = 1u << 5,
    AegisREHookCandidate_TdbMethod = 1u << 6
};

enum AegisREMetadataFlags : std::uint32_t
{
    AegisREMetadata_None = 0,
    AegisREMetadata_TdbHeader = 1u << 0,
    AegisREMetadata_TdbValidated = 1u << 1,
    AegisREMetadata_TypeTable = 1u << 2,
    AegisREMetadata_MethodTable = 1u << 3,
    AegisREMetadata_FieldTable = 1u << 4,
    AegisREMetadata_StringPool = 1u << 5,
    AegisREMetadata_DirectFunction = 1u << 6,
    AegisREMetadata_EncodedFunction = 1u << 7,
    AegisREMetadata_Truncated = 1u << 8
};

enum AegisREWorldWalkerFlags : std::uint32_t
{
    AegisREWorldWalker_None = 0,
    AegisREWorldWalker_Enabled = 1u << 0,
    AegisREWorldWalker_TdbBacked = 1u << 1,
    AegisREWorldWalker_SingletonGetterRoots = 1u << 2,
    AegisREWorldWalker_GlobalPointerRoots = 1u << 3,
    AegisREWorldWalker_TruncatedRoots = 1u << 4,
    AegisREWorldWalker_TruncatedObjects = 1u << 5,
    AegisREWorldWalker_TruncatedFields = 1u << 6,
    AegisREWorldWalker_InstanceScan = 1u << 7
};

enum AegisREConsoleFlags : std::uint32_t
{
    AegisREConsole_None = 0,
    AegisREConsole_MetadataBacked = 1u << 0,
    AegisREConsole_CandidateFound = 1u << 1,
    AegisREConsole_Attempted = 1u << 2,
    AegisREConsole_MethodReturned = 1u << 3,
    AegisREConsole_HotkeyRunning = 1u << 4,
    AegisREConsole_AegisConsoleFallback = 1u << 5,
    AegisREConsole_TruncatedCandidates = 1u << 6
};

struct AegisREVec3
{
    float x;
    float y;
    float z;
};

struct AegisREViewport
{
    float x;
    float y;
    float width;
    float height;
};

struct AegisREMatrix4x4
{
    float m[16];
    std::uint32_t flags;
};

struct AegisREComponentSnapshot
{
    std::uint64_t id;
    std::uintptr_t address;
    char name[96];
    char typeName[128];
    char category[64];
    char path[192];
    AegisREVec3 origin;
    AegisREVec3 boundsMin;
    AegisREVec3 boundsMax;
    std::int32_t group;
    std::int32_t visible;
    std::uint32_t flags;
};

struct AegisREProjectedPoint
{
    float x;
    float y;
    float depth;
    std::int32_t clipped;
};

struct AegisRETypeInfo
{
    char name[160];
    char namespaceName[96];
    wchar_t moduleName[MAX_PATH];
    std::uintptr_t address;
    std::uintptr_t rva;
    std::uint32_t flags;
};

struct AegisREHookCandidateInfo
{
    wchar_t moduleName[MAX_PATH];
    wchar_t modulePath[MAX_PATH];
    char symbolName[192];
    char reason[96];
    std::uintptr_t address;
    std::uintptr_t rva;
    std::uint32_t ordinal;
    std::uint32_t flags;
};

struct AegisREMetadataStats
{
    std::int32_t metadataBackendReady;
    std::uint32_t tdbCandidateCount;
    std::uint32_t rejectedTdbCandidateCount;
    std::uint32_t tdbVersion;
    std::uintptr_t tdbAddress;
    std::uintptr_t tdbRva;
    std::uint32_t typeDefinitionCount;
    std::uint32_t namedTypeCount;
    std::uint32_t methodDefinitionCount;
    std::uint32_t namedMethodCount;
    std::uint32_t directMethodCount;
    std::uint32_t fieldDefinitionCount;
    std::uint32_t namedFieldCount;
    std::uint32_t metadataHookCandidateCount;
    std::uint32_t flags;
    wchar_t moduleName[MAX_PATH];
    wchar_t logPath[MAX_PATH];
    wchar_t details[256];
};

struct AegisREMetadataTypeInfo
{
    char name[160];
    char namespaceName[96];
    std::uint32_t typeIndex;
    std::uint32_t parentTypeIndex;
    std::uint32_t implIndex;
    std::uint32_t size;
    std::uint32_t typeFlags;
    std::uint32_t fqnHash;
    std::uint32_t typeCrc;
    std::uint32_t fieldCount;
    std::uint32_t methodCount;
    std::uintptr_t definitionAddress;
    std::uintptr_t runtimeTypeAddress;
    std::uintptr_t managedVtableAddress;
    std::uint32_t flags;
};

struct AegisREMetadataFieldInfo
{
    char declaringType[160];
    char name[128];
    char fieldType[160];
    std::uint32_t declaringTypeIndex;
    std::uint32_t fieldTypeIndex;
    std::uint32_t offset;
    std::uint32_t flags;
};

struct AegisREMetadataMethodInfo
{
    char declaringType[160];
    char name[128];
    char returnType[160];
    std::uint32_t declaringTypeIndex;
    std::uint32_t returnTypeIndex;
    std::uintptr_t functionAddress;
    std::uintptr_t functionRva;
    std::int32_t encodedOffset;
    std::uint32_t parameterCount;
    std::uint32_t flags;
};

struct AegisREWorldWalkerStats
{
    std::int32_t enabled;
    std::int32_t ready;
    std::uint64_t scanId;
    double lastScanMs;
    std::uint32_t rootCount;
    std::uint32_t singletonRootCount;
    std::uint32_t globalPointerRootCount;
    std::uint32_t rejectedRootCount;
    std::uint32_t visitedObjectCount;
    std::uint32_t componentCount;
    std::uint32_t fieldReadCount;
    std::uint32_t maxDepthReached;
    std::uint32_t flags;
    wchar_t details[256];
};

struct AegisREConsoleStats
{
    std::int32_t enabled;
    std::int32_t hotkeyRunning;
    std::uint32_t candidateCount;
    std::uint32_t callableCandidateCount;
    std::uint32_t attemptedCount;
    std::uint32_t successfulCallCount;
    std::uint64_t toggleCount;
    std::uintptr_t lastAttemptAddress;
    std::uint32_t flags;
    wchar_t details[256];
};

struct AegisREConsoleCandidateInfo
{
    char declaringType[160];
    char methodName[128];
    char reason[128];
    std::uintptr_t functionAddress;
    std::uintptr_t functionRva;
    std::uint32_t parameterCount;
    std::uint32_t score;
    std::uint32_t flags;
};

struct AegisREAdapterTiming
{
    double componentProviderMs;
    double matrixProviderMs;
    double viewportProviderMs;
    std::uint32_t componentCount;
    std::uint32_t projectedCount;
    std::uint32_t clippedCount;
    std::uint64_t frameId;
};

struct AegisRECapabilityInfo
{
    std::int32_t reDetected;
    std::int32_t viaTypeStringsFound;
    std::int32_t appTypeStringsFound;
    std::int32_t componentProviderRegistered;
    std::int32_t viewProjectionProviderRegistered;
    std::int32_t viewportProviderRegistered;
    std::int32_t viewportValid;
    std::int32_t matrixValid;
    std::int32_t w2sProjectionWorking;
    std::int32_t snapshotReady;
    std::int32_t metadataBackendReady;
    std::uint32_t metadataTdbVersion;
    std::uint32_t metadataTypeCount;
    std::uint32_t metadataFieldCount;
    std::uint32_t metadataMethodCount;
    std::int32_t internalWorldWalkerEnabled;
    std::int32_t internalWorldWalkerReady;
    std::uint32_t internalWorldRootCount;
    std::uint32_t internalWorldObjectCount;
    std::uint32_t internalWorldComponentCount;
    std::uint32_t typeCount;
    std::uint32_t hookCandidateCount;
    wchar_t rendererBackend[32];
    wchar_t details[256];
};

using AegisREComponentProvider = std::uint32_t(AEGIS_RE_CALL*)(
    AegisREComponentSnapshot* outComponents,
    std::uint32_t capacity,
    void* userData);

using AegisREViewProjectionProvider = std::int32_t(AEGIS_RE_CALL*)(
    AegisREMatrix4x4* outMatrix,
    void* userData);

using AegisREViewportProvider = std::int32_t(AEGIS_RE_CALL*)(
    AegisREViewport* outViewport,
    void* userData);

AEGIS_UNIVERSAL_API void AegisRE_RegisterComponentProvider(AegisREComponentProvider provider, void* userData);
AEGIS_UNIVERSAL_API void AegisRE_RegisterViewProjectionProvider(AegisREViewProjectionProvider provider, void* userData);
AEGIS_UNIVERSAL_API void AegisRE_RegisterViewportProvider(AegisREViewportProvider provider, void* userData);
AEGIS_UNIVERSAL_API int AegisRE_UpdateProviders();
AEGIS_UNIVERSAL_API int AegisRE_SubmitComponentSnapshots(const AegisREComponentSnapshot* components, std::uint32_t count);
AEGIS_UNIVERSAL_API int AegisRE_SubmitViewProjection(const AegisREMatrix4x4* matrix);
AEGIS_UNIVERSAL_API int AegisRE_SubmitViewport(const AegisREViewport* viewport);
AEGIS_UNIVERSAL_API std::uint32_t AegisRE_GetComponentCount();
AEGIS_UNIVERSAL_API int AegisRE_GetComponentSnapshot(std::uint32_t index, AegisREComponentSnapshot* outComponent);
AEGIS_UNIVERSAL_API int AegisRE_GetAdapterTiming(AegisREAdapterTiming* outTiming);
AEGIS_UNIVERSAL_API int AegisRE_GetCapabilityInfo(AegisRECapabilityInfo* outInfo);
AEGIS_UNIVERSAL_API int AegisRE_ProjectWorldToScreen(const AegisREVec3* world, AegisREProjectedPoint* outPoint);
AEGIS_UNIVERSAL_API int AegisRE_WriteSnapshotJson(const wchar_t* path);
AEGIS_UNIVERSAL_API int AegisRE_LoadSnapshotJson(const wchar_t* path);
AEGIS_UNIVERSAL_API void AegisRE_PrintCurrentComponents();

AEGIS_UNIVERSAL_API int AegisRE_RefreshResolver();
AEGIS_UNIVERSAL_API int AegisRE_ScanSdkTypes();
AEGIS_UNIVERSAL_API std::uint32_t AegisRE_GetTypeCount();
AEGIS_UNIVERSAL_API int AegisRE_GetTypeInfo(std::uint32_t index, AegisRETypeInfo* outInfo);
AEGIS_UNIVERSAL_API int AegisRE_WriteTypeSdkJson(const wchar_t* path);
AEGIS_UNIVERSAL_API int AegisRE_WriteTypeSdkHeader(const wchar_t* path);
AEGIS_UNIVERSAL_API int AegisRE_WriteTypeSdkCsv(const wchar_t* path);
AEGIS_UNIVERSAL_API int AegisRE_WriteResolverReport(const wchar_t* path);

AEGIS_UNIVERSAL_API int AegisRE_ScanMetadataBackend();
AEGIS_UNIVERSAL_API int AegisRE_GetMetadataStats(AegisREMetadataStats* outStats);
AEGIS_UNIVERSAL_API std::uint32_t AegisRE_GetMetadataTypeCount();
AEGIS_UNIVERSAL_API int AegisRE_GetMetadataTypeInfo(std::uint32_t index, AegisREMetadataTypeInfo* outInfo);
AEGIS_UNIVERSAL_API std::uint32_t AegisRE_GetMetadataFieldCount();
AEGIS_UNIVERSAL_API int AegisRE_GetMetadataFieldInfo(std::uint32_t index, AegisREMetadataFieldInfo* outInfo);
AEGIS_UNIVERSAL_API std::uint32_t AegisRE_GetMetadataMethodCount();
AEGIS_UNIVERSAL_API int AegisRE_GetMetadataMethodInfo(std::uint32_t index, AegisREMetadataMethodInfo* outInfo);
AEGIS_UNIVERSAL_API int AegisRE_WriteMetadataJson(const wchar_t* path);
AEGIS_UNIVERSAL_API int AegisRE_WriteMetadataCsv(const wchar_t* path);

AEGIS_UNIVERSAL_API void AegisRE_SetInternalWorldWalkerEnabled(std::int32_t enabled);
AEGIS_UNIVERSAL_API int AegisRE_RunInternalWorldScan();
AEGIS_UNIVERSAL_API int AegisRE_GetWorldWalkerStats(AegisREWorldWalkerStats* outStats);
AEGIS_UNIVERSAL_API int AegisRE_WriteWorldWalkerReport(const wchar_t* path);

AEGIS_UNIVERSAL_API int AegisRE_ScanConsoleBackend();
AEGIS_UNIVERSAL_API int AegisRE_ToggleGameConsole();
AEGIS_UNIVERSAL_API int AegisRE_StartConsoleHotkeyThread();
AEGIS_UNIVERSAL_API void AegisRE_StopConsoleHotkeyThread();
AEGIS_UNIVERSAL_API int AegisRE_GetConsoleStats(AegisREConsoleStats* outStats);
AEGIS_UNIVERSAL_API std::uint32_t AegisRE_GetConsoleCandidateCount();
AEGIS_UNIVERSAL_API int AegisRE_GetConsoleCandidateInfo(std::uint32_t index, AegisREConsoleCandidateInfo* outInfo);

AEGIS_UNIVERSAL_API std::uint32_t AegisRE_GetHookCandidateCount();
AEGIS_UNIVERSAL_API int AegisRE_GetHookCandidateInfo(std::uint32_t index, AegisREHookCandidateInfo* outInfo);
