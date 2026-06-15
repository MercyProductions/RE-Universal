#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "AegisREEngineUniversal.h"

#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace
{
    constexpr std::uint32_t kMaxComponents = 4096;
    constexpr std::uint32_t kMaxTypes = 200000;
    constexpr std::size_t kMaxTypeLength = 180;
    constexpr std::uint32_t kMaxTdbMagicCandidates = 4096;
    constexpr ULONGLONG kTdbMagicScanBudgetMs = 2500;
    constexpr std::uint64_t kMaxTdbFallbackScanBytes = 192ull * 1024ull * 1024ull;
    constexpr std::uint64_t kMaxTdbFallbackPrivateRegionBytes = 16ull * 1024ull * 1024ull;
    constexpr std::size_t kTdbFallbackChunkSize = 4u * 1024u * 1024u;
    constexpr std::uint32_t kMaxMetadataTypes = 250000;
    constexpr std::uint32_t kMaxMetadataMethods = 1000000;
    constexpr std::uint32_t kMaxMetadataFields = 1000000;
    constexpr std::uint32_t kMaxMetadataHookCandidates = 131072;
    constexpr std::uint32_t kMaxWorldRoots = 512;
    constexpr std::uint32_t kMaxWorldObjects = 8192;
    constexpr std::uint32_t kMaxWorldFieldReads = 250000;
    constexpr std::uint32_t kMaxWorldDepth = 6;
    constexpr bool kEnableTdbSingletonGetterRoots = false;
    constexpr bool kEnableAutomaticGlobalRootScan = false;
    constexpr ULONGLONG kWorldRootScanBudgetMs = 1500;
    constexpr std::uint64_t kMaxWorldRootScanBytes = 96ull * 1024ull * 1024ull;
    constexpr ULONGLONG kWorldInstanceScanBudgetMs = 12;
    constexpr ULONGLONG kWorldInstanceForceScanBudgetMs = 900;
    constexpr std::uint64_t kMaxWorldInstanceScanBytes = 16ull * 1024ull * 1024ull;
    constexpr std::uint64_t kMaxWorldInstanceForceScanBytes = 192ull * 1024ull * 1024ull;
    constexpr std::size_t kWorldInstanceScanChunk = 64u * 1024u;
    constexpr DWORD kWorldScanIntervalMs = 500;
    constexpr std::uint32_t kMaxConsoleCandidates = 128;
    constexpr std::uint32_t kMaxConsoleAttemptsPerToggle = 6;
    constexpr std::uint32_t kTdbMagic = 0x00424454; // "TDB\0"

    struct ProviderState
    {
        AegisREComponentProvider componentProvider = nullptr;
        void* componentUserData = nullptr;
        AegisREViewProjectionProvider matrixProvider = nullptr;
        void* matrixUserData = nullptr;
        AegisREViewportProvider viewportProvider = nullptr;
        void* viewportUserData = nullptr;
    };

    struct TypeRecord
    {
        std::string name;
        std::string namespaceName;
        std::wstring moduleName;
        std::uintptr_t address = 0;
        std::uintptr_t rva = 0;
        std::uint32_t flags = AegisREType_None;
    };

    struct HookCandidate
    {
        std::wstring moduleName;
        std::wstring modulePath;
        std::string symbolName;
        std::string reason;
        std::uintptr_t address = 0;
        std::uintptr_t rva = 0;
        std::uint32_t ordinal = 0;
        std::uint32_t flags = AegisREHookCandidate_None;
    };

    struct SectionRange
    {
        const std::uint8_t* begin = nullptr;
        std::size_t size = 0;
        std::uintptr_t rva = 0;
        bool executable = false;
        bool writable = false;
    };

    struct TdbLayoutDescriptor
    {
        const char* name = "";
        std::uint32_t minVersion = 0;
        std::uint32_t maxVersion = 0;
        std::uint32_t typeIndexBits = 18;
        std::uint32_t fieldIndexBits = 18;
        std::size_t numTypesOffset = 0;
        std::size_t numMethodsOffset = 0;
        std::size_t numFieldsOffset = 0;
        std::size_t numTypeImplOffset = 0;
        std::size_t numFieldImplOffset = 0;
        std::size_t numMethodImplOffset = 0;
        std::size_t numStringPoolOffset = 0;
        std::size_t numBytePoolOffset = 0;
        std::size_t typesOffset = 0;
        std::size_t typesImplOffset = 0;
        std::size_t methodsOffset = 0;
        std::size_t methodsImplOffset = 0;
        std::size_t fieldsOffset = 0;
        std::size_t fieldsImplOffset = 0;
        std::size_t stringPoolOffset = 0;
        std::size_t bytePoolOffset = 0;
        std::size_t typeStride = 0;
        std::size_t typeImplStride = 0;
        std::size_t methodStride = 0;
        std::size_t methodImplStride = 0;
        std::size_t fieldStride = 0;
        std::size_t fieldImplStride = 0;
        bool hasImplSplit = true;
        bool methodsUseDirectPointers = true;
    };

    struct TdbCandidate
    {
        std::uintptr_t address = 0;
        std::uintptr_t rva = 0;
        std::wstring moduleName;
        std::wstring modulePath;
        const TdbLayoutDescriptor* layout = nullptr;
        std::uint32_t version = 0;
        std::uint32_t numTypes = 0;
        std::uint32_t numMethods = 0;
        std::uint32_t numFields = 0;
        std::uint32_t numTypeImpl = 0;
        std::uint32_t numFieldImpl = 0;
        std::uint32_t numMethodImpl = 0;
        std::uint32_t numStringPool = 0;
        std::uint32_t numBytePool = 0;
        std::uintptr_t types = 0;
        std::uintptr_t typesImpl = 0;
        std::uintptr_t methods = 0;
        std::uintptr_t methodsImpl = 0;
        std::uintptr_t fields = 0;
        std::uintptr_t fieldsImpl = 0;
        std::uintptr_t stringPool = 0;
        std::uintptr_t bytePool = 0;
        std::uint32_t score = 0;
        std::uint32_t namedTypeSamples = 0;
        std::uint32_t flags = AegisREMetadata_None;
        std::string reason;
    };

    struct MetadataTypeRecord
    {
        std::string name;
        std::string namespaceName;
        std::uint32_t typeIndex = 0;
        std::uint32_t parentTypeIndex = 0;
        std::uint32_t implIndex = 0;
        std::uint32_t size = 0;
        std::uint32_t typeFlags = 0;
        std::uint32_t fqnHash = 0;
        std::uint32_t typeCrc = 0;
        std::uint32_t fieldStart = 0;
        std::uint32_t methodStart = 0;
        std::uint32_t fieldCount = 0;
        std::uint32_t methodCount = 0;
        std::uintptr_t definitionAddress = 0;
        std::uintptr_t runtimeTypeAddress = 0;
        std::uintptr_t managedVtableAddress = 0;
        std::int32_t fieldPtrOffset = 0;
        std::uint32_t flags = AegisREMetadata_TypeTable;
    };

    struct MetadataFieldRecord
    {
        std::string name;
        std::uint32_t declaringTypeIndex = 0;
        std::uint32_t fieldTypeIndex = 0;
        std::uint32_t offset = 0;
        std::uint32_t flags = AegisREMetadata_FieldTable;
    };

    struct MetadataMethodRecord
    {
        std::string name;
        std::uint32_t declaringTypeIndex = 0;
        std::uint32_t returnTypeIndex = 0;
        std::uintptr_t functionAddress = 0;
        std::uintptr_t functionRva = 0;
        std::int32_t encodedOffset = 0;
        std::uint32_t parameterCount = 0;
        std::uint32_t flags = AegisREMetadata_MethodTable;
    };

    struct WorldRootCandidate
    {
        std::uintptr_t objectAddress = 0;
        std::uintptr_t sourceAddress = 0;
        std::uint32_t typeIndex = 0;
        std::uint32_t score = 0;
        std::string reason;
        std::string typeName;
    };

    struct LiveInstanceScanStats
    {
        std::uint64_t objectInfoHits = 0;
        std::uint64_t baseCandidates = 0;
        std::uint64_t validObjects = 0;
        std::uint64_t interestingObjects = 0;
        std::uint64_t positionedObjects = 0;
        std::array<std::string, 8> sampleTypes;
        std::uint32_t sampleTypeCount = 0;
    };

    struct ConsoleCandidate
    {
        std::string declaringType;
        std::string methodName;
        std::string reason;
        std::uintptr_t functionAddress = 0;
        std::uintptr_t functionRva = 0;
        std::uint32_t parameterCount = 0;
        std::uint32_t score = 0;
        std::uint32_t flags = 0;
        bool callable = false;
    };

    struct ExecutableRange
    {
        std::uintptr_t begin = 0;
        std::uintptr_t end = 0;
        std::uintptr_t moduleBase = 0;
        std::wstring moduleName;
        std::wstring modulePath;
        bool mainModule = false;
        bool rendererModule = false;
    };

    std::mutex g_mutex;
    std::mutex g_metadataLogMutex;
    std::atomic_bool g_resolverBusy = false;
    std::atomic_bool g_resolverReadyOnce = false;
    ProviderState g_providers;
    std::vector<AegisREComponentSnapshot> g_components;
    std::vector<TypeRecord> g_types;
    std::vector<HookCandidate> g_hookCandidates;
    std::vector<TdbCandidate> g_tdbCandidates;
    std::vector<TdbCandidate> g_rejectedTdbCandidates;
    TdbCandidate g_bestTdb;
    std::vector<MetadataTypeRecord> g_metadataTypes;
    std::vector<MetadataFieldRecord> g_metadataFields;
    std::vector<MetadataMethodRecord> g_metadataMethods;
    std::vector<ConsoleCandidate> g_consoleCandidates;
    std::vector<ExecutableRange> g_executableRanges;
    std::unordered_map<std::uintptr_t, std::uint32_t> g_typeIndexByDefinitionAddress;
    std::unordered_map<std::uint32_t, std::uint32_t> g_metadataVectorIndexByTypeIndex;
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> g_fieldsByDeclaringType;
    std::uint32_t g_metadataNamedTypeCount = 0;
    std::uint32_t g_metadataNamedFieldCount = 0;
    std::uint32_t g_metadataNamedMethodCount = 0;
    std::uint32_t g_metadataDirectMethodCount = 0;
    std::uint32_t g_metadataHookCandidateCount = 0;
    std::vector<WorldRootCandidate> g_worldRoots;
    AegisREWorldWalkerStats g_worldStats = {};
    DWORD g_worldLastScanTick = 0;
    bool g_worldWalkerEnabled = true;
    bool g_worldRootsScanned = false;
    std::uintptr_t g_worldInstanceScanCursor = 0;
    AegisREMatrix4x4 g_viewProjection = {};
    AegisREViewport g_viewport = {};
    AegisREAdapterTiming g_timing = {};
    bool g_hasMatrix = false;
    bool g_hasViewport = false;
    bool g_typeScanCompleted = false;
    bool g_hookScanCompleted = false;
    bool g_consoleScanCompleted = false;
    bool g_metadataScanCompleted = false;
    bool g_metadataBackendReady = false;
    std::uint32_t g_viaTypeCount = 0;
    std::uint32_t g_appTypeCount = 0;
    AegisREConsoleStats g_consoleStats = {};
    HANDLE g_consoleHotkeyThread = nullptr;
    std::atomic_bool g_consoleHotkeyStop = false;
    std::atomic_bool g_consoleHotkeyRunning = false;

    struct ResolverBusyScope
    {
        const char* label = nullptr;
        ULONGLONG startTick = 0;
        bool active = false;

        explicit ResolverBusyScope(const char* labelValue)
            : label(labelValue), startTick(::GetTickCount64())
        {
            active = !g_resolverBusy.exchange(true);
            if (active)
                AegisUniversal_LogPrintfA("[AegisRE] %s started", label ? label : "Resolver work");
            else
                AegisUniversal_LogPrintfA("[AegisRE] %s requested while resolver is already busy; skipping", label ? label : "Resolver work");
        }

        ~ResolverBusyScope()
        {
            if (!active)
                return;

            const ULONGLONG elapsed = ::GetTickCount64() - startTick;
            AegisUniversal_LogPrintfA("[AegisRE] RESOLVER COMPLETE: %s | elapsed %llums", label ? label : "Resolver work", static_cast<unsigned long long>(elapsed));
            g_resolverReadyOnce.store(true);
            g_resolverBusy.store(false);
        }
    };

    void RebuildProjectionStatsLocked();
    void BuildMetadataBackendLocked();

    const TdbLayoutDescriptor kTdbLayouts[] = {
        {
            "TDB69/70 short header", 69, 70, 18, 18,
            0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x50, 0x54,
            0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0xC8, 0xD0,
            0x50, 0x30, 0x10, 0x0C, 0x08, 0x0C, true, true
        },
        {
            "TDB69/70 full header", 69, 70, 18, 18,
            0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x50, 0x54,
            0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0xD0, 0xD8,
            0x50, 0x30, 0x10, 0x0C, 0x08, 0x0C, true, true
        },
        {
            "TDB71/73 full header", 71, 73, 19, 19,
            0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x50, 0x54,
            0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0xD0, 0xD8,
            0x48, 0x30, 0x0C, 0x0C, 0x08, 0x0C, true, false
        },
        {
            "TDB74/81 full header", 74, 81, 19, 20,
            0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x50, 0x54,
            0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0xD0, 0xD8,
            0x50, 0x30, 0x0C, 0x0C, 0x08, 0x0C, true, false
        },
        {
            "TDB82/84 new header", 82, 84, 19, 20,
            0x08, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x58, 0x5C,
            0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0xD8, 0xE0,
            0x50, 0x30, 0x0C, 0x0C, 0x08, 0x0C, true, false
        },
        {
            "TDB66/67 legacy header", 66, 68, 17, 17,
            0x0C, 0x10, 0x14, 0, 0, 0, 0x40, 0x44,
            0x50, 0, 0x58, 0, 0x60, 0, 0x98, 0xA0,
            0x78, 0, 0x20, 0, 0x18, 0, false, true
        }
    };

    template <std::size_t N>
    void CopyAnsi(char (&dest)[N], const std::string& value)
    {
        strncpy_s(dest, value.c_str(), _TRUNCATE);
    }

    template <std::size_t N>
    void CopyWide(wchar_t (&dest)[N], const std::wstring& value)
    {
        wcsncpy_s(dest, value.c_str(), _TRUNCATE);
    }

    std::string ToLowerAscii(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        return value;
    }

    std::wstring ToLowerWide(std::wstring value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
            return static_cast<wchar_t>(::towlower(ch));
        });
        return value;
    }

    bool ContainsAscii(const std::string& value, const char* needle)
    {
        return needle && ToLowerAscii(value).find(ToLowerAscii(needle)) != std::string::npos;
    }

    bool ContainsWide(const std::wstring& value, const wchar_t* needle)
    {
        return needle && ToLowerWide(value).find(ToLowerWide(needle)) != std::wstring::npos;
    }

    std::string NarrowWide(const std::wstring& value)
    {
        std::string out;
        out.reserve(value.size());
        for (wchar_t ch : value)
            out.push_back(ch >= 0 && ch <= 0x7f ? static_cast<char>(ch) : '?');
        return out;
    }

    std::wstring WidenAscii(const std::string& value)
    {
        std::wstring out;
        out.reserve(value.size());
        for (unsigned char ch : value)
            out.push_back(static_cast<wchar_t>(ch));
        return out;
    }

    std::string JsonEscape(const std::string& value)
    {
        std::string escaped;
        escaped.reserve(value.size() + 8);
        for (char ch : value)
        {
            switch (ch)
            {
            case '\\': escaped += "\\\\"; break;
            case '"': escaped += "\\\""; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default: escaped.push_back(ch); break;
            }
        }
        return escaped;
    }

    std::string JsonEscapeWide(const std::wstring& value)
    {
        return JsonEscape(NarrowWide(value));
    }

    std::string CsvEscape(const std::string& value)
    {
        if (value.find_first_of(",\"\r\n") == std::string::npos)
            return value;

        std::string escaped = "\"";
        for (char ch : value)
        {
            if (ch == '"')
                escaped.push_back('"');
            escaped.push_back(ch);
        }
        escaped.push_back('"');
        return escaped;
    }

    std::string PointerHex(std::uintptr_t value)
    {
        std::ostringstream stream;
        stream << "0x" << std::hex << value;
        return stream.str();
    }

    std::wstring TempFilePath(const wchar_t* fileName)
    {
        wchar_t tempPath[MAX_PATH] = {};
        if (::GetTempPathW(MAX_PATH, tempPath) == 0)
            return fileName ? std::wstring(fileName) : std::wstring();

        std::wstring path = tempPath;
        if (!path.empty() && path.back() != L'\\')
            path.push_back(L'\\');
        if (fileName)
            path += fileName;
        return path;
    }

    std::wstring ProfileSiblingPath(const wchar_t* suffix)
    {
        std::wstring name = AegisUniversal_GetReportFileName();
        const std::wstring token = L"_Report.txt";
        const std::size_t pos = name.rfind(token);
        if (pos != std::wstring::npos && pos + token.size() == name.size())
            name = name.substr(0, pos) + suffix;
        else
            name += suffix;
        return TempFilePath(name.c_str());
    }

    std::wstring MetadataLogPath()
    {
        return ProfileSiblingPath(L"_MetadataBackend.log");
    }

    void AppendMetadataLogLineA(const char* text)
    {
        if (!text || !text[0])
            return;

        std::lock_guard<std::mutex> lock(g_metadataLogMutex);
        const std::wstring path = MetadataLogPath();
        const HANDLE file = ::CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return;

        SYSTEMTIME time = {};
        ::GetLocalTime(&time);

        char prefix[96] = {};
        const int prefixLength = std::snprintf(prefix, sizeof(prefix), "[%04u-%02u-%02u %02u:%02u:%02u.%03u] ",
            static_cast<unsigned>(time.wYear),
            static_cast<unsigned>(time.wMonth),
            static_cast<unsigned>(time.wDay),
            static_cast<unsigned>(time.wHour),
            static_cast<unsigned>(time.wMinute),
            static_cast<unsigned>(time.wSecond),
            static_cast<unsigned>(time.wMilliseconds));

        DWORD written = 0;
        if (prefixLength > 0)
            ::WriteFile(file, prefix, static_cast<DWORD>(prefixLength), &written, nullptr);
        ::WriteFile(file, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
        ::WriteFile(file, "\r\n", 2, &written, nullptr);
        ::FlushFileBuffers(file);
        ::CloseHandle(file);
    }

    void LogMetadata(const char* format, ...)
    {
        char body[2048] = {};
        va_list args;
        va_start(args, format);
        vsnprintf_s(body, _TRUNCATE, format, args);
        va_end(args);

        char line[2200] = {};
        _snprintf_s(line, _TRUNCATE, "[AegisRE][Metadata] %s", body);
        AegisUniversal_LogA(line);
        AppendMetadataLogLineA(line);
    }

    void LogConsole(const char* format, ...)
    {
        char body[2048] = {};
        va_list args;
        va_start(args, format);
        vsnprintf_s(body, _TRUNCATE, format, args);
        va_end(args);

        char line[2200] = {};
        _snprintf_s(line, _TRUNCATE, "[AegisRE][Console] %s", body);
        AegisUniversal_LogA(line);
        AppendMetadataLogLineA(line);
    }

    bool IsReadableProtect(DWORD protect)
    {
        if (protect & PAGE_GUARD)
            return false;
        if (protect == PAGE_NOACCESS)
            return false;

        const DWORD baseProtect = protect & 0xFF;
        return baseProtect == PAGE_READONLY ||
            baseProtect == PAGE_READWRITE ||
            baseProtect == PAGE_WRITECOPY ||
            baseProtect == PAGE_EXECUTE_READ ||
            baseProtect == PAGE_EXECUTE_READWRITE ||
            baseProtect == PAGE_EXECUTE_WRITECOPY;
    }

    bool IsExecutableProtect(DWORD protect)
    {
        if (protect & PAGE_GUARD)
            return false;

        const DWORD baseProtect = protect & 0xFF;
        return baseProtect == PAGE_EXECUTE ||
            baseProtect == PAGE_EXECUTE_READ ||
            baseProtect == PAGE_EXECUTE_READWRITE ||
            baseProtect == PAGE_EXECUTE_WRITECOPY;
    }

    bool IsReadableWritableDataProtect(DWORD protect)
    {
        if (protect & PAGE_GUARD)
            return false;
        const DWORD baseProtect = protect & 0xFF;
        return baseProtect == PAGE_READWRITE || baseProtect == PAGE_WRITECOPY;
    }

    bool IsReadableMemory(std::uintptr_t address, std::size_t size)
    {
        if (!address || !size)
            return false;

        MEMORY_BASIC_INFORMATION mbi = {};
        if (::VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) != sizeof(mbi))
            return false;
        if (mbi.State != MEM_COMMIT || !IsReadableProtect(mbi.Protect))
            return false;

        const std::uintptr_t regionStart = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const std::uintptr_t regionEnd = regionStart + mbi.RegionSize;
        if (address < regionStart || address >= regionEnd)
            return false;
        return size <= regionEnd - address;
    }

    bool IsExecutableMemory(std::uintptr_t address)
    {
        if (!address)
            return false;

        MEMORY_BASIC_INFORMATION mbi = {};
        if (::VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) != sizeof(mbi))
            return false;
        return mbi.State == MEM_COMMIT && IsExecutableProtect(mbi.Protect);
    }

    bool SafeCopyMemory(const void* source, void* dest, std::size_t size)
    {
        __try
        {
            std::memcpy(dest, source, size);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    bool ReadU32(std::uintptr_t address, std::uint32_t& out)
    {
        out = 0;
        return address && SafeCopyMemory(reinterpret_cast<const void*>(address), &out, sizeof(out));
    }

    bool ReadI32(std::uintptr_t address, std::int32_t& out)
    {
        out = 0;
        return address && SafeCopyMemory(reinterpret_cast<const void*>(address), &out, sizeof(out));
    }

    bool ReadU64(std::uintptr_t address, std::uint64_t& out)
    {
        out = 0;
        return address && SafeCopyMemory(reinterpret_cast<const void*>(address), &out, sizeof(out));
    }

    bool ReadPtr(std::uintptr_t address, std::uintptr_t& out)
    {
        out = 0;
        return address && SafeCopyMemory(reinterpret_cast<const void*>(address), &out, sizeof(out));
    }

    bool ReadCString(std::uintptr_t address, char* out, std::size_t capacity, std::size_t* outLength)
    {
        if (!address || !out || capacity < 2)
            return false;

        __try
        {
            std::size_t index = 0;
            for (; index + 1 < capacity; ++index)
            {
                const char ch = reinterpret_cast<const char*>(address)[index];
                if (ch == '\0')
                    break;
                out[index] = ch;
            }
            out[index] = '\0';
            if (outLength)
                *outLength = index;
            return index + 1 < capacity;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            if (capacity)
                out[0] = '\0';
            if (outLength)
                *outLength = 0;
            return false;
        }
    }

    std::uint32_t ScanTdbMagicRange(const std::uint8_t* begin, std::size_t size, std::uintptr_t* out, std::uint32_t capacity)
    {
        if (!begin || !out || !capacity || size < sizeof(std::uint32_t))
            return 0;

        std::uint32_t count = 0;
        __try
        {
            for (std::size_t offset = 0; offset + sizeof(std::uint32_t) <= size; offset += sizeof(std::uint32_t))
            {
                if (*reinterpret_cast<const std::uint32_t*>(begin + offset) != kTdbMagic)
                    continue;
                out[count++] = reinterpret_cast<std::uintptr_t>(begin + offset);
                if (count >= capacity)
                    break;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return count;
        }
        return count;
    }

    bool RangeContainsAsciiNeedle(const std::uint8_t* begin, std::size_t size, const char* needle)
    {
        if (!begin || !needle || !needle[0])
            return false;

        const std::size_t needleLength = std::strlen(needle);
        if (size < needleLength)
            return false;

        __try
        {
            for (std::size_t offset = 0; offset + needleLength <= size; ++offset)
            {
                if (std::memcmp(begin + offset, needle, needleLength) == 0)
                    return true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
        return false;
    }

    bool IsFinite(float value)
    {
        return std::isfinite(value);
    }

    bool IsValidViewport(const AegisREViewport& viewport)
    {
        return IsFinite(viewport.x) && IsFinite(viewport.y) &&
            IsFinite(viewport.width) && IsFinite(viewport.height) &&
            viewport.width > 1.0f && viewport.height > 1.0f;
    }

    bool IsValidMatrix(const AegisREMatrix4x4& matrix)
    {
        bool anyNonZero = false;
        for (float value : matrix.m)
        {
            if (!IsFinite(value))
                return false;
            anyNonZero = anyNonZero || std::fabs(value) > 0.000001f;
        }
        return anyNonZero;
    }

    LARGE_INTEGER NowCounter()
    {
        LARGE_INTEGER value = {};
        ::QueryPerformanceCounter(&value);
        return value;
    }

    double ElapsedMs(LARGE_INTEGER start, LARGE_INTEGER end)
    {
        LARGE_INTEGER frequency = {};
        ::QueryPerformanceFrequency(&frequency);
        if (frequency.QuadPart == 0)
            return 0.0;
        return (static_cast<double>(end.QuadPart - start.QuadPart) * 1000.0) /
            static_cast<double>(frequency.QuadPart);
    }

    std::vector<AegisUniversalModuleInfo> CurrentModules()
    {
        if (!AegisUniversal_IsInitialized())
            AegisUniversal_Initialize();

        std::vector<AegisUniversalModuleInfo> modules;
        const std::uint32_t count = AegisUniversal_GetModuleCount();
        modules.reserve(count);
        for (std::uint32_t index = 0; index < count; ++index)
        {
            AegisUniversalModuleInfo module = {};
            if (AegisUniversal_GetModuleInfo(index, &module))
                modules.push_back(module);
        }
        return modules;
    }

    bool IsMainModule(const AegisUniversalModuleInfo& module)
    {
        AegisUniversalRuntimeInfo runtime = {};
        AegisUniversal_GetRuntimeInfo(&runtime);
        return module.path[0] && runtime.processPath[0] &&
            ToLowerWide(module.path) == ToLowerWide(runtime.processPath);
    }

    bool SameDirectoryAsProcess(const AegisUniversalModuleInfo& module)
    {
        AegisUniversalRuntimeInfo runtime = {};
        AegisUniversal_GetRuntimeInfo(&runtime);
        try
        {
            const auto moduleDir = std::filesystem::path(module.path).parent_path().wstring();
            const auto processDir = std::filesystem::path(runtime.processPath).parent_path().wstring();
            return !moduleDir.empty() && !processDir.empty() && ToLowerWide(moduleDir) == ToLowerWide(processDir);
        }
        catch (...)
        {
            return false;
        }
    }

    bool IsLikelyReModule(const AegisUniversalModuleInfo& module)
    {
        if (IsMainModule(module))
            return true;
        if ((module.flags & AegisUniversalSignature_Core) != 0)
            return true;
        if (!SameDirectoryAsProcess(module))
            return false;

        const std::wstring name = ToLowerWide(module.name);
        return name.find(L"re") != std::wstring::npos ||
            name.find(L"capcom") != std::wstring::npos ||
            name.find(L"crashreport") != std::wstring::npos ||
            name.find(L"amd_ags") != std::wstring::npos ||
            name.find(L"steam_api") != std::wstring::npos;
    }

    bool IsRendererModule(const std::wstring& name)
    {
        return ContainsWide(name, L"d3d") || ContainsWide(name, L"dxgi") ||
            ContainsWide(name, L"vulkan") || ContainsWide(name, L"opengl");
    }

    bool IsAudioSymbol(const std::string& name)
    {
        return ContainsAscii(name, "SoundEngine") || ContainsAscii(name, "SpatialAudio") ||
            ContainsAscii(name, "Ak") || ContainsAscii(name, "Wwise");
    }

    std::string NamespaceOf(const std::string& typeName)
    {
        const std::size_t pos = typeName.find_last_of('.');
        if (pos == std::string::npos)
            return {};
        return typeName.substr(0, pos);
    }

    std::string LeafNameOf(const std::string& typeName)
    {
        const std::size_t pos = typeName.find_last_of('.');
        if (pos == std::string::npos || pos + 1 >= typeName.size())
            return typeName;
        return typeName.substr(pos + 1);
    }

    bool IsTypeCharacter(unsigned char ch)
    {
        return std::isalnum(ch) ||
            ch == '_' || ch == '.' || ch == '$' || ch == ':' ||
            ch == '<' || ch == '>' || ch == '/' || ch == '`';
    }

    std::uint32_t ClassifyTypeFlags(const std::string& name)
    {
        std::uint32_t flags = AegisREType_None;
        const std::string lower = ToLowerAscii(name);
        if (lower.rfind("via.", 0) == 0)
            flags |= AegisREType_Via;
        if (lower.rfind("app.", 0) == 0)
            flags |= AegisREType_App;
        if (lower.find("component") != std::string::npos)
            flags |= AegisREType_Component;
        if (lower.find("gameobject") != std::string::npos || lower.find(".object") != std::string::npos)
            flags |= AegisREType_GameObject | AegisREType_Entity;
        if (lower.find("transform") != std::string::npos)
            flags |= AegisREType_Transform | AegisREType_Component;
        if (lower.find("camera") != std::string::npos)
            flags |= AegisREType_Camera | AegisREType_Component;
        if (lower.find("player") != std::string::npos || lower.find("survivor") != std::string::npos)
            flags |= AegisREType_Player | AegisREType_LikelyTarget;
        if (lower.find("npc") != std::string::npos)
            flags |= AegisREType_Npc | AegisREType_LikelyTarget;
        if (lower.find(".ai") != std::string::npos || lower.find("behavior") != std::string::npos ||
            lower.find("fsm") != std::string::npos || lower.find("goal") != std::string::npos ||
            lower.find("evaluator") != std::string::npos)
            flags |= AegisREType_Ai;
        if (lower.find("enemy") != std::string::npos || lower.find(".em0") != std::string::npos ||
            lower.find(".em1") != std::string::npos)
            flags |= AegisREType_Enemy | AegisREType_LikelyTarget;
        if (lower.find("entity") != std::string::npos || lower.find("character") != std::string::npos)
            flags |= AegisREType_Entity;
        return flags;
    }

    std::uint32_t TypeFlagsToComponentFlags(std::uint32_t typeFlags)
    {
        std::uint32_t flags = AegisREComponent_TypeCatalog;
        if (typeFlags & AegisREType_Component)
            flags |= AegisREComponent_Component;
        if (typeFlags & AegisREType_GameObject)
            flags |= AegisREComponent_GameObject;
        if (typeFlags & AegisREType_Transform)
            flags |= AegisREComponent_Transform;
        if (typeFlags & AegisREType_Camera)
            flags |= AegisREComponent_Camera;
        if (typeFlags & AegisREType_Player)
            flags |= AegisREComponent_Player;
        if (typeFlags & AegisREType_Npc)
            flags |= AegisREComponent_Npc;
        if (typeFlags & AegisREType_Ai)
            flags |= AegisREComponent_Ai;
        if (typeFlags & AegisREType_Enemy)
            flags |= AegisREComponent_Enemy;
        if (typeFlags & AegisREType_Entity)
            flags |= AegisREComponent_Entity;
        if (typeFlags & (AegisREType_Player | AegisREType_Npc | AegisREType_Enemy))
            flags |= AegisREComponent_LikelyTarget;
        return flags;
    }

    const char* CategoryForTypeFlags(std::uint32_t flags)
    {
        if (flags & AegisREType_Player)
            return "Player";
        if (flags & AegisREType_Enemy)
            return "Enemy";
        if (flags & AegisREType_Npc)
            return "NPC";
        if (flags & AegisREType_Ai)
            return "AI";
        if (flags & AegisREType_Camera)
            return "Camera";
        if (flags & AegisREType_Transform)
            return "Transform";
        if (flags & AegisREType_Component)
            return "Component";
        if (flags & AegisREType_Entity)
            return "Entity";
        return "Type";
    }

    void AddTypeCandidate(
        std::unordered_map<std::string, TypeRecord>& byName,
        const std::string& name,
        const AegisUniversalModuleInfo& module,
        std::uintptr_t address,
        std::uint32_t encodingFlag)
    {
        if (name.size() < 5 || name.size() > kMaxTypeLength)
            return;
        if (name.find("..") != std::string::npos)
            return;

        const std::uint32_t classFlags = ClassifyTypeFlags(name);
        if ((classFlags & (AegisREType_Via | AegisREType_App)) == 0)
            return;

        auto found = byName.find(name);
        if (found != byName.end())
        {
            found->second.flags |= encodingFlag | classFlags;
            return;
        }

        TypeRecord record;
        record.name = name;
        record.namespaceName = NamespaceOf(name);
        record.moduleName = module.name;
        record.address = address;
        record.rva = module.baseAddress && address >= module.baseAddress ? address - module.baseAddress : 0;
        record.flags = encodingFlag | classFlags;
        byName.emplace(record.name, std::move(record));
    }

    bool ReadPeSections(const AegisUniversalModuleInfo& module, std::vector<SectionRange>& ranges)
    {
        if (!module.baseAddress || !module.imageSize)
            return false;

        __try
        {
            const auto* base = reinterpret_cast<const std::uint8_t*>(module.baseAddress);
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
                return false;

            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return false;

            const auto* section = IMAGE_FIRST_SECTION(nt);
            for (WORD index = 0; index < nt->FileHeader.NumberOfSections; ++index, ++section)
            {
                if ((section->Characteristics & IMAGE_SCN_MEM_READ) == 0)
                    continue;
                if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0)
                    continue;

                const std::uint32_t virtualSize = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;
                if (virtualSize == 0 || section->VirtualAddress >= module.imageSize)
                    continue;

                const std::uint32_t clamped = std::min<std::uint32_t>(virtualSize, module.imageSize - section->VirtualAddress);
                if (clamped == 0)
                    continue;

                SectionRange range = {};
                range.begin = base + section->VirtualAddress;
                range.size = clamped;
                range.rva = section->VirtualAddress;
                range.executable = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                range.writable = (section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                ranges.push_back(range);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
        return !ranges.empty();
    }

    void RefreshExecutableRangesLocked()
    {
        g_executableRanges.clear();

        for (const AegisUniversalModuleInfo& module : CurrentModules())
        {
            if (!module.baseAddress || !module.imageSize)
                continue;

            std::vector<SectionRange> ranges;
            if (!ReadPeSections(module, ranges))
                continue;

            const bool mainModule = IsMainModule(module);
            const bool rendererModule = IsRendererModule(module.name);
            for (const SectionRange& range : ranges)
            {
                if (!range.executable || !range.begin || !range.size)
                    continue;

                ExecutableRange executable = {};
                executable.begin = reinterpret_cast<std::uintptr_t>(range.begin);
                executable.end = executable.begin + range.size;
                executable.moduleBase = module.baseAddress;
                executable.moduleName = module.name;
                executable.modulePath = module.path;
                executable.mainModule = mainModule;
                executable.rendererModule = rendererModule;
                g_executableRanges.push_back(std::move(executable));
            }
        }

        LogMetadata("Executable range cache refreshed: %u ranges",
            static_cast<unsigned>(g_executableRanges.size()));
    }

    bool ResolveExecutableAddressFast(
        std::uintptr_t address,
        std::wstring* moduleName = nullptr,
        std::wstring* modulePath = nullptr,
        std::uintptr_t* rva = nullptr,
        bool* mainModule = nullptr,
        bool* rendererModule = nullptr)
    {
        if (!address)
            return false;

        for (const ExecutableRange& range : g_executableRanges)
        {
            if (address < range.begin || address >= range.end)
                continue;

            if (moduleName)
                *moduleName = range.moduleName;
            if (modulePath)
                *modulePath = range.modulePath;
            if (rva)
                *rva = address - range.moduleBase;
            if (mainModule)
                *mainModule = range.mainModule;
            if (rendererModule)
                *rendererModule = range.rendererModule;
            return true;
        }

        return false;
    }

    bool MatchAsciiPrefix(const std::uint8_t* data, std::size_t remaining, const char* prefix)
    {
        const std::size_t length = std::strlen(prefix);
        return remaining >= length && std::memcmp(data, prefix, length) == 0;
    }

    bool MatchWidePrefix(const std::uint8_t* data, std::size_t remaining, const char* prefix)
    {
        const std::size_t length = std::strlen(prefix);
        if (remaining < length * 2)
            return false;
        for (std::size_t index = 0; index < length; ++index)
        {
            if (data[index * 2] != static_cast<unsigned char>(prefix[index]) || data[index * 2 + 1] != 0)
                return false;
        }
        return true;
    }

    void ScanAsciiTypes(
        const AegisUniversalModuleInfo& module,
        const SectionRange& range,
        std::unordered_map<std::string, TypeRecord>& byName)
    {
        static constexpr const char* prefixes[] = { "via.", "app." };
        const std::uint8_t* data = range.begin;
        for (std::size_t offset = 0; offset + 5 < range.size;)
        {
            bool matched = false;
            for (const char* prefix : prefixes)
            {
                if (!MatchAsciiPrefix(data + offset, range.size - offset, prefix))
                    continue;

                std::size_t end = offset;
                while (end < range.size && IsTypeCharacter(data[end]) && end - offset < kMaxTypeLength)
                    ++end;

                const std::string name(reinterpret_cast<const char*>(data + offset), end - offset);
                AddTypeCandidate(byName, name, module, reinterpret_cast<std::uintptr_t>(data + offset), AegisREType_Ascii);
                offset = std::max(end, offset + 1);
                matched = true;
                break;
            }
            if (!matched)
                ++offset;
        }
    }

    void ScanWideTypes(
        const AegisUniversalModuleInfo& module,
        const SectionRange& range,
        std::unordered_map<std::string, TypeRecord>& byName)
    {
        static constexpr const char* prefixes[] = { "via.", "app." };
        const std::uint8_t* data = range.begin;
        for (std::size_t offset = 0; offset + 10 < range.size;)
        {
            bool matched = false;
            for (const char* prefix : prefixes)
            {
                if (!MatchWidePrefix(data + offset, range.size - offset, prefix))
                    continue;

                std::string name;
                std::size_t end = offset;
                while (end + 1 < range.size && data[end + 1] == 0 &&
                    IsTypeCharacter(data[end]) && name.size() < kMaxTypeLength)
                {
                    name.push_back(static_cast<char>(data[end]));
                    end += 2;
                }

                AddTypeCandidate(byName, name, module, reinterpret_cast<std::uintptr_t>(data + offset), AegisREType_Utf16);
                offset = std::max(end, offset + 2);
                matched = true;
                break;
            }
            if (!matched)
                offset += 2;
        }
    }

    void BuildTypeCatalogLocked()
    {
        std::unordered_map<std::string, TypeRecord> byName;
        for (const AegisUniversalModuleInfo& module : CurrentModules())
        {
            if (!IsLikelyReModule(module))
                continue;

            std::vector<SectionRange> ranges;
            if (!ReadPeSections(module, ranges))
                continue;

            for (const SectionRange& range : ranges)
            {
                ScanAsciiTypes(module, range, byName);
                ScanWideTypes(module, range, byName);
                if (byName.size() >= kMaxTypes)
                    break;
            }
            if (byName.size() >= kMaxTypes)
                break;
        }

        g_types.clear();
        g_types.reserve(byName.size());
        g_viaTypeCount = 0;
        g_appTypeCount = 0;
        for (auto& item : byName)
        {
            if (item.second.flags & AegisREType_Via)
                ++g_viaTypeCount;
            if (item.second.flags & AegisREType_App)
                ++g_appTypeCount;
            g_types.push_back(std::move(item.second));
        }

        std::sort(g_types.begin(), g_types.end(), [](const TypeRecord& left, const TypeRecord& right) {
            return ToLowerAscii(left.name) < ToLowerAscii(right.name);
        });

        if (!g_providers.componentProvider && g_components.empty())
        {
            for (const TypeRecord& type : g_types)
            {
                const std::uint32_t componentFlags = TypeFlagsToComponentFlags(type.flags);
                const bool componentLike =
                    (componentFlags & (AegisREComponent_Component | AegisREComponent_GameObject |
                        AegisREComponent_Transform | AegisREComponent_Camera | AegisREComponent_Player |
                        AegisREComponent_Npc | AegisREComponent_Ai | AegisREComponent_Enemy |
                        AegisREComponent_Entity)) != 0;
                if (!componentLike)
                    continue;

                AegisREComponentSnapshot component = {};
                component.id = static_cast<std::uint64_t>(g_components.size() + 1);
                component.address = type.address;
                CopyAnsi(component.name, LeafNameOf(type.name));
                CopyAnsi(component.typeName, type.name);
                CopyAnsi(component.category, CategoryForTypeFlags(type.flags));
                component.boundsMin = { -0.5f, -0.5f, -0.5f };
                component.boundsMax = { 0.5f, 0.5f, 0.5f };
                component.visible = 0;
                component.flags = componentFlags;
                g_components.push_back(component);
                if (g_components.size() >= kMaxComponents)
                    break;
            }
            RebuildProjectionStatsLocked();
        }
        g_typeScanCompleted = true;
    }

    std::uint64_t MaskBits(std::uint32_t bits)
    {
        if (bits >= 64)
            return ~0ull;
        return (1ull << bits) - 1ull;
    }

    std::uint32_t ExtractBits(std::uint64_t value, std::uint32_t shift, std::uint32_t bits)
    {
        return static_cast<std::uint32_t>((value >> shift) & MaskBits(bits));
    }

    bool IsMetadataStringChar(unsigned char ch)
    {
        return ch >= 0x20 && ch < 0x7f && ch != '"' && ch != '\\';
    }

    bool ReadPoolString(const TdbCandidate& tdb, std::uint32_t offset, std::string& out, std::size_t maxLength = 180)
    {
        out.clear();
        if (!tdb.stringPool || offset >= tdb.numStringPool)
            return false;
        if (maxLength < 2)
            return false;

        char buffer[256] = {};
        std::size_t length = 0;
        const std::size_t capacity = std::min<std::size_t>(sizeof(buffer), maxLength + 1);
        if (!ReadCString(tdb.stringPool + offset, buffer, capacity, &length))
            return false;
        if (length == 0 || length >= maxLength)
            return false;

        for (std::size_t index = 0; index < length; ++index)
        {
            if (!IsMetadataStringChar(static_cast<unsigned char>(buffer[index])))
                return false;
        }

        out.assign(buffer, length);
        return true;
    }

    std::string ComposeFullTypeName(const std::string& namespaceName, const std::string& name)
    {
        if (name.empty())
            return {};
        if (namespaceName.empty())
            return name;
        return namespaceName + "." + name;
    }

    bool ResolveAddressModule(
        std::uintptr_t address,
        std::wstring& moduleName,
        std::wstring& modulePath,
        std::uintptr_t& rva)
    {
        moduleName.clear();
        modulePath.clear();
        rva = 0;
        if (!address)
            return false;

        for (const AegisUniversalModuleInfo& module : CurrentModules())
        {
            const std::uintptr_t begin = module.baseAddress;
            const std::uintptr_t end = begin + module.imageSize;
            if (begin && address >= begin && address < end)
            {
                moduleName = module.name;
                modulePath = module.path;
                rva = address - begin;
                return true;
            }
        }
        moduleName = L"anonymous";
        return false;
    }

    bool ReadHeaderU32(const TdbCandidate& tdb, std::size_t offset, std::uint32_t& out)
    {
        if (offset == 0)
        {
            out = 0;
            return true;
        }
        return ReadU32(tdb.address + offset, out);
    }

    bool ReadHeaderPtr(const TdbCandidate& tdb, std::size_t offset, std::uintptr_t& out)
    {
        if (offset == 0)
        {
            out = 0;
            return true;
        }
        return ReadPtr(tdb.address + offset, out);
    }

    bool StringPoolHasKnownMarkers(const TdbCandidate& tdb)
    {
        if (!tdb.stringPool || tdb.numStringPool < 512)
            return false;

        const std::size_t scanSize = std::min<std::size_t>(tdb.numStringPool, 4u * 1024u * 1024u);
        const auto* begin = reinterpret_cast<const std::uint8_t*>(tdb.stringPool);
        return RangeContainsAsciiNeedle(begin, scanSize, "via.") ||
            RangeContainsAsciiNeedle(begin, scanSize, "app.") ||
            RangeContainsAsciiNeedle(begin, scanSize, "System.");
    }

    bool DecodeTypeRecord(const TdbCandidate& tdb, std::uint32_t index, MetadataTypeRecord& record)
    {
        if (!tdb.layout || !tdb.types || index >= tdb.numTypes)
            return false;

        const TdbLayoutDescriptor& layout = *tdb.layout;
        const std::uintptr_t address = tdb.types + static_cast<std::uintptr_t>(index) * layout.typeStride;
        record = {};
        record.typeIndex = index;
        record.definitionAddress = address;
        record.flags = AegisREMetadata_TypeTable;

        if (layout.hasImplSplit)
        {
            std::uint64_t word0 = 0;
            std::uint64_t word1 = 0;
            std::uint64_t memberWord = 0;
            std::uint32_t value = 0;
            if (!ReadU64(address, word0) || !ReadU64(address + 8, word1))
                return false;

            const std::uint32_t typeBits = layout.typeIndexBits;
            const std::uint32_t fieldBits = layout.fieldIndexBits;
            record.typeIndex = ExtractBits(word0, 0, typeBits);
            record.parentTypeIndex = ExtractBits(word0, typeBits, typeBits);
            record.implIndex = ExtractBits(word1, typeBits * 2, 18);
            if (!ReadU32(address + 0x10, record.typeFlags))
                return false;
            if (!ReadU32(address + 0x14, record.size))
                return false;
            if (!ReadU32(address + 0x18, record.fqnHash))
                return false;
            if (!ReadU32(address + 0x1C, record.typeCrc))
                return false;

            if (tdb.version < 71)
            {
                ReadPtr(address + 0x40, record.runtimeTypeAddress);
                ReadPtr(address + 0x48, record.managedVtableAddress);
            }
            else
            {
                ReadPtr(address + 0x38, record.runtimeTypeAddress);
                ReadPtr(address + 0x40, record.managedVtableAddress);
            }

            if (tdb.version < 71)
            {
                if (!ReadU32(address + 0x28, record.methodStart) ||
                    !ReadU32(address + 0x2C, record.fieldStart))
                {
                    return false;
                }
            }
            else
            {
                if (!ReadU64(address + 0x20, memberWord))
                    return false;
                record.methodStart = ExtractBits(memberWord, 22, 22);
                record.fieldStart = ExtractBits(memberWord, 44, fieldBits);
            }

            if (tdb.typesImpl && record.implIndex < std::max<std::uint32_t>(tdb.numTypeImpl, 1))
            {
                const std::uintptr_t impl = tdb.typesImpl + static_cast<std::uintptr_t>(record.implIndex) * layout.typeImplStride;
                std::uint32_t nameOffset = 0;
                std::uint32_t namespaceOffset = 0;
                if (tdb.version >= 83)
                {
                    std::uint64_t implNames = 0;
                    if (ReadU64(impl, implNames))
                    {
                        nameOffset = ExtractBits(implNames, 0, 28);
                        namespaceOffset = ExtractBits(implNames, 28, 28);
                    }
                }
                else
                {
                    std::int32_t signedName = 0;
                    std::int32_t signedNamespace = 0;
                    if (ReadI32(impl, signedName) && signedName >= 0)
                        nameOffset = static_cast<std::uint32_t>(signedName);
                    if (ReadI32(impl + 4, signedNamespace) && signedNamespace >= 0)
                        namespaceOffset = static_cast<std::uint32_t>(signedNamespace);
                }

                std::string leaf;
                std::string ns;
                if (ReadPoolString(tdb, nameOffset, leaf, 160))
                {
                    ReadPoolString(tdb, namespaceOffset, ns, 96);
                    record.namespaceName = ns;
                    record.name = ComposeFullTypeName(ns, leaf);
                    record.flags |= AegisREMetadata_StringPool;
                }

                if (tdb.version < 71)
                {
                    std::uint32_t methods = 0;
                    std::uint32_t fields = 0;
                    if (ReadU32(impl + 0x14, fields))
                        record.fieldCount = std::min<std::uint32_t>(fields, 0xFFFF);
                    if (ReadU32(impl + 0x10, methods))
                        record.methodCount = (methods >> 16) & 0xFFFF;
                }
                else
                {
                    std::uint64_t countsWord = 0;
                    if (ReadU64(impl + 0x10, countsWord))
                        record.fieldCount = ExtractBits(countsWord, 33, 24);
                    if (ReadU32(impl + 0x18, value))
                        record.methodCount = value & 0xFFFF;
                }
            }
        }
        else
        {
            std::uint64_t word0 = 0;
            if (!ReadU64(address, word0))
                return false;

            const std::uint32_t typeBits = layout.typeIndexBits;
            record.typeIndex = ExtractBits(word0, 0, typeBits);
            record.parentTypeIndex = ExtractBits(word0, typeBits + (typeBits == 17 ? 13 : typeBits), typeBits);
            ReadU32(address + 0x08, record.fqnHash);
            ReadU32(address + 0x0C, record.typeCrc);
            ReadU32(address + 0x20, record.typeFlags);
            ReadU32(address + 0x30, record.size);
            ReadPtr(address + 0x68, record.runtimeTypeAddress);
            ReadPtr(address + 0x70, record.managedVtableAddress);

            std::uint32_t nameOffset = 0;
            std::uint32_t namespaceOffset = 0;
            ReadU32(address + 0x18, nameOffset);
            ReadU32(address + 0x1C, namespaceOffset);
            std::string leaf;
            std::string ns;
            if (ReadPoolString(tdb, nameOffset, leaf, 160))
            {
                ReadPoolString(tdb, namespaceOffset, ns, 96);
                record.namespaceName = ns;
                record.name = ComposeFullTypeName(ns, leaf);
                record.flags |= AegisREMetadata_StringPool;
            }

            std::uint64_t memberMethodWord = 0;
            std::uint64_t memberFieldWord = 0;
            if (ReadU64(address + 0x38, memberMethodWord))
            {
                record.methodCount = ExtractBits(memberMethodWord, 0, 12);
                record.methodStart = ExtractBits(memberMethodWord, 12, 19);
            }
            if (ReadU64(address + 0x3C, memberFieldWord))
            {
                record.fieldCount = ExtractBits(memberFieldWord, 0, 12);
                record.fieldStart = ExtractBits(memberFieldWord, 12, 19);
            }
        }

        if (record.name.empty())
        {
            std::ostringstream stream;
            stream << "<type_" << index << ">";
            record.name = stream.str();
        }

        if (record.managedVtableAddress && IsReadableMemory(record.managedVtableAddress - sizeof(void*), sizeof(std::int32_t)))
        {
            std::int32_t fieldPtrOffset = 0;
            if (ReadI32(record.managedVtableAddress - sizeof(void*), fieldPtrOffset) &&
                fieldPtrOffset >= -0x10000 && fieldPtrOffset <= 0x100000)
            {
                record.fieldPtrOffset = fieldPtrOffset;
            }
        }

        return true;
    }

    bool DecodeFieldRecord(const TdbCandidate& tdb, std::uint32_t index, MetadataFieldRecord& record)
    {
        if (!tdb.layout || !tdb.fields || index >= tdb.numFields)
            return false;

        const TdbLayoutDescriptor& layout = *tdb.layout;
        const std::uintptr_t address = tdb.fields + static_cast<std::uintptr_t>(index) * layout.fieldStride;
        record = {};
        record.flags = AegisREMetadata_FieldTable;

        if (layout.hasImplSplit)
        {
            std::uint64_t word = 0;
            if (!ReadU64(address, word))
                return false;

            const std::uint32_t typeBits = layout.typeIndexBits;
            std::uint32_t implIndex = 0;
            std::uint32_t nameOffset = 0;
            record.declaringTypeIndex = ExtractBits(word, 0, typeBits);

            if (tdb.version < 71)
            {
                implIndex = ExtractBits(word, typeBits, 20);
                record.offset = ExtractBits(word, typeBits + 20, 26);
                if (!tdb.fieldsImpl || implIndex >= tdb.numFieldImpl)
                    return true;
                const std::uintptr_t impl = tdb.fieldsImpl + static_cast<std::uintptr_t>(implIndex) * layout.fieldImplStride;
                std::uint32_t implWord = 0;
                if (ReadU32(impl + 4, implWord))
                    record.fieldTypeIndex = implWord & static_cast<std::uint32_t>(MaskBits(typeBits));
                if (ReadU32(impl + 8, implWord))
                    nameOffset = implWord & 0x3FFFFFFFu;
            }
            else
            {
                implIndex = ExtractBits(word, typeBits, typeBits);
                record.fieldTypeIndex = ExtractBits(word, typeBits * 2, typeBits);
                if (!tdb.fieldsImpl || implIndex >= tdb.numFieldImpl)
                    return true;
                const std::uintptr_t impl = tdb.fieldsImpl + static_cast<std::uintptr_t>(implIndex) * layout.fieldImplStride;
                std::uint32_t implWord = 0;
                if (ReadU32(impl + 4, implWord))
                    record.offset = implWord & 0x03FFFFFFu;
                if (ReadU32(impl + 8, implWord))
                    nameOffset = implWord & (tdb.version >= 83 ? 0x0FFFFFFFu : 0x3FFFFFFFu);
            }

            if (ReadPoolString(tdb, nameOffset, record.name, 128))
                record.flags |= AegisREMetadata_StringPool;
        }
        else
        {
            std::uint64_t word = 0;
            if (!ReadU64(address, word))
                return false;
            const std::uint32_t typeBits = layout.typeIndexBits;
            record.declaringTypeIndex = ExtractBits(word, 0, typeBits);
            record.fieldTypeIndex = ExtractBits(word, typeBits, typeBits);
            std::uint32_t nameOffset = 0;
            ReadU32(address + 0x08, nameOffset);
            ReadU32(address + 0x10, record.offset);
            if (ReadPoolString(tdb, nameOffset, record.name, 128))
                record.flags |= AegisREMetadata_StringPool;
        }

        return true;
    }

    bool DecodeMethodRecord(const TdbCandidate& tdb, std::uint32_t index, MetadataMethodRecord& record)
    {
        if (!tdb.layout || !tdb.methods || index >= tdb.numMethods)
            return false;

        const TdbLayoutDescriptor& layout = *tdb.layout;
        const std::uintptr_t address = tdb.methods + static_cast<std::uintptr_t>(index) * layout.methodStride;
        record = {};
        record.flags = AegisREMetadata_MethodTable;

        if (layout.hasImplSplit)
        {
            std::uint32_t implIndex = 0;
            std::uint32_t params = 0;
            std::uint32_t nameOffset = 0;

            if (tdb.version < 71)
            {
                std::uint64_t word = 0;
                if (!ReadU64(address, word))
                    return false;
                record.declaringTypeIndex = ExtractBits(word, 0, layout.typeIndexBits);
                implIndex = ExtractBits(word, layout.typeIndexBits, 20);
                params = ExtractBits(word, layout.typeIndexBits + 20, 26);
                ReadPtr(address + 8, record.functionAddress);
                if (ResolveExecutableAddressFast(record.functionAddress, nullptr, nullptr, &record.functionRva))
                    record.flags |= AegisREMetadata_DirectFunction;
            }
            else
            {
                std::uint32_t word0 = 0;
                std::uint32_t word1 = 0;
                if (!ReadU32(address, word0) || !ReadU32(address + 4, word1))
                    return false;
                record.declaringTypeIndex = word0 & static_cast<std::uint32_t>(MaskBits(layout.typeIndexBits));
                params = ((word0 >> layout.typeIndexBits) & 0x1FFFu) | (((word1 >> layout.typeIndexBits) & 0x1FFFu) << 13);
                implIndex = word1 & static_cast<std::uint32_t>(MaskBits(layout.typeIndexBits));
                ReadI32(address + 8, record.encodedOffset);
                if (record.encodedOffset != 0)
                    record.flags |= AegisREMetadata_EncodedFunction;
            }

            if (tdb.methodsImpl && implIndex < tdb.numMethodImpl)
            {
                const std::uintptr_t impl = tdb.methodsImpl + static_cast<std::uintptr_t>(implIndex) * layout.methodImplStride;
                ReadU32(impl + 8, nameOffset);
                if (ReadPoolString(tdb, nameOffset, record.name, 128))
                    record.flags |= AegisREMetadata_StringPool;
            }

            if (tdb.bytePool && params < tdb.numBytePool)
            {
                std::uint32_t paramHeader = 0;
                std::uint32_t returnType = 0;
                if (ReadU32(tdb.bytePool + params, paramHeader))
                    record.parameterCount = paramHeader & 0xFFFFu;
                if (ReadU32(tdb.bytePool + params + 4, returnType))
                    record.returnTypeIndex = returnType;
            }
        }
        else
        {
            std::uint64_t word = 0;
            if (!ReadU64(address, word))
                return false;
            const std::uint32_t typeBits = layout.typeIndexBits;
            record.declaringTypeIndex = ExtractBits(word, 0, typeBits);
            record.parameterCount = ExtractBits(word, typeBits + 16, 6);
            record.returnTypeIndex = ExtractBits(word, typeBits + 30, typeBits);
            std::uint32_t nameOffset = 0;
            ReadU32(address + 0x0C, nameOffset);
            ReadPtr(address + 0x18, record.functionAddress);
            if (ResolveExecutableAddressFast(record.functionAddress, nullptr, nullptr, &record.functionRva))
                record.flags |= AegisREMetadata_DirectFunction;
            if (ReadPoolString(tdb, nameOffset, record.name, 128))
                record.flags |= AegisREMetadata_StringPool;
        }

        return true;
    }

    bool ValidateTdbCandidateAt(std::uintptr_t address, const TdbLayoutDescriptor& layout, TdbCandidate& out, std::string& rejectReason)
    {
        out = {};
        out.address = address;
        out.layout = &layout;
        out.flags = AegisREMetadata_TdbHeader;

        std::uint32_t magic = 0;
        if (!ReadU32(address, magic) || magic != kTdbMagic)
        {
            rejectReason = "missing TDB magic";
            return false;
        }

        if (!ReadU32(address + 4, out.version) ||
            out.version < layout.minVersion ||
            out.version > layout.maxVersion)
        {
            rejectReason = "version does not match layout";
            return false;
        }

        if (!ReadHeaderU32(out, layout.numTypesOffset, out.numTypes) ||
            !ReadHeaderU32(out, layout.numMethodsOffset, out.numMethods) ||
            !ReadHeaderU32(out, layout.numFieldsOffset, out.numFields) ||
            !ReadHeaderU32(out, layout.numTypeImplOffset, out.numTypeImpl) ||
            !ReadHeaderU32(out, layout.numFieldImplOffset, out.numFieldImpl) ||
            !ReadHeaderU32(out, layout.numMethodImplOffset, out.numMethodImpl) ||
            !ReadHeaderU32(out, layout.numStringPoolOffset, out.numStringPool) ||
            !ReadHeaderU32(out, layout.numBytePoolOffset, out.numBytePool) ||
            !ReadHeaderPtr(out, layout.typesOffset, out.types) ||
            !ReadHeaderPtr(out, layout.typesImplOffset, out.typesImpl) ||
            !ReadHeaderPtr(out, layout.methodsOffset, out.methods) ||
            !ReadHeaderPtr(out, layout.methodsImplOffset, out.methodsImpl) ||
            !ReadHeaderPtr(out, layout.fieldsOffset, out.fields) ||
            !ReadHeaderPtr(out, layout.fieldsImplOffset, out.fieldsImpl) ||
            !ReadHeaderPtr(out, layout.stringPoolOffset, out.stringPool) ||
            !ReadHeaderPtr(out, layout.bytePoolOffset, out.bytePool))
        {
            rejectReason = "header field read failed";
            return false;
        }

        if (out.numTypes < 32 || out.numTypes > 1000000 ||
            out.numMethods > 5000000 ||
            out.numFields > 5000000 ||
            out.numStringPool < 256 || out.numStringPool > 512u * 1024u * 1024u)
        {
            rejectReason = "implausible counts";
            return false;
        }

        if (!out.types || !out.methods || !out.stringPool)
        {
            rejectReason = "required table pointer is null";
            return false;
        }

        if (layout.hasImplSplit && (!out.typesImpl || !out.methodsImpl))
        {
            rejectReason = "impl table pointer is null";
            return false;
        }

        if (!IsReadableMemory(out.types, std::min<std::size_t>(layout.typeStride, 0x20)) ||
            !IsReadableMemory(out.methods, std::min<std::size_t>(layout.methodStride, 0x10)) ||
            !IsReadableMemory(out.stringPool, 1))
        {
            rejectReason = "table or string pool is not readable";
            return false;
        }

        const bool hasKnownStrings = StringPoolHasKnownMarkers(out);
        if (!hasKnownStrings)
        {
            rejectReason = "string pool has no known RE/System markers";
            return false;
        }

        const std::uint32_t samples = std::min<std::uint32_t>(out.numTypes, 1024);
        for (std::uint32_t index = 0; index < samples; ++index)
        {
            MetadataTypeRecord sample = {};
            if (!DecodeTypeRecord(out, index, sample))
                continue;
            if (!sample.name.empty() && sample.name[0] != '<')
                ++out.namedTypeSamples;
        }

        if (out.namedTypeSamples < 4)
        {
            rejectReason = "too few valid named type samples";
            return false;
        }

        ResolveAddressModule(out.address, out.moduleName, out.modulePath, out.rva);
        out.flags |= AegisREMetadata_TdbValidated |
            AegisREMetadata_TypeTable |
            AegisREMetadata_MethodTable |
            AegisREMetadata_StringPool;
        if (out.fields)
            out.flags |= AegisREMetadata_FieldTable;
        out.score = 100 + out.namedTypeSamples * 4;
        out.reason = "validated";
        return true;
    }

    void CollectTdbMagicCandidates(std::vector<std::uintptr_t>& candidates)
    {
        candidates.clear();
        std::unordered_set<std::uintptr_t> seen;
        const ULONGLONG startTick = ::GetTickCount64();
        std::uint64_t moduleBytesScanned = 0;
        std::uint64_t fallbackBytesScanned = 0;
        std::uint32_t moduleCount = 0;
        std::uint32_t sectionCount = 0;
        std::uint32_t fallbackRegionCount = 0;

        auto elapsedMs = [&]() -> ULONGLONG {
            return ::GetTickCount64() - startTick;
        };

        auto budgetExpired = [&]() -> bool {
            return elapsedMs() >= kTdbMagicScanBudgetMs;
        };

        auto appendCandidate = [&](std::uintptr_t address) {
            if (!address || seen.find(address) != seen.end())
                return;
            seen.insert(address);
            candidates.push_back(address);
        };

        LogMetadata("TDB magic scan: module section pass started, budget=%llums",
            static_cast<unsigned long long>(kTdbMagicScanBudgetMs));

        for (const AegisUniversalModuleInfo& module : CurrentModules())
        {
            if (budgetExpired())
            {
                LogMetadata("TDB magic scan: module pass stopped by time budget after %llums",
                    static_cast<unsigned long long>(elapsedMs()));
                return;
            }

            if (!IsLikelyReModule(module))
                continue;

            std::vector<SectionRange> ranges;
            if (!ReadPeSections(module, ranges))
                continue;

            ++moduleCount;
            for (const SectionRange& range : ranges)
            {
                if (budgetExpired())
                {
                    LogMetadata("TDB magic scan: module pass stopped by time budget after %llums",
                        static_cast<unsigned long long>(elapsedMs()));
                    return;
                }

                std::uintptr_t local[128] = {};
                const std::uint32_t count = ScanTdbMagicRange(range.begin, range.size, local, static_cast<std::uint32_t>(std::size(local)));
                for (std::uint32_t index = 0; index < count; ++index)
                    appendCandidate(local[index]);
                moduleBytesScanned += range.size;
                ++sectionCount;
                if (count)
                {
                    LogMetadata("TDB magic scan: found %u candidate(s) in module=%s sectionRva=0x%llx size=%llu",
                        static_cast<unsigned>(count),
                        NarrowWide(module.name).c_str(),
                        static_cast<unsigned long long>(range.rva),
                        static_cast<unsigned long long>(range.size));
                }
                if (candidates.size() >= kMaxTdbMagicCandidates)
                {
                    LogMetadata("TDB magic scan: candidate cap reached during module pass (%u)",
                        static_cast<unsigned>(candidates.size()));
                    return;
                }
            }
        }

        LogMetadata("TDB magic scan: module pass complete, modules=%u sections=%u bytes=%llu candidates=%u elapsed=%llums",
            static_cast<unsigned>(moduleCount),
            static_cast<unsigned>(sectionCount),
            static_cast<unsigned long long>(moduleBytesScanned),
            static_cast<unsigned>(candidates.size()),
            static_cast<unsigned long long>(elapsedMs()));

        if (!candidates.empty())
        {
            LogMetadata("TDB magic scan: fallback skipped because module pass found candidate(s)");
            return;
        }

        if (budgetExpired())
        {
            LogMetadata("TDB magic scan: fallback skipped because module pass used the time budget");
            return;
        }

        LogMetadata("TDB magic scan: bounded memory fallback started, byteCap=%llumb",
            static_cast<unsigned long long>(kMaxTdbFallbackScanBytes / (1024ull * 1024ull)));

        SYSTEM_INFO systemInfo = {};
        ::GetNativeSystemInfo(&systemInfo);
        std::uintptr_t address = reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
        const std::uintptr_t maxAddress = reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);

        while (address < maxAddress && candidates.size() < kMaxTdbMagicCandidates)
        {
            if (budgetExpired())
            {
                LogMetadata("TDB magic scan: fallback stopped by time budget after %llums bytes=%llu candidates=%u",
                    static_cast<unsigned long long>(elapsedMs()),
                    static_cast<unsigned long long>(fallbackBytesScanned),
                    static_cast<unsigned>(candidates.size()));
                break;
            }

            if (fallbackBytesScanned >= kMaxTdbFallbackScanBytes)
            {
                LogMetadata("TDB magic scan: fallback byte cap reached bytes=%llu candidates=%u",
                    static_cast<unsigned long long>(fallbackBytesScanned),
                    static_cast<unsigned>(candidates.size()));
                break;
            }

            MEMORY_BASIC_INFORMATION mbi = {};
            if (::VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) != sizeof(mbi))
                break;

            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEnd = regionBase + mbi.RegionSize;
            if (mbi.State == MEM_COMMIT && IsReadableProtect(mbi.Protect) && mbi.RegionSize >= sizeof(std::uint32_t))
            {
                const bool scanRegion =
                    mbi.Type == MEM_IMAGE ||
                    mbi.Type == MEM_MAPPED ||
                    (mbi.Type == MEM_PRIVATE && mbi.RegionSize <= kMaxTdbFallbackPrivateRegionBytes);

                if (scanRegion)
                {
                    ++fallbackRegionCount;
                    for (std::uintptr_t chunk = regionBase; chunk < regionEnd && candidates.size() < kMaxTdbMagicCandidates; chunk += kTdbFallbackChunkSize)
                    {
                        if (budgetExpired() || fallbackBytesScanned >= kMaxTdbFallbackScanBytes)
                            break;

                        const std::uint64_t remainingCap = kMaxTdbFallbackScanBytes - fallbackBytesScanned;
                        const std::uint64_t remainingRegion = regionEnd - chunk;
                        const std::size_t size = static_cast<std::size_t>(
                            std::min<std::uint64_t>(
                                std::min<std::uint64_t>(static_cast<std::uint64_t>(kTdbFallbackChunkSize), remainingRegion),
                                remainingCap));
                        if (size < sizeof(std::uint32_t))
                            break;

                        std::uintptr_t local[128] = {};
                        const std::uint32_t count = ScanTdbMagicRange(
                            reinterpret_cast<const std::uint8_t*>(chunk),
                            size,
                            local,
                            static_cast<std::uint32_t>(std::size(local)));
                        for (std::uint32_t index = 0; index < count; ++index)
                            appendCandidate(local[index]);
                        fallbackBytesScanned += size;
                        if (count)
                        {
                            LogMetadata("TDB magic scan: fallback found %u candidate(s) at region=%s type=0x%lx scannedBytes=%llu",
                                static_cast<unsigned>(count),
                                PointerHex(regionBase).c_str(),
                                static_cast<unsigned long>(mbi.Type),
                                static_cast<unsigned long long>(fallbackBytesScanned));
                        }
                    }
                }
            }

            if (regionEnd <= address)
                break;
            address = regionEnd;
        }

        LogMetadata("TDB magic scan: fallback complete, regions=%u bytes=%llu candidates=%u elapsed=%llums",
            static_cast<unsigned>(fallbackRegionCount),
            static_cast<unsigned long long>(fallbackBytesScanned),
            static_cast<unsigned>(candidates.size()),
            static_cast<unsigned long long>(elapsedMs()));
    }

    void DecodeMetadataTablesLocked(const TdbCandidate& tdb)
    {
        g_metadataTypes.clear();
        g_metadataFields.clear();
        g_metadataMethods.clear();
        g_typeIndexByDefinitionAddress.clear();
        g_metadataVectorIndexByTypeIndex.clear();
        g_fieldsByDeclaringType.clear();
        g_metadataNamedTypeCount = 0;
        g_metadataNamedFieldCount = 0;
        g_metadataNamedMethodCount = 0;
        g_metadataDirectMethodCount = 0;

        const std::uint32_t typeLimit = std::min<std::uint32_t>(tdb.numTypes, kMaxMetadataTypes);
        const std::uint32_t fieldLimit = std::min<std::uint32_t>(tdb.numFields, kMaxMetadataFields);
        const std::uint32_t methodLimit = std::min<std::uint32_t>(tdb.numMethods, kMaxMetadataMethods);

        LogMetadata("Decoding metadata tables: raw types=%u fields=%u methods=%u limits=%u/%u/%u",
            static_cast<unsigned>(tdb.numTypes),
            static_cast<unsigned>(tdb.numFields),
            static_cast<unsigned>(tdb.numMethods),
            static_cast<unsigned>(typeLimit),
            static_cast<unsigned>(fieldLimit),
            static_cast<unsigned>(methodLimit));

        LARGE_INTEGER stageStart = NowCounter();
        g_metadataTypes.reserve(typeLimit);
        for (std::uint32_t index = 0; index < typeLimit; ++index)
        {
            MetadataTypeRecord record = {};
            if (!DecodeTypeRecord(tdb, index, record))
                continue;
            if (!record.name.empty() && record.name[0] != '<')
                ++g_metadataNamedTypeCount;
            g_typeIndexByDefinitionAddress[record.definitionAddress] = record.typeIndex;
            g_metadataVectorIndexByTypeIndex[record.typeIndex] = static_cast<std::uint32_t>(g_metadataTypes.size());
            g_metadataTypes.push_back(std::move(record));
        }
        LARGE_INTEGER stageEnd = NowCounter();
        LogMetadata("Decoded type table: records=%u named=%u ms=%.2f",
            static_cast<unsigned>(g_metadataTypes.size()),
            static_cast<unsigned>(g_metadataNamedTypeCount),
            ElapsedMs(stageStart, stageEnd));

        stageStart = NowCounter();
        g_metadataFields.reserve(std::min<std::uint32_t>(fieldLimit, 200000));
        for (std::uint32_t index = 0; index < fieldLimit; ++index)
        {
            MetadataFieldRecord record = {};
            if (!DecodeFieldRecord(tdb, index, record))
                continue;
            if (!record.name.empty())
                ++g_metadataNamedFieldCount;
            g_fieldsByDeclaringType[record.declaringTypeIndex].push_back(static_cast<std::uint32_t>(g_metadataFields.size()));
            g_metadataFields.push_back(std::move(record));
        }
        stageEnd = NowCounter();
        LogMetadata("Decoded field table: records=%u named=%u ms=%.2f",
            static_cast<unsigned>(g_metadataFields.size()),
            static_cast<unsigned>(g_metadataNamedFieldCount),
            ElapsedMs(stageStart, stageEnd));

        stageStart = NowCounter();
        g_metadataMethods.reserve(std::min<std::uint32_t>(methodLimit, 300000));
        for (std::uint32_t index = 0; index < methodLimit; ++index)
        {
            MetadataMethodRecord record = {};
            if (!DecodeMethodRecord(tdb, index, record))
                continue;
            if (!record.name.empty())
                ++g_metadataNamedMethodCount;
            if (record.flags & AegisREMetadata_DirectFunction)
                ++g_metadataDirectMethodCount;
            g_metadataMethods.push_back(std::move(record));
        }
        stageEnd = NowCounter();
        LogMetadata("Decoded method table: records=%u named=%u direct=%u ms=%.2f",
            static_cast<unsigned>(g_metadataMethods.size()),
            static_cast<unsigned>(g_metadataNamedMethodCount),
            static_cast<unsigned>(g_metadataDirectMethodCount),
            ElapsedMs(stageStart, stageEnd));

        if (tdb.numTypes > typeLimit || tdb.numFields > fieldLimit || tdb.numMethods > methodLimit)
            g_bestTdb.flags |= AegisREMetadata_Truncated;

        LogMetadata("Decoded metadata tables: types=%u/%u named=%u, fields=%u/%u named=%u, methods=%u/%u named=%u direct=%u",
            static_cast<unsigned>(g_metadataTypes.size()),
            static_cast<unsigned>(tdb.numTypes),
            static_cast<unsigned>(g_metadataNamedTypeCount),
            static_cast<unsigned>(g_metadataFields.size()),
            static_cast<unsigned>(tdb.numFields),
            static_cast<unsigned>(g_metadataNamedFieldCount),
            static_cast<unsigned>(g_metadataMethods.size()),
            static_cast<unsigned>(tdb.numMethods),
            static_cast<unsigned>(g_metadataNamedMethodCount),
            static_cast<unsigned>(g_metadataDirectMethodCount));
    }

    std::string MetadataTypeNameByIndex(std::uint32_t index)
    {
        auto mapped = g_metadataVectorIndexByTypeIndex.find(index);
        if (mapped != g_metadataVectorIndexByTypeIndex.end() && mapped->second < g_metadataTypes.size())
            return g_metadataTypes[mapped->second].name;

        std::ostringstream stream;
        stream << "<type_" << index << ">";
        return stream.str();
    }

    const MetadataTypeRecord* MetadataTypeByIndex(std::uint32_t index)
    {
        auto mapped = g_metadataVectorIndexByTypeIndex.find(index);
        if (mapped == g_metadataVectorIndexByTypeIndex.end() || mapped->second >= g_metadataTypes.size())
            return nullptr;
        return &g_metadataTypes[mapped->second];
    }

    std::uintptr_t SafeCallNoArgPointer(std::uintptr_t functionAddress)
    {
        if (!functionAddress)
            return 0;

        using Getter = void* (*)();
        __try
        {
            return reinterpret_cast<std::uintptr_t>(reinterpret_cast<Getter>(functionAddress)());
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            AegisUniversal_LogPrintfA("[AegisRE][World] Getter 0x%llX raised SEH 0x%08X",
                static_cast<unsigned long long>(functionAddress),
                ::GetExceptionCode());
            return 0;
        }
    }

    bool ReadManagedObjectTypeIndexAtInfoOffset(
        std::uintptr_t objectAddress,
        std::uintptr_t objectInfoOffset,
        std::uint32_t& outTypeIndex)
    {
        outTypeIndex = 0;
        if (!objectAddress || (objectAddress & (sizeof(void*) - 1)) != 0)
            return false;

        if (objectAddress > UINTPTR_MAX - objectInfoOffset)
            return false;
        const std::uintptr_t objectInfoSlot = objectAddress + objectInfoOffset;
        if (!IsReadableMemory(objectInfoSlot, sizeof(void*)))
            return false;

        std::uintptr_t objectInfo = 0;
        if (!ReadPtr(objectInfoSlot, objectInfo) || !objectInfo || (objectInfo & (sizeof(void*) - 1)) != 0)
            return false;
        if (!IsReadableMemory(objectInfo, sizeof(void*) * 4))
            return false;

        std::uintptr_t classInfo = 0;
        if (!ReadPtr(objectInfo, classInfo) || !classInfo)
            return false;

        auto found = g_typeIndexByDefinitionAddress.find(classInfo);
        if (found == g_typeIndexByDefinitionAddress.end())
            return false;

        const MetadataTypeRecord* type = MetadataTypeByIndex(found->second);
        if (!type)
            return false;

        if (type->managedVtableAddress)
        {
            std::uintptr_t vtableClassInfo = 0;
            const bool vtableSelfPointsToType =
                IsReadableMemory(type->managedVtableAddress, sizeof(void*)) &&
                ReadPtr(type->managedVtableAddress, vtableClassInfo) &&
                vtableClassInfo == classInfo;
            if (objectInfo != type->managedVtableAddress && !vtableSelfPointsToType)
                return false;
        }

        outTypeIndex = found->second;
        return true;
    }

    bool ReadManagedObjectTypeIndex(std::uintptr_t objectAddress, std::uint32_t& outTypeIndex)
    {
        static constexpr std::uintptr_t kObjectInfoOffsets[] = { 0x0, 0x8, 0x10, 0x18, 0x20 };
        for (std::uintptr_t offset : kObjectInfoOffsets)
        {
            if (ReadManagedObjectTypeIndexAtInfoOffset(objectAddress, offset, outTypeIndex))
                return true;
        }
        outTypeIndex = 0;
        return false;
    }

    void CollectTypeChain(std::uint32_t typeIndex, std::vector<std::uint32_t>& out)
    {
        out.clear();
        std::unordered_set<std::uint32_t> seen;
        for (std::uint32_t current = typeIndex; out.size() < 24;)
        {
            const MetadataTypeRecord* type = MetadataTypeByIndex(current);
            if (!type || seen.find(current) != seen.end())
                break;
            seen.insert(current);
            out.push_back(current);
            if (type->parentTypeIndex == current)
                break;
            current = type->parentTypeIndex;
        }
    }

    std::uint32_t WorldTypeFlagsForTypeIndex(std::uint32_t typeIndex)
    {
        std::vector<std::uint32_t> chain;
        CollectTypeChain(typeIndex, chain);
        std::uint32_t flags = AegisREType_None;
        for (std::uint32_t current : chain)
        {
            const MetadataTypeRecord* type = MetadataTypeByIndex(current);
            if (!type)
                continue;
            flags |= ClassifyTypeFlags(type->name);
        }
        return flags;
    }

    bool IsInterestingWorldType(std::uint32_t typeIndex)
    {
        const std::uint32_t flags = WorldTypeFlagsForTypeIndex(typeIndex);
        return (flags & (AegisREType_Component | AegisREType_GameObject | AegisREType_Transform |
            AegisREType_Camera | AegisREType_Player | AegisREType_Npc | AegisREType_Ai |
            AegisREType_Enemy | AegisREType_Entity)) != 0;
    }

    bool IsPlausibleVec3(const AegisREVec3& value)
    {
        if (!IsFinite(value.x) || !IsFinite(value.y) || !IsFinite(value.z))
            return false;
        if (std::fabs(value.x) > 1000000.0f || std::fabs(value.y) > 1000000.0f || std::fabs(value.z) > 1000000.0f)
            return false;
        const float maxAbs = std::max(std::fabs(value.x), std::max(std::fabs(value.y), std::fabs(value.z)));
        return maxAbs >= 0.01f;
    }

    bool TryReadVec3(std::uintptr_t address, AegisREVec3& out)
    {
        out = {};
        if (!address || !IsReadableMemory(address, sizeof(AegisREVec3)))
            return false;
        if (!SafeCopyMemory(reinterpret_cast<const void*>(address), &out, sizeof(out)))
            return false;
        return IsPlausibleVec3(out);
    }

    bool FieldLooksLikePosition(const MetadataFieldRecord& field)
    {
        const std::string name = ToLowerAscii(field.name);
        const std::string type = ToLowerAscii(MetadataTypeNameByIndex(field.fieldTypeIndex));
        return name.find("position") != std::string::npos ||
            name.find("worldpos") != std::string::npos ||
            name == "pos" ||
            name.find("_pos") != std::string::npos ||
            name.find("location") != std::string::npos ||
            name.find("translation") != std::string::npos ||
            name.find("translate") != std::string::npos ||
            type.find("vector3") != std::string::npos ||
            type.find("vec3") != std::string::npos ||
            type.find("float3") != std::string::npos;
    }

    bool FieldLooksLikeObjectReference(const MetadataFieldRecord& field)
    {
        const std::string name = ToLowerAscii(field.name);
        const std::uint32_t flags = WorldTypeFlagsForTypeIndex(field.fieldTypeIndex);
        if (flags & (AegisREType_Transform | AegisREType_GameObject | AegisREType_Component |
            AegisREType_Player | AegisREType_Npc | AegisREType_Enemy | AegisREType_Entity))
        {
            return true;
        }

        return name.find("transform") != std::string::npos ||
            name.find("gameobject") != std::string::npos ||
            name.find("object") != std::string::npos ||
            name.find("owner") != std::string::npos ||
            name.find("parent") != std::string::npos ||
            name.find("component") != std::string::npos ||
            name.find("character") != std::string::npos ||
            name.find("player") != std::string::npos ||
            name.find("enemy") != std::string::npos;
    }

    bool TryExtractObjectPositionRecursive(
        std::uintptr_t objectAddress,
        std::uint32_t typeIndex,
        AegisREVec3& out,
        std::unordered_set<std::uintptr_t>& visited,
        std::uint32_t depth)
    {
        if (!objectAddress || visited.find(objectAddress) != visited.end())
            return false;
        visited.insert(objectAddress);

        std::vector<std::uint32_t> chain;
        CollectTypeChain(typeIndex, chain);

        for (std::uint32_t currentTypeIndex : chain)
        {
            const MetadataTypeRecord* declaringType = MetadataTypeByIndex(currentTypeIndex);
            if (!declaringType)
                continue;

            auto fields = g_fieldsByDeclaringType.find(currentTypeIndex);
            if (fields == g_fieldsByDeclaringType.end())
                continue;

            for (std::uint32_t fieldIndex : fields->second)
            {
                if (fieldIndex >= g_metadataFields.size())
                    continue;
                const MetadataFieldRecord& field = g_metadataFields[fieldIndex];
                if (!FieldLooksLikePosition(field))
                    continue;

                const std::uintptr_t candidates[] = {
                    objectAddress + static_cast<std::intptr_t>(declaringType->fieldPtrOffset) + field.offset,
                    objectAddress + 0x10 + field.offset,
                    objectAddress + 0x20 + field.offset,
                    objectAddress + field.offset
                };
                for (std::uintptr_t candidate : candidates)
                {
                    if (TryReadVec3(candidate, out))
                        return true;
                }
            }
        }

        if (depth >= 2)
            return false;

        for (std::uint32_t currentTypeIndex : chain)
        {
            const MetadataTypeRecord* declaringType = MetadataTypeByIndex(currentTypeIndex);
            if (!declaringType)
                continue;

            auto fields = g_fieldsByDeclaringType.find(currentTypeIndex);
            if (fields == g_fieldsByDeclaringType.end())
                continue;

            for (std::uint32_t fieldIndex : fields->second)
            {
                if (fieldIndex >= g_metadataFields.size())
                    continue;
                const MetadataFieldRecord& field = g_metadataFields[fieldIndex];
                if (!FieldLooksLikeObjectReference(field))
                    continue;

                const std::uintptr_t candidates[] = {
                    objectAddress + static_cast<std::intptr_t>(declaringType->fieldPtrOffset) + field.offset,
                    objectAddress + 0x10 + field.offset,
                    objectAddress + 0x20 + field.offset,
                    objectAddress + field.offset
                };

                for (std::uintptr_t candidate : candidates)
                {
                    std::uintptr_t child = 0;
                    if (!ReadPtr(candidate, child) || !child || child == objectAddress)
                        continue;

                    std::uint32_t childTypeIndex = 0;
                    if (!ReadManagedObjectTypeIndex(child, childTypeIndex))
                        continue;

                    if (TryExtractObjectPositionRecursive(child, childTypeIndex, out, visited, depth + 1))
                        return true;
                }
            }
        }

        return false;
    }

    bool TryExtractObjectPosition(std::uintptr_t objectAddress, std::uint32_t typeIndex, AegisREVec3& out)
    {
        std::unordered_set<std::uintptr_t> visited;
        visited.reserve(16);
        return TryExtractObjectPositionRecursive(objectAddress, typeIndex, out, visited, 0);
    }

    bool AddWorldRootCandidate(
        std::vector<WorldRootCandidate>& roots,
        std::unordered_set<std::uintptr_t>& seen,
        std::uintptr_t objectAddress,
        std::uintptr_t sourceAddress,
        const std::string& reason,
        std::uint32_t score)
    {
        if (roots.size() >= kMaxWorldRoots)
            return false;
        if (seen.find(objectAddress) != seen.end())
            return false;

        std::uint32_t typeIndex = 0;
        if (!ReadManagedObjectTypeIndex(objectAddress, typeIndex))
            return false;

        WorldRootCandidate root;
        root.objectAddress = objectAddress;
        root.sourceAddress = sourceAddress;
        root.typeIndex = typeIndex;
        root.score = score;
        root.reason = reason;
        root.typeName = MetadataTypeNameByIndex(typeIndex);
        roots.push_back(std::move(root));
        seen.insert(objectAddress);
        return true;
    }

    bool MethodLooksLikeSafeSingletonGetter(const MetadataMethodRecord& method)
    {
        if ((method.flags & AegisREMetadata_DirectFunction) == 0 || !method.functionAddress)
            return false;
        if (method.parameterCount != 0)
            return false;

        const std::string methodName = ToLowerAscii(method.name);
        const std::string owner = ToLowerAscii(MetadataTypeNameByIndex(method.declaringTypeIndex));
        if (methodName != "get_instance" && methodName != "getinstance" && methodName != "instance")
            return false;

        return owner.find("singleton") != std::string::npos ||
            owner.find("manager") != std::string::npos ||
            owner.find("scene") != std::string::npos ||
            owner.find("world") != std::string::npos ||
            owner.find("game") != std::string::npos ||
            owner.find("app.") != std::string::npos;
    }

    void BuildInternalWorldRootsLocked()
    {
        g_worldRoots.clear();
        g_worldRootsScanned = true;
        g_worldStats.singletonRootCount = 0;
        g_worldStats.globalPointerRootCount = 0;
        g_worldStats.rejectedRootCount = 0;

        if (!g_metadataScanCompleted)
            BuildMetadataBackendLocked();
        if (!g_metadataBackendReady)
        {
            LogMetadata("World walker root scan skipped: metadata backend not ready");
            return;
        }

        std::unordered_set<std::uintptr_t> seenRoots;

        if (kEnableTdbSingletonGetterRoots)
        {
            for (const MetadataMethodRecord& method : g_metadataMethods)
            {
                if (!MethodLooksLikeSafeSingletonGetter(method))
                    continue;

                const std::uintptr_t object = SafeCallNoArgPointer(method.functionAddress);
                if (!object)
                    continue;

                if (AddWorldRootCandidate(g_worldRoots, seenRoots, object, method.functionAddress, "TDB singleton getter", 200))
                    ++g_worldStats.singletonRootCount;
                else
                    ++g_worldStats.rejectedRootCount;

                if (g_worldRoots.size() >= kMaxWorldRoots)
                    break;
            }
        }
        else
        {
            LogMetadata("World walker singleton getter roots disabled for automatic startup scan");
        }

        const ULONGLONG rootStartTick = ::GetTickCount64();
        std::uint64_t rootBytesScanned = 0;
        std::uint32_t rootSectionsScanned = 0;

        for (const AegisUniversalModuleInfo& module : CurrentModules())
        {
            if (!IsLikelyReModule(module))
                continue;

            std::vector<SectionRange> ranges;
            if (!ReadPeSections(module, ranges))
                continue;

            for (const SectionRange& range : ranges)
            {
                if (range.executable || !range.writable)
                    continue;
                if (::GetTickCount64() - rootStartTick >= kWorldRootScanBudgetMs)
                {
                    g_worldStats.flags |= AegisREWorldWalker_TruncatedRoots;
                    LogMetadata("World walker root scan stopped by time budget after %llums bytes=%llu roots=%u",
                        static_cast<unsigned long long>(::GetTickCount64() - rootStartTick),
                        static_cast<unsigned long long>(rootBytesScanned),
                        static_cast<unsigned>(g_worldRoots.size()));
                    return;
                }
                if (rootBytesScanned >= kMaxWorldRootScanBytes)
                {
                    g_worldStats.flags |= AegisREWorldWalker_TruncatedRoots;
                    LogMetadata("World walker root scan stopped by byte cap bytes=%llu roots=%u",
                        static_cast<unsigned long long>(rootBytesScanned),
                        static_cast<unsigned>(g_worldRoots.size()));
                    return;
                }

                ++rootSectionsScanned;

                for (std::size_t offset = 0; offset + sizeof(std::uintptr_t) <= range.size; offset += sizeof(std::uintptr_t))
                {
                    if ((offset & 0xFFFFu) == 0)
                    {
                        if (::GetTickCount64() - rootStartTick >= kWorldRootScanBudgetMs ||
                            rootBytesScanned >= kMaxWorldRootScanBytes)
                        {
                            g_worldStats.flags |= AegisREWorldWalker_TruncatedRoots;
                            LogMetadata("World walker root scan stopped during section after %llums bytes=%llu roots=%u",
                                static_cast<unsigned long long>(::GetTickCount64() - rootStartTick),
                                static_cast<unsigned long long>(rootBytesScanned),
                                static_cast<unsigned>(g_worldRoots.size()));
                            return;
                        }
                    }

                    std::uintptr_t object = 0;
                    const std::uintptr_t slot = reinterpret_cast<std::uintptr_t>(range.begin + offset);
                    if (!ReadPtr(slot, object) || !object)
                        continue;

                    if (AddWorldRootCandidate(g_worldRoots, seenRoots, object, slot, "module/global pointer", 100))
                        ++g_worldStats.globalPointerRootCount;
                    else
                        ++g_worldStats.rejectedRootCount;

                    if (g_worldRoots.size() >= kMaxWorldRoots)
                    {
                        g_worldStats.flags |= AegisREWorldWalker_TruncatedRoots;
                        LogMetadata("World walker root scan capped at %u roots", kMaxWorldRoots);
                        return;
                    }
                }

                rootBytesScanned += range.size;
            }
        }

        LogMetadata("World walker roots: total=%u singleton=%u globals=%u rejected=%u sections=%u bytes=%llu ms=%llu",
            static_cast<unsigned>(g_worldRoots.size()),
            static_cast<unsigned>(g_worldStats.singletonRootCount),
            static_cast<unsigned>(g_worldStats.globalPointerRootCount),
            static_cast<unsigned>(g_worldStats.rejectedRootCount),
            static_cast<unsigned>(rootSectionsScanned),
            static_cast<unsigned long long>(rootBytesScanned),
            static_cast<unsigned long long>(::GetTickCount64() - rootStartTick));
    }

    void QueueObjectIfValid(
        std::vector<std::pair<std::uintptr_t, std::uint32_t>>& queue,
        std::unordered_set<std::uintptr_t>& visited,
        std::uintptr_t objectAddress,
        std::uint32_t depth)
    {
        if (!objectAddress || visited.find(objectAddress) != visited.end())
            return;

        std::uint32_t typeIndex = 0;
        if (!ReadManagedObjectTypeIndex(objectAddress, typeIndex))
            return;

        visited.insert(objectAddress);
        if (queue.size() < kMaxWorldObjects)
            queue.push_back({ objectAddress, depth });
        else
            g_worldStats.flags |= AegisREWorldWalker_TruncatedObjects;
    }

    void AddWorldComponentSnapshot(
        std::vector<AegisREComponentSnapshot>& components,
        std::uintptr_t objectAddress,
        std::uint32_t typeIndex)
    {
        if (components.size() >= kMaxComponents)
        {
            g_worldStats.flags |= AegisREWorldWalker_TruncatedObjects;
            return;
        }

        const std::uint32_t typeFlags = WorldTypeFlagsForTypeIndex(typeIndex);
        const std::uint32_t componentFlags = TypeFlagsToComponentFlags(typeFlags);
        const std::string typeName = MetadataTypeNameByIndex(typeIndex);

        AegisREComponentSnapshot component = {};
        component.id = static_cast<std::uint64_t>(components.size() + 1);
        component.address = objectAddress;
        CopyAnsi(component.name, LeafNameOf(typeName));
        CopyAnsi(component.typeName, typeName);
        CopyAnsi(component.category, CategoryForTypeFlags(typeFlags));
        component.boundsMin = { -0.5f, -0.5f, -0.5f };
        component.boundsMax = { 0.5f, 0.5f, 0.5f };
        component.visible = TryExtractObjectPosition(objectAddress, typeIndex, component.origin) ? 1 : 0;
        component.flags = componentFlags | AegisREComponent_LiveSnapshot;
        components.push_back(component);
    }

    void AddWorldComponentSnapshotWithPosition(
        std::vector<AegisREComponentSnapshot>& components,
        std::uintptr_t objectAddress,
        std::uint32_t typeIndex,
        const AegisREVec3& origin)
    {
        if (components.size() >= kMaxComponents)
        {
            g_worldStats.flags |= AegisREWorldWalker_TruncatedObjects;
            return;
        }

        const std::uint32_t typeFlags = WorldTypeFlagsForTypeIndex(typeIndex);
        const std::uint32_t componentFlags = TypeFlagsToComponentFlags(typeFlags);
        const std::string typeName = MetadataTypeNameByIndex(typeIndex);

        AegisREComponentSnapshot component = {};
        component.id = static_cast<std::uint64_t>(components.size() + 1);
        component.address = objectAddress;
        CopyAnsi(component.name, LeafNameOf(typeName));
        CopyAnsi(component.typeName, typeName);
        CopyAnsi(component.category, CategoryForTypeFlags(typeFlags));
        component.origin = origin;
        component.boundsMin = { -0.5f, -0.5f, -0.5f };
        component.boundsMax = { 0.5f, 1.8f, 0.5f };
        component.visible = 1;
        component.flags = componentFlags | AegisREComponent_LiveSnapshot;
        components.push_back(component);
    }

    std::unordered_map<std::uintptr_t, std::uint32_t> BuildInterestingObjectInfoMap()
    {
        std::unordered_map<std::uintptr_t, std::uint32_t> objectInfos;
        objectInfos.reserve(8192);

        for (const MetadataTypeRecord& type : g_metadataTypes)
        {
            if (!type.managedVtableAddress)
                continue;
            if (!IsInterestingWorldType(type.typeIndex))
                continue;
            objectInfos.emplace(type.managedVtableAddress, type.typeIndex);
        }

        return objectInfos;
    }

    void ScanLiveInstanceRegion(
        const std::uint8_t* begin,
        std::size_t size,
        const std::unordered_map<std::uintptr_t, std::uint32_t>& objectInfos,
        std::vector<AegisREComponentSnapshot>& components,
        std::unordered_set<std::uintptr_t>& visited,
        LiveInstanceScanStats& stats)
    {
        if (!begin || size < sizeof(std::uintptr_t) || objectInfos.empty())
            return;

        static constexpr std::uintptr_t kObjectBaseOffsets[] = { 0x0, 0x8, 0x10, 0x18, 0x20 };
        std::array<std::uint8_t, kWorldInstanceScanChunk> buffer = {};
        for (std::size_t offset = 0; offset + sizeof(std::uintptr_t) <= size && components.size() < kMaxComponents; offset += buffer.size())
        {
            const std::size_t chunkSize = std::min<std::size_t>(buffer.size(), size - offset);
            if (chunkSize < sizeof(std::uintptr_t))
                break;
            if (!SafeCopyMemory(begin + offset, buffer.data(), chunkSize))
                continue;

            for (std::size_t cursor = 0; cursor + sizeof(std::uintptr_t) <= chunkSize && components.size() < kMaxComponents; cursor += sizeof(std::uintptr_t))
            {
                std::uintptr_t objectInfo = 0;
                std::memcpy(&objectInfo, buffer.data() + cursor, sizeof(objectInfo));
                if (!objectInfo)
                    continue;

                auto info = objectInfos.find(objectInfo);
                if (info == objectInfos.end())
                    continue;

                ++stats.objectInfoHits;
                const std::uintptr_t objectInfoSlot = reinterpret_cast<std::uintptr_t>(begin + offset + cursor);
                bool addedSnapshot = false;
                std::uintptr_t fallbackObjectAddress = 0;
                std::uint32_t fallbackTypeIndex = 0;
                for (std::uintptr_t baseOffset : kObjectBaseOffsets)
                {
                    if (objectInfoSlot < baseOffset || components.size() >= kMaxComponents)
                        continue;

                    const std::uintptr_t objectAddress = objectInfoSlot - baseOffset;
                    if ((objectAddress & (sizeof(void*) - 1)) != 0 || visited.find(objectAddress) != visited.end())
                        continue;

                    ++stats.baseCandidates;
                    std::uint32_t typeIndex = 0;
                    if (!ReadManagedObjectTypeIndex(objectAddress, typeIndex))
                        continue;
                    ++stats.validObjects;

                    if (!IsInterestingWorldType(typeIndex))
                        continue;
                    ++stats.interestingObjects;
                    if (!fallbackObjectAddress)
                    {
                        fallbackObjectAddress = objectAddress;
                        fallbackTypeIndex = typeIndex;
                    }
                    if (stats.sampleTypeCount < stats.sampleTypes.size())
                    {
                        const std::string typeName = MetadataTypeNameByIndex(typeIndex);
                        bool alreadySampled = false;
                        for (std::uint32_t sampleIndex = 0; sampleIndex < stats.sampleTypeCount; ++sampleIndex)
                        {
                            if (stats.sampleTypes[sampleIndex] == typeName)
                            {
                                alreadySampled = true;
                                break;
                            }
                        }
                        if (!alreadySampled)
                            stats.sampleTypes[stats.sampleTypeCount++] = typeName;
                    }

                    AegisREVec3 origin = {};
                    if (!TryExtractObjectPosition(objectAddress, typeIndex, origin))
                        continue;
                    ++stats.positionedObjects;

                    visited.insert(objectAddress);
                    AddWorldComponentSnapshotWithPosition(components, objectAddress, typeIndex, origin);
                    addedSnapshot = true;
                    break;
                }

                if (!addedSnapshot && fallbackObjectAddress && components.size() < kMaxComponents &&
                    visited.find(fallbackObjectAddress) == visited.end())
                {
                    visited.insert(fallbackObjectAddress);
                    AddWorldComponentSnapshot(components, fallbackObjectAddress, fallbackTypeIndex);
                }
            }
        }
    }

    void CollectLiveInstanceSnapshotsLocked(
        std::vector<AegisREComponentSnapshot>& components,
        std::unordered_set<std::uintptr_t>& visited,
        bool force)
    {
        const auto objectInfos = BuildInterestingObjectInfoMap();
        if (objectInfos.empty())
        {
            LogMetadata("World instance scan skipped: no interesting managed vtable addresses");
            return;
        }

        SYSTEM_INFO systemInfo = {};
        ::GetNativeSystemInfo(&systemInfo);
        const std::uintptr_t minAddress = reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
        const std::uintptr_t maxAddress = reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);
        if (g_worldInstanceScanCursor < minAddress || g_worldInstanceScanCursor >= maxAddress)
            g_worldInstanceScanCursor = minAddress;

        const ULONGLONG startTick = ::GetTickCount64();
        const ULONGLONG budgetMs = force ? kWorldInstanceForceScanBudgetMs : kWorldInstanceScanBudgetMs;
        const std::uint64_t byteCap = force ? kMaxWorldInstanceForceScanBytes : kMaxWorldInstanceScanBytes;
        std::uint64_t scannedBytes = 0;
        std::uint32_t scannedRegions = 0;
        LiveInstanceScanStats stats = {};
        std::uintptr_t address = g_worldInstanceScanCursor;
        bool wrapped = false;

        while (components.size() < kMaxComponents && scannedBytes < byteCap)
        {
            if (::GetTickCount64() - startTick >= budgetMs)
                break;

            MEMORY_BASIC_INFORMATION mbi = {};
            if (::VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) != sizeof(mbi))
                break;

            const std::uintptr_t regionBase = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const std::uintptr_t regionEnd = regionBase + mbi.RegionSize;

            if (mbi.State == MEM_COMMIT &&
                mbi.Type == MEM_PRIVATE &&
                IsReadableWritableDataProtect(mbi.Protect) &&
                mbi.RegionSize >= sizeof(std::uintptr_t))
            {
                const std::uint64_t remainingCap = byteCap - scannedBytes;
                const std::size_t scanSize = static_cast<std::size_t>(
                    std::min<std::uint64_t>(mbi.RegionSize, remainingCap));
                ScanLiveInstanceRegion(
                    reinterpret_cast<const std::uint8_t*>(regionBase),
                    scanSize,
                    objectInfos,
                    components,
                    visited,
                    stats);
                scannedBytes += scanSize;
                ++scannedRegions;
            }

            if (regionEnd <= address)
                break;
            address = regionEnd;
            if (address >= maxAddress)
            {
                if (wrapped)
                    break;
                address = minAddress;
                wrapped = true;
            }
            if (wrapped && address >= g_worldInstanceScanCursor)
                break;
        }

        g_worldInstanceScanCursor = address;
        if (scannedBytes >= byteCap || ::GetTickCount64() - startTick >= budgetMs)
            g_worldStats.flags |= AegisREWorldWalker_TruncatedObjects;
        if (scannedRegions)
            g_worldStats.flags |= AegisREWorldWalker_InstanceScan;

        std::string samples;
        for (std::uint32_t index = 0; index < stats.sampleTypeCount; ++index)
        {
            if (!samples.empty())
                samples += "; ";
            samples += stats.sampleTypes[index];
        }
        if (samples.empty())
            samples = "<none>";

        LogMetadata("World instance scan: infos=%u regions=%u bytes=%llu hits=%llu bases=%llu valid=%llu interesting=%llu positioned=%llu components=%u elapsed=%llums cursor=%s%s",
            static_cast<unsigned>(objectInfos.size()),
            static_cast<unsigned>(scannedRegions),
            static_cast<unsigned long long>(scannedBytes),
            static_cast<unsigned long long>(stats.objectInfoHits),
            static_cast<unsigned long long>(stats.baseCandidates),
            static_cast<unsigned long long>(stats.validObjects),
            static_cast<unsigned long long>(stats.interestingObjects),
            static_cast<unsigned long long>(stats.positionedObjects),
            static_cast<unsigned>(components.size()),
            static_cast<unsigned long long>(::GetTickCount64() - startTick),
            PointerHex(g_worldInstanceScanCursor).c_str(),
            wrapped ? " wrapped" : "");
        LogMetadata("World instance scan samples: %s", samples.c_str());
    }

    void WalkInternalWorldLocked(bool force)
    {
        if (!g_worldWalkerEnabled)
            return;

        const DWORD now = ::GetTickCount();
        if (!force && g_worldLastScanTick && now - g_worldLastScanTick < kWorldScanIntervalMs)
            return;

        LARGE_INTEGER start = NowCounter();
        g_worldLastScanTick = now;
        ++g_worldStats.scanId;
        g_worldStats.enabled = 1;
        g_worldStats.ready = 0;
        g_worldStats.flags = AegisREWorldWalker_Enabled;
        g_worldStats.visitedObjectCount = 0;
        g_worldStats.componentCount = 0;
        g_worldStats.fieldReadCount = 0;
        g_worldStats.maxDepthReached = 0;

        if (!g_metadataScanCompleted)
            BuildMetadataBackendLocked();
        if (!g_metadataBackendReady)
        {
            LARGE_INTEGER end = NowCounter();
            g_worldStats.lastScanMs = ElapsedMs(start, end);
            CopyWide(g_worldStats.details, L"Metadata backend is not ready; internal world walk skipped.");
            return;
        }

        g_worldStats.flags |= AegisREWorldWalker_TdbBacked;
        if (force || (!g_worldRootsScanned && kEnableAutomaticGlobalRootScan))
        {
            BuildInternalWorldRootsLocked();
        }
        else if (!g_worldRootsScanned)
        {
            g_worldRoots.clear();
            g_worldRootsScanned = true;
            g_worldStats.singletonRootCount = 0;
            g_worldStats.globalPointerRootCount = 0;
            g_worldStats.rejectedRootCount = 0;
            LogMetadata("World walker global root scan deferred on automatic tick; live instance scan only");
        }
        if (g_worldStats.singletonRootCount)
            g_worldStats.flags |= AegisREWorldWalker_SingletonGetterRoots;
        if (g_worldStats.globalPointerRootCount)
            g_worldStats.flags |= AegisREWorldWalker_GlobalPointerRoots;

        std::vector<std::pair<std::uintptr_t, std::uint32_t>> queue;
        queue.reserve(std::min<std::size_t>(g_worldRoots.size(), kMaxWorldRoots));
        std::unordered_set<std::uintptr_t> visited;
        visited.reserve(kMaxWorldObjects);

        for (const WorldRootCandidate& root : g_worldRoots)
            QueueObjectIfValid(queue, visited, root.objectAddress, 0);

        std::vector<AegisREComponentSnapshot> components;
        components.reserve(512);

        for (std::size_t cursor = 0; cursor < queue.size() && cursor < kMaxWorldObjects; ++cursor)
        {
            const std::uintptr_t objectAddress = queue[cursor].first;
            const std::uint32_t depth = queue[cursor].second;
            g_worldStats.maxDepthReached = std::max(g_worldStats.maxDepthReached, depth);

            std::uint32_t typeIndex = 0;
            if (!ReadManagedObjectTypeIndex(objectAddress, typeIndex))
                continue;

            if (IsInterestingWorldType(typeIndex))
                AddWorldComponentSnapshot(components, objectAddress, typeIndex);

            if (depth >= kMaxWorldDepth || g_worldStats.fieldReadCount >= kMaxWorldFieldReads)
                continue;

            std::vector<std::uint32_t> chain;
            CollectTypeChain(typeIndex, chain);
            for (std::uint32_t currentTypeIndex : chain)
            {
                const MetadataTypeRecord* declaringType = MetadataTypeByIndex(currentTypeIndex);
                if (!declaringType)
                    continue;

                auto fields = g_fieldsByDeclaringType.find(currentTypeIndex);
                if (fields == g_fieldsByDeclaringType.end())
                    continue;

                for (std::uint32_t fieldIndex : fields->second)
                {
                    if (fieldIndex >= g_metadataFields.size())
                        continue;
                    const MetadataFieldRecord& field = g_metadataFields[fieldIndex];
                    const std::uintptr_t fieldAddresses[] = {
                        objectAddress + static_cast<std::intptr_t>(declaringType->fieldPtrOffset) + field.offset,
                        objectAddress + 0x10 + field.offset,
                        objectAddress + 0x20 + field.offset,
                        objectAddress + field.offset
                    };

                    for (std::uintptr_t fieldAddress : fieldAddresses)
                    {
                        std::uintptr_t child = 0;
                        ++g_worldStats.fieldReadCount;
                        if (g_worldStats.fieldReadCount >= kMaxWorldFieldReads)
                        {
                            g_worldStats.flags |= AegisREWorldWalker_TruncatedFields;
                            break;
                        }
                        if (!ReadPtr(fieldAddress, child) || !child)
                            continue;
                        QueueObjectIfValid(queue, visited, child, depth + 1);
                    }
                    if (g_worldStats.fieldReadCount >= kMaxWorldFieldReads)
                        break;
                }
                if (g_worldStats.fieldReadCount >= kMaxWorldFieldReads)
                    break;
            }
        }

        CollectLiveInstanceSnapshotsLocked(components, visited, force);

        g_components = std::move(components);
        g_worldStats.rootCount = static_cast<std::uint32_t>(g_worldRoots.size());
        g_worldStats.visitedObjectCount = static_cast<std::uint32_t>(visited.size());
        g_worldStats.componentCount = static_cast<std::uint32_t>(g_components.size());
        const bool hasVisibleComponent = std::any_of(g_components.begin(), g_components.end(), [](const AegisREComponentSnapshot& component) {
            return component.visible != 0;
        });
        g_worldStats.ready = hasVisibleComponent ? 1 : 0;
        RebuildProjectionStatsLocked();

        LARGE_INTEGER end = NowCounter();
        g_worldStats.lastScanMs = ElapsedMs(start, end);

        std::wstringstream details;
        details << L"Internal TDB world walk: roots=" << g_worldStats.rootCount
                << L" objects=" << g_worldStats.visitedObjectCount
                << L" components=" << g_worldStats.componentCount
                << L" fields=" << g_worldStats.fieldReadCount;
        CopyWide(g_worldStats.details, details.str());

        LogMetadata("World walk scan=%llu roots=%u objects=%u components=%u fields=%u ms=%.2f",
            static_cast<unsigned long long>(g_worldStats.scanId),
            static_cast<unsigned>(g_worldStats.rootCount),
            static_cast<unsigned>(g_worldStats.visitedObjectCount),
            static_cast<unsigned>(g_worldStats.componentCount),
            static_cast<unsigned>(g_worldStats.fieldReadCount),
            g_worldStats.lastScanMs);
    }

    void AppendMetadataHookCandidatesLocked()
    {
        g_metadataHookCandidateCount = 0;
        if (!g_metadataScanCompleted)
            BuildMetadataBackendLocked();
        if (!g_metadataBackendReady || g_metadataMethods.empty())
            return;

        std::unordered_set<std::uintptr_t> seen;
        seen.reserve(g_hookCandidates.size() + 4096);
        for (const HookCandidate& hook : g_hookCandidates)
        {
            if (hook.address)
                seen.insert(hook.address);
        }

        for (const MetadataMethodRecord& method : g_metadataMethods)
        {
            if ((method.flags & AegisREMetadata_DirectFunction) == 0 || !method.functionAddress)
                continue;
            if (seen.find(method.functionAddress) != seen.end())
                continue;

            HookCandidate candidate;
            bool mainModule = false;
            bool rendererModule = false;
            if (!ResolveExecutableAddressFast(
                    method.functionAddress,
                    &candidate.moduleName,
                    &candidate.modulePath,
                    &candidate.rva,
                    &mainModule,
                    &rendererModule))
            {
                candidate.moduleName = L"unknown";
                candidate.rva = method.functionRva;
            }
            candidate.symbolName = MetadataTypeNameByIndex(method.declaringTypeIndex) + "::" +
                (method.name.empty() ? "<method>" : method.name);
            candidate.reason = "RE TDB method";
            candidate.address = method.functionAddress;
            candidate.flags = AegisREHookCandidate_MetadataOnly | AegisREHookCandidate_TdbMethod;

            if (mainModule)
                candidate.flags |= AegisREHookCandidate_MainModule;
            else
                candidate.flags |= AegisREHookCandidate_SideModule;

            if (rendererModule)
                candidate.flags |= AegisREHookCandidate_Renderer;

            seen.insert(method.functionAddress);
            g_hookCandidates.push_back(std::move(candidate));
            ++g_metadataHookCandidateCount;
            if (g_metadataHookCandidateCount >= kMaxMetadataHookCandidates)
            {
                LogMetadata("Metadata hook candidate list capped at %u direct methods", kMaxMetadataHookCandidates);
                break;
            }
        }

        LogMetadata("Added %u metadata-backed direct method hook candidates", static_cast<unsigned>(g_metadataHookCandidateCount));
    }

    void BuildMetadataBackendLocked()
    {
        if (g_metadataScanCompleted)
            return;

        g_tdbCandidates.clear();
        g_rejectedTdbCandidates.clear();
        g_bestTdb = {};
        g_metadataTypes.clear();
        g_metadataFields.clear();
        g_metadataMethods.clear();
        g_typeIndexByDefinitionAddress.clear();
        g_metadataVectorIndexByTypeIndex.clear();
        g_fieldsByDeclaringType.clear();
        g_metadataNamedTypeCount = 0;
        g_metadataNamedFieldCount = 0;
        g_metadataNamedMethodCount = 0;
        g_metadataDirectMethodCount = 0;
        g_metadataHookCandidateCount = 0;
        g_metadataBackendReady = false;

        LogMetadata("Starting metadata backend scan");
        RefreshExecutableRangesLocked();

        std::vector<std::uintptr_t> magicCandidates;
        CollectTdbMagicCandidates(magicCandidates);
        LogMetadata("Found %u raw TDB magic candidates", static_cast<unsigned>(magicCandidates.size()));

        for (std::uintptr_t address : magicCandidates)
        {
            std::uint32_t version = 0;
            if (!ReadU32(address + 4, version))
                continue;

            bool attemptedLayout = false;
            for (const TdbLayoutDescriptor& layout : kTdbLayouts)
            {
                if (version < layout.minVersion || version > layout.maxVersion)
                    continue;
                attemptedLayout = true;

                TdbCandidate candidate = {};
                std::string rejectReason;
                if (ValidateTdbCandidateAt(address, layout, candidate, rejectReason))
                {
                    g_tdbCandidates.push_back(candidate);
                    LogMetadata("Accepted TDB candidate addr=%s version=%u layout=%s score=%u namedSamples=%u types=%u fields=%u methods=%u module=%s",
                        PointerHex(candidate.address).c_str(),
                        static_cast<unsigned>(candidate.version),
                        layout.name,
                        static_cast<unsigned>(candidate.score),
                        static_cast<unsigned>(candidate.namedTypeSamples),
                        static_cast<unsigned>(candidate.numTypes),
                        static_cast<unsigned>(candidate.numFields),
                        static_cast<unsigned>(candidate.numMethods),
                        NarrowWide(candidate.moduleName).c_str());
                    if (!g_bestTdb.address || candidate.score > g_bestTdb.score)
                        g_bestTdb = candidate;
                }
                else
                {
                    TdbCandidate rejected = {};
                    rejected.address = address;
                    rejected.layout = &layout;
                    rejected.version = version;
                    rejected.reason = rejectReason;
                    ResolveAddressModule(address, rejected.moduleName, rejected.modulePath, rejected.rva);
                    g_rejectedTdbCandidates.push_back(rejected);
                    LogMetadata("Rejected TDB candidate addr=%s version=%u layout=%s reason=%s",
                        PointerHex(address).c_str(),
                        static_cast<unsigned>(version),
                        layout.name,
                        rejectReason.c_str());
                }
            }

            if (!attemptedLayout)
            {
                TdbCandidate rejected = {};
                rejected.address = address;
                rejected.version = version;
                rejected.reason = "unsupported TDB version";
                ResolveAddressModule(address, rejected.moduleName, rejected.modulePath, rejected.rva);
                g_rejectedTdbCandidates.push_back(rejected);
                LogMetadata("Rejected TDB candidate addr=%s version=%u reason=unsupported version",
                    PointerHex(address).c_str(),
                    static_cast<unsigned>(version));
            }
        }

        if (g_bestTdb.address)
        {
            g_metadataBackendReady = true;
            DecodeMetadataTablesLocked(g_bestTdb);
            LogMetadata("Best TDB selected addr=%s version=%u layout=%s types=%u methods=%u fields=%u stringPool=%s",
                PointerHex(g_bestTdb.address).c_str(),
                static_cast<unsigned>(g_bestTdb.version),
                g_bestTdb.layout ? g_bestTdb.layout->name : "unknown",
                static_cast<unsigned>(g_bestTdb.numTypes),
                static_cast<unsigned>(g_bestTdb.numMethods),
                static_cast<unsigned>(g_bestTdb.numFields),
                PointerHex(g_bestTdb.stringPool).c_str());
        }
        else
        {
            LogMetadata("No validated TDB candidate found. Internal live world walking is waiting on a validated metadata backend.");
        }

        g_metadataScanCompleted = true;
    }

    std::vector<HookCandidate> EnumeratePeExports(const AegisUniversalModuleInfo& module)
    {
        std::vector<HookCandidate> out;
        if (!module.baseAddress)
            return out;

        const auto* base = reinterpret_cast<const std::uint8_t*>(module.baseAddress);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
            return out;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return out;

        const IMAGE_DATA_DIRECTORY& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!directory.VirtualAddress || !directory.Size)
            return out;

        const auto* exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + directory.VirtualAddress);
        if (!exportDir->NumberOfNames)
            return out;

        const auto* names = reinterpret_cast<const DWORD*>(base + exportDir->AddressOfNames);
        const auto* ordinals = reinterpret_cast<const WORD*>(base + exportDir->AddressOfNameOrdinals);
        const auto* functions = reinterpret_cast<const DWORD*>(base + exportDir->AddressOfFunctions);

        out.reserve(exportDir->NumberOfNames);
        for (DWORD index = 0; index < exportDir->NumberOfNames; ++index)
        {
            const char* name = reinterpret_cast<const char*>(base + names[index]);
            if (!name || !name[0])
                continue;

            const WORD ordinalIndex = ordinals[index];
            if (ordinalIndex >= exportDir->NumberOfFunctions)
                continue;

            const DWORD rva = functions[ordinalIndex];
            if (!rva || rva >= module.imageSize)
                continue;

            HookCandidate candidate;
            candidate.moduleName = module.name;
            candidate.modulePath = module.path;
            candidate.symbolName = name;
            candidate.reason = "PE export";
            candidate.address = module.baseAddress + rva;
            candidate.rva = rva;
            candidate.ordinal = exportDir->Base + ordinalIndex;
            candidate.flags = AegisREHookCandidate_Export;
            candidate.flags |= IsMainModule(module) ? AegisREHookCandidate_MainModule : AegisREHookCandidate_SideModule;
            if (IsRendererModule(module.name) || IsRendererModule(WidenAscii(candidate.symbolName)))
                candidate.flags |= AegisREHookCandidate_Renderer;
            if (IsAudioSymbol(candidate.symbolName))
                candidate.flags |= AegisREHookCandidate_Audio;
            out.push_back(std::move(candidate));
        }
        return out;
    }

    void BuildHookCandidatesLocked()
    {
        g_hookCandidates.clear();
        for (const AegisUniversalModuleInfo& module : CurrentModules())
        {
            if (!IsLikelyReModule(module) && !IsRendererModule(module.name))
                continue;
            std::vector<HookCandidate> exports = EnumeratePeExports(module);
            g_hookCandidates.insert(g_hookCandidates.end(), exports.begin(), exports.end());
        }

        if (!g_metadataScanCompleted)
            BuildMetadataBackendLocked();
        AppendMetadataHookCandidatesLocked();

        std::sort(g_hookCandidates.begin(), g_hookCandidates.end(), [](const HookCandidate& left, const HookCandidate& right) {
            const std::wstring leftModule = ToLowerWide(left.moduleName);
            const std::wstring rightModule = ToLowerWide(right.moduleName);
            if (leftModule != rightModule)
                return leftModule < rightModule;
            return ToLowerAscii(left.symbolName) < ToLowerAscii(right.symbolName);
        });
        g_hookScanCompleted = true;
    }

    bool ContainsConsoleActivationVerb(const std::string& lower)
    {
        return lower.find("toggle") != std::string::npos ||
            lower.find("open") != std::string::npos ||
            lower.find("show") != std::string::npos ||
            lower.find("spawn") != std::string::npos ||
            lower.find("enable") != std::string::npos ||
            lower.find("activate") != std::string::npos ||
            lower.find("display") != std::string::npos ||
            lower.find("create") != std::string::npos ||
            lower.find("visible") != std::string::npos;
    }

    bool IsFrameworkConsoleType(const std::string& ownerLower)
    {
        return ownerLower.find("system.") == 0 ||
            ownerLower == "system.console" ||
            ownerLower == "console" ||
            ownerLower.find("consolestream") != std::string::npos;
    }

    bool ContainsDangerousConsoleVerb(const std::string& lower)
    {
        return lower.find("destroy") != std::string::npos ||
            lower.find("dispose") != std::string::npos ||
            lower.find("release") != std::string::npos ||
            lower.find("shutdown") != std::string::npos ||
            lower.find("clear") != std::string::npos ||
            lower.find("delete") != std::string::npos ||
            lower.find("remove") != std::string::npos ||
            lower.find("unload") != std::string::npos ||
            lower.find("reset") != std::string::npos ||
            lower.find("finalize") != std::string::npos ||
            lower.find("abort") != std::string::npos;
    }

    std::uint32_t ScoreConsoleCandidate(const std::string& ownerLower, const std::string& methodLower, std::string& reason)
    {
        reason.clear();
        if (IsFrameworkConsoleType(ownerLower))
            return 0;
        if (ContainsDangerousConsoleVerb(methodLower))
            return 0;
        if (methodLower.find(".ctor") != std::string::npos || methodLower.find("ctor") == 0)
            return 0;

        std::uint32_t score = 0;
        auto add = [&](std::uint32_t value, const char* why) {
            score += value;
            if (!reason.empty())
                reason += "; ";
            reason += why;
        };

        if (ownerLower.find("console") != std::string::npos) add(140, "owner console");
        if (methodLower.find("console") != std::string::npos) add(140, "method console");
        if (ownerLower.find("devmenu") != std::string::npos || ownerLower.find("dev_menu") != std::string::npos) add(110, "owner dev menu");
        if (methodLower.find("devmenu") != std::string::npos || methodLower.find("dev_menu") != std::string::npos) add(100, "method dev menu");
        if (ownerLower.find("debugmenu") != std::string::npos || ownerLower.find("debug_menu") != std::string::npos) add(100, "owner debug menu");
        if (methodLower.find("debugmenu") != std::string::npos || methodLower.find("debug_menu") != std::string::npos) add(90, "method debug menu");
        if (ownerLower.find("command") != std::string::npos) add(65, "owner command");
        if (methodLower.find("command") != std::string::npos) add(60, "method command");
        if (ownerLower.find("cheat") != std::string::npos || methodLower.find("cheat") != std::string::npos) add(55, "cheat token");
        if (ownerLower.find("cvar") != std::string::npos || methodLower.find("cvar") != std::string::npos) add(45, "cvar token");
        if (ownerLower.find("debug") != std::string::npos) add(35, "owner debug");
        if (methodLower.find("debug") != std::string::npos) add(30, "method debug");
        if (ContainsConsoleActivationVerb(methodLower)) add(35, "activation verb");
        if (methodLower.find("get_") == 0 || methodLower.find("is") == 0 || methodLower.find("has") == 0)
            score = score > 25 ? score - 25 : 0;

        return score;
    }

    bool IsCallableConsoleCandidate(const MetadataMethodRecord& method, const std::string& ownerLower, const std::string& methodLower, std::uint32_t score)
    {
        if ((method.flags & AegisREMetadata_DirectFunction) == 0 || !method.functionAddress || method.parameterCount != 0)
            return false;
        if (score < 120)
            return false;
        if (IsFrameworkConsoleType(ownerLower))
            return false;
        if (!ContainsConsoleActivationVerb(methodLower))
            return false;
        return true;
    }

    void BuildConsoleCandidatesLocked()
    {
        if (g_consoleScanCompleted)
            return;

        g_consoleCandidates.clear();
        g_consoleStats = {};
        g_consoleStats.enabled = 1;

        if (!g_metadataScanCompleted)
            BuildMetadataBackendLocked();
        if (!g_metadataBackendReady)
        {
            CopyWide(g_consoleStats.details, L"Metadata backend is not ready; console scan skipped.");
            LogConsole("Console scan skipped: metadata backend not ready");
            g_consoleScanCompleted = true;
            return;
        }

        std::vector<ConsoleCandidate> discovered;
        discovered.reserve(256);
        for (const MetadataMethodRecord& method : g_metadataMethods)
        {
            const std::string owner = MetadataTypeNameByIndex(method.declaringTypeIndex);
            const std::string ownerLower = ToLowerAscii(owner);
            const std::string methodLower = ToLowerAscii(method.name);
            std::string reason;
            const std::uint32_t score = ScoreConsoleCandidate(ownerLower, methodLower, reason);
            if (score < 70)
                continue;

            ConsoleCandidate candidate;
            candidate.declaringType = owner;
            candidate.methodName = method.name;
            candidate.reason = reason;
            candidate.functionAddress = method.functionAddress;
            candidate.functionRva = method.functionRva;
            candidate.parameterCount = method.parameterCount;
            candidate.score = score;
            candidate.flags = method.flags;
            candidate.callable = IsCallableConsoleCandidate(method, ownerLower, methodLower, score);
            discovered.push_back(std::move(candidate));
        }

        std::sort(discovered.begin(), discovered.end(), [](const ConsoleCandidate& left, const ConsoleCandidate& right) {
            if (left.callable != right.callable)
                return left.callable > right.callable;
            if (left.score != right.score)
                return left.score > right.score;
            if (left.declaringType != right.declaringType)
                return ToLowerAscii(left.declaringType) < ToLowerAscii(right.declaringType);
            return ToLowerAscii(left.methodName) < ToLowerAscii(right.methodName);
        });

        if (discovered.size() > kMaxConsoleCandidates)
        {
            g_consoleStats.flags |= AegisREConsole_TruncatedCandidates;
            discovered.resize(kMaxConsoleCandidates);
        }

        g_consoleCandidates = std::move(discovered);
        g_consoleStats.candidateCount = static_cast<std::uint32_t>(g_consoleCandidates.size());
        g_consoleStats.flags |= AegisREConsole_MetadataBacked;
        if (!g_consoleCandidates.empty())
            g_consoleStats.flags |= AegisREConsole_CandidateFound;

        for (const ConsoleCandidate& candidate : g_consoleCandidates)
        {
            if (candidate.callable)
                ++g_consoleStats.callableCandidateCount;
        }

        std::wstringstream details;
        details << L"Console scan: candidates=" << g_consoleStats.candidateCount
                << L" callable=" << g_consoleStats.callableCandidateCount;
        CopyWide(g_consoleStats.details, details.str());

        LogConsole("Console scan: candidates=%u callable=%u flags=0x%X",
            static_cast<unsigned>(g_consoleStats.candidateCount),
            static_cast<unsigned>(g_consoleStats.callableCandidateCount),
            static_cast<unsigned>(g_consoleStats.flags));
        for (std::size_t index = 0; index < g_consoleCandidates.size() && index < 16; ++index)
        {
            const ConsoleCandidate& candidate = g_consoleCandidates[index];
            LogConsole("Candidate %u: %s::%s score=%u params=%u callable=%s addr=%s reason=%s",
                static_cast<unsigned>(index + 1),
                candidate.declaringType.c_str(),
                candidate.methodName.c_str(),
                static_cast<unsigned>(candidate.score),
                static_cast<unsigned>(candidate.parameterCount),
                candidate.callable ? "yes" : "no",
                PointerHex(candidate.functionAddress).c_str(),
                candidate.reason.c_str());
        }

        g_consoleScanCompleted = true;
    }

    bool SafeCallNoArgVoid(std::uintptr_t functionAddress)
    {
        if (!functionAddress)
            return false;

        using Fn = void(AEGIS_RE_CALL*)();
        __try
        {
            reinterpret_cast<Fn>(functionAddress)();
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            LogConsole("Console candidate call 0x%llX raised SEH 0x%08X",
                static_cast<unsigned long long>(functionAddress),
                ::GetExceptionCode());
            return false;
        }
    }

    void ShowAegisConsoleFallback()
    {
        HWND consoleWindow = ::GetConsoleWindow();
        if (!consoleWindow)
        {
            ::AllocConsole();
            consoleWindow = ::GetConsoleWindow();
        }
        if (consoleWindow)
        {
            ::ShowWindow(consoleWindow, SW_SHOW);
            ::SetForegroundWindow(consoleWindow);
        }
    }

    int ToggleGameConsoleInternal()
    {
        std::vector<ConsoleCandidate> candidates;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            BuildConsoleCandidatesLocked();
            for (const ConsoleCandidate& candidate : g_consoleCandidates)
            {
                if (candidate.callable)
                    candidates.push_back(candidate);
            }
            ++g_consoleStats.toggleCount;
            g_consoleStats.flags |= AegisREConsole_Attempted;
        }

        LogConsole("F2 console toggle requested: callable candidates=%u", static_cast<unsigned>(candidates.size()));
        std::uint32_t attempts = 0;
        std::uint32_t successes = 0;
        std::uintptr_t lastAddress = 0;
        for (const ConsoleCandidate& candidate : candidates)
        {
            if (attempts >= kMaxConsoleAttemptsPerToggle)
                break;
            ++attempts;
            lastAddress = candidate.functionAddress;
            LogConsole("Trying console candidate %u/%u: %s::%s score=%u addr=%s",
                static_cast<unsigned>(attempts),
                static_cast<unsigned>(std::min<std::size_t>(candidates.size(), kMaxConsoleAttemptsPerToggle)),
                candidate.declaringType.c_str(),
                candidate.methodName.c_str(),
                static_cast<unsigned>(candidate.score),
                PointerHex(candidate.functionAddress).c_str());
            if (SafeCallNoArgVoid(candidate.functionAddress))
            {
                ++successes;
                LogConsole("Console candidate returned: %s::%s", candidate.declaringType.c_str(), candidate.methodName.c_str());
                break;
            }
        }

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_consoleStats.attemptedCount += attempts;
            g_consoleStats.successfulCallCount += successes;
            g_consoleStats.lastAttemptAddress = lastAddress;
            if (successes)
                g_consoleStats.flags |= AegisREConsole_MethodReturned;
            if (g_consoleHotkeyRunning.load())
                g_consoleStats.flags |= AegisREConsole_HotkeyRunning;

            std::wstringstream details;
            details << L"Console toggle: attempts=" << attempts
                    << L" returned=" << successes
                    << L" callable=" << candidates.size();
            CopyWide(g_consoleStats.details, details.str());
        }

        if (!successes)
        {
            ShowAegisConsoleFallback();
            std::lock_guard<std::mutex> lock(g_mutex);
            g_consoleStats.flags |= AegisREConsole_AegisConsoleFallback;
            if (candidates.empty())
                CopyWide(g_consoleStats.details, L"No callable RE console method found; showing Aegis console fallback.");
            LogConsole("No RE console candidate returned; Aegis console fallback shown");
        }

        return successes ? 1 : 0;
    }

    DWORD WINAPI ConsoleHotkeyThreadProc(void*)
    {
        g_consoleHotkeyRunning.store(true);
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_consoleStats.hotkeyRunning = 1;
            g_consoleStats.flags |= AegisREConsole_HotkeyRunning;
        }
        LogConsole("F2 console hotkey thread started");

        bool wasDown = false;
        while (!g_consoleHotkeyStop.load())
        {
            const bool down = (::GetAsyncKeyState(VK_F2) & 0x8000) != 0;
            if (down && !wasDown)
                ToggleGameConsoleInternal();
            wasDown = down;
            ::Sleep(35);
        }

        g_consoleHotkeyRunning.store(false);
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_consoleStats.hotkeyRunning = 0;
            g_consoleStats.flags &= ~AegisREConsole_HotkeyRunning;
        }
        LogConsole("F2 console hotkey thread stopped");
        return 0;
    }

    bool ProjectWithConvention(
        const AegisREMatrix4x4& matrix,
        const AegisREViewport& viewport,
        const AegisREVec3& world,
        bool columnMajor,
        bool openGlDepth,
        bool yFlip,
        AegisREProjectedPoint& outPoint)
    {
        const float* m = matrix.m;
        float clipX = 0.0f;
        float clipY = 0.0f;
        float clipZ = 0.0f;
        float clipW = 0.0f;

        if (columnMajor)
        {
            clipX = world.x * m[0] + world.y * m[4] + world.z * m[8] + m[12];
            clipY = world.x * m[1] + world.y * m[5] + world.z * m[9] + m[13];
            clipZ = world.x * m[2] + world.y * m[6] + world.z * m[10] + m[14];
            clipW = world.x * m[3] + world.y * m[7] + world.z * m[11] + m[15];
        }
        else
        {
            clipX = world.x * m[0] + world.y * m[1] + world.z * m[2] + m[3];
            clipY = world.x * m[4] + world.y * m[5] + world.z * m[6] + m[7];
            clipZ = world.x * m[8] + world.y * m[9] + world.z * m[10] + m[11];
            clipW = world.x * m[12] + world.y * m[13] + world.z * m[14] + m[15];
        }

        if (!IsFinite(clipX) || !IsFinite(clipY) || !IsFinite(clipZ) || !IsFinite(clipW) || std::fabs(clipW) < 0.00001f)
            return false;

        const float ndcX = clipX / clipW;
        const float ndcY = clipY / clipW;
        const float ndcZ = clipZ / clipW;
        if (!IsFinite(ndcX) || !IsFinite(ndcY) || !IsFinite(ndcZ))
            return false;

        outPoint.x = viewport.x + ((ndcX * 0.5f) + 0.5f) * viewport.width;
        outPoint.y = viewport.y + (yFlip ? ((ndcY * 0.5f) + 0.5f) : (0.5f - (ndcY * 0.5f))) * viewport.height;
        outPoint.depth = ndcZ;

        const bool depthClipped = openGlDepth ? (ndcZ < -1.0f || ndcZ > 1.0f) : (ndcZ < 0.0f || ndcZ > 1.0f);
        const bool xyClipped = ndcX < -1.0f || ndcX > 1.0f || ndcY < -1.0f || ndcY > 1.0f;
        outPoint.clipped = (xyClipped || depthClipped || clipW < 0.0f) ? 1 : 0;
        return IsFinite(outPoint.x) && IsFinite(outPoint.y);
    }

    bool ProjectCurrentLocked(const AegisREVec3& world, AegisREProjectedPoint& outPoint)
    {
        if (!g_hasMatrix || !g_hasViewport || !IsValidMatrix(g_viewProjection) || !IsValidViewport(g_viewport))
            return false;

        const std::uint32_t flags = g_viewProjection.flags;
        const bool wantsColumn = (flags & AegisREMatrix_ColumnMajor) != 0;
        const bool wantsRow = (flags & AegisREMatrix_RowMajor) != 0;
        const bool openGlDepth = (flags & AegisREMatrix_OpenGLDepth) != 0 || (flags & AegisREMatrix_D3DDepth) == 0;
        const bool yFlip = (flags & AegisREMatrix_YFlip) != 0;

        if (wantsColumn || wantsRow)
            return ProjectWithConvention(g_viewProjection, g_viewport, world, wantsColumn, openGlDepth, yFlip, outPoint);

        AegisREProjectedPoint row = {};
        if (ProjectWithConvention(g_viewProjection, g_viewport, world, false, openGlDepth, yFlip, row) && !row.clipped)
        {
            outPoint = row;
            return true;
        }

        AegisREProjectedPoint column = {};
        if (ProjectWithConvention(g_viewProjection, g_viewport, world, true, openGlDepth, yFlip, column))
        {
            outPoint = column;
            return true;
        }

        if (ProjectWithConvention(g_viewProjection, g_viewport, world, false, openGlDepth, yFlip, row))
        {
            outPoint = row;
            return true;
        }
        return false;
    }

    void RebuildProjectionStatsLocked()
    {
        g_timing.componentCount = static_cast<std::uint32_t>(g_components.size());
        g_timing.projectedCount = 0;
        g_timing.clippedCount = 0;

        for (const AegisREComponentSnapshot& component : g_components)
        {
            AegisREProjectedPoint point = {};
            if (!ProjectCurrentLocked(component.origin, point))
                continue;
            if (point.clipped)
                ++g_timing.clippedCount;
            else
                ++g_timing.projectedCount;
        }
    }

    HWND FindGameWindow()
    {
        struct EnumData
        {
            DWORD pid;
            HWND hwnd;
            int bestArea;
        } data = { ::GetCurrentProcessId(), nullptr, 0 };

        ::EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            auto* data = reinterpret_cast<EnumData*>(lParam);
            DWORD pid = 0;
            ::GetWindowThreadProcessId(hwnd, &pid);
            if (pid != data->pid || !::IsWindowVisible(hwnd))
                return TRUE;

            wchar_t className[128] = {};
            ::GetClassNameW(hwnd, className, 128);
            if (wcscmp(className, L"ConsoleWindowClass") == 0 || wcscmp(className, L"AegisOverlayClass") == 0)
                return TRUE;

            RECT rect = {};
            ::GetClientRect(hwnd, &rect);
            const int area = (rect.right - rect.left) * (rect.bottom - rect.top);
            if (area > data->bestArea)
            {
                data->bestArea = area;
                data->hwnd = hwnd;
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&data));
        return data.hwnd;
    }

    bool DefaultViewport(AegisREViewport& outViewport)
    {
        HWND hwnd = FindGameWindow();
        if (!hwnd)
            return false;

        RECT rect = {};
        if (!::GetClientRect(hwnd, &rect))
            return false;

        outViewport = {};
        outViewport.width = static_cast<float>(rect.right - rect.left);
        outViewport.height = static_cast<float>(rect.bottom - rect.top);
        return IsValidViewport(outViewport);
    }

    std::wstring DetectRendererBackend()
    {
        bool hasD3D12 = false;
        bool hasD3D11 = false;
        bool hasOpenGL = false;
        bool hasVulkan = false;
        for (const AegisUniversalModuleInfo& module : CurrentModules())
        {
            const std::wstring name = ToLowerWide(module.name);
            hasD3D12 = hasD3D12 || name.find(L"d3d12") != std::wstring::npos;
            hasD3D11 = hasD3D11 || name.find(L"d3d11") != std::wstring::npos || name.find(L"dxgi") != std::wstring::npos;
            hasOpenGL = hasOpenGL || name.find(L"opengl") != std::wstring::npos;
            hasVulkan = hasVulkan || name.find(L"vulkan") != std::wstring::npos;
        }
        if (hasD3D12)
            return L"D3D12";
        if (hasD3D11)
            return L"D3D11";
        if (hasVulkan)
            return L"Vulkan";
        if (hasOpenGL)
            return L"OpenGL";
        return L"Unknown";
    }

    std::uint32_t SafeComponentProvider(AegisREComponentProvider provider, AegisREComponentSnapshot* out, std::uint32_t capacity, void* userData)
    {
        __try
        {
            return provider ? provider(out, capacity, userData) : 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            AegisUniversal_LogPrintfA("[AegisRE] Component provider raised SEH 0x%08X", ::GetExceptionCode());
            return 0;
        }
    }

    bool SafeMatrixProvider(AegisREViewProjectionProvider provider, AegisREMatrix4x4* out, void* userData)
    {
        __try
        {
            return provider && provider(out, userData) != 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            AegisUniversal_LogPrintfA("[AegisRE] Matrix provider raised SEH 0x%08X", ::GetExceptionCode());
            return false;
        }
    }

    bool SafeViewportProvider(AegisREViewportProvider provider, AegisREViewport* out, void* userData)
    {
        __try
        {
            return provider && provider(out, userData) != 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            AegisUniversal_LogPrintfA("[AegisRE] Viewport provider raised SEH 0x%08X", ::GetExceptionCode());
            return false;
        }
    }

    void FillTypeInfo(const TypeRecord& record, AegisRETypeInfo& outInfo)
    {
        outInfo = {};
        CopyAnsi(outInfo.name, record.name);
        CopyAnsi(outInfo.namespaceName, record.namespaceName);
        CopyWide(outInfo.moduleName, record.moduleName);
        outInfo.address = record.address;
        outInfo.rva = record.rva;
        outInfo.flags = record.flags;
    }

    void FillHookInfo(const HookCandidate& candidate, AegisREHookCandidateInfo& outInfo)
    {
        outInfo = {};
        CopyWide(outInfo.moduleName, candidate.moduleName);
        CopyWide(outInfo.modulePath, candidate.modulePath);
        CopyAnsi(outInfo.symbolName, candidate.symbolName);
        CopyAnsi(outInfo.reason, candidate.reason);
        outInfo.address = candidate.address;
        outInfo.rva = candidate.rva;
        outInfo.ordinal = candidate.ordinal;
        outInfo.flags = candidate.flags;
    }

    void FillMetadataStats(AegisREMetadataStats& outStats)
    {
        outStats = {};
        outStats.metadataBackendReady = g_metadataBackendReady ? 1 : 0;
        outStats.tdbCandidateCount = static_cast<std::uint32_t>(g_tdbCandidates.size());
        outStats.rejectedTdbCandidateCount = static_cast<std::uint32_t>(g_rejectedTdbCandidates.size());
        outStats.tdbVersion = g_bestTdb.version;
        outStats.tdbAddress = g_bestTdb.address;
        outStats.tdbRva = g_bestTdb.rva;
        outStats.typeDefinitionCount = static_cast<std::uint32_t>(g_metadataTypes.size());
        outStats.namedTypeCount = g_metadataNamedTypeCount;
        outStats.methodDefinitionCount = static_cast<std::uint32_t>(g_metadataMethods.size());
        outStats.namedMethodCount = g_metadataNamedMethodCount;
        outStats.directMethodCount = g_metadataDirectMethodCount;
        outStats.fieldDefinitionCount = static_cast<std::uint32_t>(g_metadataFields.size());
        outStats.namedFieldCount = g_metadataNamedFieldCount;
        outStats.metadataHookCandidateCount = g_metadataHookCandidateCount;
        outStats.flags = g_bestTdb.flags;
        CopyWide(outStats.moduleName, g_bestTdb.moduleName);
        CopyWide(outStats.logPath, MetadataLogPath());

        std::wstringstream details;
        if (g_metadataBackendReady)
        {
            details << L"TDB v" << g_bestTdb.version
                    << L" " << WidenAscii(g_bestTdb.layout ? g_bestTdb.layout->name : "unknown")
                    << L"; types=" << g_metadataTypes.size()
                    << L"; methods=" << g_metadataMethods.size()
                    << L"; fields=" << g_metadataFields.size();
        }
        else
        {
            details << L"No validated TDB found; see metadata log for rejected candidates.";
        }
        CopyWide(outStats.details, details.str());
    }

    void FillMetadataTypeInfo(const MetadataTypeRecord& record, AegisREMetadataTypeInfo& outInfo)
    {
        outInfo = {};
        CopyAnsi(outInfo.name, record.name);
        CopyAnsi(outInfo.namespaceName, record.namespaceName);
        outInfo.typeIndex = record.typeIndex;
        outInfo.parentTypeIndex = record.parentTypeIndex;
        outInfo.implIndex = record.implIndex;
        outInfo.size = record.size;
        outInfo.typeFlags = record.typeFlags;
        outInfo.fqnHash = record.fqnHash;
        outInfo.typeCrc = record.typeCrc;
        outInfo.fieldCount = record.fieldCount;
        outInfo.methodCount = record.methodCount;
        outInfo.definitionAddress = record.definitionAddress;
        outInfo.runtimeTypeAddress = record.runtimeTypeAddress;
        outInfo.managedVtableAddress = record.managedVtableAddress;
        outInfo.flags = record.flags;
    }

    void FillMetadataFieldInfo(const MetadataFieldRecord& record, AegisREMetadataFieldInfo& outInfo)
    {
        outInfo = {};
        CopyAnsi(outInfo.declaringType, MetadataTypeNameByIndex(record.declaringTypeIndex));
        CopyAnsi(outInfo.name, record.name);
        CopyAnsi(outInfo.fieldType, MetadataTypeNameByIndex(record.fieldTypeIndex));
        outInfo.declaringTypeIndex = record.declaringTypeIndex;
        outInfo.fieldTypeIndex = record.fieldTypeIndex;
        outInfo.offset = record.offset;
        outInfo.flags = record.flags;
    }

    void FillMetadataMethodInfo(const MetadataMethodRecord& record, AegisREMetadataMethodInfo& outInfo)
    {
        outInfo = {};
        CopyAnsi(outInfo.declaringType, MetadataTypeNameByIndex(record.declaringTypeIndex));
        CopyAnsi(outInfo.name, record.name);
        CopyAnsi(outInfo.returnType, MetadataTypeNameByIndex(record.returnTypeIndex));
        outInfo.declaringTypeIndex = record.declaringTypeIndex;
        outInfo.returnTypeIndex = record.returnTypeIndex;
        outInfo.functionAddress = record.functionAddress;
        outInfo.functionRva = record.functionRva;
        outInfo.encodedOffset = record.encodedOffset;
        outInfo.parameterCount = record.parameterCount;
        outInfo.flags = record.flags;
    }

    void EnsureResolverLocked()
    {
        if (!g_typeScanCompleted)
            BuildTypeCatalogLocked();
        if (!g_metadataScanCompleted)
            BuildMetadataBackendLocked();
        if (!g_hookScanCompleted)
            BuildHookCandidatesLocked();
    }

    std::string ExtractJsonString(const std::string& object, const char* key)
    {
        const std::string token = std::string("\"") + key + "\"";
        std::size_t pos = object.find(token);
        if (pos == std::string::npos)
            return {};
        pos = object.find(':', pos);
        pos = object.find('"', pos);
        if (pos == std::string::npos)
            return {};
        ++pos;

        std::string result;
        for (; pos < object.size(); ++pos)
        {
            const char ch = object[pos];
            if (ch == '\\' && pos + 1 < object.size())
            {
                result.push_back(object[pos + 1]);
                ++pos;
                continue;
            }
            if (ch == '"')
                break;
            result.push_back(ch);
        }
        return result;
    }

    bool ExtractJsonFloat(const std::string& object, const char* key, float& outValue)
    {
        const std::string token = std::string("\"") + key + "\"";
        std::size_t pos = object.find(token);
        if (pos == std::string::npos)
            return false;
        pos = object.find(':', pos);
        if (pos == std::string::npos)
            return false;

        char* end = nullptr;
        const float value = std::strtof(object.c_str() + pos + 1, &end);
        if (end == object.c_str() + pos + 1 || !IsFinite(value))
            return false;
        outValue = value;
        return true;
    }

    bool ExtractJsonUInt64(const std::string& object, const char* key, std::uint64_t& outValue)
    {
        const std::string token = std::string("\"") + key + "\"";
        std::size_t pos = object.find(token);
        if (pos == std::string::npos)
            return false;
        pos = object.find(':', pos);
        if (pos == std::string::npos)
            return false;

        char* end = nullptr;
        const unsigned long long value = std::strtoull(object.c_str() + pos + 1, &end, 0);
        if (end == object.c_str() + pos + 1)
            return false;
        outValue = value;
        return true;
    }

    bool ExtractJsonInt(const std::string& object, const char* key, std::int32_t& outValue)
    {
        std::uint64_t value = 0;
        if (!ExtractJsonUInt64(object, key, value))
            return false;
        outValue = static_cast<std::int32_t>(value);
        return true;
    }
}

AEGIS_UNIVERSAL_API void AegisRE_RegisterComponentProvider(AegisREComponentProvider provider, void* userData)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_providers.componentProvider = provider;
    g_providers.componentUserData = userData;
}

AEGIS_UNIVERSAL_API void AegisRE_RegisterViewProjectionProvider(AegisREViewProjectionProvider provider, void* userData)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_providers.matrixProvider = provider;
    g_providers.matrixUserData = userData;
}

AEGIS_UNIVERSAL_API void AegisRE_RegisterViewportProvider(AegisREViewportProvider provider, void* userData)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_providers.viewportProvider = provider;
    g_providers.viewportUserData = userData;
}

AEGIS_UNIVERSAL_API int AegisRE_UpdateProviders()
{
    ProviderState providers = {};
    {
        std::unique_lock<std::mutex> lock(g_mutex, std::try_to_lock);
        if (!lock.owns_lock())
            return 0;
        providers = g_providers;
    }

    std::vector<AegisREComponentSnapshot> components;
    components.resize(kMaxComponents);

    LARGE_INTEGER start = NowCounter();
    const std::uint32_t componentCount = SafeComponentProvider(
        providers.componentProvider,
        components.data(),
        static_cast<std::uint32_t>(components.size()),
        providers.componentUserData);
    LARGE_INTEGER afterComponents = NowCounter();
    components.resize(std::min<std::uint32_t>(componentCount, kMaxComponents));

    AegisREMatrix4x4 matrix = {};
    const bool hasMatrix = SafeMatrixProvider(providers.matrixProvider, &matrix, providers.matrixUserData) && IsValidMatrix(matrix);
    LARGE_INTEGER afterMatrix = NowCounter();

    AegisREViewport viewport = {};
    bool hasViewport = SafeViewportProvider(providers.viewportProvider, &viewport, providers.viewportUserData) && IsValidViewport(viewport);
    if (!hasViewport)
        hasViewport = DefaultViewport(viewport);
    LARGE_INTEGER afterViewport = NowCounter();

    std::unique_lock<std::mutex> lock(g_mutex, std::try_to_lock);
    if (!lock.owns_lock())
        return 0;
    if (providers.componentProvider)
        g_components = std::move(components);
    if (hasMatrix)
    {
        g_viewProjection = matrix;
        g_hasMatrix = true;
    }
    if (hasViewport)
    {
        g_viewport = viewport;
        g_hasViewport = true;
    }
    if (!providers.componentProvider)
        WalkInternalWorldLocked(false);

    ++g_timing.frameId;
    g_timing.componentProviderMs = ElapsedMs(start, afterComponents);
    g_timing.matrixProviderMs = ElapsedMs(afterComponents, afterMatrix);
    g_timing.viewportProviderMs = ElapsedMs(afterMatrix, afterViewport);
    RebuildProjectionStatsLocked();
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_SubmitComponentSnapshots(const AegisREComponentSnapshot* components, std::uint32_t count)
{
    if (!components && count)
        return 0;

    std::lock_guard<std::mutex> lock(g_mutex);
    const std::uint32_t clamped = std::min<std::uint32_t>(count, kMaxComponents);
    g_components.assign(components, components + clamped);
    for (AegisREComponentSnapshot& component : g_components)
        component.flags |= AegisREComponent_LiveSnapshot;
    RebuildProjectionStatsLocked();
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_SubmitViewProjection(const AegisREMatrix4x4* matrix)
{
    if (!matrix || !IsValidMatrix(*matrix))
        return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    g_viewProjection = *matrix;
    g_hasMatrix = true;
    RebuildProjectionStatsLocked();
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_SubmitViewport(const AegisREViewport* viewport)
{
    if (!viewport || !IsValidViewport(*viewport))
        return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    g_viewport = *viewport;
    g_hasViewport = true;
    RebuildProjectionStatsLocked();
    return 1;
}

AEGIS_UNIVERSAL_API std::uint32_t AegisRE_GetComponentCount()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return static_cast<std::uint32_t>(g_components.size());
}

AEGIS_UNIVERSAL_API int AegisRE_GetComponentSnapshot(std::uint32_t index, AegisREComponentSnapshot* outComponent)
{
    if (!outComponent)
        return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (index >= g_components.size())
        return 0;
    *outComponent = g_components[index];
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_GetAdapterTiming(AegisREAdapterTiming* outTiming)
{
    if (!outTiming)
        return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    *outTiming = g_timing;
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_GetCapabilityInfo(AegisRECapabilityInfo* outInfo)
{
    if (!outInfo)
        return 0;

    std::lock_guard<std::mutex> lock(g_mutex);
    EnsureResolverLocked();

    *outInfo = {};
    outInfo->reDetected = AegisUniversal_IsEngineDetected();
    outInfo->viaTypeStringsFound = g_viaTypeCount > 0 ? 1 : 0;
    outInfo->appTypeStringsFound = g_appTypeCount > 0 ? 1 : 0;
    outInfo->componentProviderRegistered = g_providers.componentProvider ? 1 : 0;
    outInfo->viewProjectionProviderRegistered = g_providers.matrixProvider ? 1 : 0;
    outInfo->viewportProviderRegistered = g_providers.viewportProvider ? 1 : 0;
    outInfo->viewportValid = g_hasViewport && IsValidViewport(g_viewport) ? 1 : 0;
    outInfo->matrixValid = g_hasMatrix && IsValidMatrix(g_viewProjection) ? 1 : 0;
    outInfo->snapshotReady = !g_components.empty() ? 1 : 0;
    outInfo->metadataBackendReady = g_metadataBackendReady ? 1 : 0;
    outInfo->metadataTdbVersion = g_bestTdb.version;
    outInfo->metadataTypeCount = static_cast<std::uint32_t>(g_metadataTypes.size());
    outInfo->metadataFieldCount = static_cast<std::uint32_t>(g_metadataFields.size());
    outInfo->metadataMethodCount = static_cast<std::uint32_t>(g_metadataMethods.size());
    outInfo->internalWorldWalkerEnabled = g_worldWalkerEnabled ? 1 : 0;
    outInfo->internalWorldWalkerReady = g_worldStats.ready;
    outInfo->internalWorldRootCount = g_worldStats.rootCount;
    outInfo->internalWorldObjectCount = g_worldStats.visitedObjectCount;
    outInfo->internalWorldComponentCount = g_worldStats.componentCount;
    outInfo->typeCount = static_cast<std::uint32_t>(g_types.size());
    outInfo->hookCandidateCount = static_cast<std::uint32_t>(g_hookCandidates.size());
    CopyWide(outInfo->rendererBackend, DetectRendererBackend());

    if (!g_components.empty())
    {
        AegisREProjectedPoint projected = {};
        outInfo->w2sProjectionWorking = ProjectCurrentLocked(g_components.front().origin, projected) ? 1 : 0;
    }

    std::wstringstream details;
    details << L"types via=" << g_viaTypeCount << L" app=" << g_appTypeCount
            << L"; hooks=" << g_hookCandidates.size()
            << L"; live components=" << g_components.size()
            << L"; metadata=" << (g_metadataBackendReady ? L"TDB" : L"waiting");
    if (g_metadataBackendReady)
        details << L" v" << g_bestTdb.version << L" methods=" << g_metadataMethods.size() << L" fields=" << g_metadataFields.size();
    if (!g_providers.componentProvider)
        details << L"; internal walker roots=" << g_worldStats.rootCount << L" objects=" << g_worldStats.visitedObjectCount;
    CopyWide(outInfo->details, details.str());
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_ProjectWorldToScreen(const AegisREVec3* world, AegisREProjectedPoint* outPoint)
{
    if (!world || !outPoint)
        return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    *outPoint = {};
    return ProjectCurrentLocked(*world, *outPoint) ? 1 : 0;
}

AEGIS_UNIVERSAL_API int AegisRE_WriteSnapshotJson(const wchar_t* path)
{
    const std::wstring outPath = path && path[0] ? path : ProfileSiblingPath(L"_Components.json");
    std::vector<AegisREComponentSnapshot> components;
    AegisREAdapterTiming timing = {};
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        components = g_components;
        timing = g_timing;
    }

    std::ofstream out(std::filesystem::path(outPath), std::ios::binary | std::ios::trunc);
    if (!out)
        return 0;

    out << "{\n";
    out << "  \"format\": \"AegisREComponentSnapshot\",\n";
    out << "  \"version\": 1,\n";
    out << "  \"frameId\": " << timing.frameId << ",\n";
    out << "  \"components\": [\n";
    for (std::size_t index = 0; index < components.size(); ++index)
    {
        const AegisREComponentSnapshot& c = components[index];
        out << "    { \"id\": " << c.id
            << ", \"address\": " << c.address
            << ", \"addressHex\": \"" << PointerHex(c.address)
            << "\", \"name\": \"" << JsonEscape(c.name)
            << "\", \"typeName\": \"" << JsonEscape(c.typeName)
            << "\", \"category\": \"" << JsonEscape(c.category)
            << "\", \"path\": \"" << JsonEscape(c.path)
            << "\", \"origin\": [" << c.origin.x << ", " << c.origin.y << ", " << c.origin.z
            << "], \"boundsMin\": [" << c.boundsMin.x << ", " << c.boundsMin.y << ", " << c.boundsMin.z
            << "], \"boundsMax\": [" << c.boundsMax.x << ", " << c.boundsMax.y << ", " << c.boundsMax.z
            << "], \"group\": " << c.group
            << ", \"visible\": " << c.visible
            << ", \"flags\": " << c.flags << " }";
        if (index + 1 < components.size())
            out << ",";
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_LoadSnapshotJson(const wchar_t* path)
{
    if (!path || !path[0])
        return 0;

    std::ifstream in(std::filesystem::path(path), std::ios::binary);
    if (!in)
        return 0;

    const std::string json((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::vector<AegisREComponentSnapshot> loaded;
    std::size_t pos = json.find('{');
    while (pos != std::string::npos && loaded.size() < kMaxComponents)
    {
        const std::size_t end = json.find('}', pos);
        if (end == std::string::npos)
            break;

        const std::string object = json.substr(pos, end - pos + 1);
        if (object.find("\"typeName\"") != std::string::npos)
        {
            AegisREComponentSnapshot c = {};
            std::uint64_t value = 0;
            if (ExtractJsonUInt64(object, "id", value))
                c.id = value;
            if (ExtractJsonUInt64(object, "address", value))
                c.address = static_cast<std::uintptr_t>(value);
            CopyAnsi(c.name, ExtractJsonString(object, "name"));
            CopyAnsi(c.typeName, ExtractJsonString(object, "typeName"));
            CopyAnsi(c.category, ExtractJsonString(object, "category"));
            CopyAnsi(c.path, ExtractJsonString(object, "path"));
            ExtractJsonInt(object, "group", c.group);
            loaded.push_back(c);
        }
        pos = json.find('{', end + 1);
    }

    std::lock_guard<std::mutex> lock(g_mutex);
    g_components = std::move(loaded);
    RebuildProjectionStatsLocked();
    return 1;
}

AEGIS_UNIVERSAL_API void AegisRE_PrintCurrentComponents()
{
    std::vector<AegisREComponentSnapshot> components;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        components = g_components;
    }

    AegisUniversal_LogPrintfA("[AegisRE] Components: %u", static_cast<unsigned>(components.size()));
    for (std::size_t index = 0; index < components.size() && index < 256; ++index)
    {
        const auto& c = components[index];
        AegisUniversal_LogPrintfA("[AegisRE] #%u 0x%llX %s <%s> %s pos=(%.2f, %.2f, %.2f) flags=0x%X",
            static_cast<unsigned>(index),
            static_cast<unsigned long long>(c.address),
            c.name,
            c.typeName,
            c.category,
            c.origin.x,
            c.origin.y,
            c.origin.z,
            c.flags);
    }
}

AEGIS_UNIVERSAL_API int AegisRE_RefreshResolver()
{
    ResolverBusyScope busy("Resolver refresh");
    if (!busy.active)
        return 0;

    AegisUniversal_Refresh();
    std::lock_guard<std::mutex> lock(g_mutex);
    g_typeScanCompleted = false;
    g_hookScanCompleted = false;
    g_consoleScanCompleted = false;
    g_metadataScanCompleted = false;
    g_worldRootsScanned = false;
    BuildTypeCatalogLocked();
    BuildMetadataBackendLocked();
    BuildHookCandidatesLocked();
    BuildConsoleCandidatesLocked();
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_IsResolverBusy()
{
    return (g_resolverBusy.load() || !g_resolverReadyOnce.load()) ? 1 : 0;
}

AEGIS_UNIVERSAL_API int AegisRE_ScanSdkTypes()
{
    ResolverBusyScope busy("Type SDK scan");
    if (!busy.active)
        return 0;

    std::lock_guard<std::mutex> lock(g_mutex);
    g_typeScanCompleted = false;
    BuildTypeCatalogLocked();
    return g_types.empty() ? 0 : 1;
}

AEGIS_UNIVERSAL_API std::uint32_t AegisRE_GetTypeCount()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_typeScanCompleted)
        BuildTypeCatalogLocked();
    return static_cast<std::uint32_t>(g_types.size());
}

AEGIS_UNIVERSAL_API int AegisRE_GetTypeInfo(std::uint32_t index, AegisRETypeInfo* outInfo)
{
    if (!outInfo)
        return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_typeScanCompleted)
        BuildTypeCatalogLocked();
    if (index >= g_types.size())
        return 0;
    FillTypeInfo(g_types[index], *outInfo);
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_WriteTypeSdkJson(const wchar_t* path)
{
    const std::wstring outPath = path && path[0] ? path : ProfileSiblingPath(L"_RETypeSDK.json");
    std::vector<TypeRecord> types;
    std::uint32_t viaCount = 0;
    std::uint32_t appCount = 0;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_typeScanCompleted)
            BuildTypeCatalogLocked();
        types = g_types;
        viaCount = g_viaTypeCount;
        appCount = g_appTypeCount;
    }

    std::ofstream out(std::filesystem::path(outPath), std::ios::binary | std::ios::trunc);
    if (!out)
        return 0;

    out << "{\n";
    out << "  \"format\": \"AegisRETypeSdk\",\n";
    out << "  \"version\": 1,\n";
    out << "  \"viaTypeCount\": " << viaCount << ",\n";
    out << "  \"appTypeCount\": " << appCount << ",\n";
    out << "  \"typeCount\": " << types.size() << ",\n";
    out << "  \"types\": [\n";
    for (std::size_t index = 0; index < types.size(); ++index)
    {
        const TypeRecord& type = types[index];
        out << "    { \"name\": \"" << JsonEscape(type.name)
            << "\", \"namespace\": \"" << JsonEscape(type.namespaceName)
            << "\", \"module\": \"" << JsonEscapeWide(type.moduleName)
            << "\", \"address\": " << type.address
            << ", \"addressHex\": \"" << PointerHex(type.address)
            << "\", \"rva\": " << type.rva
            << ", \"rvaHex\": \"" << PointerHex(type.rva)
            << "\", \"flags\": " << type.flags << " }";
        if (index + 1 < types.size())
            out << ",";
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_WriteTypeSdkHeader(const wchar_t* path)
{
    const std::wstring outPath = path && path[0] ? path : ProfileSiblingPath(L"_RETypeSDK.h");
    std::vector<TypeRecord> types;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_typeScanCompleted)
            BuildTypeCatalogLocked();
        types = g_types;
    }

    std::ofstream out(std::filesystem::path(outPath), std::ios::binary | std::ios::trunc);
    if (!out)
        return 0;

    out << "#pragma once\n\n";
    out << "// Generated by Aegis RE Engine Universal.\n";
    out << "// Entries are discovered from live PE image metadata strings; no game offsets are baked in.\n\n";
    out << "#include <stdint.h>\n\n";
    out << "typedef struct AegisREGeneratedType\n";
    out << "{\n";
    out << "    const char* name;\n";
    out << "    const char* moduleName;\n";
    out << "    uint64_t rva;\n";
    out << "    uint32_t flags;\n";
    out << "} AegisREGeneratedType;\n\n";
    out << "static const AegisREGeneratedType kAegisREGeneratedTypes[] = {\n";
    for (const TypeRecord& type : types)
    {
        out << "    { \"" << JsonEscape(type.name)
            << "\", \"" << JsonEscapeWide(type.moduleName)
            << "\", UINT64_C(" << type.rva << "), "
            << type.flags << "u },\n";
    }
    out << "};\n\n";
    out << "static const unsigned int kAegisREGeneratedTypeCount = "
        << static_cast<unsigned int>(types.size()) << "u;\n";
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_WriteTypeSdkCsv(const wchar_t* path)
{
    const std::wstring outPath = path && path[0] ? path : ProfileSiblingPath(L"_RETypeSDK.csv");
    std::vector<TypeRecord> types;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_typeScanCompleted)
            BuildTypeCatalogLocked();
        types = g_types;
    }

    std::ofstream out(std::filesystem::path(outPath), std::ios::binary | std::ios::trunc);
    if (!out)
        return 0;

    out << "Name,Namespace,Module,RVA,Address,Flags,Category\n";
    for (const TypeRecord& type : types)
    {
        out << CsvEscape(type.name) << ","
            << CsvEscape(type.namespaceName) << ","
            << CsvEscape(NarrowWide(type.moduleName)) << ","
            << PointerHex(type.rva) << ","
            << PointerHex(type.address) << ","
            << PointerHex(type.flags) << ","
            << CategoryForTypeFlags(type.flags) << "\n";
    }
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_WriteResolverReport(const wchar_t* path)
{
    const std::wstring outPath = path && path[0] ? path : ProfileSiblingPath(L"_Resolver.json");
    AegisRECapabilityInfo capability = {};
    AegisRE_GetCapabilityInfo(&capability);
    AegisREMetadataStats metadata = {};
    AegisRE_GetMetadataStats(&metadata);

    std::vector<HookCandidate> hooks;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        EnsureResolverLocked();
        hooks = g_hookCandidates;
    }

    std::ofstream out(std::filesystem::path(outPath), std::ios::binary | std::ios::trunc);
    if (!out)
        return 0;

    out << "{\n";
    out << "  \"format\": \"AegisREResolver\",\n";
    out << "  \"version\": 1,\n";
    out << "  \"reDetected\": " << (capability.reDetected ? "true" : "false") << ",\n";
    out << "  \"rendererBackend\": \"" << JsonEscapeWide(capability.rendererBackend) << "\",\n";
    out << "  \"details\": \"" << JsonEscapeWide(capability.details) << "\",\n";
    out << "  \"notes\": [\n";
    out << "    \"RE Engine retail games are usually monolithic EXEs; engine APIs are not expected to be exported by a separate engine DLL.\",\n";
    out << "    \"PE exports are listed directly; validated RE TDB method pointers are also surfaced as metadata-backed hook candidates when the current title stores direct function pointers.\",\n";
    out << "    \"The internal world walker uses validated TDB type definitions, singleton getter candidates, and module/global object pointers; all traversal is bounded and pointer-validated.\"\n";
    out << "  ],\n";
    out << "  \"metadataBackend\": {\n";
    out << "    \"ready\": " << (metadata.metadataBackendReady ? "true" : "false") << ",\n";
    out << "    \"tdbVersion\": " << metadata.tdbVersion << ",\n";
    out << "    \"tdbAddress\": " << metadata.tdbAddress << ",\n";
    out << "    \"tdbAddressHex\": \"" << PointerHex(metadata.tdbAddress) << "\",\n";
    out << "    \"tdbRvaHex\": \"" << PointerHex(metadata.tdbRva) << "\",\n";
    out << "    \"module\": \"" << JsonEscapeWide(metadata.moduleName) << "\",\n";
    out << "    \"types\": " << metadata.typeDefinitionCount << ",\n";
    out << "    \"namedTypes\": " << metadata.namedTypeCount << ",\n";
    out << "    \"fields\": " << metadata.fieldDefinitionCount << ",\n";
    out << "    \"namedFields\": " << metadata.namedFieldCount << ",\n";
    out << "    \"methods\": " << metadata.methodDefinitionCount << ",\n";
    out << "    \"namedMethods\": " << metadata.namedMethodCount << ",\n";
    out << "    \"directMethods\": " << metadata.directMethodCount << ",\n";
    out << "    \"metadataHookCandidates\": " << metadata.metadataHookCandidateCount << ",\n";
    out << "    \"logPath\": \"" << JsonEscapeWide(metadata.logPath) << "\",\n";
    out << "    \"details\": \"" << JsonEscapeWide(metadata.details) << "\"\n";
    out << "  },\n";
    out << "  \"internalWorldWalker\": {\n";
    out << "    \"enabled\": " << (g_worldWalkerEnabled ? "true" : "false") << ",\n";
    out << "    \"ready\": " << (g_worldStats.ready ? "true" : "false") << ",\n";
    out << "    \"scanId\": " << g_worldStats.scanId << ",\n";
    out << "    \"lastScanMs\": " << g_worldStats.lastScanMs << ",\n";
    out << "    \"roots\": " << g_worldStats.rootCount << ",\n";
    out << "    \"singletonRoots\": " << g_worldStats.singletonRootCount << ",\n";
    out << "    \"globalPointerRoots\": " << g_worldStats.globalPointerRootCount << ",\n";
    out << "    \"visitedObjects\": " << g_worldStats.visitedObjectCount << ",\n";
    out << "    \"components\": " << g_worldStats.componentCount << ",\n";
    out << "    \"fieldReads\": " << g_worldStats.fieldReadCount << ",\n";
    out << "    \"flags\": " << g_worldStats.flags << ",\n";
    out << "    \"details\": \"" << JsonEscapeWide(g_worldStats.details) << "\"\n";
    out << "  },\n";
    out << "  \"hookCandidates\": [\n";
    for (std::size_t index = 0; index < hooks.size(); ++index)
    {
        const HookCandidate& hook = hooks[index];
        out << "    { \"module\": \"" << JsonEscapeWide(hook.moduleName)
            << "\", \"symbol\": \"" << JsonEscape(hook.symbolName)
            << "\", \"reason\": \"" << JsonEscape(hook.reason)
            << "\", \"address\": " << hook.address
            << ", \"addressHex\": \"" << PointerHex(hook.address)
            << "\", \"rva\": " << hook.rva
            << ", \"rvaHex\": \"" << PointerHex(hook.rva)
            << "\", \"ordinal\": " << hook.ordinal
            << ", \"flags\": " << hook.flags << " }";
        if (index + 1 < hooks.size())
            out << ",";
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_ScanMetadataBackend()
{
    ResolverBusyScope busy("Metadata backend scan");
    if (!busy.active)
        return 0;

    std::lock_guard<std::mutex> lock(g_mutex);
    g_metadataScanCompleted = false;
    g_hookScanCompleted = false;
    g_consoleScanCompleted = false;
    BuildMetadataBackendLocked();
    return g_metadataBackendReady ? 1 : 0;
}

AEGIS_UNIVERSAL_API int AegisRE_GetMetadataStats(AegisREMetadataStats* outStats)
{
    if (!outStats)
        return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_metadataScanCompleted)
        BuildMetadataBackendLocked();
    FillMetadataStats(*outStats);
    return 1;
}

AEGIS_UNIVERSAL_API std::uint32_t AegisRE_GetMetadataTypeCount()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_metadataScanCompleted)
        BuildMetadataBackendLocked();
    return static_cast<std::uint32_t>(g_metadataTypes.size());
}

AEGIS_UNIVERSAL_API int AegisRE_GetMetadataTypeInfo(std::uint32_t index, AegisREMetadataTypeInfo* outInfo)
{
    if (!outInfo)
        return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_metadataScanCompleted)
        BuildMetadataBackendLocked();
    if (index >= g_metadataTypes.size())
        return 0;
    FillMetadataTypeInfo(g_metadataTypes[index], *outInfo);
    return 1;
}

AEGIS_UNIVERSAL_API std::uint32_t AegisRE_GetMetadataFieldCount()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_metadataScanCompleted)
        BuildMetadataBackendLocked();
    return static_cast<std::uint32_t>(g_metadataFields.size());
}

AEGIS_UNIVERSAL_API int AegisRE_GetMetadataFieldInfo(std::uint32_t index, AegisREMetadataFieldInfo* outInfo)
{
    if (!outInfo)
        return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_metadataScanCompleted)
        BuildMetadataBackendLocked();
    if (index >= g_metadataFields.size())
        return 0;
    FillMetadataFieldInfo(g_metadataFields[index], *outInfo);
    return 1;
}

AEGIS_UNIVERSAL_API std::uint32_t AegisRE_GetMetadataMethodCount()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_metadataScanCompleted)
        BuildMetadataBackendLocked();
    return static_cast<std::uint32_t>(g_metadataMethods.size());
}

AEGIS_UNIVERSAL_API int AegisRE_GetMetadataMethodInfo(std::uint32_t index, AegisREMetadataMethodInfo* outInfo)
{
    if (!outInfo)
        return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_metadataScanCompleted)
        BuildMetadataBackendLocked();
    if (index >= g_metadataMethods.size())
        return 0;
    FillMetadataMethodInfo(g_metadataMethods[index], *outInfo);
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_WriteMetadataJson(const wchar_t* path)
{
    const std::wstring outPath = path && path[0] ? path : ProfileSiblingPath(L"_Metadata.json");
    std::ofstream out(std::filesystem::path(outPath), std::ios::binary | std::ios::trunc);
    if (!out)
        return 0;

    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_metadataScanCompleted)
        BuildMetadataBackendLocked();

    AegisREMetadataStats stats = {};
    FillMetadataStats(stats);

    out << "{\n";
    out << "  \"format\": \"AegisREMetadata\",\n";
    out << "  \"version\": 1,\n";
    out << "  \"backendReady\": " << (stats.metadataBackendReady ? "true" : "false") << ",\n";
    out << "  \"tdbVersion\": " << stats.tdbVersion << ",\n";
    out << "  \"tdbAddress\": " << stats.tdbAddress << ",\n";
    out << "  \"tdbAddressHex\": \"" << PointerHex(stats.tdbAddress) << "\",\n";
    out << "  \"tdbRvaHex\": \"" << PointerHex(stats.tdbRva) << "\",\n";
    out << "  \"module\": \"" << JsonEscapeWide(stats.moduleName) << "\",\n";
    out << "  \"layout\": \"" << JsonEscape(g_bestTdb.layout ? g_bestTdb.layout->name : "") << "\",\n";
    out << "  \"logPath\": \"" << JsonEscapeWide(stats.logPath) << "\",\n";
    out << "  \"counts\": {\n";
    out << "    \"acceptedTdbCandidates\": " << stats.tdbCandidateCount << ",\n";
    out << "    \"rejectedTdbCandidates\": " << stats.rejectedTdbCandidateCount << ",\n";
    out << "    \"types\": " << stats.typeDefinitionCount << ",\n";
    out << "    \"namedTypes\": " << stats.namedTypeCount << ",\n";
    out << "    \"fields\": " << stats.fieldDefinitionCount << ",\n";
    out << "    \"namedFields\": " << stats.namedFieldCount << ",\n";
    out << "    \"methods\": " << stats.methodDefinitionCount << ",\n";
    out << "    \"namedMethods\": " << stats.namedMethodCount << ",\n";
    out << "    \"directMethods\": " << stats.directMethodCount << ",\n";
    out << "    \"metadataHookCandidates\": " << stats.metadataHookCandidateCount << "\n";
    out << "  },\n";

    out << "  \"tdbCandidates\": [\n";
    for (std::size_t index = 0; index < g_tdbCandidates.size(); ++index)
    {
        const TdbCandidate& candidate = g_tdbCandidates[index];
        out << "    { \"addressHex\": \"" << PointerHex(candidate.address)
            << "\", \"rvaHex\": \"" << PointerHex(candidate.rva)
            << "\", \"module\": \"" << JsonEscapeWide(candidate.moduleName)
            << "\", \"version\": " << candidate.version
            << ", \"layout\": \"" << JsonEscape(candidate.layout ? candidate.layout->name : "")
            << "\", \"score\": " << candidate.score
            << ", \"namedTypeSamples\": " << candidate.namedTypeSamples
            << ", \"types\": " << candidate.numTypes
            << ", \"methods\": " << candidate.numMethods
            << ", \"fields\": " << candidate.numFields
            << ", \"stringPoolHex\": \"" << PointerHex(candidate.stringPool)
            << "\" }";
        if (index + 1 < g_tdbCandidates.size())
            out << ",";
        out << "\n";
    }
    out << "  ],\n";

    out << "  \"rejectedTdbCandidates\": [\n";
    for (std::size_t index = 0; index < g_rejectedTdbCandidates.size(); ++index)
    {
        const TdbCandidate& candidate = g_rejectedTdbCandidates[index];
        out << "    { \"addressHex\": \"" << PointerHex(candidate.address)
            << "\", \"rvaHex\": \"" << PointerHex(candidate.rva)
            << "\", \"module\": \"" << JsonEscapeWide(candidate.moduleName)
            << "\", \"version\": " << candidate.version
            << ", \"layout\": \"" << JsonEscape(candidate.layout ? candidate.layout->name : "")
            << "\", \"reason\": \"" << JsonEscape(candidate.reason) << "\" }";
        if (index + 1 < g_rejectedTdbCandidates.size())
            out << ",";
        out << "\n";
    }
    out << "  ],\n";

    out << "  \"types\": [\n";
    for (std::size_t index = 0; index < g_metadataTypes.size(); ++index)
    {
        const MetadataTypeRecord& type = g_metadataTypes[index];
        out << "    { \"index\": " << type.typeIndex
            << ", \"name\": \"" << JsonEscape(type.name)
            << "\", \"namespace\": \"" << JsonEscape(type.namespaceName)
            << "\", \"parentTypeIndex\": " << type.parentTypeIndex
            << ", \"implIndex\": " << type.implIndex
            << ", \"size\": " << type.size
            << ", \"typeFlags\": " << type.typeFlags
            << ", \"fqnHashHex\": \"" << PointerHex(type.fqnHash)
            << "\", \"typeCrcHex\": \"" << PointerHex(type.typeCrc)
            << "\", \"methodStart\": " << type.methodStart
            << ", \"methodCount\": " << type.methodCount
            << ", \"fieldStart\": " << type.fieldStart
            << ", \"fieldCount\": " << type.fieldCount
            << ", \"definitionAddressHex\": \"" << PointerHex(type.definitionAddress)
            << "\", \"runtimeTypeAddressHex\": \"" << PointerHex(type.runtimeTypeAddress)
            << "\", \"managedVtableAddressHex\": \"" << PointerHex(type.managedVtableAddress)
            << "\", \"fieldPtrOffset\": " << type.fieldPtrOffset
            << ", \"flags\": " << type.flags << " }";
        if (index + 1 < g_metadataTypes.size())
            out << ",";
        out << "\n";
    }
    out << "  ],\n";

    out << "  \"fields\": [\n";
    for (std::size_t index = 0; index < g_metadataFields.size(); ++index)
    {
        const MetadataFieldRecord& field = g_metadataFields[index];
        out << "    { \"declaringTypeIndex\": " << field.declaringTypeIndex
            << ", \"declaringType\": \"" << JsonEscape(MetadataTypeNameByIndex(field.declaringTypeIndex))
            << "\", \"name\": \"" << JsonEscape(field.name)
            << "\", \"fieldTypeIndex\": " << field.fieldTypeIndex
            << ", \"fieldType\": \"" << JsonEscape(MetadataTypeNameByIndex(field.fieldTypeIndex))
            << "\", \"offset\": " << field.offset
            << ", \"offsetHex\": \"" << PointerHex(field.offset)
            << "\", \"flags\": " << field.flags << " }";
        if (index + 1 < g_metadataFields.size())
            out << ",";
        out << "\n";
    }
    out << "  ],\n";

    out << "  \"methods\": [\n";
    for (std::size_t index = 0; index < g_metadataMethods.size(); ++index)
    {
        const MetadataMethodRecord& method = g_metadataMethods[index];
        out << "    { \"declaringTypeIndex\": " << method.declaringTypeIndex
            << ", \"declaringType\": \"" << JsonEscape(MetadataTypeNameByIndex(method.declaringTypeIndex))
            << "\", \"name\": \"" << JsonEscape(method.name)
            << "\", \"returnTypeIndex\": " << method.returnTypeIndex
            << ", \"returnType\": \"" << JsonEscape(MetadataTypeNameByIndex(method.returnTypeIndex))
            << "\", \"functionAddress\": " << method.functionAddress
            << ", \"functionAddressHex\": \"" << PointerHex(method.functionAddress)
            << "\", \"functionRvaHex\": \"" << PointerHex(method.functionRva)
            << "\", \"encodedOffset\": " << method.encodedOffset
            << ", \"parameterCount\": " << method.parameterCount
            << ", \"flags\": " << method.flags << " }";
        if (index + 1 < g_metadataMethods.size())
            out << ",";
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";

    LogMetadata("Metadata JSON written: %s", NarrowWide(outPath).c_str());
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_WriteMetadataCsv(const wchar_t* path)
{
    const std::wstring outPath = path && path[0] ? path : ProfileSiblingPath(L"_Metadata.csv");
    std::ofstream out(std::filesystem::path(outPath), std::ios::binary | std::ios::trunc);
    if (!out)
        return 0;

    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_metadataScanCompleted)
        BuildMetadataBackendLocked();

    out << "Kind,Index,Owner,Name,Type,Offset,Address,RVA,Flags,Extra\n";
    for (const MetadataTypeRecord& type : g_metadataTypes)
    {
        out << "Type,"
            << type.typeIndex << ",,"
            << CsvEscape(type.name) << ",,"
            << type.size << ","
            << PointerHex(type.definitionAddress) << ",,"
            << PointerHex(type.flags) << ","
            << CsvEscape(std::string("parent=") + std::to_string(type.parentTypeIndex) + "; methods=" + std::to_string(type.methodCount) + "; fields=" + std::to_string(type.fieldCount))
            << "\n";
    }

    for (const MetadataFieldRecord& field : g_metadataFields)
    {
        out << "Field,"
            << field.declaringTypeIndex << ","
            << CsvEscape(MetadataTypeNameByIndex(field.declaringTypeIndex)) << ","
            << CsvEscape(field.name) << ","
            << CsvEscape(MetadataTypeNameByIndex(field.fieldTypeIndex)) << ","
            << PointerHex(field.offset) << ",,,"
            << PointerHex(field.flags) << ",\n";
    }

    for (const MetadataMethodRecord& method : g_metadataMethods)
    {
        out << "Method,"
            << method.declaringTypeIndex << ","
            << CsvEscape(MetadataTypeNameByIndex(method.declaringTypeIndex)) << ","
            << CsvEscape(method.name) << ","
            << CsvEscape(MetadataTypeNameByIndex(method.returnTypeIndex)) << ",,"
            << PointerHex(method.functionAddress) << ","
            << PointerHex(method.functionRva) << ","
            << PointerHex(method.flags) << ","
            << CsvEscape(std::string("params=") + std::to_string(method.parameterCount) + "; encoded=" + std::to_string(method.encodedOffset))
            << "\n";
    }

    LogMetadata("Metadata CSV written: %s", NarrowWide(outPath).c_str());
    return 1;
}

AEGIS_UNIVERSAL_API void AegisRE_SetInternalWorldWalkerEnabled(std::int32_t enabled)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_worldWalkerEnabled = enabled != 0;
    if (!g_worldWalkerEnabled)
    {
        g_worldStats.enabled = 0;
        g_worldStats.ready = 0;
    }
    LogMetadata("Internal world walker %s", g_worldWalkerEnabled ? "enabled" : "disabled");
}

AEGIS_UNIVERSAL_API int AegisRE_RunInternalWorldScan()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_worldRootsScanned = false;
    WalkInternalWorldLocked(true);
    return g_worldStats.ready ? 1 : 0;
}

AEGIS_UNIVERSAL_API int AegisRE_GetWorldWalkerStats(AegisREWorldWalkerStats* outStats)
{
    if (!outStats)
        return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    *outStats = g_worldStats;
    outStats->enabled = g_worldWalkerEnabled ? 1 : 0;
    outStats->rootCount = static_cast<std::uint32_t>(g_worldRoots.size());
    if (!outStats->details[0])
        CopyWide(outStats->details, g_worldWalkerEnabled ? L"Internal world walker has not run yet." : L"Internal world walker disabled.");
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_WriteWorldWalkerReport(const wchar_t* path)
{
    const std::wstring outPath = path && path[0] ? path : ProfileSiblingPath(L"_WorldWalker.json");
    std::ofstream out(std::filesystem::path(outPath), std::ios::binary | std::ios::trunc);
    if (!out)
        return 0;

    std::lock_guard<std::mutex> lock(g_mutex);
    std::vector<AegisREComponentSnapshot> liveComponents;
    liveComponents.reserve(g_components.size());
    for (const AegisREComponentSnapshot& component : g_components)
    {
        if (component.flags & AegisREComponent_LiveSnapshot)
            liveComponents.push_back(component);
    }

    out << "{\n";
    out << "  \"format\": \"AegisREWorldWalker\",\n";
    out << "  \"version\": 1,\n";
    out << "  \"enabled\": " << (g_worldWalkerEnabled ? "true" : "false") << ",\n";
    out << "  \"ready\": " << (g_worldStats.ready ? "true" : "false") << ",\n";
    out << "  \"scanId\": " << g_worldStats.scanId << ",\n";
    out << "  \"lastScanMs\": " << g_worldStats.lastScanMs << ",\n";
    out << "  \"flags\": " << g_worldStats.flags << ",\n";
    out << "  \"details\": \"" << JsonEscapeWide(g_worldStats.details) << "\",\n";
    out << "  \"counts\": {\n";
    out << "    \"roots\": " << g_worldRoots.size() << ",\n";
    out << "    \"singletonRoots\": " << g_worldStats.singletonRootCount << ",\n";
    out << "    \"globalPointerRoots\": " << g_worldStats.globalPointerRootCount << ",\n";
    out << "    \"rejectedRoots\": " << g_worldStats.rejectedRootCount << ",\n";
    out << "    \"visitedObjects\": " << g_worldStats.visitedObjectCount << ",\n";
    out << "    \"components\": " << g_worldStats.componentCount << ",\n";
    out << "    \"fieldReads\": " << g_worldStats.fieldReadCount << ",\n";
    out << "    \"maxDepth\": " << g_worldStats.maxDepthReached << "\n";
    out << "  },\n";
    out << "  \"roots\": [\n";
    for (std::size_t index = 0; index < g_worldRoots.size(); ++index)
    {
        const WorldRootCandidate& root = g_worldRoots[index];
        out << "    { \"objectAddress\": " << root.objectAddress
            << ", \"objectAddressHex\": \"" << PointerHex(root.objectAddress)
            << "\", \"sourceAddressHex\": \"" << PointerHex(root.sourceAddress)
            << "\", \"typeIndex\": " << root.typeIndex
            << ", \"typeName\": \"" << JsonEscape(root.typeName)
            << "\", \"reason\": \"" << JsonEscape(root.reason)
            << "\", \"score\": " << root.score << " }";
        if (index + 1 < g_worldRoots.size())
            out << ",";
        out << "\n";
    }
    out << "  ],\n";
    out << "  \"components\": [\n";
    for (std::size_t index = 0; index < liveComponents.size(); ++index)
    {
        const AegisREComponentSnapshot& component = liveComponents[index];
        out << "    { \"addressHex\": \"" << PointerHex(component.address)
            << "\", \"name\": \"" << JsonEscape(component.name)
            << "\", \"typeName\": \"" << JsonEscape(component.typeName)
            << "\", \"category\": \"" << JsonEscape(component.category)
            << "\", \"origin\": [" << component.origin.x << ", " << component.origin.y << ", " << component.origin.z
            << "], \"visible\": " << component.visible
            << ", \"flags\": " << component.flags << " }";
        if (index + 1 < liveComponents.size())
            out << ",";
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";

    LogMetadata("World walker report written: %s", NarrowWide(outPath).c_str());
    return 1;
}

AEGIS_UNIVERSAL_API int AegisRE_ScanConsoleBackend()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_consoleScanCompleted = false;
    BuildConsoleCandidatesLocked();
    return g_consoleStats.candidateCount ? 1 : 0;
}

AEGIS_UNIVERSAL_API int AegisRE_ToggleGameConsole()
{
    return ToggleGameConsoleInternal();
}

AEGIS_UNIVERSAL_API int AegisRE_StartConsoleHotkeyThread()
{
    if (g_consoleHotkeyThread)
        return 1;

    g_consoleHotkeyStop.store(false);
    HANDLE thread = ::CreateThread(nullptr, 0, ConsoleHotkeyThreadProc, nullptr, 0, nullptr);
    if (!thread)
    {
        LogConsole("Failed to start F2 console hotkey thread: GetLastError=%lu", ::GetLastError());
        return 0;
    }

    g_consoleHotkeyThread = thread;
    return 1;
}

AEGIS_UNIVERSAL_API void AegisRE_StopConsoleHotkeyThread()
{
    HANDLE thread = g_consoleHotkeyThread;
    if (!thread)
        return;

    g_consoleHotkeyStop.store(true);
    const DWORD wait = ::WaitForSingleObject(thread, 2000);
    if (wait == WAIT_TIMEOUT)
        LogConsole("F2 console hotkey thread did not stop within timeout");
    ::CloseHandle(thread);
    g_consoleHotkeyThread = nullptr;
}

AEGIS_UNIVERSAL_API int AegisRE_GetConsoleStats(AegisREConsoleStats* outStats)
{
    if (!outStats)
        return 0;

    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_consoleScanCompleted)
        BuildConsoleCandidatesLocked();
    *outStats = g_consoleStats;
    outStats->hotkeyRunning = g_consoleHotkeyRunning.load() ? 1 : 0;
    if (outStats->hotkeyRunning)
        outStats->flags |= AegisREConsole_HotkeyRunning;
    if (!outStats->details[0])
        CopyWide(outStats->details, L"Console backend has not reported yet.");
    return 1;
}

AEGIS_UNIVERSAL_API std::uint32_t AegisRE_GetConsoleCandidateCount()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_consoleScanCompleted)
        BuildConsoleCandidatesLocked();
    return static_cast<std::uint32_t>(g_consoleCandidates.size());
}

AEGIS_UNIVERSAL_API int AegisRE_GetConsoleCandidateInfo(std::uint32_t index, AegisREConsoleCandidateInfo* outInfo)
{
    if (!outInfo)
        return 0;

    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_consoleScanCompleted)
        BuildConsoleCandidatesLocked();
    if (index >= g_consoleCandidates.size())
        return 0;

    const ConsoleCandidate& candidate = g_consoleCandidates[index];
    *outInfo = {};
    CopyAnsi(outInfo->declaringType, candidate.declaringType);
    CopyAnsi(outInfo->methodName, candidate.methodName);
    CopyAnsi(outInfo->reason, candidate.reason);
    outInfo->functionAddress = candidate.functionAddress;
    outInfo->functionRva = candidate.functionRva;
    outInfo->parameterCount = candidate.parameterCount;
    outInfo->score = candidate.score;
    outInfo->flags = candidate.flags;
    if (candidate.callable)
        outInfo->flags |= 0x80000000u;
    return 1;
}

AEGIS_UNIVERSAL_API std::uint32_t AegisRE_GetHookCandidateCount()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_hookScanCompleted)
        BuildHookCandidatesLocked();
    return static_cast<std::uint32_t>(g_hookCandidates.size());
}

AEGIS_UNIVERSAL_API int AegisRE_GetHookCandidateInfo(std::uint32_t index, AegisREHookCandidateInfo* outInfo)
{
    if (!outInfo)
        return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_hookScanCompleted)
        BuildHookCandidatesLocked();
    if (index >= g_hookCandidates.size())
        return 0;
    FillHookInfo(g_hookCandidates[index], *outInfo);
    return 1;
}
