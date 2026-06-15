#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "AegisREEngineUniversal.h"
#include "AegisUniversalOverlay.h"

#include "imgui.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <string>
#include <vector>

namespace
{
    struct Rect2D
    {
        float minX = 0.0f;
        float minY = 0.0f;
        float maxX = 0.0f;
        float maxY = 0.0f;
        bool valid = false;
    };

    bool g_drawEnabled = true;
    bool g_draw2DBoxes = true;
    bool g_draw3DBoxes = true;
    bool g_drawLines = true;
    bool g_drawLabels = true;
    bool g_hideInvisible = false;
    bool g_liveOnly = true;
    bool g_internalWalkerEnabled = false;
    bool g_players = true;
    bool g_npcs = true;
    bool g_ai = true;
    bool g_enemies = true;
    bool g_entities = true;
    bool g_misc = false;
    float g_boxThickness = 1.4f;
    float g_lineThickness = 1.2f;
    ImVec4 g_playerColor = ImVec4(0.35f, 0.9f, 0.55f, 1.0f);
    ImVec4 g_enemyColor = ImVec4(1.0f, 0.35f, 0.25f, 1.0f);
    ImVec4 g_entityColor = ImVec4(0.55f, 0.78f, 1.0f, 1.0f);
    ImVec4 g_lineColor = ImVec4(1.0f, 0.78f, 0.25f, 0.9f);
    char g_typeSearch[96] = {};
    char g_componentSearch[96] = {};
    char g_hookSearch[96] = {};
    char g_metadataSearch[96] = {};
    char g_consoleSearch[96] = {};

    AegisREVec3 Add(const AegisREVec3& a, const AegisREVec3& b)
    {
        return { a.x + b.x, a.y + b.y, a.z + b.z };
    }

    bool ContainsAnsi(const char* haystack, const char* needle)
    {
        if (!haystack || !needle || !needle[0])
            return true;

        std::string h = haystack;
        std::string n = needle;
        std::transform(h.begin(), h.end(), h.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return h.find(n) != std::string::npos;
    }

    bool PassComponentFilter(const AegisREComponentSnapshot& component)
    {
        if (g_liveOnly && (component.flags & AegisREComponent_LiveSnapshot) == 0)
            return false;
        if (g_hideInvisible && !component.visible)
            return false;
        if (!ContainsAnsi(component.name, g_componentSearch) &&
            !ContainsAnsi(component.typeName, g_componentSearch) &&
            !ContainsAnsi(component.category, g_componentSearch))
        {
            return false;
        }

        const bool isPlayer = (component.flags & AegisREComponent_Player) != 0;
        const bool isNpc = (component.flags & AegisREComponent_Npc) != 0;
        const bool isAi = (component.flags & AegisREComponent_Ai) != 0;
        const bool isEnemy = (component.flags & AegisREComponent_Enemy) != 0;
        const bool isEntity = (component.flags & AegisREComponent_Entity) != 0;
        const bool isMisc = !isPlayer && !isNpc && !isAi && !isEnemy && !isEntity;

        return (g_players && isPlayer) ||
            (g_npcs && isNpc) ||
            (g_ai && isAi) ||
            (g_enemies && isEnemy) ||
            (g_entities && isEntity) ||
            (g_misc && isMisc);
    }

    ImU32 ColorForComponent(const AegisREComponentSnapshot& component)
    {
        if (component.flags & AegisREComponent_Enemy)
            return ImGui::ColorConvertFloat4ToU32(g_enemyColor);
        if (component.flags & AegisREComponent_Player)
            return ImGui::ColorConvertFloat4ToU32(g_playerColor);
        return ImGui::ColorConvertFloat4ToU32(g_entityColor);
    }

    bool ProjectBounds3D(const AegisREComponentSnapshot& component, Rect2D& rect)
    {
        const std::array<AegisREVec3, 8> corners = {
            Add(component.origin, { component.boundsMin.x, component.boundsMin.y, component.boundsMin.z }),
            Add(component.origin, { component.boundsMax.x, component.boundsMin.y, component.boundsMin.z }),
            Add(component.origin, { component.boundsMin.x, component.boundsMax.y, component.boundsMin.z }),
            Add(component.origin, { component.boundsMax.x, component.boundsMax.y, component.boundsMin.z }),
            Add(component.origin, { component.boundsMin.x, component.boundsMin.y, component.boundsMax.z }),
            Add(component.origin, { component.boundsMax.x, component.boundsMin.y, component.boundsMax.z }),
            Add(component.origin, { component.boundsMin.x, component.boundsMax.y, component.boundsMax.z }),
            Add(component.origin, { component.boundsMax.x, component.boundsMax.y, component.boundsMax.z })
        };

        rect = {};
        for (const AegisREVec3& corner : corners)
        {
            AegisREProjectedPoint point = {};
            if (!AegisRE_ProjectWorldToScreen(&corner, &point) || point.clipped ||
                !std::isfinite(point.x) || !std::isfinite(point.y))
            {
                continue;
            }

            if (!rect.valid)
            {
                rect.minX = rect.maxX = point.x;
                rect.minY = rect.maxY = point.y;
                rect.valid = true;
            }
            else
            {
                rect.minX = std::min(rect.minX, point.x);
                rect.minY = std::min(rect.minY, point.y);
                rect.maxX = std::max(rect.maxX, point.x);
                rect.maxY = std::max(rect.maxY, point.y);
            }
        }
        return rect.valid && rect.maxX > rect.minX && rect.maxY > rect.minY;
    }

    bool ProjectOriginBox(const AegisREComponentSnapshot& component, Rect2D& rect)
    {
        AegisREProjectedPoint point = {};
        if (!AegisRE_ProjectWorldToScreen(&component.origin, &point) || point.clipped ||
            !std::isfinite(point.x) || !std::isfinite(point.y))
        {
            return false;
        }

        rect.minX = point.x - 14.0f;
        rect.maxX = point.x + 14.0f;
        rect.minY = point.y - 24.0f;
        rect.maxY = point.y + 24.0f;
        rect.valid = true;
        return true;
    }

    void DrawComponentOverlay()
    {
        if (!g_drawEnabled)
            return;
        if (!ImGui::GetCurrentContext())
            return;
        if (AegisRE_IsResolverBusy())
            return;

        ImDrawList* drawList = ImGui::GetForegroundDrawList();
        if (!drawList)
            return;
        const ImVec2 display = ImGui::GetIO().DisplaySize;
        const ImU32 lineColor = ImGui::ColorConvertFloat4ToU32(g_lineColor);
        const std::uint32_t count = std::min<std::uint32_t>(AegisRE_GetComponentCount(), 1024);

        for (std::uint32_t index = 0; index < count; ++index)
        {
            AegisREComponentSnapshot component = {};
            if (!AegisRE_GetComponentSnapshot(index, &component) || !PassComponentFilter(component))
                continue;
            if (!component.visible)
                continue;

            Rect2D box = {};
            const bool has3D = g_draw3DBoxes && ProjectBounds3D(component, box);
            if (!has3D && (!g_draw2DBoxes || !ProjectOriginBox(component, box)))
                continue;

            const ImU32 boxColor = ColorForComponent(component);
            if (g_draw3DBoxes && has3D)
                drawList->AddRect(ImVec2(box.minX, box.minY), ImVec2(box.maxX, box.maxY), boxColor, 0.0f, 0, g_boxThickness);
            if (g_draw2DBoxes)
            {
                Rect2D origin = {};
                if (ProjectOriginBox(component, origin))
                    drawList->AddRect(ImVec2(origin.minX, origin.minY), ImVec2(origin.maxX, origin.maxY), boxColor, 0.0f, 0, g_boxThickness);
            }
            if (g_drawLines)
                drawList->AddLine(ImVec2(display.x * 0.5f, display.y), ImVec2((box.minX + box.maxX) * 0.5f, box.maxY), lineColor, g_lineThickness);
            if (g_drawLabels)
                drawList->AddText(ImVec2(box.minX, std::max(0.0f, box.minY - 16.0f)), boxColor, component.name[0] ? component.name : component.typeName);
        }
    }

    void DrawComponentTable()
    {
        ImGui::InputText("Component search", g_componentSearch, sizeof(g_componentSearch));
        if (AegisRE_IsResolverBusy())
        {
            ImGui::TextUnformatted("Resolver is still running; component data will unlock when it completes.");
            return;
        }

        const std::uint32_t count = std::min<std::uint32_t>(AegisRE_GetComponentCount(), 512);
        if (ImGui::BeginTable("re-components", 7, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
        {
            ImGui::TableSetupColumn("Address");
            ImGui::TableSetupColumn("Name");
            ImGui::TableSetupColumn("Type");
            ImGui::TableSetupColumn("Category");
            ImGui::TableSetupColumn("Origin");
            ImGui::TableSetupColumn("Visible");
            ImGui::TableSetupColumn("Flags");
            ImGui::TableHeadersRow();
            for (std::uint32_t index = 0; index < count; ++index)
            {
                AegisREComponentSnapshot c = {};
                if (!AegisRE_GetComponentSnapshot(index, &c) || !PassComponentFilter(c))
                    continue;
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("0x%llX", static_cast<unsigned long long>(c.address));
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(c.name);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(c.typeName);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(c.category);
                ImGui::TableNextColumn();
                ImGui::Text("%.2f, %.2f, %.2f", c.origin.x, c.origin.y, c.origin.z);
                ImGui::TableNextColumn();
                ImGui::Text("%s", c.visible ? "yes" : "no");
                ImGui::TableNextColumn();
                ImGui::Text("0x%08X", c.flags);
            }
            ImGui::EndTable();
        }
    }

    void DrawTypeTable()
    {
        ImGui::InputText("Type search", g_typeSearch, sizeof(g_typeSearch));
        const std::uint32_t count = std::min<std::uint32_t>(AegisRE_GetTypeCount(), 1000);
        if (ImGui::BeginTable("re-types", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
        {
            ImGui::TableSetupColumn("Name");
            ImGui::TableSetupColumn("Namespace");
            ImGui::TableSetupColumn("Module");
            ImGui::TableSetupColumn("RVA");
            ImGui::TableSetupColumn("Flags");
            ImGui::TableHeadersRow();
            for (std::uint32_t index = 0; index < count; ++index)
            {
                AegisRETypeInfo type = {};
                if (!AegisRE_GetTypeInfo(index, &type) || !ContainsAnsi(type.name, g_typeSearch))
                    continue;
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(type.name);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(type.namespaceName);
                ImGui::TableNextColumn();
                ImGui::Text("%ls", type.moduleName);
                ImGui::TableNextColumn();
                ImGui::Text("0x%llX", static_cast<unsigned long long>(type.rva));
                ImGui::TableNextColumn();
                ImGui::Text("0x%08X", type.flags);
            }
            ImGui::EndTable();
        }
    }

    void DrawHookTable()
    {
        ImGui::InputText("Hook search", g_hookSearch, sizeof(g_hookSearch));
        const std::uint32_t count = std::min<std::uint32_t>(AegisRE_GetHookCandidateCount(), 1000);
        if (ImGui::BeginTable("re-hooks", 6, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
        {
            ImGui::TableSetupColumn("Module");
            ImGui::TableSetupColumn("Symbol");
            ImGui::TableSetupColumn("Reason");
            ImGui::TableSetupColumn("RVA");
            ImGui::TableSetupColumn("Address");
            ImGui::TableSetupColumn("Flags");
            ImGui::TableHeadersRow();
            for (std::uint32_t index = 0; index < count; ++index)
            {
                AegisREHookCandidateInfo hook = {};
                if (!AegisRE_GetHookCandidateInfo(index, &hook) || !ContainsAnsi(hook.symbolName, g_hookSearch))
                    continue;
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%ls", hook.moduleName);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(hook.symbolName);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(hook.reason);
                ImGui::TableNextColumn();
                ImGui::Text("0x%llX", static_cast<unsigned long long>(hook.rva));
                ImGui::TableNextColumn();
                ImGui::Text("0x%llX", static_cast<unsigned long long>(hook.address));
                ImGui::TableNextColumn();
                ImGui::Text("0x%08X", hook.flags);
            }
            ImGui::EndTable();
        }
    }

    void DrawConsoleTable()
    {
        ImGui::InputText("Console search", g_consoleSearch, sizeof(g_consoleSearch));
        const std::uint32_t count = std::min<std::uint32_t>(AegisRE_GetConsoleCandidateCount(), 256);
        if (ImGui::BeginTable("re-console-candidates", 7, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
        {
            ImGui::TableSetupColumn("Owner");
            ImGui::TableSetupColumn("Method");
            ImGui::TableSetupColumn("Score");
            ImGui::TableSetupColumn("Params");
            ImGui::TableSetupColumn("Address");
            ImGui::TableSetupColumn("Flags");
            ImGui::TableSetupColumn("Reason");
            ImGui::TableHeadersRow();
            for (std::uint32_t index = 0; index < count; ++index)
            {
                AegisREConsoleCandidateInfo candidate = {};
                if (!AegisRE_GetConsoleCandidateInfo(index, &candidate))
                    continue;
                if (!ContainsAnsi(candidate.declaringType, g_consoleSearch) &&
                    !ContainsAnsi(candidate.methodName, g_consoleSearch) &&
                    !ContainsAnsi(candidate.reason, g_consoleSearch))
                {
                    continue;
                }

                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(candidate.declaringType);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(candidate.methodName);
                ImGui::TableNextColumn();
                ImGui::Text("%u", candidate.score);
                ImGui::TableNextColumn();
                ImGui::Text("%u", candidate.parameterCount);
                ImGui::TableNextColumn();
                ImGui::Text("0x%llX", static_cast<unsigned long long>(candidate.functionAddress));
                ImGui::TableNextColumn();
                ImGui::Text("0x%08X%s", candidate.flags, (candidate.flags & 0x80000000u) ? " callable" : "");
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(candidate.reason);
            }
            ImGui::EndTable();
        }
    }

    void DrawMetadataTable()
    {
        ImGui::InputText("Metadata search", g_metadataSearch, sizeof(g_metadataSearch));

        const std::uint32_t methodCount = std::min<std::uint32_t>(AegisRE_GetMetadataMethodCount(), 700);
        if (ImGui::BeginTable("re-metadata-methods", 7, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
        {
            ImGui::TableSetupColumn("Owner");
            ImGui::TableSetupColumn("Method");
            ImGui::TableSetupColumn("Return");
            ImGui::TableSetupColumn("Address");
            ImGui::TableSetupColumn("RVA");
            ImGui::TableSetupColumn("Params");
            ImGui::TableSetupColumn("Flags");
            ImGui::TableHeadersRow();
            for (std::uint32_t index = 0; index < methodCount; ++index)
            {
                AegisREMetadataMethodInfo method = {};
                if (!AegisRE_GetMetadataMethodInfo(index, &method))
                    continue;
                if (!ContainsAnsi(method.declaringType, g_metadataSearch) &&
                    !ContainsAnsi(method.name, g_metadataSearch) &&
                    !ContainsAnsi(method.returnType, g_metadataSearch))
                {
                    continue;
                }
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(method.declaringType);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(method.name);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(method.returnType);
                ImGui::TableNextColumn();
                ImGui::Text("0x%llX", static_cast<unsigned long long>(method.functionAddress));
                ImGui::TableNextColumn();
                ImGui::Text("0x%llX", static_cast<unsigned long long>(method.functionRva));
                ImGui::TableNextColumn();
                ImGui::Text("%u", method.parameterCount);
                ImGui::TableNextColumn();
                ImGui::Text("0x%08X", method.flags);
            }
            ImGui::EndTable();
        }

        const std::uint32_t fieldCount = std::min<std::uint32_t>(AegisRE_GetMetadataFieldCount(), 700);
        if (ImGui::BeginTable("re-metadata-fields", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
        {
            ImGui::TableSetupColumn("Owner");
            ImGui::TableSetupColumn("Field");
            ImGui::TableSetupColumn("Type");
            ImGui::TableSetupColumn("Offset");
            ImGui::TableSetupColumn("Flags");
            ImGui::TableHeadersRow();
            for (std::uint32_t index = 0; index < fieldCount; ++index)
            {
                AegisREMetadataFieldInfo field = {};
                if (!AegisRE_GetMetadataFieldInfo(index, &field))
                    continue;
                if (!ContainsAnsi(field.declaringType, g_metadataSearch) &&
                    !ContainsAnsi(field.name, g_metadataSearch) &&
                    !ContainsAnsi(field.fieldType, g_metadataSearch))
                {
                    continue;
                }
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(field.declaringType);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(field.name);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(field.fieldType);
                ImGui::TableNextColumn();
                ImGui::Text("0x%X", field.offset);
                ImGui::TableNextColumn();
                ImGui::Text("0x%08X", field.flags);
            }
            ImGui::EndTable();
        }
    }
}

extern "C" const char* AegisUniversalOverlay_GetEngineOverlayName()
{
    return "RE Engine";
}

extern "C" void AegisUniversalOverlay_PollEngineProviders()
{
    if (AegisRE_IsResolverBusy())
        return;
    AegisRE_UpdateProviders();
}

extern "C" void AegisUniversalOverlay_DrawEngineOverlay()
{
    if (AegisRE_IsResolverBusy())
        return;
    DrawComponentOverlay();
}

extern "C" void AegisUniversalOverlay_DrawEngineMenu()
{
    if (AegisRE_IsResolverBusy())
    {
        if (ImGui::BeginTabItem("RE Resolver"))
        {
            ImGui::TextUnformatted("Resolver: running");
            ImGui::TextWrapped("TDB metadata is still being decoded. The overlay is alive; resolver tables, component walking, and metadata views will unlock when this completes.");
            ImGui::TextUnformatted("The console and REEngine_Universal_Log.txt will print RESOLVER COMPLETE when ready.");
            ImGui::EndTabItem();
        }
        return;
    }

    if (ImGui::BeginTabItem("RE Resolver"))
    {
        AegisRECapabilityInfo capability = {};
        AegisRE_GetCapabilityInfo(&capability);
        AegisREAdapterTiming timing = {};
        AegisRE_GetAdapterTiming(&timing);

        ImGui::Text("Renderer: %ls", capability.rendererBackend);
        ImGui::TextWrapped("%ls", capability.details);
        ImGui::Separator();
        ImGui::Text("RE detected: %s | via types: %s | app types: %s",
            capability.reDetected ? "yes" : "no",
            capability.viaTypeStringsFound ? "yes" : "no",
            capability.appTypeStringsFound ? "yes" : "no");
        ImGui::Text("Types: %u | hook candidates: %u | live components: %u",
            capability.typeCount,
            capability.hookCandidateCount,
            AegisRE_GetComponentCount());
        ImGui::Text("Metadata: %s | TDB v%u | defs %u | fields %u | methods %u",
            capability.metadataBackendReady ? "ready" : "waiting",
            capability.metadataTdbVersion,
            capability.metadataTypeCount,
            capability.metadataFieldCount,
            capability.metadataMethodCount);
        ImGui::Text("Internal walker: %s | roots %u | objects %u | components %u",
            capability.internalWorldWalkerReady ? "ready" : (capability.internalWorldWalkerEnabled ? "scanning" : "off"),
            capability.internalWorldRootCount,
            capability.internalWorldObjectCount,
            capability.internalWorldComponentCount);
        ImGui::Text("Providers: components %s | matrix %s | viewport %s",
            capability.componentProviderRegistered ? "yes" : "no",
            capability.viewProjectionProviderRegistered ? "yes" : "no",
            capability.viewportProviderRegistered ? "yes" : "auto");
        ImGui::Text("Viewport: %s | matrix: %s | W2S: %s",
            capability.viewportValid ? "valid" : "waiting",
            capability.matrixValid ? "valid" : "waiting",
            capability.w2sProjectionWorking ? "working" : "waiting");
        ImGui::Text("Frame %llu | projected %u | clipped %u",
            static_cast<unsigned long long>(timing.frameId),
            timing.projectedCount,
            timing.clippedCount);

        if (ImGui::Button("Refresh resolver"))
            AegisRE_RefreshResolver();
        ImGui::SameLine();
        if (ImGui::Button("Write resolver report"))
            AegisRE_WriteResolverReport(nullptr);
        ImGui::SameLine();
        if (ImGui::Button("Write component snapshot"))
            AegisRE_WriteSnapshotJson(nullptr);
        ImGui::SameLine();
        if (ImGui::Button("Write world report"))
            AegisRE_WriteWorldWalkerReport(nullptr);

        ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("RE Overlay"))
    {
        ImGui::Checkbox("Draw overlay", &g_drawEnabled);
        if (ImGui::Checkbox("Internal walker", &g_internalWalkerEnabled))
            AegisRE_SetInternalWorldWalkerEnabled(g_internalWalkerEnabled ? 1 : 0);
        ImGui::Checkbox("Live snapshots only", &g_liveOnly);
        ImGui::Checkbox("Hide invisible", &g_hideInvisible);
        ImGui::Checkbox("2D boxes", &g_draw2DBoxes);
        ImGui::Checkbox("3D boxes", &g_draw3DBoxes);
        ImGui::Checkbox("Lines", &g_drawLines);
        ImGui::Checkbox("Labels", &g_drawLabels);
        ImGui::Separator();
        ImGui::Checkbox("Players", &g_players);
        ImGui::SameLine();
        ImGui::Checkbox("NPC", &g_npcs);
        ImGui::SameLine();
        ImGui::Checkbox("AI", &g_ai);
        ImGui::Checkbox("Enemies", &g_enemies);
        ImGui::SameLine();
        ImGui::Checkbox("Entities", &g_entities);
        ImGui::SameLine();
        ImGui::Checkbox("Misc", &g_misc);
        ImGui::SliderFloat("Box thickness", &g_boxThickness, 0.5f, 6.0f, "%.1f");
        ImGui::SliderFloat("Line thickness", &g_lineThickness, 0.5f, 6.0f, "%.1f");
        ImGui::ColorEdit4("Player color", &g_playerColor.x);
        ImGui::ColorEdit4("Enemy color", &g_enemyColor.x);
        ImGui::ColorEdit4("Entity color", &g_entityColor.x);
        ImGui::ColorEdit4("Line color", &g_lineColor.x);
        ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("RE Components"))
    {
        if (ImGui::Button("Print components"))
            AegisRE_PrintCurrentComponents();
        DrawComponentTable();
        ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("RE Type SDK"))
    {
        if (ImGui::Button("Scan types"))
            AegisRE_ScanSdkTypes();
        ImGui::SameLine();
        if (ImGui::Button("Export JSON"))
            AegisRE_WriteTypeSdkJson(nullptr);
        ImGui::SameLine();
        if (ImGui::Button("Export header"))
            AegisRE_WriteTypeSdkHeader(nullptr);
        ImGui::SameLine();
        if (ImGui::Button("Export CSV"))
            AegisRE_WriteTypeSdkCsv(nullptr);
        ImGui::Text("Type count: %u", AegisRE_GetTypeCount());
        DrawTypeTable();
        ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("RE Hooks"))
    {
        ImGui::Text("Discoverable hook candidates: %u", AegisRE_GetHookCandidateCount());
        DrawHookTable();
        ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("RE Console"))
    {
        AegisREConsoleStats stats = {};
        AegisRE_GetConsoleStats(&stats);
        ImGui::TextWrapped("%ls", stats.details);
        ImGui::Text("Candidates: %u | callable %u | attempts %u | returned %u | toggles %llu",
            stats.candidateCount,
            stats.callableCandidateCount,
            stats.attemptedCount,
            stats.successfulCallCount,
            static_cast<unsigned long long>(stats.toggleCount));
        ImGui::Text("Hotkey: %s | flags 0x%08X | last 0x%llX",
            stats.hotkeyRunning ? "F2 armed" : "not running",
            stats.flags,
            static_cast<unsigned long long>(stats.lastAttemptAddress));
        if (ImGui::Button("Scan console"))
            AegisRE_ScanConsoleBackend();
        ImGui::SameLine();
        if (ImGui::Button("Toggle console (F2)"))
            AegisRE_ToggleGameConsole();
        ImGui::SameLine();
        if (ImGui::Button("Start F2 hotkey"))
            AegisRE_StartConsoleHotkeyThread();
        DrawConsoleTable();
        ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("RE Metadata"))
    {
        AegisREMetadataStats stats = {};
        AegisRE_GetMetadataStats(&stats);
        ImGui::TextWrapped("%ls", stats.details);
        ImGui::Text("Accepted TDBs: %u | rejected: %u", stats.tdbCandidateCount, stats.rejectedTdbCandidateCount);
        ImGui::Text("Named types: %u | named fields: %u | named methods: %u | direct methods: %u",
            stats.namedTypeCount,
            stats.namedFieldCount,
            stats.namedMethodCount,
            stats.directMethodCount);
        ImGui::Text("Log: %ls", stats.logPath);
        if (ImGui::Button("Rescan metadata"))
            AegisRE_ScanMetadataBackend();
        ImGui::SameLine();
        if (ImGui::Button("Export metadata JSON"))
            AegisRE_WriteMetadataJson(nullptr);
        ImGui::SameLine();
        if (ImGui::Button("Export metadata CSV"))
            AegisRE_WriteMetadataCsv(nullptr);
        DrawMetadataTable();
        ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("RE World"))
    {
        AegisREWorldWalkerStats stats = {};
        AegisRE_GetWorldWalkerStats(&stats);
        g_internalWalkerEnabled = stats.enabled != 0;

        ImGui::TextWrapped("%ls", stats.details);
        ImGui::Text("Scan %llu | %.2f ms | flags 0x%08X",
            static_cast<unsigned long long>(stats.scanId),
            stats.lastScanMs,
            stats.flags);
        ImGui::Text("Roots: %u | singleton %u | globals %u | rejected %u",
            stats.rootCount,
            stats.singletonRootCount,
            stats.globalPointerRootCount,
            stats.rejectedRootCount);
        ImGui::Text("Objects: %u | components %u | field reads %u | max depth %u",
            stats.visitedObjectCount,
            stats.componentCount,
            stats.fieldReadCount,
            stats.maxDepthReached);

        if (ImGui::Checkbox("Enable internal world walker", &g_internalWalkerEnabled))
            AegisRE_SetInternalWorldWalkerEnabled(g_internalWalkerEnabled ? 1 : 0);
        ImGui::SameLine();
        if (g_internalWalkerEnabled && ImGui::Button("Force scan"))
            AegisRE_RunInternalWorldScan();
        if (!g_internalWalkerEnabled)
            ImGui::TextUnformatted("Force scan is disabled until the internal walker is explicitly enabled.");
        ImGui::SameLine();
        if (ImGui::Button("Export world JSON"))
            AegisRE_WriteWorldWalkerReport(nullptr);

        DrawComponentTable();
        ImGui::EndTabItem();
    }
}
