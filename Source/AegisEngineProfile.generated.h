#pragma once

#include "AegisUniversalRuntime.h"

inline constexpr AegisUniversalSignature kAegisUniversalSignatures[] = {
    { L"re2.exe", nullptr, nullptr, AegisUniversalSignature_Process | AegisUniversalSignature_Core, "Process hint" },
    { L"re3.exe", nullptr, nullptr, AegisUniversalSignature_Process | AegisUniversalSignature_Core, "Process hint" },
    { L"re4.exe", nullptr, nullptr, AegisUniversalSignature_Process | AegisUniversalSignature_Core, "Process hint" },
    { L"re7.exe", nullptr, nullptr, AegisUniversalSignature_Process | AegisUniversalSignature_Core, "Process hint" },
    { L"re8.exe", nullptr, nullptr, AegisUniversalSignature_Process | AegisUniversalSignature_Core, "Process hint" },
    { L"re8gedemo.exe", nullptr, nullptr, AegisUniversalSignature_Process | AegisUniversalSignature_Core, "Process hint" },
    { L"dmc5.exe", nullptr, nullptr, AegisUniversalSignature_Process | AegisUniversalSignature_Core, "Process hint" },
    { L"mhrise.exe", nullptr, nullptr, AegisUniversalSignature_Process | AegisUniversalSignature_Core, "Process hint" },
    { L"monsterhunterwilds.exe", nullptr, nullptr, AegisUniversalSignature_Process | AegisUniversalSignature_Core, "Process hint" },
    { L"capcomarcadestadium.exe", nullptr, nullptr, AegisUniversalSignature_Process | AegisUniversalSignature_Core, "Process hint" },
    { L"capcomarcade2ndstadium.exe", nullptr, nullptr, AegisUniversalSignature_Process | AegisUniversalSignature_Core, "Process hint" },
    { nullptr, L"reframework", nullptr, AegisUniversalSignature_Module | AegisUniversalSignature_Core, "Module hint" },
    { nullptr, L"dinput8.dll", nullptr, AegisUniversalSignature_Module | AegisUniversalSignature_Core, "Module hint" },
    { nullptr, L"openvr_api.dll", nullptr, AegisUniversalSignature_Module | AegisUniversalSignature_Core, "Module hint" },
    { nullptr, L"steam_api64.dll", nullptr, AegisUniversalSignature_Module | AegisUniversalSignature_Core, "Module hint" },
    { nullptr, L"amd_ags_x64.dll", nullptr, AegisUniversalSignature_Module | AegisUniversalSignature_Core, "Module hint" },
    { nullptr, L"d3d11.dll", nullptr, AegisUniversalSignature_Module | AegisUniversalSignature_Renderer, "Renderer hint" },
    { nullptr, L"d3d12.dll", nullptr, AegisUniversalSignature_Module | AegisUniversalSignature_Renderer, "Renderer hint" },
    { nullptr, L"dxgi.dll", nullptr, AegisUniversalSignature_Module | AegisUniversalSignature_Renderer, "Renderer hint" },
    { nullptr, L"openvr_api.dll", nullptr, AegisUniversalSignature_Module | AegisUniversalSignature_Renderer, "VR renderer hint" },
    { nullptr, nullptr, "AmdPowerXpressRequestHighPerformance", AegisUniversalSignature_Export | AegisUniversalSignature_Core, "RE-family export hint" },
    { nullptr, nullptr, "NvOptimusEnablement", AegisUniversalSignature_Export | AegisUniversalSignature_Core, "RE-family export hint" },
    { nullptr, nullptr, "D3D12SDKVersion", AegisUniversalSignature_Export | AegisUniversalSignature_Renderer, "D3D12 export hint" },
    { nullptr, nullptr, "reframework_plugin_initialize", AegisUniversalSignature_Export | AegisUniversalSignature_Core, "Export hint" },
    { nullptr, nullptr, "reframework_plugin_required_version", AegisUniversalSignature_Export | AegisUniversalSignature_Core, "Export hint" },
};

inline constexpr AegisUniversalProfile kAegisUniversalProfile = {
    L"RE Engine",
    L"REEngine",
    L"REEngine_Universal_Report.txt",
    L"REEngine_Universal_Trace.txt",
    L"REEngine_Universal_Log.txt",
    kAegisUniversalSignatures,
    sizeof(kAegisUniversalSignatures) / sizeof(kAegisUniversalSignatures[0])
};

