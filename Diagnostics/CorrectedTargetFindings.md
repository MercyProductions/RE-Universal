# Corrected RE Target Findings

Checked targets:

```text
C:\Program Files (x86)\Steam\steamapps\common\RESIDENT EVIL 2  BIOHAZARD RE2 R.P.D. Demo\re2.exe
C:\Program Files (x86)\Steam\steamapps\common\Resident Evil Village BIOHAZARD VILLAGE Gold Edition Gameplay Demo\re8GEDemo.exe
C:\Program Files (x86)\Steam\steamapps\common\Capcom Arcade Stadium\CapcomArcadeStadium.exe
C:\Program Files (x86)\Steam\steamapps\common\Capcom Arcade 2nd Stadium\CapcomArcade2ndStadium.exe
```

Summary:

- `re2.exe` is x64 and exports hundreds of Wwise symbols. A quick metadata scan found about 66k `via.*` strings plus many `app.ropeway.*` game type strings.
- `re8GEDemo.exe` is x64 and exports hundreds of Wwise symbols. A quick metadata scan found about 86k `via.*` strings plus many `app.*` game type strings.
- `CapcomArcadeStadium.exe` exposes only GPU preference exports in the quick export pass and did not expose plain `via.*` strings in the quick scan.
- `CapcomArcade2ndStadium.exe` exposes GPU preference/D3D12 exports in the quick export pass and did not expose plain `via.*` strings in the quick scan.

Resolver implication:

- RE2/RE8 should produce a rich `RETypeSDK` from PE metadata strings.
- RE2/RE8 should also be the best candidates for the runtime `TDB` metadata backend. The DLL now searches committed process memory for validated `TDB` headers and writes accepted/rejected candidates to `REEngine_Universal_MetadataBackend.log`.
- Arcade Stadium builds may still be detectable by process/export hints, but live type discovery depends on metadata visibility in the loaded image.
- No hardcoded offsets were derived or stored from these targets.
