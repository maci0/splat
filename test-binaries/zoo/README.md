# Win32 PE test corpus

Freely-redistributable Windows PE binaries useful for exercising the
splat win32 platform. None of these are committed to the repo (they're
re-downloadable and live behind their respective licenses); the
`.gitignore` here keeps the directory empty in git.

## Suggested binaries

| Binary | URL | Notes |
| --- | --- | --- |
| PuTTY x64 (PE32+) | `https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe` | MSVC 14.x, 10 sections (`.pdata`, `.00cfg`, `.gxfg`, `.tls`, `_RDATA`), 2410 RUNTIME_FUNCTION entries, VS_VERSIONINFO populated. Real PE32+ workload. |
| Sysinternals PSTools | `https://download.sysinternals.com/files/PSTools.zip` | Microsoft-built MSVC 14.34 utilities. Contains both PE32 and PE32+ variants of every tool. `PsExec.exe` has 34 SafeSEH handlers; `PsExec64.exe` has 1049 .pdata entries. |
| Quake 1 source | `https://github.com/id-Software/Quake` | GPL — community builds with MSVC are widely available; exercises 3D-engine vtables and audio/D3D imports. |
| ReactOS prebuilt | `https://reactos.org/getbuilds/` | Open-source Windows reimplementation. Modern PE features (CFG, SafeSEH, manifests). |
| Old MS DLLs | Win95/98/2K install media, ReactOS source tree | MSVC 4/5/6-built system DLLs. Vintage HIGHLOW relocs, NB10 PDB records. |

## Verified results

The repo's own test corpus already covers:

- `test-binaries/Server/server.dll` — MSVC 6.0 PE32 DLL with .reloc
- `test-binaries/Europa1400Gold_TL.exe` — MSVC 6.0 PE32 EXE, RELOCS_STRIPPED

Adding any of the binaries above and dropping a matching YAML via
`create_config.py <binary>` produces an assembleable splat output.
