# ROM Inventory

The SuperMario ROM analysis project references these ROM identities by name, hash token, and stable atlas path. Raw ROM bytes are not committed to this public repository.

| Role | Stable atlas path | Notes |
|---|---|---|
| Candidate 2 MB ROM | `data/roms/old-world/2mb/1994-09 - 5BF10FD1 - Quadra 660av & 840av.ROM` | Quadra 660AV/840AV, imported and disassembled in the current project metadata. |
| Candidate 2 MB ROM | `data/roms/old-world/2mb/1994-05 - B6909089 - PowerBook 520 520c 540 540c.ROM` | PowerBook 520/520c/540/540c family candidate. |
| Candidate 2 MB ROM | `data/roms/old-world/2mb/1995-08 - 4D27039C - Powerbook 190 & 190cs.ROM` | PowerBook 190/190cs candidate. |
| Reference 1 MB ROM | `data/roms/basiliskii/Quadra-900.rom` | BasiliskII Quadra 900 ROM reference, not one of the 2 MB SuperMario candidates. |

Persistent analysis data lives in:

`services/mcp-server/data/projects/supermario-rom-analysis-mplc55nn/`

Large generated memory-page files are kept out of Git at:

`services/mcp-server/data/projects/supermario-rom-analysis-mplc55nn/memory-pages/`
