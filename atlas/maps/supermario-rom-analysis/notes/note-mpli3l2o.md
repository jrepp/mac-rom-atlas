---
id: note:mpli3l2o
title: "ROM structure pass: Quadra 660AV/840AV"
target: rom:1994-09---5--10--1----uadra-660av---840a:6973886C:2097152
kind: markdown
tags: ["overview", "finding", "structure", "disassembly"]
updated_at: 2026-05-25T19:02:29.326Z
---
# ROM structure pass: Quadra 660AV/840AV

The selected 2 MB ROM is now classified as a mixed code/data image instead of only a linear instruction stream. The current pass uses stackimport output plus server-side control-flow/reference heuristics, so every function boundary remains a hypothesis until confirmed by control flow, references, and nearby data islands.

## Current counts

| Class | Count | Notes |
|---|---:|---|
| Function candidates | 295 | 250 from the server structure pass plus stackimport sample candidates; ranked by inbound calls/references. |
| Pointer tables | 27 | Virtual addresses are based at `40800000`; the earliest detected table starts at `40803280`. |
| Data regions | 120 | Stackimport string/data clusters imported from the ROM scan. |
| Resource markers | 143 | Includes `DRVR`, `CODE`, `PACK`, `STR#`, `MENU`, `ALRT`, `DITL`, `cfrg`, and related markers. |

## Landmarks

- `40944A20` is the strongest current function candidate, with 218 inbound call references. Treat this as an important shared helper or dispatch target until callers are grouped.
- `40834154` is another high-confidence call target, with 86 inbound calls around the `40833xxx` region.
- `40803280` is the first pointer table candidate. Its entries point back into ROM space, starting with `408055D0`, `4083985A`, and `40839AB6`.
- `40800BFC`, `4080122A`, `4080CE64`, and `4080CF78` are early `DRVR` resource marker hits.

## Cautions

This is still a linear ROM disassembly with overlays. Tables, strings, and packed resource data can decode as plausible 68K instructions. Use the Structure tab to jump between candidate functions, pointer tables, data clusters, and resource markers, then confirm boundaries by following branch/call references and checking memory bytes near each target.
