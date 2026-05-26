---
id: note:mplhdsli
title: "Disassembly navigation notes"
target: rom_disassembly:rom:1994-09---5--10--1----uadra-660av---840a:6973886C:2097152:6973886C
kind: markdown
tags: ["disassembly", "navigation", "trap"]
updated_at: 2026-05-25T17:29:15.270Z
---
# Disassembly navigation notes

The current disassembly artifact for the Quadra 660AV/840AV ROM is stored as a `rom_disassembly` node and can be browsed from the Disassembly tab.

## Useful starting points

- `40800000`: ROM image start/header area. The first word sequence includes the CRC token bytes, so early linear decode includes data before code stabilizes.
- `40800074`: early startup/control setup region reached by initial jump table entries.
- `40800318`: trap dispatch setup neighborhood with `GetTrapAddress` and `SetTrapAddress` calls.

## Browser behavior

The disassembly view now annotates rows with:

- current containing label/function when visible or inferred from the preceding label,
- branch/call target links from disassembler comments,
- trap links for A-line trap words,
- memory-reference links for likely absolute addresses,
- graph annotation chips for any imported nodes at the same address.

## Caution

This is still a linear ROM disassembly. Data islands and tables will decode as plausible instructions in places. Treat function boundaries as hypotheses until confirmed by control flow and references.
