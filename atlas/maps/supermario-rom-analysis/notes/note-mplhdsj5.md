---
id: note:mplhdsj5
title: "Project orientation"
target: 
kind: markdown
tags: ["overview", "orientation", "rom"]
updated_at: 2026-05-25T17:29:15.185Z
---
# SuperMario ROM reverse engineering orientation

This project is tracking Old World Macintosh ROMs against the leaked/archived SuperMario source tree dated `1994-02-09`.

## Current workspace state

- Four ROM images are imported into the graph, including three 2MB candidates and the 1MB Quadra 900/Basilisk image.
- The Quadra 660AV/840AV ROM has a stackimport disassembly artifact with real 68K mnemonics and trap annotations.
- The graph currently emphasizes imported ROM pages, checksums, machine-family nodes, and one ROM disassembly node.

## Main question

Which 2MB ROM most closely corresponds to the SuperMario source snapshot? The candidates are:

1. PowerBook 520/540/550c ROM, 1994-05, CRC token `B6909089`
2. Quadra 660AV/840AV ROM, 1994-09, CRC token `5BF10FD1`
3. PowerBook 190/190cs ROM, 1995-08, CRC token `4D27039C`

## Working approach

Use several signals rather than one match type: source string overlap, ROM date proximity, model-specific resources, trap/call patterns, and eventually binary/object identity against compiled SuperMario components.
