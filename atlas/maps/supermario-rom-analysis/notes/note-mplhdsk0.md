---
id: note:mplhdsk0
title: "Candidate ROM evidence"
target: 
kind: markdown
tags: ["finding", "matching", "strings"]
updated_at: 2026-05-25T17:29:15.216Z
---
# Candidate ROM evidence

A source-like string overlap pass was run against the three 2MB ROM candidates, excluding obvious binary/object artifacts where possible.

## String-overlap result

| Candidate | Hits | Weighted score |
| --- | ---: | ---: |
| PowerBook 190/190cs 1995-08 | 121 | 1844 |
| Quadra 660AV/840AV 1994-09 | 91 | 1416 |
| PowerBook 520/540 1994-05 | 68 | 1150 |

## Interpretation

The PowerBook 190 ROM currently has the strongest string overlap, but this is not proof. Shared DeclData resources, later common Toolbox strings, and source tree components that postdate the original SuperMario snapshot can skew the result.

## Next checks

- Compare only high-specificity strings from OS, ProcessMgr, Toolbox, and model-specific DeclData.
- Find strings that appear in exactly one candidate ROM.
- Disassemble all three 2MB ROMs with the same base address convention and compare trap/call neighborhoods around shared strings.
- Look for exact byte sequences from known compiled source/object artifacts only after filtering generated metadata.
