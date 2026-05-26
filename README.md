# mac-rom-atlas

Knowledge atlas and reverse-engineering workspace for Old World Macintosh ROMs, SuperMario sources, disassembly overlays, MCP services, and historical technical references.

## Purpose

`mac-rom-atlas` is intended to consolidate the research assets that currently live across separate projects:

- extracted book and manual knowledge
- Old World Macintosh ROM metadata and imported memory pages
- 68k disassembly outputs, xrefs, function hypotheses, and annotations
- SuperMario source-code correlation data
- ROM resources and converted assets
- MCP/REST services and frontend reverse-engineering workflows
- analyst notes, project maps, and repeatable reverse-engineering observations

The goal is to make the ROM research workspace navigable as one project rather than a collection of one-off outputs.

## Initial Layout

- `docs/` - architecture notes, workflows, research methodology, and project decisions
- `data/` - curated indexes, normalized metadata, and generated research artifacts
- `services/` - MCP/REST services and service integration points
- `tools/` - importers, converters, disassembly helpers, and analysis scripts
- `workspaces/` - frontend and analyst-facing project workspaces

Large ROM images, generated disassembly listings, and extracted binary assets should not be committed directly until the storage policy is explicit.

## Current Source Projects

Known upstream working areas:

- `../pdf-book2md/mcp-server` - current MCP/REST server and reverse-engineering dashboard
- `../stackimport` - ROM disassembly and resource extraction tooling
- `../supermario/base/SuperMarioProj.1994-02-09` - SuperMario source tree used for overlays
- `~/Downloads/Old_World_Mac_Roms/` - local ROM source material

## Status

This repository starts as the consolidation target. The first implementation milestone is to migrate or link the current MCP server, dashboard, stackimport outputs, ROM project metadata, and book-derived knowledge into a coherent workspace.
