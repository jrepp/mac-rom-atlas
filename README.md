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

## Quick Start

```sh
npm ci --prefix services/mcp-server
npm run prepare:hooks
npm run validate
```

Run the dashboard and REST API:

```sh
npm --prefix services/mcp-server run start:rest
```

Then open `http://localhost:3000`.

## Current Source Projects

Current stable internal locations:

- `services/mcp-server` - MCP/REST server and reverse-engineering dashboard
- `services/mcp-server/public` - frontend workspace
- `services/mcp-server/data/knowledge_base.json` - transformed M68000 documentation
- `services/mcp-server/data/traps.json` - Toolbox/OS trap database
- `services/mcp-server/data/projects/` - persistent project analysis data
- `tools/stackimport` - intended location for ROM disassembly and resource extraction tooling
- `data/sources/SuperMarioProj.1994-02-09` - intended local location for SuperMario source overlays
- `data/roms/` - intended local location for ROM inputs
- `data/disassembly/` - intended local location for generated disassembly artifacts

## Status

This repository now contains the MCP service, frontend, transformed 68k documentation, trap data, and split project metadata. Raw ROM files, source PDFs, generated book output, memory-page byte dumps, and full disassembly listings remain local/ignored until a public storage policy is explicit.

## Validation

The repo has a committed pre-commit hook in `.githooks/pre-commit`. Enable it once per checkout with:

```sh
npm run prepare:hooks
```

`npm run validate` checks project JSON, atlas TSV schemas, generated map freshness, frontend script syntax, tracked-artifact policy, and the MCP TypeScript build. GitHub Actions runs the same validation on pushes and pull requests.
