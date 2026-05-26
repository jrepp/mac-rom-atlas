# M68K MCP Server

MCP and REST server for the `mac-rom-atlas` reverse-engineering workspace. It serves the transformed Motorola M68000 reference data, Toolbox/OS trap data, persistent ROM project analysis JSON, and the browser frontend.

## Setup

```sh
npm install
npm run parse
npm run build
```

## Run Modes

```sh
npm run start:rest   # REST API and web UI on http://localhost:3000
npm run start:mcp    # MCP stdio only
npm start            # REST API plus MCP stdio
```

Useful environment variables:

- `PORT=3000` changes the REST port.
- `MCP_STDIO=false` disables MCP stdio.
- `REST_API=false` disables the REST API.
- `KNOWLEDGE_BASE_PATH=/path/to/knowledge_base.json` loads a custom knowledge base.
- `PROJECTS_PATH=/path/to/projects.json` changes where reverse-engineering project state is stored.
- `PROJECTS_DIR=/path/to/projects` changes where split project state is stored.
- `STACKIMPORT_BIN=/path/to/stackimport` points at a stackimport binary. The default atlas location is `tools/stackimport/build/stackimport`.
- `SUPERMARIO_SOURCE_DIR=/path/to/SuperMarioProj.1994-02-09` points at source data for overlays. The default atlas location is `data/sources/SuperMarioProj.1994-02-09`.
- `ROM_ANALYSIS_DIR=/path/to/output` changes where generated disassembly analysis artifacts are written.

Default data locations are repo-internal and stable:

- `services/mcp-server/data/knowledge_base.json`
- `services/mcp-server/data/traps.json`
- `services/mcp-server/data/projects/`
- `data/roms/`
- `data/disassembly/`
- `data/sources/`

## REST API

- `GET /api` lists available routes.
- `GET /api/health` returns server and knowledge-base status.
- `GET /api/instructions/:mnemonic` looks up instructions, including size suffixes such as `MOVE.W`.
- `POST /api/annotate` accepts `{ "assembly": "MOVE.W D0,D1" }` and returns a summary plus line annotations.
- `POST /api/annotate` also accepts disassembly listings with address/opcode columns, for example `00000000  48E7 0F38  movem.l -[A7], D4,D5`.
- `POST /api/analyze` returns annotation output plus disassembly-level insights such as symbols, Mac OS traps, embedded data, pstrings, pseudo-ops, and code/data segmentation warnings.
- `GET /api/projects` lists persisted reverse-engineering projects.
- `POST /api/projects` creates a project with `{ "name": "My ROM" }`.
- `POST /api/projects/:id/import-analysis` imports an analyzed listing into the project graph.
- `POST /api/projects/:id/roms` imports ROM metadata, memory pages, and optional trap definitions into the graph.
- `GET /api/projects/:id/memory/:address?length=16` reads bytes from imported ROM memory pages.
- `POST /api/projects/:id/nodes`, `/edges`, and `/notes` let agents persist manual discoveries.
- `GET /api/projects/:id/types` lists user-defined project types.
- `POST /api/projects/:id/types` defines or updates a type such as a `struct`, `enum`, `alias`, or `signature`.
- `POST /api/projects/:id/apply-type` links a project node to a type with a `typed_as` edge.

`POST /api/analyze` also emits first-pass reverse-engineering type hints:

- `stack_frame` for `LINK A6, ...` frames and `[A6 +/- offset]` slots.
- `structure_candidates` for repeated `[Ax + offset]` field accesses.
- `call_arguments` for stack pushes observed before calls and traps.
- `memory_references` for all parsed base-register memory references.
- `GET /api/search?q=decimal%20carry&type=instructions&limit=5` searches with BM25 ranking.
- `GET /api/sections/:id` accepts `1`, `section_1_introduction`, or section slugs.

The embedded test UI is served from `/` when the REST API is enabled.

## MCP Tools

- `annotate_instructions`
- `analyze_disassembly`
- `get_instruction_help`
- `get_section_guide`
- `search_knowledge_base`
- `list_sections`
