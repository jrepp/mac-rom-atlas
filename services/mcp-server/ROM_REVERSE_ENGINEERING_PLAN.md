# Old World Mac ROM Reverse-Engineering Plan

Durable checklist for evolving this MCP/REST server into an agent-assisted ROM reversing workspace.

## Goal

Create a project-based reverse-engineering environment for Old World Macintosh ROMs where agents can import ROMs, inspect memory, identify code/data/resources/traps, define types, record discoveries, and build a persistent graph of evidence over time.

## Phase 1: ROM Import Foundation

- [ ] Add `POST /api/projects/:id/roms/import-path`.
- [ ] Accept local ROM paths such as `data/roms/old-world/2mb/...` or an explicit user-provided absolute path.
- [ ] Extract filename metadata: date, checksum token, model names, size bucket.
- [ ] Compute file metadata: byte length, CRC32, SHA256.
- [ ] Persist source path, import timestamp, hash metadata, and inferred machine family.
- [ ] Create graph nodes for `rom`, `rom_header`, `checksum`, `machine_model`, and `memory_page`.
- [ ] Store memory pages with configurable page size and address metadata.
- [ ] Add import safeguards for missing files, huge files, duplicate ROMs, and invalid paths.

## Phase 2: Memory Debugging

- [ ] Extend `GET /api/projects/:id/memory/:address` with typed reads: byte, word, long, signed, unsigned.
- [ ] Add hexdump endpoint: `GET /api/projects/:id/memory/:address/hexdump?length=256`.
- [ ] Add C-string and Pascal-string readers.
- [ ] Add pointer readers using project address mappings.
- [ ] Return graph annotations for bytes that overlap known nodes, labels, resources, traps, or regions.
- [ ] Add page-boundary handling for reads that span multiple pages.
- [ ] Add memory mapping records for file offset to runtime address.

## Phase 3: ROM Scanning

- [ ] Scan imported ROMs for ASCII strings.
- [ ] Scan imported ROMs for Pascal strings.
- [ ] Scan for resource signatures: `DRVR`, `PACK`, `INIT`, `WDEF`, `CDEF`, `MDEF`, `STR#`, `vers`, `CODE`, `PICT`, `ICON`, `MENU`, `ALRT`, `DLOG`, `DITL`.
- [ ] Detect likely resource maps and resource data boundaries.
- [ ] Detect pointer tables and vector-like tables.
- [ ] Detect A-line trap words and candidate trap tables.
- [ ] Produce code/data density maps per memory page.
- [ ] Persist scanner findings as graph nodes with provenance and confidence.

## Phase 4: Trap Database

- [ ] Create a seed Toolbox/OS trap database JSON file.
- [ ] Model trap records with selector, name, manager, arguments, return type, calling convention, and availability.
- [ ] Add API to list/search traps.
- [ ] Link `syscall` annotations and raw `Axxx` words to trap nodes.
- [ ] Support ROM-specific trap handler addresses.
- [ ] Support user edits and project-local overrides.
- [ ] Add graph edges: `invokes_trap`, `exports_trap`, `handles_trap`.

## Phase 5: Disassembly Pipeline

- [ ] Add endpoint to disassemble ROM memory ranges.
- [ ] Start with an external disassembler backend if available.
- [ ] Persist disassembly listings as analysis artifacts.
- [ ] Feed disassembly output into existing `/api/analyze` logic.
- [ ] Support recursive traversal from known entrypoints, trap handlers, and vector tables.
- [ ] Mark unresolved indirect jumps/calls for agent follow-up.
- [ ] Support both 68K and later PowerPC ROMs as separate architecture profiles.

## Phase 6: Code/Data Segmentation

- [ ] Add region nodes: `candidate_code`, `confirmed_code`, `candidate_data`, `confirmed_data`, `resource`, `padding`, `unknown`.
- [ ] Promote/demote region type through API.
- [ ] Use resource boundaries, strings, invalid opcode runs, branch targets, and trap handlers as segmentation evidence.
- [ ] Track provenance and confidence for every region classification.
- [ ] Warn when linear sweep disassembly crosses data islands.
- [ ] Add graph edges from regions to supporting evidence.

## Phase 7: Type Recovery

- [ ] Continue project-local type definitions: `struct`, `enum`, `alias`, `signature`, and custom kinds.
- [ ] Seed common Mac types: `Ptr`, `Handle`, `OSErr`, `Str255`, `Point`, `Rect`, `GrafPtr`, `WindowPtr`, `ControlHandle`, `MenuHandle`, `FSSpec`, `ParamBlockRec`.
- [ ] Infer stack frames from `LINK/UNLK` and `A6` references.
- [ ] Infer stack arguments from pushes before calls/traps.
- [ ] Infer structure fields from repeated `[Ax + offset]` accesses.
- [ ] Link inferred field candidates to user-defined structs via `typed_as` edges.
- [ ] Re-run analysis after type updates to improve names and argument decoding.

## Phase 8: Cross-ROM Diffing

- [ ] Add endpoint to compare two imported ROMs.
- [ ] Detect identical byte ranges.
- [ ] Detect moved code/data blocks.
- [ ] Compare resource sets and resource data.
- [ ] Compare trap tables and trap handlers.
- [ ] Compare strings and Pascal strings.
- [ ] Compare functions by mnemonic sequence and control-flow shape.
- [ ] Propagate labels/types from one ROM to matching regions in another with confidence.

## Phase 9: Agent Workflow

- [ ] Add work items for agents: claimed region, assigned task, status, priority.
- [ ] Add hypothesis nodes with evidence links.
- [ ] Add reviewed/unreviewed state for nodes and edges.
- [ ] Add confidence and provenance fields consistently to analysis-created graph facts.
- [ ] Add endpoints to query unresolved work: unknown code, indirect calls, unlabeled traps, untyped fields, data/code conflicts.
- [ ] Add audit trail for agent changes.

## Phase 10: UI And Usability

- [ ] Add project browser to web UI.
- [ ] Add ROM import form.
- [ ] Add memory hexdump viewer.
- [ ] Add graph summary view.
- [ ] Add type editor for structs, enums, aliases, and signatures.
- [ ] Add region list with confidence/provenance.
- [ ] Add trap lookup and trap-handler navigation.

## Implementation Notes

- Keep JSON project storage for now because it is inspectable and easy for agents to edit/debug.
- Preserve a migration path to SQLite once graph size or concurrent edits require it.
- Treat every inferred fact as editable, with provenance and confidence.
- Distinguish file offsets, ROM addresses, and runtime addresses from the beginning.
- Avoid pure linear sweep disassembly as the primary analysis method.
- Prefer small APIs that persist durable graph facts over one-off stateless analysis responses.

## Immediate Next Tasks

- [ ] Implement `import-path` for ROM files.
- [ ] Add CRC32/SHA256 hashing and filename metadata extraction.
- [ ] Add hexdump and typed memory read endpoints.
- [ ] Add string/Pascal-string scanner for imported ROM pages.
- [ ] Seed a minimal Toolbox trap database and link imported analysis to traps.
