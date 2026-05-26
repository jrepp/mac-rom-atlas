# Architecture

`mac-rom-atlas` should separate source material, generated analysis, and analyst-authored knowledge.

## Domains

### References

Book and manual extraction data, including instruction descriptions, trap references, hardware notes, and historical implementation context.

### ROMs

ROM import metadata, hashes, memory maps, headers, machine families, resource markers, and derived regions. Raw ROM files should remain external or move to an explicit large-file storage plan.

### Disassembly

Disassembly listings, indexes, xrefs, function hypotheses, data/table overlays, instruction semantics, runtime behavior notes, and SuperMario source-name candidates.

### Resources

Converted ROM resources such as cursors, bitmaps, fonts, icons, menus, strings, drivers, and related metadata.

### Workspaces

User-facing workflows for:

- reverse engineering and programmer navigation
- resource and data browsing
- project maps, notes, and research summaries

## Storage Principles

- Keep raw source artifacts separate from normalized indexes.
- Avoid write amplification by splitting large project state into addressable files.
- Store generated overlays in a way that can be rebuilt from ROMs, disassembly, source, and notes.
- Treat function boundaries, code/data splits, and source overlays as hypotheses unless confirmed by control flow and references.
- Use repo-relative atlas paths in project metadata, not machine-local absolute paths.
- Do not commit raw ROM bytes, source PDFs, or full memory-page dumps to the public repo without an explicit storage policy.

## Publication Format

Public, diffable atlas data lives under `atlas/maps/<dataset>/`:

- `manifest.yaml` identifies the dataset and generated files.
- `roms.tsv` lists ROM identities, stable paths, hashes, and base addresses.
- `inventory.tsv` summarizes the mapped inventory for each ROM and the current SuperMario match status.
- `regions.tsv` is a broad map of code, table, data, resource, and disassembly regions.
- `source-overlays.tsv` records correlation evidence between ROM addresses or ROM identities and SuperMario source paths/symbols.
- `source-gaps.tsv` records high-priority ROM regions that still have no confirmed SuperMario source coverage.
- `functions.tsv`, `pointer-tables.tsv`, `data-regions.tsv`, `resources.tsv`, `labels.tsv`, `strings.tsv`, `traps.tsv`, and `xrefs.tsv` provide workflow-specific indexes.
- `notes/*.md` stores analyst-authored context with YAML front matter.

The MCP server treats these files as overlay indexes. Project JSON remains the working database; atlas maps are the public interchange surface.

## Service Principles

- Expose project data through MCP and REST APIs.
- Keep frontend workflows query-driven rather than loading whole ROM-scale state into the browser.
- Make every annotation traceable to its source: stackimport, source overlay, manual knowledge, structure analysis, or analyst note.

## Validation Flow

`npm run validate` is the shared local and CI gate. It validates JSON parsing, project graph consistency, atlas TSV schemas, generated map freshness, local-path leaks, tracked raw artifacts, dashboard JavaScript syntax, and the MCP TypeScript build.
