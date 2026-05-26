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

## Service Principles

- Expose project data through MCP and REST APIs.
- Keep frontend workflows query-driven rather than loading whole ROM-scale state into the browser.
- Make every annotation traceable to its source: stackimport, source overlay, manual knowledge, structure analysis, or analyst note.
