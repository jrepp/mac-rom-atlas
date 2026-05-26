# Atlas Maps

`atlas/maps/` contains public, diffable project maps. These files are intended for humans, scripts, and the MCP server to consume without loading large project JSON or raw ROM bytes.

Each dataset directory should include:

- `manifest.yaml` with `dataset`, `project_id`, `name`, `updated_at`, `format_version`, and a `files` list.
- `roms.tsv` for ROM identities and stable repo-relative paths.
- `inventory.tsv` for per-ROM mapped inventory counts, source-overlap scores, and current match status.
- `regions.tsv` for broad code, table, data, resource, and disassembly ranges.
- `functions.tsv` for confirmed or candidate function labels.
- `source-overlays.tsv` for ROM/function-to-SuperMario correlation evidence.
- `source-gaps.tsv` for high-priority ROM regions that still lack confirmed source coverage.
- `pointer-tables.tsv` for table-like pointer regions.
- `resources.tsv` for ROM resource markers and converted resource metadata.
- `data-regions.tsv` for non-code or mixed regions.
- `labels.tsv` for address labels used by IDA-like overlays.
- `strings.tsv` for extracted string locations when string rows are published.
- `traps.tsv` for trap sites when trap rows are published.
- `xrefs.tsv` for cross references when xref rows are published.
- `notes/*.md` for analyst-authored Markdown notes with YAML front matter.

Rules:

- Use uppercase 8-digit hex addresses without `0x`.
- Keep rows sorted by address or stable ID.
- Keep paths repo-relative.
- Store evidence and confidence with generated or analyst-authored claims.
- Do not publish raw ROM bytes, full memory pages, or full disassembly listings here.
