#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

const repoRoot = path.resolve(__dirname, "..");
const args = process.argv.slice(2);
const checkMode = args.includes("--check");
const projectId = args.find((arg) => !arg.startsWith("--")) || "supermario-rom-analysis-mplc55nn";
const projectDir = path.join(repoRoot, "services", "mcp-server", "data", "projects", projectId);
const publicOutDir = path.join(repoRoot, "atlas", "maps", "supermario-rom-analysis");
const outDir = checkMode ? fs.mkdtempSync(path.join(require("os").tmpdir(), "mac-rom-atlas-maps-")) : publicOutDir;

function readJson(name) {
  return JSON.parse(fs.readFileSync(path.join(projectDir, name), "utf8"));
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function tsvEscape(value) {
  return String(value ?? "")
    .replace(/\r?\n/g, " ")
    .replace(/\t/g, " ")
    .trim();
}

function writeTsv(file, columns, rows) {
  const lines = [
    columns.join("\t"),
    ...rows.map((row) => columns.map((column) => tsvEscape(row[column])).join("\t"))
  ];
  fs.writeFileSync(path.join(outDir, file), `${lines.join("\n")}\n`);
}

function listFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  const files = [];
  for (const entry of fs.readdirSync(dir).sort()) {
    const full = path.join(dir, entry);
    if (fs.statSync(full).isDirectory()) {
      files.push(...listFiles(full));
    } else {
      files.push(full);
    }
  }
  return files;
}

function hexNumber(address) {
  if (!address) return Number.POSITIVE_INFINITY;
  const parsed = Number.parseInt(String(address).replace(/^0x/i, ""), 16);
  return Number.isFinite(parsed) ? parsed : Number.POSITIVE_INFINITY;
}

function sortedByAddress(nodes) {
  return [...nodes].sort((a, b) => hexNumber(a.address) - hexNumber(b.address) || String(a.id).localeCompare(String(b.id)));
}

function confidence(node) {
  return node.metadata?.confidence ?? node.metadata?.score ?? "";
}

function source(node) {
  return node.metadata?.source ?? "project";
}

function endAddress(node) {
  return node.metadata?.end_address ?? node.metadata?.end ?? "";
}

function label(node) {
  return node.label || node.name || node.id;
}

function crc32(value) {
  const text = String(value ?? "").trim().toUpperCase();
  if (!text) return "";
  if (/^-[0-9A-F]{1,8}$/u.test(text)) {
    const unsigned = (0x100000000 - Number.parseInt(text.slice(1), 16)) >>> 0;
    return unsigned.toString(16).toUpperCase().padStart(8, "0");
  }
  return text.replace(/^0X/u, "").padStart(8, "0");
}

function disassemblyForRom(romId) {
  return nodes.find((node) => node.type === "rom_disassembly" && node.metadata?.rom === romId);
}

function romIdForNode(node) {
  if (String(node.id).startsWith("function_candidate:")) {
    return String(node.id).replace(/^function_candidate:/u, "").replace(/:[0-9A-F]{8}$/u, "");
  }
  if (node.metadata?.rom) return node.metadata.rom;
  if (node.metadata?.disassembly) return nodes.find((candidate) => candidate.id === node.metadata.disassembly)?.metadata?.rom || "";
  return "";
}

function countNodesForRom(type, romId) {
  return nodes.filter((node) => node.type === type && (node.id.includes(romId) || node.metadata?.rom === romId)).length;
}

function sourceOverlapRows() {
  const note = notes.find((item) => /Candidate ROM evidence/iu.test(item.title || ""));
  const text = note?.text || "";
  const rows = [];
  for (const line of text.split(/\r?\n/u)) {
    const match = line.match(/^\|\s*(PowerBook 190\/190cs 1995-08|Quadra 660AV\/840AV 1994-09|PowerBook 520\/540 1994-05)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|/iu);
    if (!match) continue;
    rows.push({
      label: match[1],
      hits: Number(match[2]),
      score: Number(match[3])
    });
  }
  return rows;
}

function romOverlap(rom) {
  const overlaps = sourceOverlapRows();
  const name = label(rom).toLowerCase();
  if (name.includes("quadra-900")) return undefined;
  return overlaps.find((row) => {
    const labelText = row.label.toLowerCase();
    if (name.includes("190") && labelText.includes("190")) return true;
    if ((name.includes("660av") || name.includes("840av")) && labelText.includes("quadra")) return true;
    if ((name.includes("520") || name.includes("540")) && labelText.includes("520")) return true;
    return false;
  });
}

function sourceMatchStatus(rom) {
  const overlap = romOverlap(rom);
  if (!overlap) return "not_scored";
  if (/190/u.test(label(rom))) return "strongest_string_overlap_not_confirmed";
  if (/Quadra/u.test(label(rom))) return "disassembled_candidate_partial_overlap";
  return "candidate_lower_overlap";
}

const project = readJson("project.json");
const nodes = readJson("nodes.json");
const edges = readJson("edges.json");
const notes = readJson("notes.json");
ensureDir(outDir);
ensureDir(path.join(outDir, "notes"));

const roms = sortedByAddress(nodes.filter((node) => node.type === "rom")).sort((a, b) => String(label(a)).localeCompare(String(label(b))));
writeTsv("roms.tsv", ["id", "name", "base_address", "path", "size", "crc32", "sha256", "family", "imported_at"], roms.map((node) => ({
  id: node.id,
  name: label(node),
  base_address: node.address,
  path: node.metadata?.source_path,
  size: node.metadata?.size,
  crc32: crc32(node.metadata?.crc32),
  sha256: node.metadata?.sha256,
  family: node.metadata?.filename?.machine_family,
  imported_at: node.metadata?.import_timestamp
})));

writeTsv("inventory.tsv", ["id", "base_address", "rom_id", "name", "path", "size", "crc32", "sha256", "disassembly_id", "function_candidates", "pointer_tables", "data_regions", "resource_markers", "resource_assets", "source_overlap_hits", "source_overlap_score", "supermario_match_status", "notes"], roms.map((rom) => {
  const disassembly = disassemblyForRom(rom.id);
  const overlap = romOverlap(rom);
  return {
    id: `inventory:${rom.id}`,
    base_address: rom.address,
    rom_id: rom.id,
    name: label(rom),
    path: rom.metadata?.source_path,
    size: rom.metadata?.size,
    crc32: crc32(rom.metadata?.crc32),
    sha256: rom.metadata?.sha256,
    disassembly_id: disassembly?.id || "",
    function_candidates: countNodesForRom("function_candidate", rom.id),
    pointer_tables: countNodesForRom("pointer_table", rom.id),
    data_regions: countNodesForRom("data_region", rom.id),
    resource_markers: countNodesForRom("resource_marker", rom.id),
    resource_assets: countNodesForRom("resource_asset", rom.id),
    source_overlap_hits: overlap?.hits ?? "",
    source_overlap_score: overlap?.score ?? "",
    supermario_match_status: sourceMatchStatus(rom),
    notes: "Inventory row summarizes current mapped evidence; raw bytes and full disassembly are external."
  };
}));

const regions = sortedByAddress(nodes.filter((node) => ["function_candidate", "pointer_table", "data_region", "resource_marker", "resource_asset", "rom_disassembly"].includes(node.type)));
writeTsv("regions.tsv", ["id", "start", "end", "kind", "name", "confidence", "source", "summary"], regions.map((node) => ({
  id: node.id,
  start: node.address,
  end: endAddress(node),
  kind: node.type,
  name: label(node),
  confidence: confidence(node),
  source: source(node),
  summary: node.metadata?.context || node.metadata?.kind || node.metadata?.resource_type || node.metadata?.classification || ""
})));

const functions = sortedByAddress(nodes.filter((node) => node.type === "function_candidate" || node.type === "function"));
writeTsv("functions.tsv", ["id", "address", "end", "name", "calls", "jumps", "references", "confidence", "source", "evidence"], functions.map((node) => ({
  id: node.id,
  address: node.address,
  end: endAddress(node),
  name: label(node),
  calls: node.metadata?.calls,
  jumps: node.metadata?.jumps,
  references: node.metadata?.references,
  confidence: confidence(node),
  source: source(node),
  evidence: node.metadata?.evidence || node.metadata?.context || node.metadata?.summary
})));

writeTsv("source-overlays.tsv", ["id", "address", "rom_id", "target_kind", "target_id", "source_path", "source_symbol", "evidence_kind", "evidence", "confidence", "status"], [
  ...roms.map((rom) => {
    const overlap = romOverlap(rom);
    return {
      id: `source_overlay:${rom.id}:string-overlap`,
      address: rom.address,
      rom_id: rom.id,
      target_kind: "rom",
      target_id: rom.id,
      source_path: "data/sources/SuperMarioProj.1994-02-09",
      source_symbol: "",
      evidence_kind: "string_overlap",
      evidence: overlap ? `${overlap.hits} hits; weighted score ${overlap.score}` : "Not yet scored against SuperMario strings",
      confidence: overlap ? "medium" : "unknown",
      status: sourceMatchStatus(rom)
    };
  }),
  ...functions
    .filter((node) => node.type === "function" && node.metadata?.source === "agent_note")
    .map((node) => ({
      id: `source_overlay:${node.id}`,
      address: node.address,
      rom_id: "",
      target_kind: "function",
      target_id: node.id,
      source_path: "data/sources/SuperMarioProj.1994-02-09",
      source_symbol: node.name || "",
      evidence_kind: "manual_function_name",
      evidence: node.metadata?.evidence || "",
      confidence: confidence(node),
      status: "manual_overlay_hypothesis"
    }))
]);

const sourceGapRows = functions
  .filter((node) => node.type === "function_candidate" && source(node) !== "agent_note")
  .sort((a, b) => Number(b.metadata?.calls ?? b.metadata?.references ?? 0) - Number(a.metadata?.calls ?? a.metadata?.references ?? 0))
  .slice(0, 80)
  .map((node) => ({
    id: `source_gap:${node.id}`,
    address: node.address,
    rom_id: romIdForNode(node),
    target_kind: "function_candidate",
    target_id: node.id,
    gap_kind: "unmapped_function_candidate",
    evidence: `${node.metadata?.calls ?? 0} calls; ${node.metadata?.references ?? node.metadata?.refs?.length ?? 0} references; no confirmed SuperMario source overlay`,
    priority: Number(node.metadata?.calls ?? node.metadata?.references ?? 0) >= 40 ? "high" : "medium",
    status: "needs_source_correlation"
  }));
writeTsv("source-gaps.tsv", ["id", "address", "rom_id", "target_kind", "target_id", "gap_kind", "evidence", "priority", "status"], sourceGapRows);

const tables = sortedByAddress(nodes.filter((node) => node.type === "pointer_table"));
writeTsv("pointer-tables.tsv", ["id", "address", "end", "name", "entries", "byte_length", "confidence", "source"], tables.map((node) => ({
  id: node.id,
  address: node.address,
  end: endAddress(node),
  name: label(node),
  entries: node.metadata?.entry_count || node.metadata?.entries?.length,
  byte_length: node.metadata?.byte_length,
  confidence: confidence(node),
  source: source(node)
})));

const resources = sortedByAddress(nodes.filter((node) => node.type === "resource_marker" || node.type === "resource_asset"));
writeTsv("resources.tsv", ["id", "address", "kind", "resource_type", "resource_id", "name", "media_type", "output_file", "confidence", "source"], resources.map((node) => ({
  id: node.id,
  address: node.address,
  kind: node.type,
  resource_type: node.metadata?.resource_type,
  resource_id: node.metadata?.resource_id,
  name: label(node),
  media_type: node.metadata?.media_type,
  output_file: node.metadata?.output_file,
  confidence: confidence(node),
  source: source(node)
})));

const dataRegions = sortedByAddress(nodes.filter((node) => node.type === "data_region"));
writeTsv("data-regions.tsv", ["id", "start", "end", "kind", "name", "items", "confidence", "source", "evidence"], dataRegions.map((node) => ({
  id: node.id,
  start: node.address,
  end: endAddress(node),
  kind: node.metadata?.kind || node.metadata?.classification || "data",
  name: label(node),
  items: node.metadata?.item_count || node.metadata?.strings,
  confidence: confidence(node),
  source: source(node),
  evidence: node.metadata?.evidence || node.metadata?.context || node.metadata?.summary
})));

const strings = sortedByAddress(nodes.filter((node) => node.type === "cstring" || node.type === "pstring"));
writeTsv("strings.tsv", ["id", "address", "kind", "value", "length", "source", "page"], strings.map((node) => ({
  id: node.id,
  address: node.address,
  kind: node.type,
  value: node.metadata?.value || label(node),
  length: node.metadata?.string_length,
  source: source(node),
  page: node.metadata?.page
})));

const traps = sortedByAddress(nodes.filter((node) => node.type === "trap"));
writeTsv("traps.tsv", ["id", "address", "name", "trap_word", "manager", "description", "source"], traps.map((node) => ({
  id: node.id,
  address: node.address,
  name: label(node),
  trap_word: node.metadata?.trap_word,
  manager: node.metadata?.manager,
  description: node.metadata?.description,
  source: source(node)
})));

const labels = sortedByAddress(nodes.filter((node) =>
  node.address && ["function", "function_candidate", "symbol", "address", "pointer_table", "data_region", "resource_marker", "resource_asset", "trap"].includes(node.type)
));
writeTsv("labels.tsv", ["id", "address", "name", "kind", "confidence", "source", "target"], labels.map((node) => ({
  id: node.id,
  address: node.address,
  name: label(node),
  kind: node.type,
  confidence: confidence(node),
  source: source(node),
  target: node.metadata?.target || node.metadata?.rom || node.metadata?.disassembly_id
})));

const xrefRows = edges
  .filter((edge) => edge.metadata?.address || edge.metadata?.target || edge.metadata?.line)
  .map((edge) => ({
    id: edge.id,
    from: edge.metadata?.address || edge.from,
    to: edge.metadata?.target || edge.to,
    kind: edge.type,
    source_node: edge.from,
    target_node: edge.to,
    line: edge.metadata?.line,
    confidence: edge.metadata?.confidence,
    source: edge.metadata?.source || "project"
  }))
  .sort((a, b) => hexNumber(a.from) - hexNumber(b.from) || String(a.kind).localeCompare(String(b.kind)));
writeTsv("xrefs.tsv", ["id", "from", "to", "kind", "source_node", "target_node", "line", "confidence", "source"], xrefRows);

for (const note of notes) {
  const id = String(note.id).replace(/[^A-Za-z0-9._-]+/g, "-");
  const frontMatter = [
    "---",
    `id: ${note.id}`,
    `title: ${JSON.stringify(note.title || "Untitled note")}`,
    `target: ${note.target || ""}`,
    `kind: ${note.kind || "note"}`,
    `tags: [${(note.tags || []).map((tag) => JSON.stringify(tag)).join(", ")}]`,
    `updated_at: ${note.updated_at || note.created_at || ""}`,
    "---",
    ""
  ].join("\n");
  fs.writeFileSync(path.join(outDir, "notes", `${id}.md`), `${frontMatter}${note.text || ""}\n`);
}

const manifest = [
  "dataset: supermario-rom-analysis",
  `project_id: ${project.id}`,
  `name: ${JSON.stringify(project.name)}`,
  `updated_at: ${project.updated_at}`,
  "format_version: 1",
  "files:",
  "  - roms.tsv",
  "  - inventory.tsv",
  "  - regions.tsv",
  "  - functions.tsv",
  "  - source-overlays.tsv",
  "  - source-gaps.tsv",
  "  - pointer-tables.tsv",
  "  - resources.tsv",
  "  - data-regions.tsv",
  "  - strings.tsv",
  "  - traps.tsv",
  "  - labels.tsv",
  "  - xrefs.tsv",
  "  - notes/"
].join("\n");
fs.writeFileSync(path.join(outDir, "manifest.yaml"), `${manifest}\n`);

if (checkMode) {
  const failures = [];
  for (const generated of listFiles(outDir)) {
    const file = path.relative(outDir, generated);
    const published = path.join(publicOutDir, file);
    if (!fs.existsSync(published)) {
      failures.push(`${file} is missing from ${path.relative(repoRoot, publicOutDir)}`);
      continue;
    }
    if (fs.readFileSync(generated, "utf8") !== fs.readFileSync(published, "utf8")) {
      failures.push(`${file} is stale; run node tools/export_atlas_maps.js`);
    }
  }
  for (const published of listFiles(publicOutDir)) {
    const file = path.relative(publicOutDir, published);
    if (!fs.existsSync(path.join(outDir, file))) failures.push(`${file} is no longer generated`);
  }
  fs.rmSync(outDir, { recursive: true, force: true });
  if (failures.length > 0) {
    console.error(failures.join("\n"));
    process.exit(1);
  }
  console.log("Atlas maps are current");
} else {
  console.log(`Wrote atlas maps to ${path.relative(repoRoot, outDir)}`);
}
