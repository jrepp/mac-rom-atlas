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
  "  - regions.tsv",
  "  - functions.tsv",
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
