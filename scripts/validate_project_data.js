#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { execFileSync } = require("child_process");

const repoRoot = path.resolve(__dirname, "..");
const failures = [];

function fail(message) {
  failures.push(message);
}

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir)) {
    const full = path.join(dir, entry);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      if (entry === "node_modules" || entry === "dist" || entry === "memory-pages") continue;
      walk(full, out);
    } else {
      out.push(full);
    }
  }
  return out;
}

function rel(file) {
  return path.relative(repoRoot, file);
}

function parseJsonFiles() {
  const roots = [
    path.join(repoRoot, "services", "mcp-server", "data"),
    path.join(repoRoot, "workspaces")
  ];
  for (const file of roots.flatMap((root) => walk(root)).filter((item) => item.endsWith(".json"))) {
    try {
      JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (error) {
      fail(`${rel(file)} is invalid JSON: ${error.message}`);
    }
  }
}

function validateNoLocalPaths() {
  const files = execFileSync("git", ["ls-files"], { cwd: repoRoot, encoding: "utf8" })
    .split(/\r?\n/u)
    .filter(Boolean)
    .filter((file) =>
      file.startsWith("atlas/maps/") ||
      file.startsWith("services/mcp-server/data/") ||
      file.startsWith("workspaces/")
    )
    .filter((file) => /\.(json|ya?ml|tsv|md)$/u.test(file));
  const forbidden = [
    /\/Users\/[^\s"')]+/u,
    /~\/Downloads/u,
    /\/tmp\/[^\s"')]+/u
  ];
  for (const file of files) {
    const text = fs.readFileSync(path.join(repoRoot, file), "utf8");
    for (const pattern of forbidden) {
      const match = text.match(pattern);
      if (match) fail(`${file} contains machine-local path '${match[0]}'`);
    }
  }
}

function parseTsv(file) {
  const text = fs.readFileSync(file, "utf8");
  const lines = text.split(/\r?\n/u);
  if (lines.at(-1) !== "") fail(`${rel(file)} must end with a newline`);
  const nonEmpty = lines.filter((line) => line.length > 0);
  if (nonEmpty.length === 0) {
    fail(`${rel(file)} is empty`);
    return { headers: [], rows: [] };
  }
  const headers = nonEmpty[0].split("\t");
  const rows = [];
  nonEmpty.slice(1).forEach((line, index) => {
    const cells = line.split("\t");
    if (cells.length !== headers.length) {
      fail(`${rel(file)}:${index + 2} has ${cells.length} cells; expected ${headers.length}`);
    }
    rows.push(Object.fromEntries(headers.map((header, cellIndex) => [header, cells[cellIndex] ?? ""])));
  });
  return { headers, rows };
}

function validAddress(value) {
  return !value || /^[0-9A-F]{8}$/u.test(value);
}

function validateAtlasMaps() {
  const root = path.join(repoRoot, "atlas", "maps");
  const required = {
    "roms.tsv": ["id", "name", "base_address", "path", "size", "crc32", "sha256", "family", "imported_at"],
    "regions.tsv": ["id", "start", "end", "kind", "name", "confidence", "source", "summary"],
    "functions.tsv": ["id", "address", "end", "name", "calls", "jumps", "references", "confidence", "source", "evidence"],
    "pointer-tables.tsv": ["id", "address", "end", "name", "entries", "byte_length", "confidence", "source"],
    "resources.tsv": ["id", "address", "kind", "resource_type", "resource_id", "name", "media_type", "output_file", "confidence", "source"],
    "data-regions.tsv": ["id", "start", "end", "kind", "name", "items", "confidence", "source", "evidence"],
    "strings.tsv": ["id", "address", "kind", "value", "length", "source", "page"],
    "traps.tsv": ["id", "address", "name", "trap_word", "manager", "description", "source"],
    "labels.tsv": ["id", "address", "name", "kind", "confidence", "source", "target"],
    "xrefs.tsv": ["id", "from", "to", "kind", "source_node", "target_node", "line", "confidence", "source"]
  };
  for (const dataset of fs.existsSync(root) ? fs.readdirSync(root).sort() : []) {
    const datasetDir = path.join(root, dataset);
    if (!fs.statSync(datasetDir).isDirectory()) continue;
    for (const [file, headers] of Object.entries(required)) {
      const full = path.join(datasetDir, file);
      if (!fs.existsSync(full)) {
        fail(`${rel(full)} is missing`);
        continue;
      }
      const parsed = parseTsv(full);
      if (parsed.headers.join("\t") !== headers.join("\t")) {
        fail(`${rel(full)} has unexpected headers: ${parsed.headers.join(", ")}`);
      }
      for (const row of parsed.rows) {
        for (const key of ["address", "base_address", "start", "end", "from", "to"]) {
          if (row[key] && /^[0-9A-Fa-f]{6,}$/u.test(row[key]) && !validAddress(row[key])) {
            fail(`${rel(full)} has non-normalized ${key}: ${row[key]}`);
          }
        }
      }
    }
  }
}

function validateDashboardScript() {
  const htmlFile = path.join(repoRoot, "services", "mcp-server", "public", "index.html");
  if (!fs.existsSync(htmlFile)) return;
  const html = fs.readFileSync(htmlFile, "utf8");
  const script = html.match(/<script>([\s\S]*)<\/script>/u)?.[1];
  if (!script) {
    fail("services/mcp-server/public/index.html has no inline script to validate");
    return;
  }
  try {
    new vm.Script(script);
  } catch (error) {
    fail(`dashboard script does not parse: ${error.message}`);
  }
}

function validateGeneratedMapsCurrent() {
  try {
    execFileSync("node", ["tools/export_atlas_maps.js", "--check"], { cwd: repoRoot, stdio: "pipe" });
  } catch (error) {
    fail(String(error.stderr || error.stdout || error.message).trim());
  }
}

parseJsonFiles();
validateNoLocalPaths();
validateAtlasMaps();
validateDashboardScript();
validateGeneratedMapsCurrent();

if (failures.length > 0) {
  console.error(`Project data validation failed:\n- ${failures.join("\n- ")}`);
  process.exit(1);
}

console.log("Project data validation passed");
