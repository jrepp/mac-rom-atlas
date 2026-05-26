import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { dirname, join, resolve, basename, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool
} from "@modelcontextprotocol/sdk/types.js";
import cors from "cors";
import express, { NextFunction, Request, Response } from "express";

interface Instruction {
  name: string;
  syntax: string;
  operation: string;
  description: string;
  attributes: string;
  condition_codes: string | Record<string, string>;
  examples: string[];
  section_refs: string[];
  line_number: number;
}

interface Concept {
  line: number;
  text: string;
  type: string;
  section?: string;
}

interface KnowledgeBase {
  metadata: {
    source: string;
    total_instructions: number;
    total_concepts: number;
    sections: string[];
  };
  instructions: Instruction[];
  concepts: Concept[];
  section_boundaries: Record<string, [number, number]>;
}

interface TrapParameter {
  name: string;
  type: string;
  description: string;
}

interface TrapReturns {
  type: string;
  description: string;
}

interface ToolboxTrap {
  name: string;
  selector: string;
  trap_word: string;
  manager: string;
  description: string;
  routine: string;
  parameters: TrapParameter[];
  returns: TrapReturns;
  calling_convention: string;
  availability: string;
}

interface TrapDatabase {
  metadata: {
    source: string;
    version: string;
    total_traps: number;
    categories: string[];
  };
  traps: ToolboxTrap[];
}

type SearchType = "instructions" | "concepts" | "all";
type SearchKind = "instruction" | "concept";
type ParsedLineKind = "instruction" | "directive" | "pseudo" | "syscall";

interface ParsedAssemblyLine {
  mnemonic: string;
  operands: string;
  input: string;
  kind: ParsedLineKind;
  address?: string;
  bytes?: string[];
}

interface SearchDocument {
  id: string;
  kind: SearchKind;
  text: string;
  data: Instruction | Concept;
}

interface RankedSearchDocument extends SearchDocument {
  score: number;
}

interface SearchResult {
  type: SearchKind;
  score: number;
  data: Instruction | Concept;
}

interface Bm25Index {
  documents: SearchDocument[];
  termFrequencies: Map<string, number>[];
  documentLengths: number[];
  documentFrequency: Map<string, number>;
  averageDocumentLength: number;
}

interface DisassemblyAnnotationBase {
  line: number;
  address?: string;
  bytes?: string[];
  input: string;
  mnemonic: string;
  status: string;
  help?: string;
  trap?: string;
  data?: string;
  detail?: string;
}

interface MemoryReference {
  line: number;
  address?: string;
  mnemonic: string;
  register: string;
  offset: number;
  expression: string;
  size?: string;
}

interface ProjectNode {
  id: string;
  type: string;
  address?: string;
  name?: string;
  label?: string;
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

interface ProjectEdge {
  id: string;
  type: string;
  from: string;
  to: string;
  label?: string;
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

interface ProjectNote {
  id: string;
  title?: string;
  text: string;
  target?: string;
  tags?: string[];
  kind?: string;
  created_at: string;
  updated_at?: string;
}

interface ProjectTypeDefinition {
  id: string;
  kind: string;
  name: string;
  size?: number;
  fields?: Array<Record<string, unknown>>;
  values?: Record<string, number | string>;
  returns?: string;
  parameters?: Array<Record<string, unknown>>;
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

interface ReverseProject {
  id: string;
  name: string;
  description?: string;
  created_at: string;
  updated_at: string;
  nodes: ProjectNode[];
  edges: ProjectEdge[];
  notes: ProjectNote[];
  types: ProjectTypeDefinition[];
}

interface ProjectStore {
  projects: ReverseProject[];
}

interface SparseGraphNode {
  id: string;
  type: string;
  label?: string;
  address?: string;
  degree: {
    in: number;
    out: number;
    total: number;
  };
  attached_addresses: string[];
  metadata?: Record<string, unknown>;
}

interface SparseGraphEdge {
  id: string;
  type: string;
  from: string;
  to: string;
  label?: string;
  address?: string;
  metadata?: Record<string, unknown>;
}

interface SparseGraphOptions {
  root?: string;
  q?: string;
  depth: number;
  limit: number;
  edgeTypes?: Set<string>;
  nodeTypes?: Set<string>;
}

interface SparseGraphBuildState {
  nodes: Map<string, SparseGraphNode>;
  edges: Map<string, SparseGraphEdge>;
  out: Map<string, Array<[string, string]>>;
  in: Map<string, Array<[string, string]>>;
  byAddress: Map<string, Set<string>>;
  byType: Map<string, Set<string>>;
}

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(MODULE_DIR, "..");
const ATLAS_ROOT = resolve(PROJECT_ROOT, "..", "..");
const DATA_FILE = process.env.KNOWLEDGE_BASE_PATH
  ? resolve(process.env.KNOWLEDGE_BASE_PATH)
  : join(PROJECT_ROOT, "data", "knowledge_base.json");
const PROJECTS_FILE = process.env.PROJECTS_PATH
  ? resolve(process.env.PROJECTS_PATH)
  : join(PROJECT_ROOT, "data", "projects.json");
const PROJECTS_DIR = process.env.PROJECTS_DIR
  ? resolve(process.env.PROJECTS_DIR)
  : join(PROJECT_ROOT, "data", "projects");
const PROJECTS_INDEX_FILE = join(PROJECTS_DIR, "index.json");
const PUBLIC_DIR = join(PROJECT_ROOT, "public");
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const SERVER_VERSION = "1.0.0";
const DATA_DIRECTIVES = new Set(["DC", "DC.B", "DC.W", "DC.L", "DS", "DS.B", "DS.W", "DS.L"]);
const execFileAsync = promisify(execFile);
const STACKIMPORT_BIN = process.env.STACKIMPORT_BIN
  ? resolve(process.env.STACKIMPORT_BIN)
  : join(ATLAS_ROOT, "tools", "stackimport", "build", "stackimport");
const ROM_ANALYSIS_DIR = process.env.ROM_ANALYSIS_DIR
  ? resolve(process.env.ROM_ANALYSIS_DIR)
  : join(PROJECT_ROOT, "data", "rom-analysis");
const SUPERMARIO_SOURCE_DIR = process.env.SUPERMARIO_SOURCE_DIR
  ? resolve(process.env.SUPERMARIO_SOURCE_DIR)
  : join(ATLAS_ROOT, "data", "sources", "SuperMarioProj.1994-02-09");
const ATLAS_MAPS_DIR = process.env.ATLAS_MAPS_DIR
  ? resolve(process.env.ATLAS_MAPS_DIR)
  : join(ATLAS_ROOT, "atlas", "maps");

function loadKnowledgeBase(): KnowledgeBase {
  try {
    return JSON.parse(readFileSync(DATA_FILE, "utf8")) as KnowledgeBase;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Unable to load knowledge base at ${DATA_FILE}. Run "npm run parse" from mcp-server first. ${message}`
    );
  }
}

function nowIso(): string {
  return new Date().toISOString();
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/gu, "-").replace(/^-|-$/gu, "").slice(0, 80) || "project";
}

function storageName(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/gu, (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`);
}

function readJsonFile<T>(path: string, fallback: T): T {
  if (!existsSync(path)) return fallback;
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function writeJsonIfChanged(path: string, value: unknown) {
  mkdirSync(dirname(path), { recursive: true });
  const text = `${JSON.stringify(value, null, 2)}\n`;
  if (existsSync(path) && readFileSync(path, "utf8") === text) return false;
  writeFileSync(path, text);
  return true;
}

function splitProjectDir(projectId: string): string {
  return join(PROJECTS_DIR, storageName(projectId));
}

function loadSplitProject(projectId: string): ReverseProject | null {
  const dir = splitProjectDir(projectId);
  const meta = readJsonFile<Omit<ReverseProject, "nodes" | "edges" | "notes" | "types"> | null>(join(dir, "project.json"), null);
  if (!meta) return null;

  const nodes = readJsonFile<ProjectNode[]>(join(dir, "nodes.json"), []);
  const edges = readJsonFile<ProjectEdge[]>(join(dir, "edges.json"), []);
  const notes = readJsonFile<ProjectNote[]>(join(dir, "notes.json"), []);
  const types = readJsonFile<ProjectTypeDefinition[]>(join(dir, "types.json"), []);
  const pagesDir = join(dir, "memory-pages");
  const pageIndex = readJsonFile<{ pages?: string[] }>(join(pagesDir, "index.json"), { pages: [] });
  if (existsSync(pagesDir) && statSync(pagesDir).isDirectory()) {
    const pageFiles = pageIndex.pages?.length
      ? pageIndex.pages.map((id) => `${storageName(id)}.json`)
      : readdirSync(pagesDir).filter((file) => file.endsWith(".json") && file !== "index.json");
    for (const file of pageFiles) {
      const page = readJsonFile<ProjectNode | null>(join(pagesDir, file), null);
      if (page) nodes.push(page);
    }
  }

  return { ...meta, nodes, edges, notes, types };
}

function loadSplitProjectStore(): ProjectStore | null {
  if (!existsSync(PROJECTS_DIR)) return null;

  const index = readJsonFile<{ projects?: Array<{ id: string }> }>(PROJECTS_INDEX_FILE, { projects: [] });
  const ids = index.projects?.length
    ? index.projects.map((project) => project.id)
    : readdirSync(PROJECTS_DIR)
      .filter((entry) => {
        const dir = join(PROJECTS_DIR, entry);
        return statSync(dir).isDirectory() && existsSync(join(dir, "project.json"));
      })
      .map((entry) => decodeURIComponent(entry));

  const projects = ids
    .map((id) => loadSplitProject(id))
    .filter((project): project is ReverseProject => Boolean(project));
  return projects.length > 0 ? { projects } : null;
}

function saveSplitProject(project: ReverseProject) {
  const dir = splitProjectDir(project.id);
  const memoryPages = project.nodes.filter((node) => node.type === "memory_page");
  const regularNodes = project.nodes.filter((node) => node.type !== "memory_page");
  writeJsonIfChanged(join(dir, "project.json"), {
    id: project.id,
    name: project.name,
    description: project.description,
    created_at: project.created_at,
    updated_at: project.updated_at
  });
  writeJsonIfChanged(join(dir, "nodes.json"), regularNodes);
  writeJsonIfChanged(join(dir, "edges.json"), project.edges);
  writeJsonIfChanged(join(dir, "notes.json"), project.notes);
  writeJsonIfChanged(join(dir, "types.json"), project.types);
  writeJsonIfChanged(join(dir, "memory-pages", "index.json"), {
    pages: memoryPages.map((page) => page.id)
  });
  for (const page of memoryPages) {
    writeJsonIfChanged(join(dir, "memory-pages", `${storageName(page.id)}.json`), page);
  }
}

function loadProjectStore(): ProjectStore {
  const splitStore = loadSplitProjectStore();
  const store = splitStore ?? (existsSync(PROJECTS_FILE) ? JSON.parse(readFileSync(PROJECTS_FILE, "utf8")) as ProjectStore : { projects: [] });
  for (const project of store.projects) {
    project.nodes ??= [];
    project.edges ??= [];
    project.notes ??= [];
    project.types ??= [];
  }
  return store;
}

const projectEventClients = new Set<Response>();

function sendProjectEvent(client: Response, event: string, payload: unknown) {
  client.write(`event: ${event}\n`);
  client.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function broadcastProjectEvent(event: string, payload: unknown) {
  for (const client of projectEventClients) {
    sendProjectEvent(client, event, payload);
  }
}

function saveProjectStore(store: ProjectStore) {
  mkdirSync(PROJECTS_DIR, { recursive: true });
  for (const project of store.projects) saveSplitProject(project);
  writeJsonIfChanged(PROJECTS_INDEX_FILE, {
    format: "split-project-store-v1",
    updated_at: nowIso(),
    projects: store.projects.map(graphSummary)
  });
  broadcastProjectEvent("projects", {
    timestamp: nowIso(),
    projects: store.projects.map(graphSummary)
  });
}

function createProject(name: string, description?: string): ReverseProject {
  const timestamp = nowIso();
  return {
    id: `${slug(name)}-${Date.now().toString(36)}`,
    name,
    description,
    created_at: timestamp,
    updated_at: timestamp,
    nodes: [],
    edges: [],
    notes: [],
    types: []
  };
}

function withProject(projectId: string, callback: (project: ReverseProject) => unknown) {
  const store = loadProjectStore();
  const project = store.projects.find((candidate) => candidate.id === projectId);
  if (!project) return null;

  const result = callback(project);
  project.updated_at = nowIso();
  saveProjectStore(store);
  return result;
}

function upsertNode(project: ReverseProject, input: Omit<ProjectNode, "created_at" | "updated_at">): ProjectNode {
  const timestamp = nowIso();
  const existing = project.nodes.find((node) => node.id === input.id);
  if (existing) {
    existing.type = input.type;
    existing.address = input.address ?? existing.address;
    existing.name = input.name ?? existing.name;
    existing.label = input.label ?? existing.label;
    existing.metadata = { ...(existing.metadata ?? {}), ...(input.metadata ?? {}) };
    existing.updated_at = timestamp;
    return existing;
  }

  const node = { ...input, created_at: timestamp, updated_at: timestamp };
  project.nodes.push(node);
  return node;
}

function upsertEdge(project: ReverseProject, input: Omit<ProjectEdge, "created_at" | "updated_at">): ProjectEdge {
  const timestamp = nowIso();
  const existing = project.edges.find((edge) => edge.id === input.id);
  if (existing) {
    existing.type = input.type;
    existing.from = input.from;
    existing.to = input.to;
    existing.label = input.label ?? existing.label;
    existing.metadata = { ...(existing.metadata ?? {}), ...(input.metadata ?? {}) };
    existing.updated_at = timestamp;
    return existing;
  }

  const edge = { ...input, created_at: timestamp, updated_at: timestamp };
  project.edges.push(edge);
  return edge;
}

function upsertType(project: ReverseProject, input: Omit<ProjectTypeDefinition, "created_at" | "updated_at">): ProjectTypeDefinition {
  const timestamp = nowIso();
  const existing = project.types.find((type) => type.id === input.id || type.name === input.name);
  if (existing) {
    existing.kind = input.kind;
    existing.name = input.name;
    existing.size = input.size ?? existing.size;
    existing.fields = input.fields ?? existing.fields;
    existing.values = input.values ?? existing.values;
    existing.returns = input.returns ?? existing.returns;
    existing.parameters = input.parameters ?? existing.parameters;
    existing.metadata = { ...(existing.metadata ?? {}), ...(input.metadata ?? {}) };
    existing.updated_at = timestamp;
    upsertTypeNode(project, existing);
    return existing;
  }

  const type = { ...input, created_at: timestamp, updated_at: timestamp };
  project.types.push(type);
  upsertTypeNode(project, type);
  return type;
}

function upsertTypeNode(project: ReverseProject, type: ProjectTypeDefinition) {
  upsertNode(project, {
    id: nodeId("type", type.id),
    type: "type_definition",
    name: type.name,
    label: `${type.kind} ${type.name}`,
    metadata: {
      kind: type.kind,
      size: type.size,
      fields: type.fields,
      values: type.values,
      returns: type.returns,
      parameters: type.parameters
    }
  });
}

function nodeId(type: string, key: string): string {
  return `${type}:${key}`;
}

function edgeId(type: string, from: string, to: string): string {
  return `${type}:${from}->${to}`;
}

function graphSummary(project: ReverseProject) {
  return {
    id: project.id,
    name: project.name,
    description: project.description,
    created_at: project.created_at,
    updated_at: project.updated_at,
    counts: {
      nodes: project.nodes.length,
      edges: project.edges.length,
      notes: project.notes.length,
      types: project.types.length
    },
    node_types: groupCounts(project.nodes.map((node) => node.type)),
    edge_types: groupCounts(project.edges.map((edge) => edge.type)),
    type_kinds: groupCounts(project.types.map((type) => type.kind))
  };
}

function sparseGraphOptions(query: Record<string, unknown>): SparseGraphOptions {
  const readSet = (value: unknown) => typeof value === "string" && value.trim()
    ? new Set(value.split(",").map((item) => item.trim()).filter(Boolean))
    : undefined;
  return {
    root: typeof query.root === "string" && query.root.trim() ? query.root.trim() : undefined,
    q: typeof query.q === "string" && query.q.trim() ? query.q.trim().toLowerCase() : undefined,
    depth: Math.max(0, Math.min(4, Number(query.depth ?? 1) || 1)),
    limit: Math.max(25, Math.min(2000, Number(query.limit ?? 500) || 500)),
    edgeTypes: readSet(query.edgeTypes),
    nodeTypes: readSet(query.nodeTypes)
  };
}

function compactGraphMetadata(metadata?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!metadata) return undefined;
  const compact: Record<string, unknown> = {};
  const skip = new Set(["data_hex", "data_base64", "bytes", "raw", "lines", "entries", "refs"]);
  for (const [key, value] of Object.entries(metadata)) {
    if (skip.has(key)) continue;
    if (typeof value === "string") compact[key] = value.length > 160 ? `${value.slice(0, 157)}...` : value;
    else if (typeof value === "number" || typeof value === "boolean" || value === null) compact[key] = value;
    else if (Array.isArray(value)) compact[key] = value.slice(0, 8);
  }
  return Object.keys(compact).length ? compact : undefined;
}

function createGraphState(): SparseGraphBuildState {
  return {
    nodes: new Map(),
    edges: new Map(),
    out: new Map(),
    in: new Map(),
    byAddress: new Map(),
    byType: new Map()
  };
}

function registerSparseNode(state: SparseGraphBuildState, node: Omit<SparseGraphNode, "degree" | "attached_addresses"> & { attached_addresses?: string[] }) {
  const existing = state.nodes.get(node.id);
  const attached = new Set([...(existing?.attached_addresses ?? []), ...(node.attached_addresses ?? []), node.address].filter((value): value is string => Boolean(value)));
  const next: SparseGraphNode = {
    id: node.id,
    type: node.type,
    label: node.label ?? existing?.label,
    address: node.address ?? existing?.address,
    degree: existing?.degree ?? { in: 0, out: 0, total: 0 },
    attached_addresses: [...attached].sort(),
    metadata: node.metadata ?? existing?.metadata
  };
  state.nodes.set(next.id, next);

  const byType = state.byType.get(next.type) ?? new Set<string>();
  byType.add(next.id);
  state.byType.set(next.type, byType);

  for (const address of next.attached_addresses) {
    const byAddress = state.byAddress.get(address) ?? new Set<string>();
    byAddress.add(next.id);
    state.byAddress.set(address, byAddress);
  }
}

function registerSparseEdge(state: SparseGraphBuildState, edge: SparseGraphEdge) {
  if (state.edges.has(edge.id) || !state.nodes.has(edge.from) || !state.nodes.has(edge.to)) return;
  state.edges.set(edge.id, edge);
  const out = state.out.get(edge.from) ?? [];
  out.push([edge.to, edge.id]);
  state.out.set(edge.from, out);
  const inbound = state.in.get(edge.to) ?? [];
  inbound.push([edge.from, edge.id]);
  state.in.set(edge.to, inbound);
}

function addressNodeId(address: string) {
  return `address:${address}`;
}

function rootNodeCandidates(project: ReverseProject, root?: string): string[] {
  if (!root) return [];
  const normalized = normalizeGraphAddress(root);
  if (normalized) {
    const matching = project.nodes.filter((node) => normalizeGraphAddress(node.address) === normalized).map((node) => node.id);
    return [addressNodeId(normalized), ...matching];
  }
  return [root];
}

function serializeAdjacency<T>(map: Map<string, T[]>): Record<string, T[]> {
  return Object.fromEntries([...map.entries()].sort((a, b) => a[0].localeCompare(b[0])));
}

function serializeSetMap(map: Map<string, Set<string>>): Record<string, string[]> {
  return Object.fromEntries([...map.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([key, value]) => [key, [...value].sort()]));
}

function buildSparseLinkageGraph(project: ReverseProject, query: Record<string, unknown>) {
  const options = sparseGraphOptions(query);
  const state = createGraphState();
  const addProjectNode = (node: ProjectNode) => {
    const address = normalizeGraphAddress(node.address);
    registerSparseNode(state, {
      id: node.id,
      type: node.type,
      label: node.label ?? node.name ?? node.id,
      address,
      metadata: compactGraphMetadata(node.metadata)
    });
    if (address) {
      registerSparseNode(state, {
        id: addressNodeId(address),
        type: "address",
        label: address,
        address,
        attached_addresses: [address]
      });
    }
  };

  for (const node of project.nodes) addProjectNode(node);

  for (const edge of project.edges) {
    const from = state.nodes.has(edge.from) ? edge.from : undefined;
    const to = state.nodes.has(edge.to) ? edge.to : undefined;
    if (!from || !to) continue;
    const address = normalizeGraphAddress(typeof edge.metadata?.address === "string" ? edge.metadata.address : undefined);
    registerSparseEdge(state, {
      id: edge.id,
      type: edge.type,
      from,
      to,
      label: edge.label,
      address,
      metadata: compactGraphMetadata(edge.metadata)
    });
  }

  for (const node of project.nodes) {
    const address = normalizeGraphAddress(node.address);
    if (!address || !state.nodes.has(node.id)) continue;
    registerSparseEdge(state, {
      id: edgeId("attached_address", node.id, addressNodeId(address)),
      type: "attached_address",
      from: node.id,
      to: addressNodeId(address),
      address,
      label: address
    });
  }

  for (const disassembly of project.nodes.filter((node) => node.type === "rom_disassembly")) {
    try {
      const index = buildDisassemblyFileIndex(disassemblyPathForNode(disassembly));
      for (const [from, refs] of index.xrefsFrom.entries()) {
        const fromAddress = normalizeGraphAddress(from);
        if (!fromAddress) continue;
        registerSparseNode(state, { id: addressNodeId(fromAddress), type: "address", label: fromAddress, address: fromAddress, attached_addresses: [fromAddress] });
        for (const ref of refs) {
          const toAddress = normalizeGraphAddress(ref.to);
          if (!toAddress) continue;
          registerSparseNode(state, { id: addressNodeId(toAddress), type: "address", label: toAddress, address: toAddress, attached_addresses: [toAddress] });
          registerSparseEdge(state, {
            id: `xref:${disassembly.id}:${ref.kind}:${fromAddress}->${toAddress}:${ref.line}`,
            type: ref.kind,
            from: addressNodeId(fromAddress),
            to: addressNodeId(toAddress),
            address: fromAddress,
            label: ref.mnemonic,
            metadata: { disassembly: disassembly.id, line: ref.line, mnemonic: ref.mnemonic }
          });
        }
      }
    } catch {
      continue;
    }
  }

  const rootCandidates = rootNodeCandidates(project, options.root).filter((id) => state.nodes.has(id));
  const searchHits = options.q
    ? [...state.nodes.values()]
      .filter((node) => [node.id, node.type, node.label, node.address, ...(node.attached_addresses ?? [])].some((value) => String(value ?? "").toLowerCase().includes(options.q ?? "")))
      .map((node) => node.id)
    : [];
  const seeds = rootCandidates.length ? rootCandidates : searchHits;
  const reachable = new Set<string>();

  if (seeds.length) {
    const queue = seeds.map((id) => ({ id, depth: 0 }));
    for (const seed of seeds) reachable.add(seed);
    for (let index = 0; index < queue.length && reachable.size < options.limit; index++) {
      const item = queue[index];
      if (item.depth >= options.depth) continue;
      const links = [...(state.out.get(item.id) ?? []), ...(state.in.get(item.id) ?? []).map(([from, edge]) => [from, edge] as [string, string])];
      for (const [next] of links) {
        if (reachable.has(next)) continue;
        reachable.add(next);
        queue.push({ id: next, depth: item.depth + 1 });
        if (reachable.size >= options.limit) break;
      }
    }
  } else {
    const preferred = new Map([
      ["call", 0],
      ["jump", 1],
      ["branch", 2],
      ["memory", 3],
      ["reference", 4],
      ["attached_address", 5]
    ]);
    const candidateEdges = [...state.edges.values()].sort((a, b) => {
      const priority = (preferred.get(a.type) ?? 99) - (preferred.get(b.type) ?? 99);
      return priority || a.type.localeCompare(b.type) || a.id.localeCompare(b.id);
    });
    for (const edge of candidateEdges) {
      reachable.add(edge.from);
      reachable.add(edge.to);
      if (reachable.size >= options.limit) break;
    }
  }

  let nodes = [...reachable].map((id) => state.nodes.get(id)).filter((node): node is SparseGraphNode => Boolean(node));
  if (options.nodeTypes) nodes = nodes.filter((node) => options.nodeTypes?.has(node.type));
  const nodeIds = new Set(nodes.map((node) => node.id));
  let edges = [...state.edges.values()].filter((edge) => nodeIds.has(edge.from) && nodeIds.has(edge.to));
  if (options.edgeTypes) edges = edges.filter((edge) => options.edgeTypes?.has(edge.type));
  edges = edges.slice(0, options.limit * 4);

  const degrees = new Map<string, { in: number; out: number }>();
  for (const edge of edges) {
    degrees.set(edge.from, { in: degrees.get(edge.from)?.in ?? 0, out: (degrees.get(edge.from)?.out ?? 0) + 1 });
    degrees.set(edge.to, { in: (degrees.get(edge.to)?.in ?? 0) + 1, out: degrees.get(edge.to)?.out ?? 0 });
  }
  nodes = nodes
    .map((node) => {
      const degree = degrees.get(node.id) ?? { in: 0, out: 0 };
      return { ...node, degree: { in: degree.in, out: degree.out, total: degree.in + degree.out } };
    })
    .sort((a, b) => b.degree.total - a.degree.total || a.id.localeCompare(b.id))
    .slice(0, options.limit);

  const finalNodeIds = new Set(nodes.map((node) => node.id));
  edges = edges.filter((edge) => finalNodeIds.has(edge.from) && finalNodeIds.has(edge.to));
  const out = new Map<string, Array<[string, string]>>();
  const inbound = new Map<string, Array<[string, string]>>();
  const byAddress = new Map<string, Set<string>>();
  const byType = new Map<string, Set<string>>();
  for (const node of nodes) {
    const typeSet = byType.get(node.type) ?? new Set<string>();
    typeSet.add(node.id);
    byType.set(node.type, typeSet);
    for (const address of node.attached_addresses) {
      const addressSet = byAddress.get(address) ?? new Set<string>();
      addressSet.add(node.id);
      byAddress.set(address, addressSet);
    }
  }
  for (const edge of edges) {
    const outgoing = out.get(edge.from) ?? [];
    outgoing.push([edge.to, edge.id]);
    out.set(edge.from, outgoing);
    const incoming = inbound.get(edge.to) ?? [];
    incoming.push([edge.from, edge.id]);
    inbound.set(edge.to, incoming);
  }

  return {
    project: graphSummary(project),
    query: {
      root: options.root,
      q: options.q,
      depth: options.depth,
      limit: options.limit,
      edge_types: options.edgeTypes ? [...options.edgeTypes] : undefined,
      node_types: options.nodeTypes ? [...options.nodeTypes] : undefined
    },
    nodes,
    edges,
    adjacency: {
      out: serializeAdjacency(out),
      in: serializeAdjacency(inbound),
      by_address: serializeSetMap(byAddress),
      by_type: serializeSetMap(byType)
    },
    stats: {
      total_nodes: state.nodes.size,
      total_edges: state.edges.size,
      returned_nodes: nodes.length,
      returned_edges: edges.length,
      indexed_addresses: state.byAddress.size
    }
  };
}

const kb = loadKnowledgeBase();
const instructionByName = new Map(kb.instructions.map((instruction) => [instruction.name.toUpperCase(), instruction]));
const searchIndex = buildBm25Index(kb);

const TRAPS_FILE = process.env.TRAPS_PATH
  ? resolve(process.env.TRAPS_PATH)
  : join(PROJECT_ROOT, "data", "traps.json");

function loadTrapDatabase(): TrapDatabase {
  try {
    return JSON.parse(readFileSync(TRAPS_FILE, "utf8")) as TrapDatabase;
  } catch {
    return { metadata: { source: "", version: "0", total_traps: 0, categories: [] }, traps: [] };
  }
}

const trapDb = loadTrapDatabase();
const trapByWord = new Map<string, ToolboxTrap>();
const trapByName = new Map<string, ToolboxTrap>();

for (const trap of trapDb.traps) {
  if (trap.trap_word) trapByWord.set(trap.trap_word.toUpperCase(), trap);
  if (trap.name) trapByName.set(trap.name.toUpperCase(), trap);
}

function findTrapByWord(word: string): ToolboxTrap | undefined {
  return trapByWord.get(word.toUpperCase().replace(/^0x/, ""));
}

function findTrapByName(name: string): ToolboxTrap | undefined {
  return trapByName.get(name.toUpperCase().replace(/^_/, ""));
}

const tools: Tool[] = [
  {
    name: "annotate_instructions",
    description: "Annotate M68000 assembly with line-by-line instruction help.",
    inputSchema: {
      type: "object",
      properties: {
        assembly: {
          type: "string",
          description: "M68000 assembly code to annotate. Labels, comments, and size suffixes are supported."
        }
      },
      required: ["assembly"]
    }
  },
  {
    name: "analyze_disassembly",
    description: "Summarize a M68000 disassembly listing, including embedded data, pseudo-ops, symbols, and Mac OS trap/syscall rows.",
    inputSchema: {
      type: "object",
      properties: {
        assembly: {
          type: "string",
          description: "M68000 assembly or disassembly listing to analyze. Address/opcode columns are supported."
        }
      },
      required: ["assembly"]
    }
  },
  {
    name: "get_instruction_help",
    description: "Get detailed help for a specific M68000 instruction mnemonic.",
    inputSchema: {
      type: "object",
      properties: {
        mnemonic: {
          type: "string",
          description: "Instruction mnemonic, such as ADD, MOVE.W, JMP, or BNE."
        }
      },
      required: ["mnemonic"]
    }
  },
  {
    name: "get_section_guide",
    description: "Get a guide for a manual section with related concepts and instructions.",
    inputSchema: {
      type: "object",
      properties: {
        section: {
          type: "string",
          enum: kb.metadata.sections,
          description: "Section identifier, numeric section number, or section slug."
        }
      },
      required: ["section"]
    }
  },
  {
    name: "search_knowledge_base",
    description: "Search instructions and concepts in the M68000 knowledge base.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Search query." },
        type: { type: "string", enum: ["instructions", "concepts", "all"], default: "all" },
        limit: { type: "number", default: DEFAULT_LIMIT, description: "Maximum matches to return." }
      },
      required: ["query"]
    }
  },
  {
    name: "list_sections",
    description: "List all available M68000 manual sections.",
    inputSchema: {
      type: "object",
      properties: {}
    }
  }
];

function stripLineComments(line: string): string {
  return line
    .replace(/\/\*.*?\*\//gu, "")
    .replace(/\/\/.*$/u, "")
    .split(";")[0]
    .trim();
}

function splitDisassemblyPrefix(line: string): { address?: string; bytes?: string[]; text: string } {
  const match = line.match(/^([0-9A-Fa-f]{6,8})\s+(.+)$/u);
  if (!match) return { text: line };

  const parts = match[2].trim().split(/\s+/u);
  const bytes: string[] = [];
  let index = 0;

  while (index < parts.length && /^[0-9A-Fa-f]{2,8}$/u.test(parts[index]) && parts[index].length % 2 === 0) {
    bytes.push(parts[index].toUpperCase());
    index += 1;
  }

  return { address: match[1].toUpperCase(), bytes, text: parts.slice(index).join(" ") };
}

function parseAssemblyLine(line: string): ParsedAssemblyLine | null {
  let trimmed = stripLineComments(line);
  if (!trimmed || trimmed.startsWith("*")) return null;

  trimmed = trimmed.replace(/^([A-Za-z_.$][\w.$]*:\s*)+/, "").trim();
  if (!trimmed) return null;

  const disassembly = splitDisassemblyPrefix(trimmed);
  trimmed = disassembly.text.trim();
  if (!trimmed) return null;

  const match = trimmed.match(/^([A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z])?)(?:\s+(.*))?$/);
  if (!match) {
    const pseudoMatch = trimmed.match(/^(\.[A-Za-z][\w.]*)\s*(.*)$/u);
    if (!pseudoMatch) return null;
    return {
      mnemonic: pseudoMatch[1],
      operands: pseudoMatch[2]?.trim() ?? "",
      input: trimmed,
      kind: "pseudo",
      address: disassembly.address,
      bytes: disassembly.bytes
    };
  }

  const mnemonic = match[1];
  const upperMnemonic = mnemonic.toUpperCase();
  const kind: ParsedLineKind = upperMnemonic === "SYSCALL"
    ? "syscall"
    : DATA_DIRECTIVES.has(upperMnemonic)
      ? "directive"
      : "instruction";

  return {
    mnemonic,
    operands: match[2]?.trim() ?? "",
    input: trimmed,
    kind,
    address: disassembly.address,
    bytes: disassembly.bytes
  };
}

function instructionCandidates(mnemonic: string): string[] {
  const upper = mnemonic.trim().toUpperCase();
  const withoutSize = upper.replace(/\.(B|W|L|S|D|X|P)$/u, "");
  const candidates = [upper, withoutSize];

  if (withoutSize === "UNLINK") candidates.push("UNLK");
  if (/^B[A-Z]{2}$/u.test(withoutSize)) candidates.push("BCC");
  if (/^DB[A-Z]{2}$/u.test(withoutSize)) candidates.push("DBCC");
  if (/^S[A-Z]{2}$/u.test(withoutSize)) candidates.push("SCC");
  if (/^TRAP[A-Z]{2}$/u.test(withoutSize)) candidates.push("TRAPCC");
  if (/^FB[A-Z]{2,}$/u.test(withoutSize)) candidates.push("FBCC");
  if (/^FDB[A-Z]{2}$/u.test(withoutSize)) candidates.push("FDBCC");
  if (/^FS[A-Z]{2}$/u.test(withoutSize)) candidates.push("FSCC");
  if (/^FTRAP[A-Z]{2}$/u.test(withoutSize)) candidates.push("FTRAPCC");

  return [...new Set(candidates)];
}

function findInstruction(mnemonic: string): Instruction | null {
  for (const candidate of instructionCandidates(mnemonic)) {
    const instruction = instructionByName.get(candidate);
    if (instruction) return instruction;
  }
  return null;
}

function suggestInstructions(mnemonic: string): string[] {
  const prefix = mnemonic.replace(/\..*$/u, "").slice(0, 3).toUpperCase();
  if (!prefix) return [];

  return kb.instructions
    .filter((instruction) => instruction.name.toUpperCase().startsWith(prefix))
    .slice(0, 5)
    .map((instruction) => instruction.name);
}

function annotateInstruction(parsed: ParsedAssemblyLine, lineNumber: number) {
  const base = {
    line: lineNumber,
    address: parsed.address,
    bytes: parsed.bytes,
    input: parsed.input,
    mnemonic: parsed.mnemonic
  };

  if (parsed.kind === "directive") {
    return {
      ...base,
      status: "data",
      help: "Data directive, not an executable M68000 instruction.",
      data: parsed.operands
    };
  }

  if (parsed.kind === "pseudo") {
    return {
      ...base,
      status: "pseudo",
      help: "Disassembler pseudo-op or invalid/extension decode. This is not a documented M68000 instruction mnemonic.",
      detail: parsed.operands
    };
  }

  if (parsed.kind === "syscall") {
    return {
      ...base,
      status: "environment",
      help: "Mac OS A-line trap/syscall decoded by the disassembler. The underlying opcode dispatches through the OS trap handler rather than a normal M68000 instruction.",
      trap: parsed.operands
    };
  }

  const instruction = findInstruction(parsed.mnemonic);

  if (!instruction) {
    return {
      ...base,
      status: "unknown",
      help: `Unknown instruction: ${parsed.mnemonic}. Check spelling or processor support.`,
      suggestions: suggestInstructions(parsed.mnemonic)
    };
  }

  return {
    ...base,
    mnemonic: instruction.name,
    status: "documented",
    syntax: instruction.syntax,
    operation: instruction.operation,
    description: instruction.description,
    attributes: instruction.attributes,
    condition_codes: instruction.condition_codes
  };
}

function annotateAssembly(assembly: string) {
  return assembly
    .split("\n")
    .map((line, index) => {
      const parsed = parseAssemblyLine(line);
      return parsed ? annotateInstruction(parsed, index + 1) : null;
    })
    .filter((annotation) => annotation !== null);
}

function annotationSummary(assembly: string, annotations: Array<{ status?: string }>) {
  const status_counts = annotations.reduce<Record<string, number>>((counts, annotation) => {
    const status = annotation.status ?? "unknown";
    counts[status] = (counts[status] ?? 0) + 1;
    return counts;
  }, {});

  return {
    input_lines: assembly.split("\n").length,
    annotated_lines: annotations.length,
    skipped_lines: assembly.split("\n").length - annotations.length,
    status_counts
  };
}

function annotateAssemblyDocument(assembly: string) {
  const lines = annotateAssembly(assembly);
  return { summary: annotationSummary(assembly, lines), lines };
}

function parseHexAddress(value?: string): number | null {
  if (!value || !/^[0-9A-Fa-f]+$/u.test(value)) return null;
  return Number.parseInt(value, 16);
}

function formatAddress(value: number): string {
  return Math.max(0, value).toString(16).toUpperCase().padStart(8, "0");
}

function normalizeGraphAddress(value?: string): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim().replace(/^0x/iu, "");
  if (!/^[0-9A-Fa-f]+$/u.test(trimmed)) return undefined;
  return trimmed.toUpperCase().padStart(8, "0");
}

function computeCrc32(buffer: Buffer): string {
  let crc = 0xffffffff;
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c;
  }
  for (const byte of buffer) {
    crc = table[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff).toString(16).toUpperCase().padStart(8, "0");
}

function computeSha256(buffer: Buffer): string {
  return createHash("sha256").update(buffer).digest("hex").toUpperCase();
}

interface RomFilenameMetadata {
  raw_name: string;
  date_token?: string;
  checksum_token?: string;
  model_names: string[];
  inferred_family?: string;
  size_bucket: string;
}

function extractFilenameMetadata(filename: string, fileSize: number): RomFilenameMetadata {
  const rawName = basename(filename);
  const nameWithoutExt = rawName.replace(/\.[^.]+$/u, "").replace(/_/gu, " ");
  const tokens = nameWithoutExt.split(/\s+/).filter(Boolean);

  const datePatterns = [
    /\b(19[7-9]\d|20[0-2]\d)[-_]?(0[1-9]|1[0-2])[-_]?(0[1-9]|[12]\d|3[01])\b/u,
    /\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*[-_]?\d{2,4}\b/iu
  ];
  let dateToken: string | undefined;
  for (const pattern of datePatterns) {
    const match = nameWithoutExt.match(pattern);
    if (match) { dateToken = match[0]; break; }
  }

  const checksumPatterns = [
    /\b([0-9A-Fa-f]{8})\b/u,
    /\bcrc[-_]?([0-9A-Fa-f]{4,8})\b/iu,
    /\b([0-9A-Fa-f]{4})[-_]?checksum\b/iu
  ];
  let checksumToken: string | undefined;
  for (const pattern of checksumPatterns) {
    const match = nameWithoutExt.match(pattern);
    if (match) { checksumToken = match[1].toUpperCase(); break; }
  }

  const modelPatterns = [
    /\b(Macintosh?|[A-Z]{1,2})\s*(II|IIx|IIcx|IIci|IIsi|IIvi|IIvx|LC|LCII|LCIII|QL|SE|SE30|Classic|Portable|PowerBook|Centris|Quadra|Performa|Toast)\b/igu,
    /\b(68000|68010|68020|68030|68040|CPU32)\b/igu,
    /\b(Old World|New World)\b/igu
  ];
  const modelNames: string[] = [];
  for (const pattern of modelPatterns) {
    const matches = nameWithoutExt.matchAll(pattern);
    for (const match of matches) {
      if (match[0]) modelNames.push(match[0]);
    }
  }

  let inferredFamily: string | undefined;
  if (/\b(Quadra|Centris|Performa|Classic|LC|II|SE)\b/iu.test(nameWithoutExt)) inferredFamily = "Old World";
  else if (/\b(PowerBook|PowerMac|New World|LCIII)\b/iu.test(nameWithoutExt)) inferredFamily = "New World";
  else if (/\b(68030|68040|CPU32)\b/.test(nameWithoutExt)) inferredFamily = "Old World";

  const gb = 1024 * 1024 * 1024;
  const mb = 1024 * 1024;
  const sizeBucket = fileSize >= gb ? "4GB" : fileSize >= mb * 4 ? "4MB" : fileSize >= mb * 2 ? "2MB" : fileSize >= mb ? "1MB" : fileSize >= 512 * 1024 ? "512KB" : "256KB";

  return { raw_name: rawName, date_token: dateToken, checksum_token: checksumToken, model_names: modelNames, inferred_family: inferredFamily, size_bucket: sizeBucket };
}

function byteLength(bytes?: string[]): number {
  return bytes?.reduce((total, chunk) => total + chunk.length / 2, 0) ?? 0;
}

function uniqueValues<T>(values: T[]): T[] {
  return [...new Set(values)];
}

function groupCounts(values: string[]): Array<{ value: string; count: number }> {
  return Object.entries(values.reduce<Record<string, number>>((counts, value) => {
    counts[value] = (counts[value] ?? 0) + 1;
    return counts;
  }, {}))
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([value, count]) => ({ value, count }));
}

function extractCommentTarget(line: string): string | null {
  return line.match(/\/\*\s*([0-9A-Fa-f]{6,8})\b/u)?.[1]?.toUpperCase() ?? null;
}

function extractRelativeTarget(annotation: DisassemblyAnnotationBase): string | null {
  const address = parseHexAddress(annotation.address);
  if (address === null) return null;

  const relative = annotation.input.match(/\s([+-])0x([0-9A-Fa-f]+)\b/u);
  if (!relative) return null;

  const magnitude = Number.parseInt(relative[2], 16);
  return formatAddress(address + (relative[1] === "-" ? -magnitude : magnitude));
}

function controlFlowKind(mnemonic: string): "call" | "branch" | "return" | null {
  const upper = mnemonic.toUpperCase();
  if (upper === "BSR" || upper === "JSR") return "call";
  if (upper === "RTS" || upper === "RTE" || upper === "RTR") return "return";
  if (upper === "BRA" || upper === "JMP" || /^B[A-Z]{2}$/u.test(upper) || upper === "BCC") return "branch";
  if (upper === "DBCC" || /^DB[A-Z]{2}$/u.test(upper)) return "branch";
  return null;
}

function regionKind(status: string): "code" | "data" | "pseudo" | "environment" | "unknown" {
  if (status === "documented") return "code";
  if (status === "data") return "data";
  if (status === "pseudo") return "pseudo";
  if (status === "environment") return "environment";
  return "unknown";
}

function dataIslands(annotations: DisassemblyAnnotationBase[]) {
  const islands: Array<{ start_line: number; end_line: number; start_address?: string; end_address?: string; rows: number }> = [];
  let current: (typeof islands)[number] | null = null;

  for (const annotation of annotations) {
    if (annotation.status !== "data") {
      if (current) islands.push(current);
      current = null;
      continue;
    }

    if (!current) {
      current = {
        start_line: annotation.line,
        end_line: annotation.line,
        start_address: annotation.address,
        end_address: annotation.address,
        rows: 1
      };
      continue;
    }

    current.end_line = annotation.line;
    current.end_address = annotation.address;
    current.rows += 1;
  }

  if (current) islands.push(current);
  return islands;
}

function contiguousRegions(annotations: DisassemblyAnnotationBase[]) {
  const regions: Array<{ kind: string; start_line: number; end_line: number; start_address?: string; end_address?: string; rows: number }> = [];
  let current: (typeof regions)[number] | null = null;

  for (const annotation of annotations) {
    const kind = regionKind(annotation.status);
    if (!current || current.kind !== kind) {
      if (current) regions.push(current);
      current = {
        kind,
        start_line: annotation.line,
        end_line: annotation.line,
        start_address: annotation.address,
        end_address: annotation.address,
        rows: 1
      };
      continue;
    }

    current.end_line = annotation.line;
    current.end_address = annotation.address;
    current.rows += 1;
  }

  if (current) regions.push(current);
  return regions;
}

function instructionSize(mnemonic: string): string | undefined {
  return mnemonic.match(/\.(B|W|L)$/iu)?.[1]?.toLowerCase();
}

function extractMemoryReferences(annotations: DisassemblyAnnotationBase[]): MemoryReference[] {
  const references: MemoryReference[] = [];
  const referencePattern = /\[((?:[AD][0-7]|PC))(?:\s*([+-])\s*0x([0-9A-Fa-f]+))?[^\]]*\]/gu;

  for (const annotation of annotations) {
    for (const match of annotation.input.matchAll(referencePattern)) {
      const magnitude = match[3] ? Number.parseInt(match[3], 16) : 0;
      references.push({
        line: annotation.line,
        address: annotation.address,
        mnemonic: annotation.mnemonic,
        register: match[1].toUpperCase(),
        offset: match[2] === "-" ? -magnitude : magnitude,
        expression: match[0],
        size: instructionSize(annotation.input.split(/\s+/u)[0] ?? "")
      });
    }
  }

  return references;
}

function inferStackFrame(annotations: DisassemblyAnnotationBase[], memoryReferences: MemoryReference[]) {
  const link = annotations.find((annotation) => annotation.mnemonic.toUpperCase() === "LINK" && /\bA6\b/iu.test(annotation.input));
  const frameSizeMatch = link?.input.match(/,\s*(-?0x[0-9A-Fa-f]+|-?\d+)/u);
  const frameSize = frameSizeMatch ? parseSignedNumber(frameSizeMatch[1]) : undefined;
  const a6References = memoryReferences.filter((reference) => reference.register === "A6");

  const slots = Object.entries(a6References.reduce<Record<string, { offset: number; references: MemoryReference[] }>>((slotsByOffset, reference) => {
    const key = String(reference.offset);
    slotsByOffset[key] ??= { offset: reference.offset, references: [] };
    slotsByOffset[key].references.push(reference);
    return slotsByOffset;
  }, {}))
    .map(([, slot]) => ({
      offset: slot.offset,
      kind: slot.offset < 0 ? "local" : "parameter_or_saved_state",
      suggested_name: slot.offset < 0 ? `local_${Math.abs(slot.offset).toString(16)}` : `arg_${slot.offset.toString(16)}`,
      sizes: uniqueValues(slot.references.map((reference) => reference.size).filter((size): size is string => Boolean(size))),
      references: slot.references.map((reference) => ({ line: reference.line, address: reference.address, mnemonic: reference.mnemonic, expression: reference.expression }))
    }))
    .sort((a, b) => a.offset - b.offset);

  return { frame_register: link ? "A6" : undefined, frame_size: frameSize, link_line: link?.line, slots };
}

function parseSignedNumber(value: string): number {
  const sign = value.startsWith("-") ? -1 : 1;
  const unsigned = value.replace(/^-/, "");
  return sign * (unsigned.startsWith("0x") ? Number.parseInt(unsigned, 16) : Number.parseInt(unsigned, 10));
}

function inferStructureFields(memoryReferences: MemoryReference[]) {
  return Object.entries(memoryReferences
    .filter((reference) => reference.register !== "A6" && reference.register !== "A7" && reference.register !== "PC")
    .reduce<Record<string, Record<string, { offset: number; references: MemoryReference[] }>>>((groups, reference) => {
      groups[reference.register] ??= {};
      const key = String(reference.offset);
      groups[reference.register][key] ??= { offset: reference.offset, references: [] };
      groups[reference.register][key].references.push(reference);
      return groups;
    }, {}))
    .map(([base_register, fields]) => ({
      base_register,
      suggested_type: `${base_register}_struct`,
      fields: Object.values(fields)
        .map((field) => ({
          offset: field.offset,
          suggested_name: `field_${field.offset.toString(16)}`,
          sizes: uniqueValues(field.references.map((reference) => reference.size).filter((size): size is string => Boolean(size))),
          references: field.references.map((reference) => ({ line: reference.line, address: reference.address, mnemonic: reference.mnemonic, expression: reference.expression }))
        }))
        .sort((a, b) => a.offset - b.offset)
    }))
    .sort((a, b) => a.base_register.localeCompare(b.base_register));
}

function inferCallArguments(annotations: DisassemblyAnnotationBase[]) {
  const calls: Array<{ line: number; address?: string; mnemonic: string; target?: string | null; arguments: Array<{ line: number; address?: string; input: string; bytes?: string[] }> }> = [];
  let pendingPushes: Array<{ line: number; address?: string; input: string; bytes?: string[] }> = [];

  for (const annotation of annotations) {
    const input = annotation.input.toLowerCase();
    const isPush = /(^|\s)(move|pea|clr)\.[bwl]?\s+-\[a7\]/iu.test(annotation.input) || /\s-[a7],/iu.test(input) || /\s-\[a7\]/u.test(input);
    if (isPush) {
      pendingPushes.push({ line: annotation.line, address: annotation.address, input: annotation.input, bytes: annotation.bytes });
      pendingPushes = pendingPushes.slice(-12);
      continue;
    }

    const flowKind = controlFlowKind(annotation.mnemonic);
    if (flowKind === "call" || annotation.status === "environment") {
      calls.push({
        line: annotation.line,
        address: annotation.address,
        mnemonic: annotation.mnemonic,
        target: annotation.trap ?? undefined,
        arguments: [...pendingPushes]
      });
      pendingPushes = [];
    }

    if (/\badd\.[wl]\s+a7,/iu.test(annotation.input) || /\baddq\.[wl]\s+a7,/iu.test(annotation.input)) {
      pendingPushes = [];
    }
  }

  return calls;
}

function analyzeAssemblyDocument(assembly: string) {
  const annotated = annotateAssemblyDocument(assembly);
  const annotations = annotated.lines as DisassemblyAnnotationBase[];
  const memoryReferences = extractMemoryReferences(annotations);
  const rawLines = assembly.split("\n");
  const symbols: Array<{ line: number; name: string; kind: string }> = [];
  const pstrings: Array<{ line: number; address?: string; value: string }> = [];
  let alternateBranchMarkers = 0;

  rawLines.forEach((line, index) => {
    const symbol = line.match(/^\s*((?:fn|label)[0-9A-Fa-f]+):/u);
    if (symbol) {
      symbols.push({
        line: index + 1,
        name: symbol[1],
        kind: symbol[1].startsWith("fn") ? "function" : "label"
      });
    }

    const pstring = line.match(/pstring\s+"([^"]*)"/u);
    if (pstring) {
      pstrings.push({
        line: index + 1,
        address: line.match(/^\s*([0-9A-Fa-f]{6,8})\b/u)?.[1]?.toUpperCase(),
        value: pstring[1]
      });
    }

    if (/alternate branch/iu.test(line)) alternateBranchMarkers += 1;
  });

  const instruction_counts = annotations.reduce<Record<string, number>>((counts, annotation) => {
    if (annotation.status === "documented") {
      counts[annotation.mnemonic] = (counts[annotation.mnemonic] ?? 0) + 1;
    }
    return counts;
  }, {});

  const syscalls = annotations
    .filter((annotation) => annotation.status === "environment")
    .map((annotation) => ({
      line: annotation.line,
      address: annotation.address,
      trap: annotation.trap
    }));
  const data = annotations
    .filter((annotation) => annotation.status === "data")
    .map((annotation) => ({
      line: annotation.line,
      address: annotation.address,
      directive: annotation.mnemonic,
      data: annotation.data
    }));
  const pseudo_ops = annotations
    .filter((annotation) => annotation.status === "pseudo")
    .map((annotation) => ({
      line: annotation.line,
      address: annotation.address,
      mnemonic: annotation.mnemonic,
      detail: annotation.detail
    }));
  const control_flow = annotations
    .map((annotation) => {
      const kind = controlFlowKind(annotation.mnemonic);
      if (!kind) return null;

      const address = parseHexAddress(annotation.address);
      const target = extractCommentTarget(rawLines[annotation.line - 1] ?? "") ?? extractRelativeTarget(annotation);
      const length = byteLength(annotation.bytes);

      return {
        line: annotation.line,
        address: annotation.address,
        mnemonic: annotation.mnemonic,
        kind,
        target,
        fallthrough: address !== null && length > 0 && kind !== "return" ? formatAddress(address + length) : undefined,
        unresolved: !target && kind !== "return"
      };
    })
    .filter((edge): edge is NonNullable<typeof edge> => edge !== null);
  const syscall_summary = groupCounts(syscalls.map((syscall) => syscall.trap?.split(",")[0]?.trim()).filter((trap): trap is string => Boolean(trap)));
  const top_instructions = Object.entries(instruction_counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12)
    .map(([mnemonic, count]) => ({ mnemonic, count }));
  const known_targets = uniqueValues(control_flow.map((edge) => edge.target).filter((target): target is string => Boolean(target))).sort();
  const unresolved_control_flow = control_flow.filter((edge) => edge.unresolved);

  const warnings: string[] = [];
  if (data.length || pstrings.length) warnings.push("Embedded data/string islands are present; linear disassembly will produce false branches and invalid instructions inside data.");
  if (pseudo_ops.length) warnings.push("Pseudo/invalid decode rows are present; these are useful boundaries for improving code/data segmentation.");
  if (syscalls.length) warnings.push("Mac OS trap/syscall rows are environment-specific and should be linked to Toolbox/OS documentation, not only the M68000 PRM.");
  if (alternateBranchMarkers) warnings.push("Alternate branch markers suggest overlapping or misaligned decode paths; prefer control-flow-guided traversal over linear sweep.");
  if (unresolved_control_flow.length) warnings.push("Some control-flow instructions use register or memory indirect targets; persist these as graph edges once resolved.");

  return {
    ...annotated,
    insights: {
      symbols,
      pstrings,
      syscalls,
      syscall_summary,
      data,
      data_islands: dataIslands(annotations),
      pseudo_ops,
      regions: contiguousRegions(annotations),
      memory_references: memoryReferences,
      stack_frame: inferStackFrame(annotations, memoryReferences),
      structure_candidates: inferStructureFields(memoryReferences),
      call_arguments: inferCallArguments(annotations),
      control_flow,
      known_targets,
      unresolved_control_flow,
      alternate_branch_markers: alternateBranchMarkers,
      top_instructions,
      warnings
    }
  };
}

function importAnalysisIntoProject(project: ReverseProject, analysis: ReturnType<typeof analyzeAssemblyDocument>) {
  let nodes = 0;
  let edges = 0;

  for (const annotation of analysis.lines as DisassemblyAnnotationBase[]) {
    const key = annotation.address ?? `line:${annotation.line}`;
    const type = regionKind(annotation.status);
    const node = upsertNode(project, {
      id: nodeId("address", key),
      type,
      address: annotation.address,
      label: annotation.mnemonic,
      metadata: {
        line: annotation.line,
        bytes: annotation.bytes,
        input: annotation.input,
        status: annotation.status,
        trap: annotation.trap,
        data: annotation.data,
        detail: annotation.detail
      }
    });
    nodes += 1;

    if (annotation.status === "environment" && annotation.trap) {
      const trapName = annotation.trap.split(",")[0].trim().replace(/^_/, "");
      const trapWord = annotation.trap.match(/A[0-9A-F]{3}/u)?.[0]?.toUpperCase();
      const trapInfo = trapWord ? findTrapByWord(trapWord) : undefined;
      const trapMetadata: Record<string, unknown> = { source: "analysis", raw: annotation.trap };
      if (trapInfo) {
        trapMetadata.manager = trapInfo.manager;
        trapMetadata.description = trapInfo.description;
        trapMetadata.parameters = trapInfo.parameters;
        trapMetadata.returns = trapInfo.returns;
      }
      const trapNode = upsertNode(project, {
        id: nodeId("trap", trapName),
        type: "trap",
        name: trapName,
        label: trapInfo ? `${trapName} (${trapInfo.manager})` : trapName,
        address: trapWord ? trapWord : undefined,
        metadata: trapMetadata
      });
      upsertEdge(project, {
        id: edgeId("invokes_trap", node.id, trapNode.id),
        type: "invokes_trap",
        from: node.id,
        to: trapNode.id,
        metadata: { line: annotation.line, address: annotation.address, trap_word: trapWord }
      });
      nodes += 1;
      edges += 1;
    }
  }

  for (const symbol of analysis.insights.symbols) {
    const address = symbol.name.match(/[0-9A-Fa-f]{6,8}$/u)?.[0]?.toUpperCase();
    const symbolNode = upsertNode(project, {
      id: nodeId("symbol", symbol.name),
      type: "symbol",
      name: symbol.name,
      label: symbol.name,
      address,
      metadata: { line: symbol.line, kind: symbol.kind }
    });
    nodes += 1;

    if (address) {
      const addressNode = upsertNode(project, {
        id: nodeId("address", address),
        type: symbol.kind === "function" ? "function" : "code",
        address,
        label: symbol.name,
        metadata: { discovered_from: "symbol" }
      });
      upsertEdge(project, {
        id: edgeId("names", symbolNode.id, addressNode.id),
        type: "names",
        from: symbolNode.id,
        to: addressNode.id
      });
      nodes += 1;
      edges += 1;
    }
  }

  for (const pstring of analysis.insights.pstrings) {
    const stringNode = upsertNode(project, {
      id: nodeId("pstring", `${pstring.address ?? pstring.line}:${pstring.value}`),
      type: "pstring",
      address: pstring.address,
      label: pstring.value,
      metadata: { line: pstring.line, value: pstring.value }
    });
    nodes += 1;

    if (pstring.address) {
      const addressNode = upsertNode(project, {
        id: nodeId("address", pstring.address),
        type: "data",
        address: pstring.address,
        label: pstring.value,
        metadata: { discovered_from: "pstring_comment" }
      });
      upsertEdge(project, {
        id: edgeId("contains_string", addressNode.id, stringNode.id),
        type: "contains_string",
        from: addressNode.id,
        to: stringNode.id
      });
      nodes += 1;
      edges += 1;
    }
  }

  for (const flow of analysis.insights.control_flow) {
    if (!flow.address || !flow.target) continue;
    const from = nodeId("address", flow.address);
    const to = nodeId("address", flow.target);
    upsertNode(project, { id: from, type: "code", address: flow.address, label: flow.mnemonic, metadata: { line: flow.line } });
    upsertNode(project, { id: to, type: flow.kind === "call" ? "function" : "code", address: flow.target, metadata: { discovered_from: "control_flow" } });
    upsertEdge(project, {
      id: edgeId(flow.kind, from, to),
      type: flow.kind,
      from,
      to,
      label: flow.mnemonic,
      metadata: { line: flow.line, fallthrough: flow.fallthrough }
    });
    nodes += 2;
    edges += 1;
  }

  for (const slot of analysis.insights.stack_frame.slots) {
    const slotNode = upsertNode(project, {
      id: nodeId("stack_slot", `A6:${slot.offset}`),
      type: "stack_slot",
      label: slot.suggested_name,
      metadata: {
        offset: slot.offset,
        kind: slot.kind,
        sizes: slot.sizes,
        references: slot.references
      }
    });
    nodes += 1;

    for (const reference of slot.references) {
      if (!reference.address) continue;
      const addressNodeId = nodeId("address", reference.address);
      upsertEdge(project, {
        id: edgeId("references_stack_slot", addressNodeId, slotNode.id),
        type: "references_stack_slot",
        from: addressNodeId,
        to: slotNode.id,
        metadata: { line: reference.line, expression: reference.expression }
      });
      edges += 1;
    }
  }

  for (const candidate of analysis.insights.structure_candidates) {
    const typeCandidate = upsertNode(project, {
      id: nodeId("type_candidate", candidate.suggested_type),
      type: "type_candidate",
      label: candidate.suggested_type,
      metadata: { base_register: candidate.base_register, fields: candidate.fields }
    });
    nodes += 1;

    for (const field of candidate.fields) {
      const fieldNode = upsertNode(project, {
        id: nodeId("field_candidate", `${candidate.base_register}:${field.offset}`),
        type: "field_candidate",
        label: field.suggested_name,
        metadata: { base_register: candidate.base_register, offset: field.offset, sizes: field.sizes, references: field.references }
      });
      upsertEdge(project, {
        id: edgeId("has_field_candidate", typeCandidate.id, fieldNode.id),
        type: "has_field_candidate",
        from: typeCandidate.id,
        to: fieldNode.id
      });
      nodes += 1;
      edges += 1;
    }
  }

  for (const call of analysis.insights.call_arguments) {
    const callNode = upsertNode(project, {
      id: nodeId("callsite", call.address ?? `line:${call.line}`),
      type: "callsite",
      address: call.address,
      label: call.target ? `${call.mnemonic} ${call.target}` : call.mnemonic,
      metadata: { line: call.line, target: call.target, arguments: call.arguments }
    });
    nodes += 1;

    for (const argument of call.arguments) {
      if (!argument.address) continue;
      const argumentNode = upsertNode(project, {
        id: nodeId("argument_candidate", `${call.address ?? call.line}:${argument.line}`),
        type: "argument_candidate",
        address: argument.address,
        label: argument.input,
        metadata: argument
      });
      upsertEdge(project, {
        id: edgeId("has_argument_candidate", callNode.id, argumentNode.id),
        type: "has_argument_candidate",
        from: callNode.id,
        to: argumentNode.id
      });
      nodes += 1;
      edges += 1;
    }
  }

  return { nodes_upserted: nodes, edges_upserted: edges, project: graphSummary(project) };
}

function decodeRomData(input: { data_hex?: unknown; data_base64?: unknown }): Buffer {
  if (typeof input.data_hex === "string") {
    const hex = input.data_hex.replace(/[^0-9A-Fa-f]/gu, "");
    if (!hex || hex.length % 2 !== 0) throw new Error("data_hex must contain an even number of hex digits");
    return Buffer.from(hex, "hex");
  }

  if (typeof input.data_base64 === "string") {
    return Buffer.from(input.data_base64, "base64");
  }

  return Buffer.alloc(0);
}

function importRomIntoProject(project: ReverseProject, body: Record<string, unknown>) {
  const name = typeof body.name === "string" && body.name.trim() ? body.name.trim() : "ROM";
  const baseAddress = typeof body.base_address === "string" ? body.base_address.toUpperCase() : "00000000";
  const base = parseHexAddress(baseAddress) ?? 0;
  const bytes = decodeRomData(body);
  const pageSize = Math.max(16, Math.min(65536, Number(body.page_size ?? 4096) || 4096));
  const romId = nodeId("rom", `${slug(name)}:${baseAddress}:${bytes.length}:${Date.now().toString(36)}`);
  const romNode = upsertNode(project, {
    id: romId,
    type: "rom",
    name,
    label: name,
    address: formatAddress(base),
    metadata: { size: bytes.length, page_size: pageSize }
  });

  let pages = 0;
  for (let offset = 0; offset < bytes.length; offset += pageSize) {
    const start = formatAddress(base + offset);
    const end = formatAddress(base + Math.min(offset + pageSize, bytes.length) - 1);
    const pageBytes = bytes.subarray(offset, offset + pageSize);
    const pageNode = upsertNode(project, {
      id: nodeId("memory_page", `${romId}:${start}`),
      type: "memory_page",
      address: start,
      label: `${name} ${start}-${end}`,
      metadata: { rom: romId, offset, size: pageBytes.length, end_address: end, data_hex: pageBytes.toString("hex").toUpperCase() }
    });
    upsertEdge(project, {
      id: edgeId("contains_page", romNode.id, pageNode.id),
      type: "contains_page",
      from: romNode.id,
      to: pageNode.id
    });
    pages += 1;
  }

  const traps = Array.isArray(body.traps) ? body.traps : [];
  let trapCount = 0;
  for (const trap of traps) {
    if (!trap || typeof trap !== "object") continue;
    const trapRecord = trap as Record<string, unknown>;
    const trapName = typeof trapRecord.name === "string" ? trapRecord.name.trim() : "";
    if (!trapName) continue;

    const trapNode = upsertNode(project, {
      id: nodeId("trap", trapName),
      type: "trap",
      name: trapName,
      label: trapName,
      address: typeof trapRecord.address === "string" ? trapRecord.address.toUpperCase() : undefined,
      metadata: { source: "rom_import", selector: trapRecord.selector }
    });
    upsertEdge(project, {
      id: edgeId("exports_trap", romNode.id, trapNode.id),
      type: "exports_trap",
      from: romNode.id,
      to: trapNode.id
    });
    trapCount += 1;
  }

  return { rom: romNode, pages_created: pages, traps_imported: trapCount, project: graphSummary(project) };
}

function readProjectMemory(project: ReverseProject, addressInput: string, lengthInput: unknown) {
  const address = parseHexAddress(addressInput.replace(/^0x/iu, ""));
  if (address === null) throw new Error("Invalid hex address");

  const length = Math.max(1, Math.min(1024, Number(lengthInput ?? 16) || 16));
  const findPage = (needle: number) => project.nodes.find((node) => {
    if (node.type !== "memory_page") return false;
    const start = parseHexAddress(node.address);
    const end = parseHexAddress(typeof node.metadata?.end_address === "string" ? node.metadata.end_address : undefined);
    return start !== null && end !== null && needle >= start && needle <= end;
  });

  let page = findPage(address);
  let pageAddress = address;
  let mappedFrom: string | undefined;

  if (!page) {
    for (const rom of project.nodes.filter((node) => node.type === "rom")) {
      const analysis = disassemblyNodes(project)
        .find((node) => node.metadata?.rom === rom.id)?.metadata?.stackimport_analysis;
      const baseAddress = typeof analysis === "object" && analysis !== null
        ? (analysis as Record<string, unknown>).base_address
        : undefined;
      const virtualBase = typeof baseAddress === "string" ? parseHexAddress(baseAddress.replace(/^0x/iu, "")) : null;
      const fileBase = parseHexAddress(rom.address) ?? 0;
      const size = Number(rom.metadata?.size ?? 0) || 0;
      if (virtualBase === null || size <= 0 || address < virtualBase || address >= virtualBase + size) continue;
      const candidate = fileBase + (address - virtualBase);
      page = findPage(candidate);
      if (page) {
        pageAddress = candidate;
        mappedFrom = formatAddress(address);
        break;
      }
    }
  }

  if (!page) return null;

  const start = parseHexAddress(page.address);
  const dataHex = typeof page.metadata?.data_hex === "string" ? page.metadata.data_hex : "";
  if (start === null || !dataHex) return null;

  const pageBytes = Buffer.from(dataHex, "hex");
  const offset = pageAddress - start;
  const slice = pageBytes.subarray(offset, offset + length);

  return {
    address: formatAddress(pageAddress),
    requested_address: formatAddress(address),
    mapped_from: mappedFrom,
    page: page.id,
    page_start: page.address,
    page_end: page.metadata?.end_address,
    offset,
    length: slice.length,
    hex: slice.toString("hex").toUpperCase(),
    bytes: [...slice]
  };
}

const MAX_ROM_SIZE = 16 * 1024 * 1024;
const SUPPORTED_ROM_EXTENSIONS = new Set([".rom", ".bin", ".img", ".eeprom", ".flash"]);

function importRomFromPath(project: ReverseProject, pathInput: string, baseAddressInput?: string, pageSizeInput?: number) {
  const path = resolve(pathInput.trim());

  if (!existsSync(path)) {
    throw Object.assign(new Error(`ROM file not found: ${path}`), { status: 404 });
  }

  const stats = statSync(path);
  if (!stats.isFile()) {
    throw Object.assign(new Error(`ROM path is not a file: ${path}`), { status: 400 });
  }

  const fileSize = stats.size;
  if (fileSize === 0) {
    throw Object.assign(new Error("ROM file is empty"), { status: 400 });
  }

  if (fileSize > MAX_ROM_SIZE) {
    throw Object.assign(new Error(`ROM file too large (${fileSize} bytes). Maximum allowed is ${MAX_ROM_SIZE} bytes.`), { status: 400 });
  }

  const ext = "." + path.split(".").pop()?.toLowerCase().replace(/[^a-z0-9]/gu, "");
  if (!SUPPORTED_ROM_EXTENSIONS.has(ext) && !ext) {
    console.error(`Warning: Unexpected ROM file extension: ${ext || "none"}`);
  }

  const store = loadProjectStore();
  const existingRom = store.projects.flatMap((p) => p.nodes).find(
    (n) => n.type === "rom" && n.metadata?.source_path === path
  );
  if (existingRom) {
    throw Object.assign(new Error(`ROM already imported: ${path} (id: ${existingRom.id}). Delete it first or use the existing id.`), { status: 409 });
  }

  const bytes = readFileSync(path);
  const crc32 = computeCrc32(bytes);
  const sha256 = computeSha256(bytes);
  const metadata = extractFilenameMetadata(path, fileSize);
  const baseAddress = baseAddressInput ? parseHexAddress(baseAddressInput.replace(/^0x/iu, "")) ?? 0 : 0;
  const pageSize = Math.max(256, Math.min(65536, pageSizeInput ?? 4096));
  const romId = nodeId("rom", `${metadata.raw_name.replace(/[^a-z0-9]/gu, "-").slice(0, 40)}:${crc32}:${fileSize}`);

  const romNode = upsertNode(project, {
    id: romId,
    type: "rom",
    name: metadata.raw_name,
    label: metadata.raw_name,
    address: formatAddress(baseAddress),
    metadata: {
      size: fileSize,
      page_size: pageSize,
      source_path: path,
      import_timestamp: nowIso(),
      crc32,
      sha256,
      filename: metadata
    }
  });

  upsertNode(project, {
    id: nodeId("rom_header", `${romId}:00000000`),
    type: "rom_header",
    name: "ROM Header",
    address: formatAddress(baseAddress),
    label: `${metadata.raw_name} Header`,
    metadata: { rom: romId, offset: 0 }
  });

  upsertNode(project, {
    id: nodeId("checksum", `crc32:${crc32}`),
    type: "checksum",
    name: `CRC32:${crc32}`,
    label: `CRC32 ${crc32}`,
    metadata: { algorithm: "CRC32", value: crc32, source: "file", path }
  });

  upsertNode(project, {
    id: nodeId("checksum", `sha256:${sha256}`),
    type: "checksum",
    name: `SHA256:${sha256.slice(0, 16)}...`,
    label: `SHA256 ${sha256.slice(0, 16)}...`,
    metadata: { algorithm: "SHA256", value: sha256, source: "file", path }
  });

  if (metadata.model_names.length > 0) {
    for (const modelName of metadata.model_names) {
      const modelNode = upsertNode(project, {
        id: nodeId("machine_model", modelName.replace(/[^a-z0-9]/gu, "-").toLowerCase().slice(0, 50)),
        type: "machine_model",
        name: modelName,
        label: modelName,
        metadata: { family: metadata.inferred_family }
      });
      upsertEdge(project, {
        id: edgeId("has_model", romId, modelNode.id),
        type: "has_model",
        from: romId,
        to: modelNode.id,
        metadata: { source: "filename" }
      });
    }
  }

  if (metadata.inferred_family) {
    const familyNode = upsertNode(project, {
      id: nodeId("machine_family", metadata.inferred_family.toLowerCase().replace(/[^a-z0-9]/gu, "-")),
      type: "machine_family",
      name: metadata.inferred_family,
      label: metadata.inferred_family,
      metadata: { source: "filename" }
    });
    upsertEdge(project, {
      id: edgeId("has_family", romId, familyNode.id),
      type: "has_family",
      from: romId,
      to: familyNode.id
    });
  }

  const edgeFromChecksum = edgeId("has_checksum", romId, nodeId("checksum", `crc32:${crc32}`));
  upsertEdge(project, {
    id: edgeFromChecksum,
    type: "has_checksum",
    from: romId,
    to: nodeId("checksum", `crc32:${crc32}`)
  });
  upsertEdge(project, {
    id: edgeId("has_checksum", romId, nodeId("checksum", `sha256:${sha256}`)),
    type: "has_checksum",
    from: romId,
    to: nodeId("checksum", `sha256:${sha256}`)
  });

  let pages = 0;
  for (let offset = 0; offset < bytes.length; offset += pageSize) {
    const start = formatAddress(baseAddress + offset);
    const end = formatAddress(baseAddress + Math.min(offset + pageSize, bytes.length) - 1);
    const pageBytes = bytes.subarray(offset, offset + pageSize);
    const pageNode = upsertNode(project, {
      id: nodeId("memory_page", `${romId}:${start}`),
      type: "memory_page",
      address: start,
      label: `${metadata.raw_name} ${start}-${end}`,
      metadata: { rom: romId, offset, size: pageBytes.length, end_address: end, data_hex: pageBytes.toString("hex").toUpperCase() }
    });
    upsertEdge(project, {
      id: edgeId("contains_page", romId, pageNode.id),
      type: "contains_page",
      from: romId,
      to: pageNode.id
    });
    pages += 1;
  }

  return {
    rom: romNode,
    pages_created: pages,
    metadata: {
      filename: metadata.raw_name,
      size: fileSize,
      crc32,
      sha256,
      model_names: metadata.model_names,
      inferred_family: metadata.inferred_family,
      size_bucket: metadata.size_bucket,
      date_token: metadata.date_token,
      checksum_token: metadata.checksum_token
    },
    project: graphSummary(project)
  };
}

function findRomNode(project: ReverseProject, romIdInput?: unknown): ProjectNode {
  const roms = project.nodes.filter((node) => node.type === "rom");
  if (typeof romIdInput === "string" && romIdInput.trim()) {
    const rom = roms.find((node) => node.id === romIdInput || node.name === romIdInput || node.label === romIdInput);
    if (!rom) throw Object.assign(new Error(`ROM '${romIdInput}' not found in project`), { status: 404 });
    return rom;
  }
  if (roms.length === 1) return roms[0];
  if (roms.length === 0) throw Object.assign(new Error("No ROM nodes found in project"), { status: 404 });
  throw Object.assign(new Error("Multiple ROMs found; provide rom_id"), { status: 400 });
}

function materializeRomForStackimport(project: ReverseProject, rom: ProjectNode): string {
  const sourcePath = typeof rom.metadata?.source_path === "string" ? resolve(rom.metadata.source_path) : "";
  if (sourcePath && existsSync(sourcePath) && statSync(sourcePath).isFile()) return sourcePath;

  const pages = project.nodes
    .filter((node) => node.type === "memory_page" && node.metadata?.rom === rom.id)
    .sort((a, b) => Number(a.metadata?.offset ?? 0) - Number(b.metadata?.offset ?? 0));
  if (pages.length === 0) {
    throw Object.assign(new Error(`ROM '${rom.id}' has no source_path and no memory pages`), { status: 400 });
  }

  const chunks: Buffer[] = [];
  for (const page of pages) {
    const dataHex = typeof page.metadata?.data_hex === "string" ? page.metadata.data_hex : "";
    if (!dataHex) throw Object.assign(new Error(`Memory page '${page.id}' is missing data_hex`), { status: 400 });
    chunks.push(Buffer.from(dataHex, "hex"));
  }

  const projectDir = join(ROM_ANALYSIS_DIR, slug(project.id));
  mkdirSync(projectDir, { recursive: true });
  const romPath = join(projectDir, `${slug(rom.name ?? rom.id)}.ROM`);
  writeFileSync(romPath, Buffer.concat(chunks));
  return romPath;
}

async function disassembleRomForProject(
  project: ReverseProject,
  body: Record<string, unknown>
) {
  const rom = findRomNode(project, body.rom_id);
  const romPath = materializeRomForStackimport(project, rom);
  const baseAddress = typeof body.base_address === "string" && body.base_address.trim()
    ? body.base_address.trim()
    : `0x${rom.address ?? "00000000"}`;
  const importAnalysis = body.import_analysis !== false;
  const outputDir = typeof body.output_dir === "string" && body.output_dir.trim()
    ? resolve(body.output_dir)
    : join(ROM_ANALYSIS_DIR, slug(project.id), `${slug(rom.name ?? rom.id)}-${Date.now().toString(36)}`);
  mkdirSync(dirname(outputDir), { recursive: true });

  if (!existsSync(STACKIMPORT_BIN)) {
    throw Object.assign(new Error(`stackimport binary not found: ${STACKIMPORT_BIN}. Set STACKIMPORT_BIN or build stackimport.`), { status: 500 });
  }

  const args = ["--rom", "--rom-base", baseAddress, "--output", outputDir, romPath];
  const startedAt = nowIso();
  const { stdout, stderr } = await execFileAsync(STACKIMPORT_BIN, args, {
    cwd: dirname(STACKIMPORT_BIN),
    maxBuffer: 16 * 1024 * 1024,
    timeout: Math.max(10_000, Math.min(600_000, Number(body.timeout_ms ?? 300_000) || 300_000))
  });

  const disassemblyPath = join(outputDir, "disassembly.s");
  const analysisPath = join(outputDir, "analysis.json");
  if (!existsSync(disassemblyPath)) {
    throw Object.assign(new Error(`stackimport completed but did not write ${disassemblyPath}`), { status: 500 });
  }

  const assembly = readFileSync(disassemblyPath, "utf8");
  const stackimportAnalysis = existsSync(analysisPath)
    ? JSON.parse(readFileSync(analysisPath, "utf8")) as Record<string, unknown>
    : {};
  const analysis = importAnalysis ? analyzeAssemblyDocument(assembly) : null;
  const importResult = analysis ? importAnalysisIntoProject(project, analysis) : null;

  const disassemblyNode = upsertNode(project, {
    id: nodeId("rom_disassembly", `${rom.id}:${stackimportAnalysis.crc32 ?? Date.now().toString(36)}`),
    type: "rom_disassembly",
    name: `${rom.name ?? rom.id} disassembly`,
    label: `${rom.label ?? rom.name ?? rom.id} disassembly`,
    address: rom.address,
    metadata: {
      rom: rom.id,
      source_path: romPath,
      output_dir: outputDir,
      disassembly_path: disassemblyPath,
      analysis_path: analysisPath,
      started_at: startedAt,
      completed_at: nowIso(),
      stackimport_bin: STACKIMPORT_BIN,
      stackimport_args: args,
      stackimport_stdout: stdout,
      stackimport_stderr: stderr,
      stackimport_analysis: stackimportAnalysis,
      imported_analysis: importAnalysis
    }
  });
  upsertEdge(project, {
    id: edgeId("has_disassembly", rom.id, disassemblyNode.id),
    type: "has_disassembly",
    from: rom.id,
    to: disassemblyNode.id,
    metadata: { source: "stackimport" }
  });
  const structureImport = importStackimportStructureIntoProject(project, rom, disassemblyNode.id, stackimportAnalysis);

  return {
    rom,
    disassembly: disassemblyNode,
    output_dir: outputDir,
    disassembly_path: disassemblyPath,
    analysis_path: analysisPath,
    stackimport: stackimportAnalysis,
    structure_import: structureImport,
    import: importResult,
    project: graphSummary(project)
  };
}

interface DisassemblyLineView {
  number: number;
  text: string;
  address?: string;
  label?: string;
  function_label?: string;
  function_start?: string;
  function_end?: string;
  mnemonic?: string;
  operands?: string;
  target?: string;
  memory_refs?: string[];
  trap?: string;
  xrefs_to?: DisassemblyXref[];
  xrefs_from?: DisassemblyXref[];
  annotations?: Array<{
    id: string;
    type: string;
    label?: string;
    metadata?: Record<string, unknown>;
  }>;
  symbol_name?: string;
  repeatable_comments?: string[];
  code_class?: "code" | "data" | "resource" | "table" | "trap" | "unknown";
  kind: "label" | "instruction" | "comment" | "blank";
}

interface DisassemblyXref {
  from: string;
  to: string;
  kind: "call" | "jump" | "branch" | "memory" | "trap" | "reference";
  mnemonic?: string;
  line: number;
}

interface DisassemblyFunctionIndex {
  label: string;
  start: string;
  end?: string;
  line: number;
  instruction_count: number;
  inbound_refs: number;
  outbound_refs: number;
}

interface DisassemblyFileIndex {
  path: string;
  mtime_ms: number;
  total_lines: number;
  instruction_count: number;
  lines: DisassemblyLineView[];
  addressToOffset: Map<string, number>;
  labelToOffset: Map<string, number>;
  xrefsTo: Map<string, DisassemblyXref[]>;
  xrefsFrom: Map<string, DisassemblyXref[]>;
  functions: DisassemblyFunctionIndex[];
  functionByAddress: Map<string, DisassemblyFunctionIndex>;
}

interface SourceFileIndex {
  path: string;
  relative_path: string;
  lines: string[];
}

interface SourceMatch {
  path: string;
  line: number;
  text: string;
  before?: string[];
  after?: string[];
  score: number;
  terms: string[];
  category?: string;
}

const disassemblyIndexCache = new Map<string, DisassemblyFileIndex>();
let sourceIndexCache: { root: string; files: SourceFileIndex[] } | null = null;
let atlasMapCache: { root: string; mtime_key: string; nodes: ProjectNode[] } | null = null;

function disassemblyNodes(project: ReverseProject) {
  return project.nodes
    .filter((node) => node.type === "rom_disassembly")
    .map((node) => ({
      id: node.id,
      name: node.name,
      label: node.label,
      address: node.address,
      metadata: {
        rom: node.metadata?.rom,
        disassembly_path: node.metadata?.disassembly_path,
        analysis_path: node.metadata?.analysis_path,
        output_dir: node.metadata?.output_dir,
        stackimport_analysis: node.metadata?.stackimport_analysis,
        completed_at: node.metadata?.completed_at
      }
    }));
}

function findDisassemblyNode(project: ReverseProject, input: string) {
  const decoded = decodeURIComponent(input);
  return project.nodes.find((node) =>
    node.type === "rom_disassembly" && (node.id === decoded || node.name === decoded || node.label === decoded)
  );
}

function xrefKindForMnemonic(mnemonic?: string): DisassemblyXref["kind"] {
  const normalized = (mnemonic ?? "").toLowerCase().replace(/\..*$/u, "");
  if (normalized === "bsr" || normalized === "jsr") return "call";
  if (normalized === "jmp") return "jump";
  if (normalized.startsWith("b") || normalized === "dbra") return "branch";
  return "reference";
}

function addXref(map: Map<string, DisassemblyXref[]>, key: string, xref: DisassemblyXref) {
  const list = map.get(key) ?? [];
  list.push(xref);
  map.set(key, list);
}

function cloneDisassemblyLine(line: DisassemblyLineView): DisassemblyLineView {
  return {
    ...line,
    memory_refs: line.memory_refs ? [...line.memory_refs] : undefined,
    xrefs_to: line.xrefs_to ? [...line.xrefs_to] : undefined,
    xrefs_from: line.xrefs_from ? [...line.xrefs_from] : undefined,
    annotations: line.annotations ? [...line.annotations] : undefined,
    repeatable_comments: line.repeatable_comments ? [...line.repeatable_comments] : undefined
  };
}

function nodeOverlayClass(nodes: ProjectNode[]): DisassemblyLineView["code_class"] {
  if (nodes.some((node) => node.type === "resource_marker" || node.type === "resource_asset")) return "resource";
  if (nodes.some((node) => node.type === "pointer_table")) return "table";
  if (nodes.some((node) => node.type === "data_region")) return "data";
  if (nodes.some((node) => node.type === "trap")) return "trap";
  if (nodes.some((node) => node.type === "function" || node.type === "function_candidate" || node.type === "symbol")) return "code";
  return undefined;
}

function xrefComment(address: string, inbound: DisassemblyXref[], outbound: DisassemblyXref[]) {
  const comments: string[] = [];
  if (inbound.length > 0) {
    const sample = inbound.slice(0, 5).map((xref) => `${xref.kind.toUpperCase()} ${xref.from}`).join(", ");
    comments.push(`XREF to ${address}: ${sample}${inbound.length > 5 ? `, ... ${inbound.length - 5} more` : ""}`);
  }
  if (outbound.length > 0) {
    const sample = outbound.slice(0, 5).map((xref) => `${xref.kind.toUpperCase()} ${xref.to}`).join(", ");
    comments.push(`XREF from ${address}: ${sample}${outbound.length > 5 ? `, ... ${outbound.length - 5} more` : ""}`);
  }
  return comments;
}

function disassemblyPathForNode(node: ProjectNode) {
  const disassemblyPath = typeof node.metadata?.disassembly_path === "string" ? resolve(node.metadata.disassembly_path) : "";
  if (!disassemblyPath || !existsSync(disassemblyPath) || !statSync(disassemblyPath).isFile()) {
    throw Object.assign(new Error(`Disassembly file is missing for '${node.id}'`), { status: 404 });
  }
  return disassemblyPath;
}

function buildDisassemblyFileIndex(path: string): DisassemblyFileIndex {
  const stats = statSync(path);
  const cacheKey = `${path}:${stats.mtimeMs}:${stats.size}`;
  const cached = disassemblyIndexCache.get(cacheKey);
  if (cached) return cached;

  for (const key of disassemblyIndexCache.keys()) {
    if (key.startsWith(`${path}:`)) disassemblyIndexCache.delete(key);
  }

  const lines = readFileSync(path, "utf8")
    .split(/\r?\n/u)
    .map((line, index) => parseDisassemblyViewLine(line, index + 1));
  const addressToOffset = new Map<string, number>();
  const labelToOffset = new Map<string, number>();
  const xrefsTo = new Map<string, DisassemblyXref[]>();
  const xrefsFrom = new Map<string, DisassemblyXref[]>();

  let instructionCount = 0;
  for (let offset = 0; offset < lines.length; offset++) {
    const line = lines[offset];
    if (line.label) labelToOffset.set(line.label, offset);
    if (!line.address) continue;
    addressToOffset.set(line.address, offset);
    if (line.kind === "instruction") instructionCount += 1;

    if (line.target) {
      const xref: DisassemblyXref = {
        from: line.address,
        to: line.target,
        kind: xrefKindForMnemonic(line.mnemonic),
        mnemonic: line.mnemonic,
        line: line.number
      };
      addXref(xrefsFrom, line.address, xref);
      addXref(xrefsTo, line.target, xref);
    }

    for (const ref of line.memory_refs ?? []) {
      const xref: DisassemblyXref = {
        from: line.address,
        to: ref,
        kind: "memory",
        mnemonic: line.mnemonic,
        line: line.number
      };
      addXref(xrefsFrom, line.address, xref);
      addXref(xrefsTo, ref, xref);
    }
  }

  const functionStarts = lines
    .map((line, offset) => ({ line, offset }))
    .filter((entry) => entry.line.label && /^fn[0-9A-F]{8}$/u.test(entry.line.label));
  const functions: DisassemblyFunctionIndex[] = [];
  const functionByAddress = new Map<string, DisassemblyFunctionIndex>();
  for (let i = 0; i < functionStarts.length; i++) {
    const entry = functionStarts[i];
    const start = entry.line.label?.replace(/^fn/u, "") ?? "";
    if (!start) continue;
    const nextOffset = functionStarts[i + 1]?.offset ?? lines.length;
    const addressLines = lines.slice(entry.offset, nextOffset).filter((line) => line.address);
    const end = addressLines.at(-1)?.address;
    const outboundRefs = addressLines.reduce((count, line) => count + (line.address ? (xrefsFrom.get(line.address)?.length ?? 0) : 0), 0);
    const fn: DisassemblyFunctionIndex = {
      label: entry.line.label ?? `fn${start}`,
      start,
      end,
      line: entry.line.number,
      instruction_count: addressLines.filter((line) => line.kind === "instruction").length,
      inbound_refs: xrefsTo.get(start)?.length ?? 0,
      outbound_refs: outboundRefs
    };
    functions.push(fn);
    for (const line of addressLines) {
      if (line.address) functionByAddress.set(line.address, fn);
    }
  }

  const index: DisassemblyFileIndex = {
    path,
    mtime_ms: stats.mtimeMs,
    total_lines: lines.length,
    instruction_count: instructionCount,
    lines,
    addressToOffset,
    labelToOffset,
    xrefsTo,
    xrefsFrom,
    functions,
    functionByAddress
  };
  disassemblyIndexCache.set(cacheKey, index);
  return index;
}

function readTsv(file: string): Array<Record<string, string>> {
  if (!existsSync(file) || !statSync(file).isFile()) return [];
  const lines = readFileSync(file, "utf8").split(/\r?\n/u).filter((line) => line.trim().length > 0);
  if (lines.length < 2) return [];
  const headers = lines[0].split("\t");
  return lines.slice(1).map((line) => {
    const cells = line.split("\t");
    return Object.fromEntries(headers.map((header, index) => [header, cells[index] ?? ""]));
  });
}

function atlasMapMtimeKey(root: string) {
  if (!existsSync(root) || !statSync(root).isDirectory()) return "";
  const parts: string[] = [];
  for (const dataset of readdirSync(root).sort()) {
    const dir = join(root, dataset);
    if (!statSync(dir).isDirectory()) continue;
    for (const file of readdirSync(dir).filter((name) => name.endsWith(".tsv")).sort()) {
      const full = join(dir, file);
      const stats = statSync(full);
      parts.push(`${dataset}/${file}:${stats.mtimeMs}:${stats.size}`);
    }
  }
  return parts.join("|");
}

function atlasMapKindToNodeType(kind: string, file: string, row: Record<string, string>) {
  if (file === "functions.tsv") return row.id?.startsWith("function:") ? "function" : "function_candidate";
  if (file === "pointer-tables.tsv") return "pointer_table";
  if (file === "data-regions.tsv") return "data_region";
  if (file === "resources.tsv") return row.kind === "resource_asset" ? "resource_asset" : "resource_marker";
  if (kind === "function" || kind === "function_candidate") return kind;
  if (kind === "pointer_table" || kind === "data_region" || kind === "resource_marker" || kind === "resource_asset" || kind === "rom_disassembly") return kind;
  return "atlas_map_region";
}

function atlasRowNode(dataset: string, file: string, row: Record<string, string>): ProjectNode | null {
  const address = (row.start || row.address || "").replace(/^0x/iu, "").toUpperCase();
  if (!address) return null;
  const kind = row.kind || file.replace(/\.tsv$/u, "");
  const id = `atlas:${dataset}:${row.id || `${kind}:${address}`}`;
  const now = new Date(0).toISOString();
  const metadata: Record<string, unknown> = {
    source: "atlas_map",
    dataset,
    file,
    confidence: row.confidence,
    end_address: row.end,
    summary: row.summary,
    original_id: row.id
  };
  for (const [key, value] of Object.entries(row)) {
    if (value && !(key in metadata)) metadata[key] = value;
  }
  return {
    id,
    type: atlasMapKindToNodeType(kind, file, row),
    address,
    label: row.name || row.id || `${kind} ${address}`,
    metadata,
    created_at: now,
    updated_at: now
  };
}

function atlasMapNodes() {
  const mtimeKey = atlasMapMtimeKey(ATLAS_MAPS_DIR);
  if (atlasMapCache?.root === ATLAS_MAPS_DIR && atlasMapCache.mtime_key === mtimeKey) return atlasMapCache.nodes;

  const nodes: ProjectNode[] = [];
  if (mtimeKey) {
    for (const dataset of readdirSync(ATLAS_MAPS_DIR).sort()) {
      const dir = join(ATLAS_MAPS_DIR, dataset);
      if (!statSync(dir).isDirectory()) continue;
      for (const file of ["functions.tsv", "pointer-tables.tsv", "resources.tsv", "data-regions.tsv"]) {
        for (const row of readTsv(join(dir, file))) {
          const node = atlasRowNode(dataset, file, row);
          if (node) nodes.push(node);
        }
      }
    }
  }

  atlasMapCache = { root: ATLAS_MAPS_DIR, mtime_key: mtimeKey, nodes };
  return nodes;
}

function projectAndAtlasNodes(project: ReverseProject) {
  const existing = new Set(project.nodes.map((node) => `${node.type}:${node.address ?? ""}:${node.label ?? node.name ?? ""}`));
  const overlays = atlasMapNodes().filter((node) => !existing.has(`${node.type}:${node.address ?? ""}:${node.label ?? node.name ?? ""}`));
  return [...project.nodes, ...overlays];
}

function atlasMapQuery(query: Record<string, unknown>) {
  const address = typeof query.address === "string" && query.address.trim()
    ? query.address.replace(/^0x/iu, "").toUpperCase()
    : "";
  const q = typeof query.q === "string" ? query.q.trim().toLowerCase() : "";
  const type = typeof query.type === "string" ? query.type.trim() : "";
  const dataset = typeof query.dataset === "string" ? query.dataset.trim() : "";
  const limit = Math.max(1, Math.min(5000, Number(query.limit ?? 500) || 500));
  const numericAddress = parseHexAddress(address);

  const nodes = atlasMapNodes()
    .filter((node) => {
      if (dataset && node.metadata?.dataset !== dataset) return false;
      if (type && node.type !== type) return false;
      if (q) {
        const haystack = [
          node.id,
          node.type,
          node.address,
          node.label,
          node.name,
          node.metadata?.summary,
          node.metadata?.source,
          node.metadata?.file
        ].filter(Boolean).join(" ").toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      if (numericAddress !== null) {
        const start = parseHexAddress(node.address);
        const end = parseHexAddress(typeof node.metadata?.end_address === "string" ? node.metadata.end_address : undefined) ?? start;
        if (start === null || end === null || numericAddress < start || numericAddress > end) return false;
      }
      return true;
    })
    .sort((a, b) => {
      const left = parseHexAddress(a.address) ?? Number.MAX_SAFE_INTEGER;
      const right = parseHexAddress(b.address) ?? Number.MAX_SAFE_INTEGER;
      return left - right || a.type.localeCompare(b.type) || a.id.localeCompare(b.id);
    });

  const datasets = groupCounts(atlasMapNodes().map((node) => String(node.metadata?.dataset ?? "unknown")));
  const types = groupCounts(atlasMapNodes().map((node) => node.type));
  const files = groupCounts(atlasMapNodes().map((node) => String(node.metadata?.file ?? "unknown")));

  return {
    root: relative(ATLAS_ROOT, ATLAS_MAPS_DIR) || ".",
    filters: { address, q, type, dataset, limit },
    total: nodes.length,
    returned: Math.min(nodes.length, limit),
    datasets,
    types,
    files,
    nodes: nodes.slice(0, limit)
  };
}

function projectAddressIndex(project: ReverseProject) {
  const nodesByAddress = new Map<string, ProjectNode[]>();
  for (const node of projectAndAtlasNodes(project)) {
    if (!node.address) continue;
    const address = node.address.toUpperCase();
    const list = nodesByAddress.get(address) ?? [];
    list.push(node);
    nodesByAddress.set(address, list);
  }
  return { nodesByAddress };
}

function walkSourceFiles(root: string, out: string[] = []): string[] {
  if (!existsSync(root) || !statSync(root).isDirectory()) return out;
  for (const entry of readdirSync(root)) {
    if (entry.startsWith(".")) continue;
    const full = join(root, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      walkSourceFiles(full, out);
      continue;
    }
    if (!stat.isFile() || stat.size > 2_000_000) continue;
    if (/\.(idump|rdump|rsrc|RSRC|o|bin|rom)$/u.test(entry)) continue;
    if (!/\.(a|asm|c|h|p|r|make|txt|equ|inc)$/iu.test(entry) && !/make$/iu.test(entry)) continue;
    out.push(full);
  }
  return out;
}

function buildSourceIndex(): SourceFileIndex[] {
  if (sourceIndexCache?.root === SUPERMARIO_SOURCE_DIR) return sourceIndexCache.files;
  const files = walkSourceFiles(SUPERMARIO_SOURCE_DIR)
    .map((path) => {
      try {
        return {
          path,
          relative_path: path.replace(`${SUPERMARIO_SOURCE_DIR}/`, ""),
          lines: readFileSync(path, "utf8").split(/\r?\n/u)
        };
      } catch {
        return null;
      }
    })
    .filter((file): file is SourceFileIndex => Boolean(file));
  sourceIndexCache = { root: SUPERMARIO_SOURCE_DIR, files };
  return files;
}

function sourceTermsFromText(value: unknown): string[] {
  if (typeof value !== "string") return [];
  return [...value.matchAll(/[A-Za-z_][A-Za-z0-9_#.$]{2,}|[A-Z][A-Z0-9 ]{3}|[0-9A-F]{8}/gu)]
    .map((match) => match[0].trim())
    .filter((term) => term.length >= 4 && !/^(label|function|candidate|marker|source|stackimport)$/iu.test(term));
}

function sourceMatchCategory(file: SourceFileIndex, line: string) {
  if (/Resources\/RomResources\.r$/u.test(file.relative_path)) return "ROM resources";
  if (/Gestalt|gestalt/u.test(line) || /Gestalt/u.test(file.relative_path)) return "Machine model";
  if (/\.r$/iu.test(file.relative_path)) return "Resource source";
  if (/\/DeclData\//u.test(file.relative_path) || /decl/u.test(line)) return "Decl data";
  if (/\.(a|asm)$/iu.test(file.relative_path)) return "Assembly source";
  if (/\.(c|h)$/iu.test(file.relative_path)) return "C source";
  if (/\.(p)$/iu.test(file.relative_path)) return "Pascal source";
  return "Source";
}

function sourceMatchBias(file: SourceFileIndex, line: string) {
  let score = 0;
  if (/Resources\/RomResources\.r$/u.test(file.relative_path)) score += 12;
  if (/Resources\//u.test(file.relative_path)) score += 4;
  if (/Gestalt|gestaltPowerBook|gestaltPDM/u.test(line)) score += 8;
  if (/rrsc|resource\s+'/u.test(line)) score += 6;
  if (/DRVR|CODE|PACK|STR#|MENU|ALRT|DITL|cfrg|decl/u.test(line)) score += 4;
  return score;
}

function findSourceMatches(terms: string[], limit = 32): SourceMatch[] {
  const uniqueTerms = [...new Set(terms.map((term) => term.trim()).filter((term) => term.length >= 3))].slice(0, 32);
  if (uniqueTerms.length === 0) return [];

  const matches: SourceMatch[] = [];
  const lowerTerms = uniqueTerms.map((term) => ({ term, lower: term.toLowerCase() }));
  for (const file of buildSourceIndex()) {
    for (let index = 0; index < file.lines.length; index++) {
      const line = file.lines[index];
      const lowerLine = line.toLowerCase();
      const hitTerms = lowerTerms.filter(({ lower }) => lowerLine.includes(lower)).map(({ term }) => term);
      if (hitTerms.length === 0) continue;
      const score = sourceMatchBias(file, line) + hitTerms.reduce((sum, term) => sum + Math.min(12, term.length), 0);
      matches.push({
        path: file.relative_path,
        line: index + 1,
        text: line.trim(),
        before: file.lines.slice(Math.max(0, index - 2), index).map((contextLine) => contextLine.trimEnd()),
        after: file.lines.slice(index + 1, index + 3).map((contextLine) => contextLine.trimEnd()),
        score,
        terms: hitTerms,
        category: sourceMatchCategory(file, line)
      });
    }
  }

  return matches
    .sort((a, b) => b.score - a.score || a.path.localeCompare(b.path) || a.line - b.line)
    .slice(0, limit);
}

function baseMnemonic(mnemonic?: string) {
  return (mnemonic ?? "").trim().toUpperCase().replace(/\.(B|W|L|S|D|X|P)$/u, "");
}

function conditionCodeSummary(conditionCodes: Instruction["condition_codes"] | undefined) {
  if (!conditionCodes) return "Unknown.";
  if (typeof conditionCodes !== "string") return JSON.stringify(conditionCodes);
  return conditionCodes
    .replace(/\|/gu, " ")
    .replace(/\s+/gu, " ")
    .trim()
    .slice(0, 420);
}

function operandEffects(mnemonic: string, operands = "") {
  const normalized = baseMnemonic(mnemonic);
  const operandParts = operands.split(",").map((operand) => operand.trim()).filter(Boolean);
  const destination = operandParts.at(-1) ?? "";
  const source = operandParts.length > 1 ? operandParts.slice(0, -1).join(", ") : operandParts[0] ?? "";
  const effects = {
    reads: [] as string[],
    writes: [] as string[],
    flags: [] as string[],
    stack: [] as string[],
    pc: [] as string[],
    memory: [] as string[],
    notes: [] as string[]
  };

  if (source) effects.reads.push(source);
  if ((/^(MOVE|MOVEA|MOVEQ|LEA|ADD|ADDA|ADDQ|SUB|SUBA|SUBQ|AND|OR|EOR|CLR|NEG|NOT|EXT|SWAP|AS|LS|RO|ROX)/u.test(normalized) || /^S[A-Z]{2}$/u.test(normalized)) && destination) {
    effects.writes.push(destination);
  }
  if (/^(CMP|CMPI|CMPA|TST|BTST)/u.test(normalized)) {
    effects.notes.push("Comparison/test only; destination data is not modified.");
  }
  if (/^(ADD|ADDI|ADDQ|ADDX|SUB|SUBI|SUBQ|SUBX|CMP|CMPI|TST|AND|OR|EOR|CLR|NEG|NOT|AS|LS|RO|ROX|BCHG|BCLR|BSET|BTST)/u.test(normalized)) {
    effects.flags.push("Updates condition codes according to result.");
  }
  if (/^S[A-Z]{2}$/u.test(normalized)) {
    effects.flags.push("Reads condition codes; does not modify them.");
    effects.notes.push("Sets destination byte to true/false according to the current condition codes.");
  }
  if (/^(BRA|B[ A-Z]{1,2}|DB[A-Z]{1,2})$/u.test(normalized) || normalized.startsWith("B")) {
    effects.pc.push("May replace PC with branch target if condition is true.");
  }
  if (normalized === "JMP") effects.pc.push("Loads PC from target address.");
  if (normalized === "JSR" || normalized === "BSR") {
    effects.stack.push("Pushes return address on A7/SP.");
    effects.pc.push("Transfers control to subroutine target.");
  }
  if (normalized === "RTS" || normalized === "RTE" || normalized === "RTR") {
    effects.stack.push("Pops return state from A7/SP.");
    effects.pc.push("Returns control to caller or exception return address.");
  }
  if (normalized === "LINK") {
    effects.stack.push("Builds a stack frame, usually using A6 as frame pointer.");
    effects.writes.push("A7/SP", operands.match(/\bA[0-7]\b/u)?.[0] ?? "frame pointer");
  }
  if (normalized === "UNLK") {
    effects.stack.push("Tears down a stack frame.");
    effects.writes.push("A7/SP", operands.match(/\bA[0-7]\b/u)?.[0] ?? "frame pointer");
  }
  if (/\([^)]*\)/u.test(operands) || /\b[0-9A-F]{6,8}\b/iu.test(operands)) {
    effects.memory.push("Reads or writes memory through an effective address.");
  }
  if (normalized === "TRAP" || normalized.startsWith("_")) {
    effects.pc.push("Enters the Mac OS/toolbox trap dispatcher.");
    effects.notes.push("Runtime behavior depends on the OS trap table and calling convention.");
  }

  return effects;
}

function instructionRuntimeSummary(line: DisassemblyLineView, instruction: Instruction | null, inbound: DisassemblyXref[], outbound: DisassemblyXref[], nodes: ProjectNode[]) {
  const normalized = baseMnemonic(line.mnemonic);
  const implications: string[] = [];
  if (line.trap) implications.push(`A-line trap ${line.trap} leaves normal 68k flow and dispatches through Mac OS ROM services.`);
  if (normalized === "JSR" || normalized === "BSR") implications.push("Subroutine call; expect argument setup immediately before this instruction and result handling immediately after it.");
  if (normalized === "JMP") implications.push("Unconditional transfer; the following linear bytes may be a different block or data.");
  if (normalized.startsWith("B") && normalized !== "BSR") implications.push("Conditional or unconditional branch; both fall-through and target should be considered until control flow is confirmed.");
  if (normalized.startsWith("DB")) implications.push("Counted loop control; low word of the data register is decremented as part of the branch decision.");
  if (normalized === "LINK") implications.push("Likely function prologue; stack locals and A6-relative parameters may follow.");
  if (normalized === "UNLK" || normalized === "RTS") implications.push("Likely function epilogue or return site.");
  if ((line.memory_refs ?? []).length > 0) implications.push(`Touches ${line.memory_refs?.slice(0, 3).join(", ")}; inspect as pointer, table, global, or ROM data.`);
  if (inbound.length > 0) implications.push(`${inbound.length} inbound reference(s) make this address externally reachable.`);
  if (outbound.length > 0) implications.push(`${outbound.length} outbound reference(s) define possible next code/data locations.`);
  const resourceNode = nodes.find((node) => ["resource_marker", "resource_asset", "data_region", "pointer_table"].includes(node.type));
  if (resourceNode) implications.push(`Overlaps ${resourceNode.type}${resourceNode.label ? ` (${resourceNode.label})` : ""}; treat linear instructions here cautiously.`);
  if (!instruction && line.mnemonic) implications.push("Mnemonic is not in the M68000 knowledge base; this may be a pseudo-op, decoded data, or processor-extension instruction.");
  if (implications.length === 0) implications.push("Straight-line instruction with no indexed branch, trap, or data annotation at this address.");
  return implications;
}

function extractFunctionNameFromSourceLine(line: string) {
  const trimmed = line.trim();
  const pascal = trimmed.match(/^(?:PROCEDURE|FUNCTION)\s+([A-Za-z_][A-Za-z0-9_]*)/iu)?.[1];
  if (pascal) return pascal;
  const c = trimmed.match(/^(?:pascal\s+|extern\s+|static\s+|void\s+|OSErr\s+|Boolean\s+|short\s+|long\s+|int\s+|Handle\s+|Ptr\s+|WindowPtr\s+|DialogPtr\s+|GrafPtr\s+|PicHandle\s+|THz\s+|Size\s+|ProcPtr\s+|UniversalProcPtr\s+)*[A-Za-z_][A-Za-z0-9_*\s]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*(?:\{|$)/u)?.[1];
  if (c) return c;
  const asm = trimmed.match(/^([A-Za-z_.$][A-Za-z0-9_.$]*):/u)?.[1];
  if (asm && !/^(@|L\d|loc|label)/iu.test(asm)) return asm;
  return undefined;
}

function sourceFunctionCandidates(matches: SourceMatch[], limit = 8) {
  const scored = new Map<string, { name: string; path: string; line: number; score: number; evidence: string }>();
  for (const match of matches) {
    const direct = extractFunctionNameFromSourceLine(match.text);
    const context = [...(match.before ?? []), match.text, ...(match.after ?? [])];
    const names = [direct, ...context.map(extractFunctionNameFromSourceLine)].filter((name): name is string => Boolean(name));
    for (const name of names) {
      const score = match.score + (direct === name ? 16 : 6) + (/\.(a|asm)$/iu.test(match.path) ? 4 : 0);
      const existing = scored.get(name);
      if (!existing || score > existing.score) {
        scored.set(name, { name, path: match.path, line: match.line, score, evidence: match.text });
      }
    }
  }
  return [...scored.values()].sort((a, b) => b.score - a.score || a.name.localeCompare(b.name)).slice(0, limit);
}

function nearbyProjectNodes(project: ReverseProject, address: string, radius = 0x2000) {
  const numeric = parseHexAddress(address);
  if (numeric === null) return [];
  return projectAndAtlasNodes(project)
    .map((node) => {
      const start = parseHexAddress(node.address);
      const end = parseHexAddress(typeof node.metadata?.end_address === "string" ? node.metadata.end_address : undefined) ?? start;
      if (start === null || end === null) return null;
      const distance = numeric >= start && numeric <= end
        ? 0
        : Math.min(Math.abs(numeric - start), Math.abs(numeric - end));
      return { node, distance };
    })
    .filter((entry): entry is { node: ProjectNode; distance: number } => entry !== null && entry.distance <= radius)
    .sort((a, b) => a.distance - b.distance || String(a.node.address).localeCompare(String(b.node.address)))
    .slice(0, 24)
    .map(({ node, distance }) => ({ ...node, distance }));
}

function sourceOverlayForAddress(project: ReverseProject, disassemblyId: string, addressInput: string) {
  const address = addressInput.replace(/^0x/iu, "").toUpperCase();
  const disassemblyNode = findDisassemblyNode(project, disassemblyId);
  if (!disassemblyNode) throw Object.assign(new Error(`Disassembly '${disassemblyId}' not found`), { status: 404 });
  const index = buildDisassemblyFileIndex(disassemblyPathForNode(disassemblyNode));
  const disassembly = readDisassembly(project, disassemblyId, { address, limit: 80 });
  const activeLines = disassembly.lines.filter((line) => line.address === address || line.target === address);
  const selectedLine = activeLines.find((line) => line.address === address) ?? activeLines[0];
  const nodes = projectAndAtlasNodes(project).filter((node) => node.address === address);
  const selectedFunction = index.functionByAddress.get(address);
  const inbound = index.xrefsTo.get(address) ?? [];
  const outbound = index.xrefsFrom.get(address) ?? [];
  const relatedAddresses = [
    selectedFunction?.start,
    selectedFunction?.end,
    ...inbound.slice(0, 16).map((xref) => xref.from),
    ...outbound.slice(0, 16).map((xref) => xref.to),
    ...activeLines.flatMap((line) => [line.target, ...(line.memory_refs ?? [])])
  ].filter((candidate): candidate is string => typeof candidate === "string" && candidate.length > 0);
  const terms = [
    address,
    selectedFunction?.label,
    ...activeLines.flatMap((line) => [
      line.function_label,
      line.mnemonic,
      ...sourceTermsFromText(line.operands),
      ...sourceTermsFromText(line.text)
    ]),
    ...nodes.flatMap((node) => [
      node.type,
      node.label,
      node.name,
      sourceTermsFromText(node.metadata?.resource_type),
      sourceTermsFromText(node.metadata?.kind),
      sourceTermsFromText(node.metadata?.classification),
      sourceTermsFromText(node.metadata?.context)
    ]).flat()
  ].filter((term): term is string => typeof term === "string" && term.length > 0);
  const sourceMatches = findSourceMatches(terms);
  const instruction = selectedLine?.mnemonic ? findInstruction(selectedLine.mnemonic) : null;

  return {
    address,
    source_root: SUPERMARIO_SOURCE_DIR,
    terms: [...new Set(terms)].slice(0, 32),
    navigation: {
      function: selectedFunction,
      inbound: inbound.slice(0, 48),
      outbound: outbound.slice(0, 48),
      related_addresses: [...new Set(relatedAddresses)].slice(0, 48),
      nearby_nodes: nearbyProjectNodes(project, address)
    },
    disassembly,
    nodes,
    instruction_semantics: selectedLine?.kind === "instruction" ? {
      line: selectedLine,
      mnemonic: selectedLine.mnemonic,
      operands: selectedLine.operands,
      help: instruction ? {
        mnemonic: instruction.name,
        syntax: instruction.syntax,
        operation: instruction.operation,
        description: instruction.description,
        attributes: instruction.attributes,
        condition_codes: conditionCodeSummary(instruction.condition_codes),
        line_number: instruction.line_number
      } : null,
      effects: operandEffects(selectedLine.mnemonic ?? "", selectedLine.operands),
      runtime_implications: instructionRuntimeSummary(selectedLine, instruction, inbound, outbound, nodes)
    } : null,
    supermario_function_candidates: sourceFunctionCandidates(sourceMatches),
    source_matches: sourceMatches
  };
}

function parseDisassemblyViewLine(text: string, number: number): DisassemblyLineView {
  if (!text.trim()) return { number, text, kind: "blank" };
  if (text.trimStart().startsWith(";")) return { number, text, kind: "comment" };

  const label = text.match(/^([A-Za-z_.$][A-Za-z0-9_.$]*):\s*$/u);
  if (label) return { number, text, label: label[1], kind: "label" };

  const instruction = text.match(/^([0-9A-F]{8})\s+(?:[0-9A-F]{2,4}(?:\s+[0-9A-F]{2,4})*)?\s+([.A-Za-z][.A-Za-z0-9]*)\s*(.*?)\s*$/u);
  if (!instruction) return { number, text, kind: "comment" };

  const operands = instruction[3].trim();
  const target =
    operands.match(/\/\*\s*([0-9A-F]{8})\s*\*\//u)?.[1] ??
    operands.match(/\b(label[0-9A-F]{8})\b/u)?.[1]?.replace(/^label/u, "") ??
    undefined;
  const trap = text.match(/\$A[0-9A-F]{3}/u)?.[0]?.slice(1);
  const memoryRefs = [...operands.matchAll(/\b(?:0x)?([0-9A-F]{6,8})\b/gu)]
    .map((match) => match[1].toUpperCase().padStart(8, "0"))
    .filter((address) => address !== target);

  return {
    number,
    text,
    address: instruction[1],
    mnemonic: instruction[2],
    operands,
    target,
    memory_refs: [...new Set(memoryRefs)],
    trap,
    kind: "instruction"
  };
}

function annotateDisassemblyWindow(
  project: ReverseProject,
  index: DisassemblyFileIndex,
  lines: DisassemblyLineView[],
  initialFunction = ""
) {
  const { nodesByAddress } = projectAddressIndex(project);
  let currentFunction = initialFunction;
  for (const line of lines) {
    if (line.label) {
      currentFunction = line.label;
      line.function_label = currentFunction;
      continue;
    }
    if (line.address) {
      line.function_label = currentFunction;
      const comments: string[] = [];
      const fn = index.functionByAddress.get(line.address);
      if (fn) {
        line.function_label = fn.label;
        line.function_start = fn.start;
        line.function_end = fn.end;
        line.symbol_name = fn.label;
        if (fn.start === line.address) {
          comments.push(`FUNCTION ${fn.label} starts here; ${fn.instruction_count} instructions, ${fn.inbound_refs} inbound refs.`);
        }
      }
      line.xrefs_to = index.xrefsTo.get(line.address)?.slice(0, 24) ?? [];
      line.xrefs_from = index.xrefsFrom.get(line.address)?.slice(0, 24) ?? [];
      const matchingNodes = nodesByAddress.get(line.address) ?? [];
      if (matchingNodes.length > 0) {
        line.code_class = nodeOverlayClass(matchingNodes);
        line.annotations = matchingNodes.slice(0, 8).map((node) => ({
          id: node.id,
          type: node.type,
          label: node.label ?? node.name,
          metadata: node.metadata
        }));
        const named = matchingNodes.find((node) => node.type === "function" || node.type === "symbol" || node.type === "function_candidate");
        if (named?.label || named?.name) {
          line.function_label = named.label ?? named.name;
          line.symbol_name = named.label ?? named.name;
        }
        for (const node of matchingNodes.slice(0, 4)) {
          if (node.type === "data_region") comments.push(`DATA ${node.label ?? node.name ?? node.type}${node.metadata?.end_address ? ` through ${node.metadata.end_address}` : ""}.`);
          if (node.type === "pointer_table") comments.push(`POINTER TABLE ${node.label ?? node.name ?? ""} ${node.metadata?.entry_count ?? ""} entries.`.trim());
          if (node.type === "resource_marker" || node.type === "resource_asset") comments.push(`RESOURCE ${node.label ?? node.name ?? node.type}.`);
          if (node.type === "trap") comments.push(`TRAP ${node.label ?? node.name ?? node.address ?? ""}.`);
        }
      }
      comments.push(...xrefComment(line.address, line.xrefs_to, line.xrefs_from));
      if (line.target) comments.push(`CONTROL TARGET ${line.target}.`);
      if ((line.memory_refs ?? []).length > 0) comments.push(`MEMORY REF ${(line.memory_refs ?? []).slice(0, 4).join(", ")}.`);
      const noteTitles = project.notes
        .filter((note) => note.target?.toUpperCase() === line.address)
        .map((note) => note.title || note.text.slice(0, 80))
        .slice(0, 3);
      comments.push(...noteTitles.map((title) => `NOTE ${title}`));
      if (comments.length > 0) line.repeatable_comments = [...new Set(comments)].slice(0, 8);
      if (!line.code_class && line.trap) line.code_class = "trap";
      if (!line.code_class) line.code_class = "code";
    }
  }
  return lines;
}

function readDisassembly(project: ReverseProject, disassemblyId: string, query: Record<string, unknown>) {
  const node = findDisassemblyNode(project, disassemblyId);
  if (!node) throw Object.assign(new Error(`Disassembly '${disassemblyId}' not found`), { status: 404 });

  const index = buildDisassemblyFileIndex(disassemblyPathForNode(node));
  const allLines = index.lines;
  const addressInput = typeof query.address === "string" ? query.address.replace(/^0x/iu, "").toUpperCase() : "";
  const searchInput = typeof query.q === "string" ? query.q.trim().toLowerCase() : "";
  const limit = Math.max(25, Math.min(1000, Number(query.limit ?? 250) || 250));
  let offset = Math.max(0, Number(query.offset ?? 0) || 0);
  let lines = allLines;

  if (addressInput) {
    const found = index.addressToOffset.get(addressInput) ?? index.labelToOffset.get(`label${addressInput}`) ?? index.labelToOffset.get(`fn${addressInput}`) ?? -1;
    if (found >= 0) offset = Math.max(0, found - Math.floor(limit / 4));
  }

  if (searchInput) {
    lines = allLines.filter((line) => line.text.toLowerCase().includes(searchInput));
    offset = 0;
  }

  const initialFunction = [...allLines]
    .slice(0, offset)
    .reverse()
    .find((line) => line.label)?.label ?? "";
  const window = annotateDisassemblyWindow(project, index, lines.slice(offset, offset + limit).map(cloneDisassemblyLine), initialFunction);
  return {
    disassembly: {
      id: node.id,
      name: node.name,
      label: node.label,
      metadata: node.metadata
    },
    total_lines: lines.length,
    source_total_lines: allLines.length,
    index: {
      instruction_count: index.instruction_count,
      function_count: index.functions.length,
      xrefs: [...index.xrefsFrom.values()].reduce((count, refs) => count + refs.length, 0),
      indexed_addresses: index.addressToOffset.size,
      indexed_labels: index.labelToOffset.size
    },
    offset,
    limit,
    lines: window
  };
}

function disassemblyIndexSummary(project: ReverseProject, disassemblyId: string) {
  const node = findDisassemblyNode(project, disassemblyId);
  if (!node) throw Object.assign(new Error(`Disassembly '${disassemblyId}' not found`), { status: 404 });
  const index = buildDisassemblyFileIndex(disassemblyPathForNode(node));
  const structureCounts = project.nodes.reduce<Record<string, number>>((counts, node) => {
    counts[node.type] = (counts[node.type] ?? 0) + 1;
    return counts;
  }, {});
  const xrefCount = [...index.xrefsFrom.values()].reduce((count, refs) => count + refs.length, 0);
  return {
    disassembly: { id: node.id, label: node.label ?? node.name },
    total_lines: index.total_lines,
    instructions: index.instruction_count,
    indexed_addresses: index.addressToOffset.size,
    indexed_labels: index.labelToOffset.size,
    functions: index.functions.length,
    xrefs: xrefCount,
    structure: {
      function_candidates: structureCounts.function_candidate ?? 0,
      pointer_tables: structureCounts.pointer_table ?? 0,
      data_regions: structureCounts.data_region ?? 0,
      resource_markers: structureCounts.resource_marker ?? 0,
      resource_assets: structureCounts.resource_asset ?? 0
    },
    top_functions: [...index.functions]
      .sort((a, b) => b.inbound_refs - a.inbound_refs || b.instruction_count - a.instruction_count)
      .slice(0, 50)
  };
}

function disassemblyXrefs(project: ReverseProject, disassemblyId: string, addressInput: string) {
  const node = findDisassemblyNode(project, disassemblyId);
  if (!node) throw Object.assign(new Error(`Disassembly '${disassemblyId}' not found`), { status: 404 });
  const index = buildDisassemblyFileIndex(disassemblyPathForNode(node));
  const address = addressInput.replace(/^0x/iu, "").toUpperCase();
  return {
    address,
    inbound: index.xrefsTo.get(address) ?? [],
    outbound: index.xrefsFrom.get(address) ?? [],
    function: index.functionByAddress.get(address)
  };
}

interface ParsedDisassemblyInstruction {
  address: string;
  mnemonic: string;
  operands: string;
  target?: string;
  trap?: string;
  label?: string;
}

function readRomBytesForNode(project: ReverseProject, rom: ProjectNode): Buffer {
  const sourcePath = typeof rom.metadata?.source_path === "string" ? resolve(rom.metadata.source_path) : "";
  if (sourcePath && existsSync(sourcePath) && statSync(sourcePath).isFile()) return readFileSync(sourcePath);

  const pages = project.nodes
    .filter((node) => node.type === "memory_page" && node.metadata?.rom === rom.id)
    .sort((a, b) => Number(a.metadata?.offset ?? 0) - Number(b.metadata?.offset ?? 0));
  return Buffer.concat(pages.map((page) => Buffer.from(String(page.metadata?.data_hex ?? ""), "hex")));
}

function parsedDisassemblyInstructions(project: ReverseProject, disassemblyId: string): ParsedDisassemblyInstruction[] {
  const node = findDisassemblyNode(project, disassemblyId);
  if (!node) throw Object.assign(new Error(`Disassembly '${disassemblyId}' not found`), { status: 404 });
  const disassemblyPath = typeof node.metadata?.disassembly_path === "string" ? resolve(node.metadata.disassembly_path) : "";
  if (!disassemblyPath || !existsSync(disassemblyPath) || !statSync(disassemblyPath).isFile()) {
    throw Object.assign(new Error(`Disassembly file is missing for '${node.id}'`), { status: 404 });
  }

  let currentLabel = "";
  const result: ParsedDisassemblyInstruction[] = [];
  const lines = readFileSync(disassemblyPath, "utf8").split(/\r?\n/u);
  for (let index = 0; index < lines.length; index++) {
    const parsed = parseDisassemblyViewLine(lines[index], index + 1);
    if (parsed.label) {
      currentLabel = parsed.label;
      continue;
    }
    if (parsed.kind !== "instruction" || !parsed.address || !parsed.mnemonic) continue;
    result.push({
      address: parsed.address,
      mnemonic: parsed.mnemonic.toLowerCase(),
      operands: parsed.operands ?? "",
      target: parsed.target,
      trap: parsed.trap,
      label: currentLabel
    });
  }
  return result;
}

function importStackimportStructureIntoProject(
  project: ReverseProject,
  rom: ProjectNode,
  disassemblyId: string,
  stackimportAnalysis: Record<string, unknown>
) {
  let nodes = 0;
  let edges = 0;

  const functionCandidates = Array.isArray(stackimportAnalysis.function_candidates_sample)
    ? stackimportAnalysis.function_candidates_sample
    : [];
  for (const entry of functionCandidates) {
    if (!entry || typeof entry !== "object") continue;
    const candidate = entry as Record<string, unknown>;
    if (typeof candidate.address !== "string") continue;
    const address = candidate.address.toUpperCase();
    const node = upsertNode(project, {
      id: nodeId("function_candidate", `${rom.id}:${address}`),
      type: "function_candidate",
      address,
      label: typeof candidate.label === "string" && candidate.label ? candidate.label : `Function candidate ${address}`,
      metadata: {
        source: "stackimport",
        disassembly: disassemblyId,
        calls: candidate.calls,
        jumps: candidate.jumps,
        references: candidate.references,
        confidence: candidate.confidence
      }
    });
    upsertEdge(project, {
      id: edgeId("contains_function_candidate", rom.id, node.id),
      type: "contains_function_candidate",
      from: rom.id,
      to: node.id
    });
    nodes += 1;
    edges += 1;
  }

  const pointerTables = Array.isArray(stackimportAnalysis.pointer_table_regions_sample)
    ? stackimportAnalysis.pointer_table_regions_sample
    : [];
  for (const entry of pointerTables) {
    if (!entry || typeof entry !== "object") continue;
    const table = entry as Record<string, unknown>;
    if (typeof table.address !== "string") continue;
    const address = table.address.toUpperCase();
    const node = upsertNode(project, {
      id: nodeId("pointer_table", `${rom.id}:${address}`),
      type: "pointer_table",
      address,
      label: `Pointer table ${address}`,
      metadata: {
        source: "stackimport",
        disassembly: disassemblyId,
        entry_count: table.entry_count,
        targets: Array.isArray(table.targets) ? table.targets : []
      }
    });
    upsertEdge(project, {
      id: edgeId("contains_pointer_table", rom.id, node.id),
      type: "contains_pointer_table",
      from: rom.id,
      to: node.id
    });
    nodes += 1;
    edges += 1;
  }

  const dataRegions = Array.isArray(stackimportAnalysis.data_regions_sample)
    ? stackimportAnalysis.data_regions_sample
    : [];
  for (const entry of dataRegions) {
    if (!entry || typeof entry !== "object") continue;
    const region = entry as Record<string, unknown>;
    if (typeof region.start !== "string") continue;
    const start = region.start.toUpperCase();
    const node = upsertNode(project, {
      id: nodeId("data_region", `${rom.id}:${start}:${String(region.end ?? "")}`),
      type: "data_region",
      address: start,
      label: `${String(region.kind ?? "data")} ${start}`,
      metadata: {
        source: "stackimport",
        disassembly: disassemblyId,
        end_address: region.end,
        kind: region.kind,
        item_count: region.item_count,
        confidence: region.confidence
      }
    });
    upsertEdge(project, {
      id: edgeId("contains_data_region", rom.id, node.id),
      type: "contains_data_region",
      from: rom.id,
      to: node.id
    });
    nodes += 1;
    edges += 1;
  }

  const resourceMarkers = Array.isArray(stackimportAnalysis.resource_markers_sample)
    ? stackimportAnalysis.resource_markers_sample
    : [];
  for (const entry of resourceMarkers) {
    if (!entry || typeof entry !== "object") continue;
    const marker = entry as Record<string, unknown>;
    if (typeof marker.address !== "string") continue;
    const address = marker.address.toUpperCase();
    const type = typeof marker.type === "string" ? marker.type : "resource";
    const node = upsertNode(project, {
      id: nodeId("resource_marker", `${rom.id}:${address}:${type}`),
      type: "resource_marker",
      address,
      label: `${type} marker ${address}`,
      metadata: {
        source: "stackimport",
        disassembly: disassemblyId,
        resource_type: type,
        context: marker.context
      }
    });
    upsertEdge(project, {
      id: edgeId("contains_resource_marker", rom.id, node.id),
      type: "contains_resource_marker",
      from: rom.id,
      to: node.id
    });
    nodes += 1;
    edges += 1;
  }

  const resourceAssets = Array.isArray(stackimportAnalysis.resource_assets_sample)
    ? stackimportAnalysis.resource_assets_sample
    : [];
  for (const entry of resourceAssets) {
    if (!entry || typeof entry !== "object") continue;
    const asset = entry as Record<string, unknown>;
    const type = typeof asset.type === "string" ? asset.type : "????";
    const id = typeof asset.id === "number" || typeof asset.id === "string" ? String(asset.id) : String(asset.order ?? "unknown");
    const address = typeof asset.address === "string" ? asset.address.toUpperCase() : undefined;
    const node = upsertNode(project, {
      id: nodeId("resource_asset", `${rom.id}:${type}:${id}:${String(asset.variant_index ?? 0)}`),
      type: "resource_asset",
      address,
      label: `${type} #${id}`,
      metadata: {
        source: "stackimport",
        disassembly: disassemblyId,
        resource_type: type,
        resource_id: asset.id,
        name: asset.name,
        native_size: asset.native_size,
        output_file: asset.output_file,
        media_type: asset.media_type,
        width: asset.width,
        height: asset.height,
        variant_index: asset.variant_index,
        status: asset.status
      }
    });
    upsertEdge(project, {
      id: edgeId("contains_resource_asset", rom.id, node.id),
      type: "contains_resource_asset",
      from: rom.id,
      to: node.id
    });
    nodes += 1;
    edges += 1;
  }

  return { nodes_upserted: nodes, edges_upserted: edges };
}

function removeStaleGeneratedStructure(project: ReverseProject, rom: ProjectNode, base: number, end: number) {
  const generatedTypes = new Set(["function_candidate", "pointer_table", "data_region", "resource_marker"]);
  const removed = new Set<string>();

  project.nodes = project.nodes.filter((node) => {
    if (!generatedTypes.has(node.type)) return true;
    if (node.metadata?.source !== "rom_structure_analysis") return true;
    if (!node.id.includes(rom.id)) return true;

    const address = parseHexAddress(node.address);
    if (address !== null && address >= base && address < end) return true;
    removed.add(node.id);
    return false;
  });

  if (removed.size > 0) {
    project.edges = project.edges.filter((edge) => !removed.has(edge.from) && !removed.has(edge.to));
  }

  return removed.size;
}

function classifyRomStructure(project: ReverseProject, body: Record<string, unknown>) {
  const rom = findRomNode(project, body.rom_id);
  const disassemblyId = typeof body.disassembly_id === "string" && body.disassembly_id.trim()
    ? body.disassembly_id.trim()
    : disassemblyNodes(project).find((node) => node.metadata.rom === rom.id)?.id;
  if (!disassemblyId) throw Object.assign(new Error(`No disassembly found for ROM '${rom.id}'`), { status: 404 });

  const disassemblyNode = findDisassemblyNode(project, disassemblyId);
  const disassemblyBase = typeof disassemblyNode?.metadata?.stackimport_analysis === "object" &&
    disassemblyNode.metadata.stackimport_analysis !== null &&
    typeof (disassemblyNode.metadata.stackimport_analysis as Record<string, unknown>).base_address === "string"
    ? (disassemblyNode.metadata.stackimport_analysis as Record<string, unknown>).base_address as string
    : undefined;
  const base = parseHexAddress(disassemblyBase?.replace(/^0x/iu, "") ?? rom.address) ?? 0;
  const bytes = readRomBytesForNode(project, rom);
  const end = base + bytes.length;
  const staleGeneratedNodesRemoved = removeStaleGeneratedStructure(project, rom, base, end);
  const instructions = parsedDisassemblyInstructions(project, disassemblyId);
  const byAddress = new Map(instructions.map((instruction) => [instruction.address, instruction]));
  const inbound = new Map<string, { calls: number; jumps: number; refs: Set<string> }>();

  for (const instruction of instructions) {
    if (!instruction.target || !byAddress.has(instruction.target)) continue;
    const bucket = inbound.get(instruction.target) ?? { calls: 0, jumps: 0, refs: new Set<string>() };
    if (instruction.mnemonic === "bsr" || instruction.mnemonic === "jsr") bucket.calls += 1;
    else bucket.jumps += 1;
    bucket.refs.add(instruction.address);
    inbound.set(instruction.target, bucket);
  }

  const maxFunctions = Math.max(10, Math.min(500, Number(body.max_functions ?? 200) || 200));
  const functionCandidates = [...inbound.entries()]
    .map(([address, value]) => {
      const instruction = byAddress.get(address);
      const score = value.calls * 3 + value.jumps + Math.min(8, value.refs.size);
      return { address, score, calls: value.calls, jumps: value.jumps, refs: [...value.refs], label: instruction?.label };
    })
    .filter((candidate) => candidate.calls > 0 || candidate.score >= 3)
    .sort((a, b) => b.score - a.score || a.address.localeCompare(b.address))
    .slice(0, maxFunctions);

  const pointerTables: Array<{ address: string; entries: string[]; byte_length: number }> = [];
  for (let offset = 0; offset + 16 <= bytes.length;) {
    const entries: string[] = [];
    let cursor = offset;
    while (cursor + 4 <= bytes.length) {
      const value = bytes.readUInt32BE(cursor);
      if (value < base || value >= end || (value & 1) !== 0) break;
      entries.push(formatAddress(value));
      cursor += 4;
    }
    if (entries.length >= 4) {
      pointerTables.push({ address: formatAddress(base + offset), entries: entries.slice(0, 64), byte_length: entries.length * 4 });
      offset = cursor;
    } else {
      offset += 2;
    }
  }

  const resourceTypes = ["DRVR", "ndrv", "decl", "boot", "CODE", "PACK", "STR#", "STR ", "MENU", "ALRT", "DITL", "cfrg", "ptch", "rsrc"];
  const resourceMarkers: Array<{ address: string; type: string; context: string }> = [];
  for (const type of resourceTypes) {
    const needle = Buffer.from(type, "ascii");
    let offset = bytes.indexOf(needle);
    while (offset >= 0 && resourceMarkers.length < 500) {
      const start = Math.max(0, offset - 16);
      const finish = Math.min(bytes.length, offset + 48);
      resourceMarkers.push({
        address: formatAddress(base + offset),
        type,
        context: bytes.subarray(start, finish).toString("latin1").replace(/[^\x20-\x7E]/gu, ".")
      });
      offset = bytes.indexOf(needle, offset + 1);
    }
  }

  const stringNodes = project.nodes
    .filter((node) => (node.type === "cstring" || node.type === "pstring") && node.address)
    .map((node) => ({ node, address: parseHexAddress(node.address) ?? 0 }))
    .filter((item) => item.address >= base && item.address < end)
    .sort((a, b) => a.address - b.address);
  const stringRegions: Array<{ start: string; end: string; strings: number; label: string }> = [];
  let regionStart = -1;
  let regionEnd = -1;
  let count = 0;
  for (const item of stringNodes) {
    const length = Number(item.node.metadata?.string_length ?? 0) || String(item.node.metadata?.value ?? "").length;
    if (regionStart < 0 || item.address - regionEnd > 256) {
      if (count >= 3) stringRegions.push({ start: formatAddress(regionStart), end: formatAddress(regionEnd), strings: count, label: "Dense string/data area" });
      regionStart = item.address;
      count = 0;
    }
    regionEnd = Math.max(regionEnd, item.address + length);
    count += 1;
  }
  if (count >= 3) stringRegions.push({ start: formatAddress(regionStart), end: formatAddress(regionEnd), strings: count, label: "Dense string/data area" });

  let nodes = 0;
  let edges = 0;
  for (const candidate of functionCandidates) {
    const functionNode = upsertNode(project, {
      id: nodeId("function_candidate", `${rom.id}:${candidate.address}`),
      type: "function_candidate",
      address: candidate.address,
      label: candidate.label && !candidate.label.startsWith("label") ? candidate.label : `Function candidate ${candidate.address}`,
      metadata: { source: "rom_structure_analysis", disassembly: disassemblyId, confidence_score: candidate.score, calls: candidate.calls, jumps: candidate.jumps, refs: candidate.refs }
    });
    nodes += 1;
    upsertEdge(project, {
      id: edgeId("contains_function_candidate", rom.id, functionNode.id),
      type: "contains_function_candidate",
      from: rom.id,
      to: functionNode.id
    });
    edges += 1;
  }

  for (const table of pointerTables.slice(0, Math.max(10, Math.min(300, Number(body.max_tables ?? 120) || 120)))) {
    const tableNode = upsertNode(project, {
      id: nodeId("pointer_table", `${rom.id}:${table.address}`),
      type: "pointer_table",
      address: table.address,
      label: `Pointer table ${table.address}`,
      metadata: { source: "rom_structure_analysis", entries: table.entries, entry_count: table.entries.length, byte_length: table.byte_length }
    });
    nodes += 1;
    upsertEdge(project, {
      id: edgeId("contains_pointer_table", rom.id, tableNode.id),
      type: "contains_pointer_table",
      from: rom.id,
      to: tableNode.id
    });
    edges += 1;
  }

  for (const marker of resourceMarkers.slice(0, Math.max(10, Math.min(300, Number(body.max_resources ?? 120) || 120)))) {
    const resourceNode = upsertNode(project, {
      id: nodeId("resource_marker", `${rom.id}:${marker.address}:${marker.type}`),
      type: "resource_marker",
      address: marker.address,
      label: `${marker.type} marker ${marker.address}`,
      metadata: { source: "rom_structure_analysis", resource_type: marker.type, context: marker.context }
    });
    nodes += 1;
    upsertEdge(project, {
      id: edgeId("contains_resource_marker", rom.id, resourceNode.id),
      type: "contains_resource_marker",
      from: rom.id,
      to: resourceNode.id
    });
    edges += 1;
  }

  for (const region of stringRegions.slice(0, Math.max(10, Math.min(200, Number(body.max_string_regions ?? 80) || 80)))) {
    const regionNode = upsertNode(project, {
      id: nodeId("data_region", `${rom.id}:${region.start}:${region.end}`),
      type: "data_region",
      address: region.start,
      label: `${region.label} ${region.start}-${region.end}`,
      metadata: { source: "rom_structure_analysis", end_address: region.end, strings: region.strings, classification: "string_cluster" }
    });
    nodes += 1;
    upsertEdge(project, {
      id: edgeId("contains_data_region", rom.id, regionNode.id),
      type: "contains_data_region",
      from: rom.id,
      to: regionNode.id
    });
    edges += 1;
  }

  return {
    rom,
    disassembly_id: disassemblyId,
    summary: {
      instructions: instructions.length,
      function_candidates: functionCandidates.length,
      pointer_tables: pointerTables.length,
      resource_markers: resourceMarkers.length,
      string_regions: stringRegions.length,
      nodes_upserted: nodes,
      edges_upserted: edges,
      stale_generated_nodes_removed: staleGeneratedNodesRemoved
    },
    samples: {
      function_candidates: functionCandidates.slice(0, 20),
      pointer_tables: pointerTables.slice(0, 20),
      resource_markers: resourceMarkers.slice(0, 20),
      string_regions: stringRegions.slice(0, 20)
    },
    project: graphSummary(project)
  };
}

function resolveSectionId(value: string): string | null {
  const trimmed = value.trim();
  if (kb.section_boundaries[trimmed]) return trimmed;

  const numeric = trimmed.match(/^(?:section_)?(\d+)$/u);
  if (numeric) return kb.metadata.sections[Number(numeric[1]) - 1] ?? null;

  const prefixed = trimmed.startsWith("section_") ? trimmed : `section_${trimmed}`;
  if (kb.section_boundaries[prefixed]) return prefixed;

  return kb.metadata.sections.find((section) => section.endsWith(`_${trimmed}`)) ?? null;
}

function getSectionGuide(sectionInput: string) {
  const section = resolveSectionId(sectionInput);
  if (!section) return null;

  const boundary = kb.section_boundaries[section];
  if (!boundary) return null;

  const [start, end] = boundary;
  const concepts = kb.concepts.filter((concept) => concept.section === section);
  const instructions = kb.instructions.filter(
    (instruction) => instruction.line_number >= start && instruction.line_number <= end
  );

  return { id: section, concepts, instructions, line_range: [start, end] };
}

function isSearchType(value: unknown): value is SearchType {
  return value === "instructions" || value === "concepts" || value === "all";
}

function parseLimit(value: unknown): number {
  const limit = Number(value ?? DEFAULT_LIMIT);
  if (!Number.isFinite(limit)) return DEFAULT_LIMIT;
  return Math.max(1, Math.min(MAX_LIMIT, Math.trunc(limit)));
}

function searchTypeToKind(type: SearchType): SearchKind | null {
  if (type === "instructions") return "instruction";
  if (type === "concepts") return "concept";
  return null;
}

function tokenize(value: string): string[] {
  return value
    .toLowerCase()
    .replace(/([a-z])([0-9])/gu, "$1 $2")
    .replace(/([0-9])([a-z])/gu, "$1 $2")
    .match(/[a-z0-9]+/gu) ?? [];
}

function instructionSearchText(instruction: Instruction): string {
  return [
    instruction.name,
    instruction.name,
    instruction.name,
    instruction.syntax,
    instruction.operation,
    instruction.description,
    instruction.attributes,
    typeof instruction.condition_codes === "string" ? instruction.condition_codes : JSON.stringify(instruction.condition_codes)
  ].filter(Boolean).join(" ");
}

function conceptSearchText(concept: Concept): string {
  return [concept.text, concept.type, concept.section].filter(Boolean).join(" ");
}

function buildBm25Index(knowledgeBase: KnowledgeBase): Bm25Index {
  const documents: SearchDocument[] = [
    ...knowledgeBase.instructions.map((instruction) => ({
      id: `instruction:${instruction.name}:${instruction.line_number}`,
      kind: "instruction" as const,
      text: instructionSearchText(instruction),
      data: instruction
    })),
    ...knowledgeBase.concepts.map((concept) => ({
      id: `concept:${concept.line}`,
      kind: "concept" as const,
      text: conceptSearchText(concept),
      data: concept
    }))
  ];

  const documentFrequency = new Map<string, number>();
  const documentLengths: number[] = [];
  const termFrequencies = documents.map((document) => {
    const terms = tokenize(document.text);
    const frequencies = new Map<string, number>();
    documentLengths.push(terms.length);

    for (const term of terms) {
      frequencies.set(term, (frequencies.get(term) ?? 0) + 1);
    }

    for (const term of frequencies.keys()) {
      documentFrequency.set(term, (documentFrequency.get(term) ?? 0) + 1);
    }

    return frequencies;
  });

  const totalLength = documentLengths.reduce((sum, length) => sum + length, 0);

  return {
    documents,
    termFrequencies,
    documentLengths,
    documentFrequency,
    averageDocumentLength: documents.length ? totalLength / documents.length : 0
  };
}

function scoreBoost(document: SearchDocument, queryTerms: string[]): number {
  if (document.kind !== "instruction") return 0;

  const instruction = document.data as Instruction;
  const name = instruction.name.toLowerCase();
  const query = queryTerms.join("");
  if (!query) return 0;

  if (name === query) return 8;
  if (query.startsWith(name)) return 7;
  if (name.startsWith(query)) return 4;
  if (instruction.syntax.toLowerCase().includes(queryTerms.join(" "))) return 1;
  return 0;
}

function bm25Search(index: Bm25Index, queryInput: string, type: SearchType): RankedSearchDocument[] {
  const queryTerms = [...new Set(tokenize(queryInput))];
  if (!queryTerms.length || !index.documents.length) return [];

  const k1 = 1.2;
  const b = 0.75;
  const kind = searchTypeToKind(type);

  return index.documents
    .map((document, indexPosition) => {
      if (kind && document.kind !== kind) {
        return null;
      }

      const frequencies = index.termFrequencies[indexPosition];
      const documentLength = index.documentLengths[indexPosition] || 1;
      let score = 0;

      for (const term of queryTerms) {
        const termFrequency = frequencies.get(term) ?? 0;
        if (!termFrequency) continue;

        const matchingDocuments = index.documentFrequency.get(term) ?? 0;
        const inverseDocumentFrequency = Math.log(1 + (index.documents.length - matchingDocuments + 0.5) / (matchingDocuments + 0.5));
        const normalizedFrequency = termFrequency + k1 * (1 - b + b * (documentLength / index.averageDocumentLength));
        score += inverseDocumentFrequency * ((termFrequency * (k1 + 1)) / normalizedFrequency);
      }

      score += scoreBoost(document, queryTerms);

      return score > 0 ? { ...document, score } : null;
    })
    .filter((document): document is RankedSearchDocument => document !== null)
    .sort((a, b) => b.score - a.score);
}

function toSearchResult(match: RankedSearchDocument): SearchResult {
  return {
    type: match.kind,
    score: Number(match.score.toFixed(4)),
    data: match.data
  };
}

function searchKnowledgeBase(queryInput: string, typeInput: unknown = "all", limitInput?: unknown) {
  const query = queryInput.trim();
  const type = isSearchType(typeInput) ? typeInput : "all";
  const limit = parseLimit(limitInput);
  const rankedMatches = bm25Search(searchIndex, query, type);
  const matches = rankedMatches.slice(0, limit).map(toSearchResult);

  return { query, type, limit, total: rankedMatches.length, ranking: "bm25", matches };
}

function getStringArg(args: Record<string, unknown>, key: string): string | null {
  const value = args[key];
  return typeof value === "string" ? value : null;
}

function mcpText(value: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: typeof value === "string" ? value : JSON.stringify(value, null, 2)
      }
    ]
  };
}

function mcpError(message: string) {
  return { ...mcpText(message), isError: true };
}

const server = new Server(
  { name: "m68k-knowledge-server", version: SERVER_VERSION },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, () => ({ tools }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name } = request.params;
  const args = (request.params.arguments ?? {}) as Record<string, unknown>;

  try {
    switch (name) {
      case "annotate_instructions": {
        const assembly = getStringArg(args, "assembly");
        if (!assembly) return mcpError("Missing required string argument: assembly");
        return mcpText(annotateAssemblyDocument(assembly));
      }
      case "analyze_disassembly": {
        const assembly = getStringArg(args, "assembly");
        if (!assembly) return mcpError("Missing required string argument: assembly");
        return mcpText(analyzeAssemblyDocument(assembly));
      }
      case "get_instruction_help": {
        const mnemonic = getStringArg(args, "mnemonic");
        if (!mnemonic) return mcpError("Missing required string argument: mnemonic");
        const instruction = findInstruction(mnemonic);
        return instruction ? mcpText(instruction) : mcpError(`Instruction '${mnemonic}' not found.`);
      }
      case "get_section_guide": {
        const section = getStringArg(args, "section");
        if (!section) return mcpError("Missing required string argument: section");
        const guide = getSectionGuide(section);
        return guide ? mcpText(guide) : mcpError(`Section '${section}' not found.`);
      }
      case "search_knowledge_base": {
        const query = getStringArg(args, "query");
        if (!query) return mcpError("Missing required string argument: query");
        return mcpText(searchKnowledgeBase(query, args.type, args.limit));
      }
      case "list_sections": {
        return mcpText(kb.metadata.sections);
      }
      default:
        return mcpError(`Unknown tool: ${name}`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return mcpError(message);
  }
});

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.static(PUBLIC_DIR));

const apiRoutes = {
  health: "GET /api/health",
  metadata: "GET /api/metadata",
  instructions: "GET /api/instructions",
  instruction: "GET /api/instructions/:mnemonic",
  annotate: "POST /api/annotate { assembly: string }",
  analyze: "POST /api/analyze { assembly: string }",
  projects: "GET/POST /api/projects",
  project: "GET /api/projects/:id",
  projectGraph: "GET /api/projects/:id/graph?root=&q=&depth=1&limit=500&edgeTypes=&nodeTypes=",
  projectNodes: "POST /api/projects/:id/nodes",
  projectEdges: "POST /api/projects/:id/edges",
  projectNotes: "GET/POST /api/projects/:id/notes",
  projectNote: "GET/PATCH /api/projects/:id/notes/:noteId",
  projectTypes: "GET/POST /api/projects/:id/types",
  projectApplyType: "POST /api/projects/:id/apply-type { target, type_id, role? }",
  projectAnalysisImport: "POST /api/projects/:id/import-analysis { assembly: string }",
  projectRomImport: "POST /api/projects/:id/roms { name, base_address, data_hex|data_base64, traps? }",
  projectRomDisassemble: "POST /api/projects/:id/roms/disassemble { rom_id?, base_address?, import_analysis? }",
  projectRomStructure: "POST /api/projects/:id/roms/structure { rom_id, disassembly_id?, max_functions?, max_tables? }",
  projectDisassemblies: "GET /api/projects/:id/disassemblies",
  projectDisassembly: "GET /api/projects/:id/disassemblies/:disassemblyId?offset=0&limit=250&q=&address=",
  projectDisassemblyIndex: "GET /api/projects/:id/disassemblies/:disassemblyId/index",
  projectDisassemblyXrefs: "GET /api/projects/:id/disassemblies/:disassemblyId/xrefs/:address",
  projectDisassemblySourceOverlay: "GET /api/projects/:id/disassemblies/:disassemblyId/source-overlay/:address",
  projectAtlasMaps: "GET /api/projects/:id/atlas-maps?address=",
  projectEvents: "GET /api/projects/:id/events",
  projectMemoryRead: "GET /api/projects/:id/memory/:address?length=16",
  sections: "GET /api/sections",
  section: "GET /api/sections/:id",
  search: "GET /api/search?q=add&type=all&limit=20"
};

app.get("/api", (_req, res) => {
  res.json({
    name: "m68k-knowledge-server",
    version: SERVER_VERSION,
    ranking: "bm25",
    routes: apiRoutes
  });
});

app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    version: SERVER_VERSION,
    timestamp: new Date().toISOString(),
    knowledge_base: {
      instructions: kb.instructions.length,
      concepts: kb.concepts.length,
      search_documents: searchIndex.documents.length
    },
    projects: loadProjectStore().projects.length
  });
});

app.get("/api/metadata", (_req, res) => {
  res.json(kb.metadata);
});

app.get("/api/instructions", (_req, res) => {
  res.json({ count: kb.instructions.length, instructions: kb.instructions.map((instruction) => instruction.name) });
});

app.get("/api/instructions/:mnemonic", (req, res) => {
  const instruction = findInstruction(req.params.mnemonic);
  if (!instruction) return res.status(404).json({ error: `Instruction '${req.params.mnemonic}' not found` });
  return res.json(instruction);
});

app.post("/api/annotate", (req, res) => {
  const { assembly } = req.body as { assembly?: unknown };
  if (typeof assembly !== "string" || !assembly.trim()) {
    return res.status(400).json({ error: "Missing non-empty 'assembly' string in request body" });
  }

  return res.json(annotateAssemblyDocument(assembly));
});

app.post("/api/analyze", (req, res) => {
  const { assembly } = req.body as { assembly?: unknown };
  if (typeof assembly !== "string" || !assembly.trim()) {
    return res.status(400).json({ error: "Missing non-empty 'assembly' string in request body" });
  }

  return res.json(analyzeAssemblyDocument(assembly));
});

app.get("/api/projects", (_req, res) => {
  const store = loadProjectStore();
  return res.json({ projects: store.projects.map(graphSummary) });
});

app.post("/api/projects", (req, res) => {
  const { name, description } = req.body as { name?: unknown; description?: unknown };
  if (typeof name !== "string" || !name.trim()) {
    return res.status(400).json({ error: "Missing non-empty 'name' string in request body" });
  }

  const store = loadProjectStore();
  const project = createProject(name.trim(), typeof description === "string" ? description : undefined);
  store.projects.push(project);
  saveProjectStore(store);
  return res.status(201).json(project);
});

app.get("/api/projects/:id", (req, res) => {
  const project = loadProjectStore().projects.find((candidate) => candidate.id === req.params.id);
  if (!project) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
  return res.json(project);
});

app.get("/api/projects/:id/graph", (req, res, next) => {
  try {
    const project = loadProjectStore().projects.find((candidate) => candidate.id === req.params.id);
    if (!project) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
    return res.json(buildSparseLinkageGraph(project, req.query as Record<string, unknown>));
  } catch (error) {
    return next(error);
  }
});

app.get("/api/projects/:id/events", (req, res) => {
  const project = loadProjectStore().projects.find((candidate) => candidate.id === req.params.id);
  if (!project) return res.status(404).json({ error: `Project '${req.params.id}' not found` });

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  projectEventClients.add(res);
  sendProjectEvent(res, "projects", {
    timestamp: nowIso(),
    projects: loadProjectStore().projects.map(graphSummary)
  });
  const heartbeat = setInterval(() => {
    sendProjectEvent(res, "heartbeat", { timestamp: nowIso() });
  }, 30_000);

  req.on("close", () => {
    clearInterval(heartbeat);
    projectEventClients.delete(res);
  });
});

app.get("/api/projects/:id/disassemblies", (req, res) => {
  const project = loadProjectStore().projects.find((candidate) => candidate.id === req.params.id);
  if (!project) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
  return res.json({ disassemblies: disassemblyNodes(project) });
});

app.get("/api/projects/:id/disassemblies/:disassemblyId", (req, res, next) => {
  try {
    const project = loadProjectStore().projects.find((candidate) => candidate.id === req.params.id);
    if (!project) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
    return res.json(readDisassembly(project, req.params.disassemblyId, req.query));
  } catch (error) {
    return next(error);
  }
});

app.get("/api/projects/:id/disassemblies/:disassemblyId/index", (req, res, next) => {
  try {
    const project = loadProjectStore().projects.find((candidate) => candidate.id === req.params.id);
    if (!project) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
    return res.json(disassemblyIndexSummary(project, req.params.disassemblyId));
  } catch (error) {
    return next(error);
  }
});

app.get("/api/projects/:id/disassemblies/:disassemblyId/xrefs/:address", (req, res, next) => {
  try {
    const project = loadProjectStore().projects.find((candidate) => candidate.id === req.params.id);
    if (!project) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
    return res.json(disassemblyXrefs(project, req.params.disassemblyId, req.params.address));
  } catch (error) {
    return next(error);
  }
});

app.get("/api/projects/:id/disassemblies/:disassemblyId/source-overlay/:address", (req, res, next) => {
  try {
    const project = loadProjectStore().projects.find((candidate) => candidate.id === req.params.id);
    if (!project) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
    return res.json(sourceOverlayForAddress(project, req.params.disassemblyId, req.params.address));
  } catch (error) {
    return next(error);
  }
});

app.get("/api/projects/:id/atlas-maps", (req, res, next) => {
  try {
    const project = loadProjectStore().projects.find((candidate) => candidate.id === req.params.id);
    if (!project) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
    return res.json(atlasMapQuery(req.query as Record<string, unknown>));
  } catch (error) {
    return next(error);
  }
});

app.post("/api/projects/:id/nodes", (req, res) => {
  const { id, type, address, name, label, metadata } = req.body as Record<string, unknown>;
  if (typeof id !== "string" || typeof type !== "string") {
    return res.status(400).json({ error: "Missing required string fields: id, type" });
  }

  const result = withProject(req.params.id, (project) => upsertNode(project, {
    id,
    type,
    address: typeof address === "string" ? address.toUpperCase() : undefined,
    name: typeof name === "string" ? name : undefined,
    label: typeof label === "string" ? label : undefined,
    metadata: metadata && typeof metadata === "object" ? metadata as Record<string, unknown> : undefined
  }));
  if (!result) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
  return res.status(201).json(result);
});

app.post("/api/projects/:id/edges", (req, res) => {
  const { id, type, from, to, label, metadata } = req.body as Record<string, unknown>;
  if (typeof id !== "string" || typeof type !== "string" || typeof from !== "string" || typeof to !== "string") {
    return res.status(400).json({ error: "Missing required string fields: id, type, from, to" });
  }

  const result = withProject(req.params.id, (project) => upsertEdge(project, {
    id,
    type,
    from,
    to,
    label: typeof label === "string" ? label : undefined,
    metadata: metadata && typeof metadata === "object" ? metadata as Record<string, unknown> : undefined
  }));
  if (!result) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
  return res.status(201).json(result);
});

app.get("/api/projects/:id/notes", (req, res) => {
  const project = loadProjectStore().projects.find((candidate) => candidate.id === req.params.id);
  if (!project) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
  const { tag, target, kind } = req.query;
  let notes = [...project.notes];
  if (typeof tag === "string" && tag.trim()) {
    notes = notes.filter((note) => note.tags?.some((candidate) => candidate.toLowerCase() === tag.toLowerCase()));
  }
  if (typeof target === "string" && target.trim()) {
    notes = notes.filter((note) => note.target === target);
  }
  if (typeof kind === "string" && kind.trim()) {
    notes = notes.filter((note) => note.kind === kind);
  }
  notes.sort((a, b) => String(b.updated_at ?? b.created_at).localeCompare(String(a.updated_at ?? a.created_at)));
  return res.json({ notes });
});

app.post("/api/projects/:id/notes", (req, res) => {
  const { title, text, target, tags, kind } = req.body as {
    title?: unknown; text?: unknown; target?: unknown; tags?: unknown; kind?: unknown;
  };
  if (typeof text !== "string" || !text.trim()) {
    return res.status(400).json({ error: "Missing non-empty 'text' string in request body" });
  }

  const result = withProject(req.params.id, (project) => {
    const timestamp = nowIso();
    const note: ProjectNote = {
      id: `note:${Date.now().toString(36)}`,
      title: typeof title === "string" && title.trim() ? title.trim() : undefined,
      text: text.trim(),
      target: typeof target === "string" ? target : undefined,
      tags: Array.isArray(tags) ? tags.filter((tag): tag is string => typeof tag === "string") : undefined,
      kind: typeof kind === "string" && kind.trim() ? kind.trim() : "note",
      created_at: timestamp,
      updated_at: timestamp
    };
    project.notes.push(note);
    return note;
  });
  if (!result) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
  return res.status(201).json(result);
});

app.get("/api/projects/:id/notes/:noteId", (req, res) => {
  const project = loadProjectStore().projects.find((candidate) => candidate.id === req.params.id);
  if (!project) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
  const note = project.notes.find((candidate) => candidate.id === decodeURIComponent(req.params.noteId));
  if (!note) return res.status(404).json({ error: `Note '${req.params.noteId}' not found` });
  return res.json(note);
});

app.patch("/api/projects/:id/notes/:noteId", (req, res) => {
  const { title, text, target, tags, kind } = req.body as {
    title?: unknown; text?: unknown; target?: unknown; tags?: unknown; kind?: unknown;
  };
  const result = withProject(req.params.id, (project) => {
    const note = project.notes.find((candidate) => candidate.id === decodeURIComponent(req.params.noteId));
    if (!note) throw Object.assign(new Error(`Note '${req.params.noteId}' not found`), { status: 404 });
    if (typeof title === "string") note.title = title.trim() || undefined;
    if (typeof text === "string") {
      if (!text.trim()) throw Object.assign(new Error("Note text cannot be empty"), { status: 400 });
      note.text = text.trim();
    }
    if (typeof target === "string") note.target = target.trim() || undefined;
    if (Array.isArray(tags)) note.tags = tags.filter((tag): tag is string => typeof tag === "string");
    if (typeof kind === "string") note.kind = kind.trim() || "note";
    note.updated_at = nowIso();
    return note;
  });
  if (!result) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
  return res.json(result);
});

app.get("/api/projects/:id/types", (req, res) => {
  const project = loadProjectStore().projects.find((candidate) => candidate.id === req.params.id);
  if (!project) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
  return res.json({ types: project.types ?? [] });
});

app.post("/api/projects/:id/types", (req, res) => {
  const { id, kind, name, size, fields, values, returns, parameters, metadata } = req.body as Record<string, unknown>;
  if (typeof kind !== "string" || typeof name !== "string" || !name.trim()) {
    return res.status(400).json({ error: "Missing required string fields: kind, name" });
  }

  const typeId = typeof id === "string" && id.trim() ? id.trim() : `${kind}:${slug(name)}`;
  const result = withProject(req.params.id, (project) => upsertType(project, {
    id: typeId,
    kind,
    name: name.trim(),
    size: typeof size === "number" ? size : undefined,
    fields: Array.isArray(fields) ? fields.filter((field): field is Record<string, unknown> => Boolean(field) && typeof field === "object") : undefined,
    values: values && typeof values === "object" && !Array.isArray(values) ? values as Record<string, number | string> : undefined,
    returns: typeof returns === "string" ? returns : undefined,
    parameters: Array.isArray(parameters) ? parameters.filter((parameter): parameter is Record<string, unknown> => Boolean(parameter) && typeof parameter === "object") : undefined,
    metadata: metadata && typeof metadata === "object" ? metadata as Record<string, unknown> : undefined
  }));
  if (!result) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
  return res.status(201).json(result);
});

app.post("/api/projects/:id/apply-type", (req, res) => {
  const { target, type_id, role, metadata } = req.body as Record<string, unknown>;
  if (typeof target !== "string" || typeof type_id !== "string") {
    return res.status(400).json({ error: "Missing required string fields: target, type_id" });
  }

  const result = withProject(req.params.id, (project) => {
    const type = project.types.find((candidate) => candidate.id === type_id || candidate.name === type_id);
    if (!type) throw new Error(`Type '${type_id}' not found`);

    const typeNodeId = nodeId("type", type.id);
    upsertTypeNode(project, type);
    return upsertEdge(project, {
      id: edgeId("typed_as", target, typeNodeId),
      type: "typed_as",
      from: target,
      to: typeNodeId,
      label: typeof role === "string" ? role : undefined,
      metadata: metadata && typeof metadata === "object" ? metadata as Record<string, unknown> : undefined
    });
  });
  if (!result) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
  return res.status(201).json(result);
});

app.post("/api/projects/:id/import-analysis", (req, res) => {
  const { assembly } = req.body as { assembly?: unknown };
  if (typeof assembly !== "string" || !assembly.trim()) {
    return res.status(400).json({ error: "Missing non-empty 'assembly' string in request body" });
  }

  const analysis = analyzeAssemblyDocument(assembly);
  const result = withProject(req.params.id, (project) => importAnalysisIntoProject(project, analysis));
  if (!result) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
  return res.json({ import: result, analysis });
});

app.post("/api/projects/:id/roms", (req, res, next) => {
  try {
    const result = withProject(req.params.id, (project) => importRomIntoProject(project, req.body as Record<string, unknown>));
    if (!result) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
    return res.status(201).json(result);
  } catch (error) {
    return next(error);
  }
});

app.post("/api/projects/:id/roms/import-path", (req, res, next) => {
  try {
    const { path, base_address, page_size } = req.body as { path?: unknown; base_address?: unknown; page_size?: unknown };
    if (typeof path !== "string" || !path.trim()) {
      return res.status(400).json({ error: "Missing required 'path' string field" });
    }

    const result = withProject(req.params.id, (project) =>
      importRomFromPath(
        project,
        path,
        typeof base_address === "string" ? base_address : undefined,
        typeof page_size === "number" ? page_size : undefined
      )
    );
    if (!result) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
    return res.status(201).json(result);
  } catch (error) {
    return next(error);
  }
});

app.post("/api/projects/:id/roms/disassemble", async (req, res, next) => {
  try {
    const store = loadProjectStore();
    const project = store.projects.find((candidate) => candidate.id === req.params.id);
    if (!project) return res.status(404).json({ error: `Project '${req.params.id}' not found` });

    const result = await disassembleRomForProject(project, req.body as Record<string, unknown>);
    project.updated_at = nowIso();
    saveProjectStore(store);
    return res.json(result);
  } catch (error) {
    return next(error);
  }
});

app.post("/api/projects/:id/roms/structure", (req, res, next) => {
  try {
    const result = withProject(req.params.id, (project) => classifyRomStructure(project, req.body as Record<string, unknown>));
    if (!result) return res.status(404).json({ error: `Project '${req.params.id}' not found` });
    return res.json(result);
  } catch (error) {
    return next(error);
  }
});

app.get("/api/projects/:id/memory/:address", (req, res, next) => {
  try {
    const project = loadProjectStore().projects.find((candidate) => candidate.id === req.params.id);
    if (!project) return res.status(404).json({ error: `Project '${req.params.id}' not found` });

    const type = req.query.type as string | undefined;
    const memory = readProjectMemory(project, req.params.address, req.query.length);
    if (!memory) return res.status(404).json({ error: `No imported memory page contains '${req.params.address}'` });

    if (!type || type === "raw") {
      return res.json(memory);
    }

    const bytes = memory.bytes;
    const result: Record<string, unknown> = { ...memory };

    if (type === "byte") {
      result.value = bytes[0];
      result.signed = bytes[0] > 127 ? bytes[0] - 256 : bytes[0];
      result.unsigned = bytes[0];
    } else if (type === "word") {
      if (bytes.length < 2) return res.status(400).json({ error: "Not enough bytes for word read" });
      const val = (bytes[0] << 8) | bytes[1];
      result.value = val;
      result.signed = val > 32767 ? val - 65536 : val;
      result.unsigned = val;
    } else if (type === "long") {
      if (bytes.length < 4) return res.status(400).json({ error: "Not enough bytes for long read" });
      const val = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
      result.value = val;
      result.signed = val > 2147483647 ? val - 4294967296 : val;
      result.unsigned = val;
    } else if (type === "cstring") {
      const end = bytes.indexOf(0);
      const strBytes = end >= 0 ? bytes.slice(0, end) : bytes;
      result.value = String.fromCharCode(...strBytes);
      result.length = strBytes.length;
      if (end >= 0) result.null_terminated = true;
    } else if (type === "pstring") {
      const len = bytes[0] ?? 0;
      const strBytes = bytes.slice(1, 1 + len);
      result.length = len;
      result.value = String.fromCharCode(...strBytes);
      result.max_length = bytes[0] ?? 0;
    } else if (type === "pointer") {
      if (bytes.length < 4) return res.status(400).json({ error: "Not enough bytes for pointer read" });
      const ptr = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
      result.value = formatAddress(ptr);
      result.target_address = formatAddress(ptr);
    }

    const annotations: Array<{ offset: number; node_id?: string; label?: string; type?: string }> = [];
    for (const node of project.nodes) {
      if (node.type === "symbol" || node.type === "function" || node.type === "code" || node.type === "data") {
        if (node.address) {
          const nodeAddr = parseHexAddress(node.address);
          if (nodeAddr !== null && nodeAddr >= memory.offset && nodeAddr < memory.offset + bytes.length) {
            annotations.push({ offset: nodeAddr - memory.offset, node_id: node.id, label: node.label, type: node.type });
          }
        }
      }
    }
    if (annotations.length > 0) result.annotations = annotations;

    return res.json(result);
  } catch (error) {
    return next(error);
  }
});

app.get("/api/projects/:id/memory/:address/hexdump", (req, res, next) => {
  try {
    const project = loadProjectStore().projects.find((candidate) => candidate.id === req.params.id);
    if (!project) return res.status(404).json({ error: `Project '${req.params.id}' not found` });

    const length = Math.max(1, Math.min(4096, Number(req.query.length ?? 256) || 256));
    const memory = readProjectMemory(project, req.params.address, length);
    if (!memory) return res.status(404).json({ error: `No imported memory page contains '${req.params.address}'` });

    const bytes = memory.bytes;
    const address = parseHexAddress(memory.mapped_from ?? memory.requested_address ?? memory.address) ?? 0;
    const lines: Array<{ offset: number; address: string; hex: string; ascii: string }> = [];

    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const lineAddr = address + i;
      const hexParts: string[] = [];
      const asciiParts: string[] = [];

      for (let j = 0; j < 16; j++) {
        if (j < chunk.length) {
          hexParts.push(chunk[j].toString(16).toUpperCase().padStart(2, "0"));
          asciiParts.push(chunk[j] >= 32 && chunk[j] <= 126 ? String.fromCharCode(chunk[j]) : ".");
        } else {
          hexParts.push("  ");
          asciiParts.push(" ");
        }
      }

      lines.push({
        offset: i,
        address: formatAddress(lineAddr),
        hex: hexParts.join(" "),
        ascii: asciiParts.join("")
      });
    }

    return res.json({
      start_address: memory.address,
      requested_address: memory.requested_address,
      mapped_from: memory.mapped_from,
      length: bytes.length,
      lines
    });
  } catch (error) {
    return next(error);
  }
});

app.post("/api/projects/:id/scan-strings", (req, res, next) => {
  try {
    const project = loadProjectStore().projects.find((candidate) => candidate.id === req.params.id);
    if (!project) return res.status(404).json({ error: `Project '${req.params.id}' not found` });

    const { min_length, pascal_only, ascii_only, offset, length } = req.body as {
      min_length?: unknown; pascal_only?: unknown; ascii_only?: unknown; offset?: unknown; length?: unknown;
    };

    const minLen = Math.max(1, Math.min(256, Number(min_length ?? 4) || 4));
    const pageNodes = project.nodes.filter((n) => n.type === "memory_page");
    if (pageNodes.length === 0) return res.status(404).json({ error: "No ROM pages found in project" });

    const allStrings: Array<{ address: string; type: string; value: string; length: number; page: string }> = [];
    const scannedPages: string[] = [];

    for (const page of pageNodes) {
      scannedPages.push(page.id);
      const dataHex = page.metadata?.data_hex as string | undefined;
      if (!dataHex) continue;

      const pageBytes = Buffer.from(dataHex, "hex");
      const start = parseHexAddress(page.address) ?? 0;
      const scanStart = typeof offset === "number" ? offset : 0;
      const scanLen = typeof length === "number" ? length : pageBytes.length;
      const slice = pageBytes.subarray(scanStart, scanStart + scanLen);

      if (!ascii_only) {
        let asciiStart = -1;
        let asciiLen = 0;
        for (let i = 0; i < slice.length; i++) {
          const byte = slice[i];
          const isPrintable = byte >= 32 && byte <= 126;
          if (isPrintable) {
            if (asciiStart < 0) { asciiStart = i; asciiLen = 1; }
            else { asciiLen += 1; }
          } else {
            if (asciiLen >= minLen) {
              const addr = formatAddress(start + scanStart + asciiStart);
              const value = slice.slice(asciiStart, asciiStart + asciiLen).toString("ascii");
              allStrings.push({ address: addr, type: "cstring", value, length: asciiLen, page: page.id });
            }
            asciiStart = -1;
            asciiLen = 0;
          }
        }
        if (asciiLen >= minLen) {
          const addr = formatAddress(start + scanStart + asciiStart);
          const value = slice.slice(asciiStart, asciiStart + asciiLen).toString("ascii");
          allStrings.push({ address: addr, type: "cstring", value, length: asciiLen, page: page.id });
        }
      }

      if (!pascal_only) {
        for (let i = 0; i < slice.length; i++) {
          const len = slice[i];
          if (len === 0 || len > 255) continue;
          if (i + 1 + len > slice.length) continue;
          let isPrintable = true;
          for (let j = 1; j <= len; j++) {
            const b = slice[i + j];
            if (b < 32 || b > 126) { isPrintable = false; break; }
          }
          if (!isPrintable) continue;
          if (len < minLen) continue;
          const addr = formatAddress(start + scanStart + i);
          const value = slice.slice(i + 1, i + 1 + len).toString("ascii");
          allStrings.push({ address: addr, type: "pstring", value, length: len, page: page.id });
          i += len;
        }
      }
    }

    for (const str of allStrings) {
      const strNode = upsertNode(project, {
        id: nodeId("string", `${str.address}:${str.type}:${str.value.slice(0, 20)}`),
        type: str.type,
        address: str.address,
        label: str.value.slice(0, 40),
        metadata: { value: str.value, string_length: str.length, page: str.page, scanned_from: scannedPages }
      });
      const pageNodeId = nodeId("memory_page", `${str.page}:${str.address}`);
      upsertEdge(project, {
        id: edgeId("contains_string", pageNodeId, strNode.id),
        type: "contains_string",
        from: pageNodeId,
        to: strNode.id
      });
    }

    return res.json({ strings_found: allStrings.length, pages_scanned: scannedPages.length, strings: allStrings });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/sections", (_req, res) => {
  const sections = kb.metadata.sections.map((section, index) => ({
    id: section,
    number: index + 1,
    title: section.replace(/^section_\d+_/u, "").replace(/_/gu, " "),
    range: kb.section_boundaries[section]
  }));
  res.json(sections);
});

app.get("/api/sections/:id", (req, res) => {
  const guide = getSectionGuide(req.params.id);
  if (!guide) return res.status(404).json({ error: `Section '${req.params.id}' not found` });
  return res.json(guide);
});

app.get("/api/traps", (req, res) => {
  const { manager, search } = req.query;
  let results = trapDb.traps;
  if (typeof manager === "string" && manager.trim()) {
    results = results.filter((t) => t.manager.toLowerCase().includes(manager.toLowerCase()));
  }
  if (typeof search === "string" && search.trim()) {
    const q = search.toLowerCase();
    results = results.filter((t) =>
      t.name.toLowerCase().includes(q) ||
      t.trap_word.toLowerCase().includes(q) ||
      t.description.toLowerCase().includes(q)
    );
  }
  return res.json({ count: results.length, traps: results });
});

app.get("/api/traps/:word", (req, res) => {
  const trap = findTrapByWord(req.params.word);
  if (!trap) return res.status(404).json({ error: `Trap '${req.params.word}' not found in database` });
  return res.json(trap);
});

app.get("/api/traps/name/:name", (req, res) => {
  const trap = findTrapByName(req.params.name);
  if (!trap) return res.status(404).json({ error: `Trap '${req.params.name}' not found in database` });
  return res.json(trap);
});

app.get("/api/search", (req, res) => {
  const { q, type, limit } = req.query;
  if (typeof q !== "string" || !q.trim()) {
    return res.status(400).json({ error: "Missing non-empty 'q' query parameter" });
  }

  return res.json(searchKnowledgeBase(q, type, limit));
});

function errorHandler(err: Error, _req: Request, res: Response, _next: NextFunction) {
  const statusValue = (err as Error & { status?: unknown }).status;
  const status = typeof statusValue === "number" ? statusValue : 500;
  console.error("API Error:", err.message);
  res.status(status).json({ error: err.message });
}

app.use(errorHandler);

const PORT = parseInt(process.env.PORT || "3000", 10);
const ENABLE_REST = process.env.REST_API !== "false";
const ENABLE_MCP = process.env.MCP_STDIO !== "false";

async function main() {
  if (!ENABLE_REST && !ENABLE_MCP) {
    throw new Error("REST_API and MCP_STDIO cannot both be disabled.");
  }

  if (ENABLE_REST) {
    app.listen(PORT, () => {
      console.error(`REST API running on http://localhost:${PORT}`);
    });
  }

  if (ENABLE_MCP) {
    await server.connect(new StdioServerTransport());
    console.error("MCP server running on stdio");
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
