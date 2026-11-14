// github-core-clone-01: a standalone GitHub-compatible git forge.
// Node 22 TypeScript, zero dependencies (node:http, node:zlib, node:crypto only).
// One process, fully in-memory store, git objects kept byte-for-byte verbatim.
// Surfaces: git smart HTTP (upload-pack v2 / receive-pack v0), REST v3,
// GraphQL, MCP. Viewer identity is the scenario viewer: adaiversen (id 1000).

import { createHash, randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

export interface ForgeOptions {
  token: string;
  trialNowSec: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const VIEWER_LOGIN = 'adaiversen';
export const VIEWER_ID = 1000;
export const VIEWER_NAME = 'ada iversen';
export const VIEWER_EMAIL = 'adaiversen@example.invalid';
export const DEFAULT_BRANCH = 'main';
export const ZERO_OID = '0000000000000000000000000000000000000000';
const AGENT = 'github-core-clone/1.0.0';

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

export function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

export function gitObjectId(type: string, bytes: Buffer): string {
  const header = Buffer.from(`${type} ${bytes.length}\0`, 'ascii');
  return sha1Hex(Buffer.concat([header, bytes]));
}

export function nowIso(trialNowSec: number): string {
  return new Date(trialNowSec * 1000).toISOString();
}

export function gitTimestamp(trialNowSec: number): string {
  return `${trialNowSec} +0000`;
}

export function encodeGlobalId(kind: string, ...parts: (string | number)[]): string {
  return Buffer.from([kind, ...parts].join(':'), 'utf8').toString('base64');
}

export function decodeGlobalId(id: string): { kind: string; parts: string[] } | null {
  try {
    const decoded = Buffer.from(id, 'base64').toString('utf8');
    const parts = decoded.split(':');
    if (parts.length < 2) return null;
    return { kind: parts[0], parts: parts.slice(1) };
  } catch {
    return null;
  }
}

export function escapeHtmlJson(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r');
}

// ---------------------------------------------------------------------------
// pkt-line framing (git wire protocol)
// ---------------------------------------------------------------------------

export function pktLine(data: Buffer | string): Buffer {
  const payload = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  const len = payload.length + 4;
  const head = Buffer.alloc(4);
  head.write(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, payload]);
}

export const FLUSH_PKT = Buffer.from('0000', 'ascii');
export const DELIM_PKT = Buffer.from('0001', 'ascii');
export const RESPONSE_END_PKT = Buffer.from('0002', 'ascii');

export interface PktParseResult {
  lines: Buffer[];
  rest: Buffer;
  sawFlush: boolean;
  sawDelim: boolean;
  sawResponseEnd: boolean;
}

/** Parse pkt-lines from the front of buf until a flush/delim/response-end or EOF. */
export function parsePktLines(buf: Buffer): PktParseResult {
  const lines: Buffer[] = [];
  let off = 0;
  let sawFlush = false;
  let sawDelim = false;
  let sawResponseEnd = false;
  while (off + 4 <= buf.length) {
    const header = buf.subarray(off, off + 4).toString('ascii');
    if (header === '0000') {
      sawFlush = true;
      off += 4;
      break;
    }
    if (header === '0001') {
      sawDelim = true;
      off += 4;
      continue;
    }
    if (header === '0002') {
      sawResponseEnd = true;
      off += 4;
      break;
    }
    const len = parseInt(header, 16);
    if (Number.isNaN(len) || len < 4 || off + len > buf.length) break;
    lines.push(buf.subarray(off + 4, off + len));
    off += len;
  }
  return { lines, rest: buf.subarray(off), sawFlush, sawDelim, sawResponseEnd };
}

// ---------------------------------------------------------------------------
// pack files (whole objects only, no deltas; deflate level 1)
// ---------------------------------------------------------------------------

const PACK_TYPE_CODE: Record<string, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const PACK_CODE_TYPE: Record<number, string> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

export interface PackObject {
  oid: string;
  type: string;
  bytes: Buffer;
}

export function buildPack(objects: PackObject[]): Buffer {
  const parts: Buffer[] = [Buffer.alloc(12)];
  parts[0].write('PACK', 0, 'ascii');
  parts[0].writeUInt32BE(2, 4);
  parts[0].writeUInt32BE(objects.length, 8);
  for (const obj of objects) {
    const typeCode = PACK_TYPE_CODE[obj.type];
    const compressed = deflateSync(obj.bytes, { level: 1 });
    const size = obj.bytes.length;
    const head: number[] = [];
    let remaining = size;
    let first = (typeCode << 4) | (remaining & 0x0f);
    remaining >>= 4;
    if (remaining > 0) first |= 0x80;
    head.push(first);
    while (remaining > 0) {
      let b = remaining & 0x7f;
      remaining >>= 7;
      if (remaining > 0) b |= 0x80;
      head.push(b);
    }
    parts.push(Buffer.from(head));
    parts.push(compressed);
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

/** Parse a pack file containing whole objects only. Throws on deltas/corruption.
 * One inflate per object: `inflateSync(..., {info: true})` reports the bytes the
 * engine consumed (`engine.bytesWritten`), which is the deflate stream length. */
export function parsePack(buf: Buffer): PackObject[] {
  if (buf.length < 12 || buf.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('not a pack file');
  }
  const count = buf.readUInt32BE(8);
  let off = 12;
  const out: PackObject[] = [];
  for (let i = 0; i < count; i++) {
    const first = buf[off];
    const typeCode = (first >> 4) & 0x07;
    let size = first & 0x0f;
    let shift = 4;
    off++;
    while (buf[off - 1] & 0x80) {
      size |= (buf[off] & 0x7f) << shift;
      shift += 7;
      off++;
    }
    const type = PACK_CODE_TYPE[typeCode];
    if (type === undefined) throw new Error(`unsupported pack object type ${typeCode}`);
    const result = inflateSync(buf.subarray(off), { info: true }) as { buffer: Buffer; engine: { bytesWritten: number } };
    const raw = result.buffer;
    const consumed = result.engine.bytesWritten;
    if (!consumed || consumed <= 0) throw new Error('zlib stream consumed no bytes');
    off += consumed;
    if (raw.length !== size) throw new Error('pack object size mismatch');
    out.push({ oid: gitObjectId(type, raw), type, bytes: raw });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Git object model (parsed views; raw bytes are stored verbatim)
// ---------------------------------------------------------------------------

export interface CommitParsed {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

export function parseCommit(bytes: Buffer): CommitParsed {
  const text = bytes.toString('utf8');
  const sep = text.indexOf('\n\n');
  const head = sep === -1 ? text : text.slice(0, sep);
  const message = sep === -1 ? '' : text.slice(sep + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

export function buildCommitBytes(opts: {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}): Buffer {
  let head = `tree ${opts.tree}\n`;
  for (const p of opts.parents) head += `parent ${p}\n`;
  head += `author ${opts.author}\ncommitter ${opts.committer}\n`;
  return Buffer.from(`${head}\n${opts.message}`, 'utf8');
}

export interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

export function parseTree(bytes: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < bytes.length) {
    const sp = bytes.indexOf(0x20, off);
    const mode = bytes.subarray(off, sp).toString('ascii');
    const nul = bytes.indexOf(0, sp + 1);
    const name = bytes.subarray(sp + 1, nul).toString('utf8');
    const oid = bytes.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}

export function buildTreeBytes(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const an = a.mode === '40000' ? `${a.name}/` : a.name;
    const bn = b.mode === '40000' ? `${b.name}/` : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

export function parseTag(bytes: Buffer): { object: string; type: string; tag: string; message: string } {
  const text = bytes.toString('utf8');
  const sep = text.indexOf('\n\n');
  const head = sep === -1 ? text : text.slice(0, sep);
  const message = sep === -1 ? '' : text.slice(sep + 2);
  let object = '';
  let type = '';
  let tag = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
  }
  return { object, type, tag, message };
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

export interface IssueComment {
  id: number;
  body: string;
  createdSeq: number;
}

export interface Issue {
  id: number;
  number: number;
  repoId: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  createdSeq: number;
  updatedSeq: number;
  comments: IssueComment[];
  jsonBuf: Buffer | null;
}

export interface Pull {
  id: number;
  number: number;
  repoId: number;
  title: string;
  body: string;
  state: 'open' | 'closed' | 'merged';
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  createdSeq: number;
  mergedAt: string | null;
  mergeCommitSha: string | null;
}

export interface Label {
  name: string;
  color: string;
  description: string;
}

export interface Repo {
  id: number;
  name: string;
  owner: string;
  description: string;
  privateRepo: boolean;
  defaultBranch: string;
  refs: Map<string, string>;
  objects: Map<string, PackObject>;
  commits: Map<string, CommitParsed>;
  issues: Issue[];
  pulls: Pull[];
  labels: Map<string, Label>;
  issueSeq: number;
  pullSeq: number;
  commentSeq: number;
  version: number;
  advV2: Buffer | null;
  advV0Up: Buffer | null;
  advV0Recv: Buffer | null;
  lsCache: Map<string, Buffer>;
  fetchCache: Map<string, Buffer>;
  repoJsonBuf: Buffer | null;
  issueJsonCache: Map<number, Buffer>;
  shallow: Set<string>;
}

export interface Store {
  token: string;
  trialNowSec: number;
  repos: Map<string, Repo>;
  reposById: Map<number, Repo>;
  nextRepoId: number;
  nextIssueId: number;
  nextPullId: number;
  nextCommentId: number;
  seq: number;
  reqCounter: number;
}

const DEFAULT_LABELS: [string, string, string][] = [
  ['bug', 'd73a4a', "Something isn't working"],
  ['enhancement', 'a2eeef', 'New feature or request'],
  ['documentation', '0075ca', 'Improvements or additions to documentation'],
  ['question', 'd876e3', 'Further information is requested'],
  ['duplicate', 'cfd3d7', 'This issue or pull request already exists'],
  ['invalid', 'e4e7ed', "This doesn't seem right"],
  ['wontfix', 'ffffff', 'This will not be worked on'],
  ['help wanted', '008672', 'Extra attention is needed'],
  ['good first issue', '7057ff', 'Good for newcomers'],
];

export function createStore(token: string, trialNowSec: number): Store {
  return {
    token,
    trialNowSec,
    repos: new Map(),
    reposById: new Map(),
    nextRepoId: 1,
    nextIssueId: 1,
    nextPullId: 1,
    nextCommentId: 1,
    seq: 0,
    reqCounter: 0,
  };
}

export function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

export function createRepo(store: Store, owner: string, name: string, description: string, privateRepo: boolean): Repo {
  const repo: Repo = {
    id: store.nextRepoId++,
    name,
    owner,
    description,
    privateRepo,
    defaultBranch: DEFAULT_BRANCH,
    refs: new Map(),
    objects: new Map(),
    commits: new Map(),
    issues: [],
    pulls: [],
    labels: new Map(),
    issueSeq: 0,
    pullSeq: 0,
    commentSeq: 0,
    version: 0,
    advV2: null,
    advV0Up: null,
    advV0Recv: null,
    lsCache: new Map(),
    fetchCache: new Map(),
    repoJsonBuf: null,
    issueJsonCache: new Map(),
    shallow: new Set(),
  };
  for (const [n, c, d] of DEFAULT_LABELS) repo.labels.set(n, { name: n, color: c, description: d });
  store.repos.set(repoKey(owner, name), repo);
  store.reposById.set(repo.id, repo);
  return repo;
}

export function findRepo(store: Store, owner: string, name: string): Repo | undefined {
  return store.repos.get(repoKey(owner, name));
}

export function deleteRepo(store: Store, owner: string, name: string): boolean {
  const repo = store.repos.get(repoKey(owner, name));
  if (repo === undefined) return false;
  store.repos.delete(repoKey(owner, name));
  store.reposById.delete(repo.id);
  return true;
}

export function putObject(repo: Repo, obj: PackObject): void {
  if (!repo.objects.has(obj.oid)) repo.objects.set(obj.oid, obj);
}

export function getCommit(repo: Repo, oid: string): CommitParsed | undefined {
  let parsed = repo.commits.get(oid);
  if (parsed !== undefined) return parsed;
  const obj = repo.objects.get(oid);
  if (obj === undefined || obj.type !== 'commit') return undefined;
  parsed = parseCommit(obj.bytes);
  repo.commits.set(oid, parsed);
  return parsed;
}

export function bumpVersion(repo: Repo): void {
  repo.version++;
  repo.advV2 = null;
  repo.advV0Up = null;
  repo.advV0Recv = null;
  repo.lsCache.clear();
  repo.fetchCache.clear();
}

export function setRef(repo: Repo, refname: string, oid: string): void {
  repo.refs.set(refname, oid);
  bumpVersion(repo);
}

export function deleteRef(repo: Repo, refname: string): boolean {
  const ok = repo.refs.delete(refname);
  if (ok) bumpVersion(repo);
  return ok;
}

export const EMPTY_TREE_OID = gitObjectId('tree', Buffer.alloc(0));

export function ensureEmptyTree(repo: Repo): void {
  if (!repo.objects.has(EMPTY_TREE_OID)) {
    repo.objects.set(EMPTY_TREE_OID, { oid: EMPTY_TREE_OID, type: 'tree', bytes: Buffer.alloc(0) });
  }
}

// ---------------------------------------------------------------------------
// Git core: ancestry, trees, fetch computation, merge
// ---------------------------------------------------------------------------

/** All commit ancestors of `tip`, including `tip` itself. */
export function commitAncestors(repo: Repo, tip: string): Set<string> {
  const out = new Set<string>();
  const queue = [tip];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (out.has(oid)) continue;
    const c = getCommit(repo, oid);
    if (c === undefined) continue;
    out.add(oid);
    for (const p of c.parents) queue.push(p);
  }
  return out;
}

/** First common ancestor of two tips, by BFS from head against base's ancestor set. */
export function mergeBase(repo: Repo, headTip: string, baseTip: string): string | null {
  const baseAncestors = commitAncestors(repo, baseTip);
  const queue = [headTip];
  const seen = new Set<string>();
  while (queue.length > 0) {
    const oid = queue.shift() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    if (baseAncestors.has(oid)) return oid;
    const c = getCommit(repo, oid);
    if (c === undefined) continue;
    for (const p of c.parents) queue.push(p);
  }
  return null;
}

/** Flatten a tree to path -> {oid, mode}, recursively. */
export function flattenTree(repo: Repo, treeOid: string, prefix: string, out: Map<string, { oid: string; mode: string }>): void {
  const obj = repo.objects.get(treeOid);
  if (obj === undefined || obj.type !== 'tree') return;
  for (const entry of parseTree(obj.bytes)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') flattenTree(repo, entry.oid, path, out);
    else out.set(path, { oid: entry.oid, mode: entry.mode });
  }
}

/** Build (and store) a tree from a flat path map. */
export function buildTreeFromPaths(repo: Repo, paths: Map<string, { oid: string; mode: string }>): string {
  ensureEmptyTree(repo);
  const build = (prefix: string): string => {
    const entries: TreeEntry[] = [];
    const subdirs = new Map<string, Map<string, { oid: string; mode: string }>>();
    for (const [path, value] of paths) {
      if (!path.startsWith(prefix)) continue;
      const rest = path.slice(prefix.length);
      const slash = rest.indexOf('/');
      if (slash === -1) {
        entries.push({ mode: value.mode, name: rest, oid: value.oid });
      } else {
        const dir = rest.slice(0, slash);
        let sub = subdirs.get(dir);
        if (sub === undefined) {
          sub = new Map();
          subdirs.set(dir, sub);
        }
        sub.set(path, value);
      }
    }
    for (const [dir, sub] of subdirs) {
      const subPrefix = prefix === '' ? `${dir}/` : `${prefix}${dir}/`;
      entries.push({ mode: '40000', name: dir, oid: build(subPrefix) });
    }
    const bytes = buildTreeBytes(entries);
    const oid = gitObjectId('tree', bytes);
    putObject(repo, { oid, type: 'tree', bytes });
    return oid;
  };
  return build('');
}

/** Set (or delete, when blobOid is null) one path in a tree; returns the new tree oid. */
export function setTreePath(repo: Repo, treeOid: string | null, segments: string[], blobOid: string | null): string {
  ensureEmptyTree(repo);
  const entries = new Map<string, TreeEntry>();
  if (treeOid !== null) {
    const obj = repo.objects.get(treeOid);
    if (obj !== undefined && obj.type === 'tree') {
      for (const e of parseTree(obj.bytes)) entries.set(e.name, e);
    }
  }
  const [head, ...tail] = segments;
  if (tail.length === 0) {
    if (blobOid === null) entries.delete(head);
    else entries.set(head, { mode: '100644', name: head, oid: blobOid });
  } else {
    const existing = entries.get(head);
    const subOid = existing !== undefined && existing.mode === '40000' ? existing.oid : null;
    const next = setTreePath(repo, subOid, tail, blobOid);
    if (next === EMPTY_TREE_OID) entries.delete(head);
    else entries.set(head, { mode: '40000', name: head, oid: next });
  }
  const bytes = buildTreeBytes([...entries.values()]);
  const oid = gitObjectId('tree', bytes);
  putObject(repo, { oid, type: 'tree', bytes });
  return oid;
}

function countLines(text: string): number {
  if (text === '') return 0;
  const parts = text.split('\n');
  if (parts[parts.length - 1] === '') parts.pop();
  return parts.length;
}

function diffLineCounts(oldText: string, newText: string): { additions: number; deletions: number } {
  const oldLines = oldText === '' ? [] : oldText.split('\n');
  const newLines = newText === '' ? [] : newText.split('\n');
  if (oldLines.length > 0 && oldLines[oldLines.length - 1] === '') oldLines.pop();
  if (newLines.length > 0 && newLines[newLines.length - 1] === '') newLines.pop();
  let prefix = 0;
  while (prefix < oldLines.length && prefix < newLines.length && oldLines[prefix] === newLines[prefix]) prefix++;
  let suffix = 0;
  while (
    suffix < oldLines.length - prefix &&
    suffix < newLines.length - prefix &&
    oldLines[oldLines.length - 1 - suffix] === newLines[newLines.length - 1 - suffix]
  ) {
    suffix++;
  }
  return { additions: newLines.length - prefix - suffix, deletions: oldLines.length - prefix - suffix };
}

export interface DiffFile {
  path: string;
  status: 'added' | 'modified' | 'removed';
  additions: number;
  deletions: number;
}

/** File-level diff between two trees (base -> head). */
export function diffTrees(repo: Repo, baseTreeOid: string, headTreeOid: string): DiffFile[] {
  const base = new Map<string, { oid: string; mode: string }>();
  const head = new Map<string, { oid: string; mode: string }>();
  flattenTree(repo, baseTreeOid, '', base);
  flattenTree(repo, headTreeOid, '', head);
  const out: DiffFile[] = [];
  const paths = new Set([...base.keys(), ...head.keys()]);
  for (const path of paths) {
    const b = base.get(path);
    const h = head.get(path);
    if (b === undefined && h !== undefined) {
      const blob = repo.objects.get(h.oid);
      const text = blob !== undefined ? blob.bytes.toString('utf8') : '';
      out.push({ path, status: 'added', additions: countLines(text), deletions: 0 });
    } else if (b !== undefined && h === undefined) {
      const blob = repo.objects.get(b.oid);
      const text = blob !== undefined ? blob.bytes.toString('utf8') : '';
      out.push({ path, status: 'removed', additions: 0, deletions: countLines(text) });
    } else if (b !== undefined && h !== undefined && b.oid !== h.oid) {
      const oldBlob = repo.objects.get(b.oid);
      const newBlob = repo.objects.get(h.oid);
      const counts = diffLineCounts(
        oldBlob !== undefined ? oldBlob.bytes.toString('utf8') : '',
        newBlob !== undefined ? newBlob.bytes.toString('utf8') : '',
      );
      out.push({ path, status: 'modified', additions: counts.additions, deletions: counts.deletions });
    }
  }
  out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return out;
}

/**
 * File-level three-way merge: base tree vs head tree vs base-branch tree.
 * Conflict when the same path changed on both sides with different content.
 */
export function threeWayMerge(
  repo: Repo,
  baseTip: string,
  headTip: string,
  baseBranchTip: string,
): { conflict: boolean; treeOid: string } {
  const mergeBaseOid = mergeBase(repo, headTip, baseBranchTip);
  const baseTree = mergeBaseOid === null ? EMPTY_TREE_OID : (getCommit(repo, mergeBaseOid)?.tree ?? EMPTY_TREE_OID);
  const headCommit = getCommit(repo, headTip);
  const baseCommit = getCommit(repo, baseBranchTip);
  const headTree = headCommit?.tree ?? EMPTY_TREE_OID;
  const branchTree = baseCommit?.tree ?? EMPTY_TREE_OID;
  const baseMap = new Map<string, { oid: string; mode: string }>();
  const headMap = new Map<string, { oid: string; mode: string }>();
  const branchMap = new Map<string, { oid: string; mode: string }>();
  flattenTree(repo, baseTree, '', baseMap);
  flattenTree(repo, headTree, '', headMap);
  flattenTree(repo, branchTree, '', branchMap);
  const merged = new Map<string, { oid: string; mode: string }>();
  let conflict = false;
  const paths = new Set([...baseMap.keys(), ...headMap.keys(), ...branchMap.keys()]);
  for (const path of paths) {
    const b = baseMap.get(path);
    const h = headMap.get(path);
    const t = branchMap.get(path);
    const bOid = b?.oid;
    const hOid = h?.oid;
    const tOid = t?.oid;
    if (hOid === tOid) {
      if (h !== undefined) merged.set(path, h);
    } else if (bOid === hOid) {
      if (t !== undefined) merged.set(path, t);
    } else if (bOid === tOid) {
      if (h !== undefined) merged.set(path, h);
    } else {
      conflict = true;
    }
  }
  const treeOid = buildTreeFromPaths(repo, merged);
  return { conflict, treeOid };
}

export interface FetchResult {
  objects: PackObject[];
  shallow: string[];
  unshallow: string[];
}

/**
 * Compute the objects for one upload-pack fetch.
 * wants: tip oids. haves: oids the client claims. clientShallow: the client's
 * shallow boundaries (sent as `shallow` lines). depth: null for a full fetch.
 * A have that is a client shallow boundary counts as "partially had": the
 * commit itself is had, but its parents are not. Unshallow lists boundaries
 * whose history this fetch extends; shallow lists the new depth boundary.
 */
export function computeFetch(
  repo: Repo,
  wants: string[],
  haves: string[],
  clientShallow: string[],
  depth: number | null,
): FetchResult {
  const shallowSet = new Set(clientShallow);
  // Objects the client already holds: everything reachable from the haves,
  // stopping at shallow boundaries (the boundary commit and its tree are held,
  // its parents are not). These are never re-sent.
  const hadObjects = new Set<string>();
  const fullyHad = new Set<string>();
  const addTreeObjects = (treeOid: string): void => {
    const stack = [treeOid];
    const seenTrees = new Set<string>();
    while (stack.length > 0) {
      const t = stack.pop() as string;
      if (seenTrees.has(t)) continue;
      seenTrees.add(t);
      hadObjects.add(t);
      const obj = repo.objects.get(t);
      if (obj === undefined || obj.type !== 'tree') continue;
      for (const entry of parseTree(obj.bytes)) {
        if (entry.mode === '40000') stack.push(entry.oid);
        else hadObjects.add(entry.oid);
      }
    }
  };
  const hseen = new Set<string>();
  const hq = [...haves];
  while (hq.length > 0) {
    const oid = hq.pop() as string;
    if (hseen.has(oid)) continue;
    hseen.add(oid);
    const c = getCommit(repo, oid);
    if (c === undefined) continue;
    hadObjects.add(oid);
    addTreeObjects(c.tree);
    if (shallowSet.has(oid)) continue;
    fullyHad.add(oid);
    for (const p of c.parents) hq.push(p);
  }
  // Non-commit wants (annotated tags): the object itself is always sent, and
  // its target joins the commit walk.
  const extraObjects: PackObject[] = [];
  const commitWants: string[] = [];
  for (const w of wants) {
    const obj = repo.objects.get(w);
    if (obj === undefined) continue;
    if (obj.type === 'commit') {
      commitWants.push(w);
      continue;
    }
    extraObjects.push(obj);
    if (obj.type === 'tag') commitWants.push(parseTag(obj.bytes).object);
  }
  const gen = new Map<string, number>();
  const wanted: string[] = [];
  const wq: [string, number][] = commitWants.map((w) => [w, 0] as [string, number]);
  while (wq.length > 0) {
    const [oid, g] = wq.shift() as [string, number];
    if (gen.has(oid)) continue;
    if (fullyHad.has(oid)) continue;
    const c = getCommit(repo, oid);
    if (c === undefined) continue;
    gen.set(oid, g);
    wanted.push(oid);
    if (depth !== null && g >= depth - 1) continue;
    for (const p of c.parents) wq.push([p, g + 1]);
  }
  const shallow: string[] = [];
  const unshallow: string[] = [];
  for (const oid of wanted) {
    const g = gen.get(oid) as number;
    if (depth !== null && g === depth - 1) shallow.push(oid);
    else if (shallowSet.has(oid)) unshallow.push(oid);
  }
  const objects: PackObject[] = [];
  const seen = new Set<string>();
  const addObj = (oid: string): void => {
    if (seen.has(oid) || hadObjects.has(oid)) return;
    const obj = repo.objects.get(oid);
    if (obj === undefined) return;
    seen.add(oid);
    objects.push(obj);
  };
  for (const obj of extraObjects) addObj(obj.oid);
  const walkTree = (treeOid: string): void => {
    const obj = repo.objects.get(treeOid);
    if (obj === undefined || obj.type !== 'tree') return;
    addObj(treeOid);
    for (const entry of parseTree(obj.bytes)) {
      if (entry.mode === '40000') walkTree(entry.oid);
      else addObj(entry.oid);
    }
  };
  for (const oid of wanted) {
    addObj(oid);
    const c = getCommit(repo, oid);
    if (c !== undefined) walkTree(c.tree);
  }
  return { objects, shallow, unshallow };
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

export function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export function nextRequestId(store: Store): string {
  store.reqCounter += 1;
  return `req-${store.reqCounter}`;
}

export function sendJson(res: ServerResponse, status: number, store: Store, value: unknown): void {
  const body = Buffer.from(JSON.stringify(value), 'utf8');
  res.writeHead(status, {
    'content-type': 'application/json',
    'x-github-request-id': nextRequestId(store),
    'content-length': body.length,
  });
  res.end(body);
}

export function sendBuffer(res: ServerResponse, status: number, store: Store, body: Buffer, contentType: string): void {
  res.writeHead(status, {
    'content-type': contentType,
    'x-github-request-id': nextRequestId(store),
    'content-length': body.length,
  });
  res.end(body);
}

export function sendError(res: ServerResponse, status: number, store: Store, message: string): void {
  sendJson(res, status, store, { message });
}

export function isAuthorized(store: Store, req: IncomingMessage): boolean {
  const auth = req.headers['authorization'];
  return typeof auth === 'string' && auth === `Bearer ${store.token}`;
}

export function parseJsonBody(body: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (body.length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(body.toString('utf8')) };
  } catch {
    return { ok: false };
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// ---------------------------------------------------------------------------
// Git smart HTTP
// ---------------------------------------------------------------------------

function sortedRefs(repo: Repo): [string, string][] {
  return [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

function buildAdvV2(): Buffer {
  return Buffer.concat([
    pktLine('# service=git-upload-pack\n'),
    FLUSH_PKT,
    pktLine('version 2\n'),
    pktLine(`agent=${AGENT}\n`),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow filter\n'),
    pktLine('object-format=sha1\n'),
    FLUSH_PKT,
  ]);
}

function buildAdvV0(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps =
    service === 'git-upload-pack'
      ? `side-band-64k thin-pack ofs-delta shallow multi_ack_detailed agent=${AGENT} symref=HEAD:refs/heads/main`
      : `report-status side-band-64k delete-refs ofs-delta agent=${AGENT} symref=HEAD:refs/heads/main`;
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), FLUSH_PKT];
  const refs = sortedRefs(repo);
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    const headOid = repo.refs.get('refs/heads/main') ?? ZERO_OID;
    parts.push(pktLine(`${headOid} HEAD\0${caps}\n`));
    for (const [name, oid] of refs) {
      parts.push(pktLine(`${oid} ${name}\n`));
      const obj = repo.objects.get(oid);
      if (obj !== undefined && obj.type === 'tag') {
        parts.push(pktLine(`${parseTag(obj.bytes).object} ${name}^{}\n`));
      }
    }
  }
  parts.push(FLUSH_PKT);
  return Buffer.concat(parts);
}

export function handleGitInfoRefs(store: Store, req: IncomingMessage, res: ServerResponse, owner: string, name: string, service: string): void {
  const repo = findRepo(store, owner, name);
  if (repo === undefined) {
    sendError(res, 404, store, 'Not Found');
    return;
  }
  if (service === 'git-upload-pack') {
    if (req.headers['git-protocol'] === 'version=2') {
      if (repo.advV2 === null) repo.advV2 = buildAdvV2();
      sendBuffer(res, 200, store, repo.advV2, 'application/x-git-upload-pack-advertisement');
      return;
    }
    if (repo.advV0Up === null) repo.advV0Up = buildAdvV0(repo, 'git-upload-pack');
    sendBuffer(res, 200, store, repo.advV0Up, 'application/x-git-upload-pack-advertisement');
    return;
  }
  if (service === 'git-receive-pack') {
    if (repo.advV0Recv === null) repo.advV0Recv = buildAdvV0(repo, 'git-receive-pack');
    sendBuffer(res, 200, store, repo.advV0Recv, 'application/x-git-receive-pack-advertisement');
    return;
  }
  sendError(res, 404, store, 'Not Found');
}

interface LsRefsOptions {
  peel: boolean;
  symrefs: boolean;
  unborn: boolean;
  prefixes: string[];
}

function buildLsRefs(repo: Repo, opts: LsRefsOptions): Buffer {
  const parts: Buffer[] = [];
  const refs = sortedRefs(repo);
  const headOid = repo.refs.get('refs/heads/main');
  const matches = (name: string): boolean => opts.prefixes.length === 0 || opts.prefixes.some((p) => name.startsWith(p));
  if (refs.length === 0) {
    if (opts.unborn) parts.push(pktLine('unborn HEAD symref-target:refs/heads/main\n'));
  } else {
    if (headOid === undefined) {
      if (opts.unborn) parts.push(pktLine('unborn HEAD symref-target:refs/heads/main\n'));
    } else if (matches('HEAD')) {
      let line = `${headOid} HEAD`;
      if (opts.symrefs) line += ' symref-target:refs/heads/main';
      parts.push(pktLine(`${line}\n`));
    }
    for (const [name, oid] of refs) {
      if (!matches(name)) continue;
      let line = `${oid} ${name}`;
      if (opts.peel) {
        const obj = repo.objects.get(oid);
        if (obj !== undefined && obj.type === 'tag') line += ` peeled:${parseTag(obj.bytes).object}`;
      }
      parts.push(pktLine(`${line}\n`));
    }
  }
  parts.push(FLUSH_PKT);
  return Buffer.concat(parts);
}

function sidebandPack(pack: Buffer): Buffer[] {
  const parts: Buffer[] = [];
  for (let off = 0; off < pack.length; off += 32768) {
    const chunk = pack.subarray(off, Math.min(pack.length, off + 32768));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  return parts;
}

function buildFetchV2(result: FetchResult): Buffer {
  const parts: Buffer[] = [pktLine('acknowledgments\n'), pktLine('NAK\n'), DELIM_PKT];
  if (result.shallow.length > 0 || result.unshallow.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const oid of result.shallow) parts.push(pktLine(`shallow ${oid}\n`));
    for (const oid of result.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
    parts.push(DELIM_PKT);
  }
  parts.push(pktLine('packfile\n'));
  parts.push(...sidebandPack(buildPack(result.objects)));
  parts.push(FLUSH_PKT);
  return Buffer.concat(parts);
}

function buildFetchV0(result: FetchResult): Buffer {
  const parts: Buffer[] = [pktLine('NAK\n')];
  for (const oid of result.shallow) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of result.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  parts.push(...sidebandPack(buildPack(result.objects)));
  parts.push(FLUSH_PKT);
  return Buffer.concat(parts);
}

interface FetchArgs {
  wants: string[];
  haves: string[];
  shallow: string[];
  depth: number | null;
}

function parseFetchArgs(lines: Buffer[]): FetchArgs {
  const args: FetchArgs = { wants: [], haves: [], shallow: [], depth: null };
  for (const raw of lines) {
    const line = raw.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('want ')) {
      const rest = line.slice(5);
      const oid = rest.slice(0, 40);
      if (/^[0-9a-f]{40}$/.test(oid)) args.wants.push(oid);
    } else if (line.startsWith('have ')) {
      args.haves.push(line.slice(5, 45));
    } else if (line.startsWith('shallow ')) {
      args.shallow.push(line.slice(8, 48));
    } else if (line.startsWith('deepen ')) {
      const n = Number.parseInt(line.slice(7), 10);
      if (Number.isFinite(n) && n > 0) args.depth = n;
    }
  }
  return args;
}

export function handleUploadPack(store: Store, req: IncomingMessage, res: ServerResponse, owner: string, name: string, body: Buffer): void {
  const repo = findRepo(store, owner, name);
  if (repo === undefined) {
    sendError(res, 404, store, 'Not Found');
    return;
  }
  const parsed = parsePktLines(body);
  const firstLine = parsed.lines.length > 0 ? parsed.lines[0].toString('utf8').replace(/\n$/, '') : '';
  const isV2 = req.headers['git-protocol'] === 'version=2';
  if (isV2 && firstLine === 'command=ls-refs') {
    const opts: LsRefsOptions = { peel: false, symrefs: false, unborn: false, prefixes: [] };
    for (const raw of parsed.lines.slice(1)) {
      const line = raw.toString('utf8').replace(/\n$/, '');
      if (line === 'peel') opts.peel = true;
      else if (line === 'symrefs') opts.symrefs = true;
      else if (line === 'unborn') opts.unborn = true;
      else if (line.startsWith('ref-prefix ')) opts.prefixes.push(line.slice(11));
    }
    const key = JSON.stringify(opts);
    let out = repo.lsCache.get(key);
    if (out === undefined) {
      out = buildLsRefs(repo, opts);
      repo.lsCache.set(key, out);
    }
    sendBuffer(res, 200, store, out, 'application/x-git-upload-pack-result');
    return;
  }
  let args: FetchArgs;
  if (isV2 && firstLine === 'command=fetch') {
    args = parseFetchArgs(parsed.lines.slice(1));
  } else if (!isV2) {
    const section1 = parseFetchArgs(parsed.lines);
    const section2 = parsePktLines(parsed.rest);
    args = {
      wants: section1.wants,
      haves: section2.lines.map((l) => l.toString('utf8').replace(/\n$/, '')).filter((l) => l.startsWith('have ')).map((l) => l.slice(5, 45)),
      shallow: section1.shallow,
      depth: section1.depth,
    };
  } else {
    sendError(res, 400, store, 'Bad Request');
    return;
  }
  const key = JSON.stringify(args);
  let out = repo.fetchCache.get(key);
  if (out === undefined) {
    const result = computeFetch(repo, args.wants, args.haves, args.shallow, args.depth);
    out = isV2 ? buildFetchV2(result) : buildFetchV0(result);
    repo.fetchCache.set(key, out);
  }
  sendBuffer(res, 200, store, out, 'application/x-git-upload-pack-result');
}

function isDescendant(repo: Repo, tip: string, ancestor: string): boolean {
  if (tip === ancestor) return true;
  const queue = [tip];
  const seen = new Set<string>();
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    if (oid === ancestor) return true;
    const c = getCommit(repo, oid);
    if (c === undefined) continue;
    for (const p of c.parents) queue.push(p);
  }
  return false;
}

export function handleReceivePack(store: Store, req: IncomingMessage, res: ServerResponse, owner: string, name: string, body: Buffer): void {
  const repo = findRepo(store, owner, name);
  if (repo === undefined) {
    sendError(res, 404, store, 'Not Found');
    return;
  }
  const parsed = parsePktLines(body);
  const commands: { oldOid: string; newOid: string; ref: string }[] = [];
  for (const raw of parsed.lines) {
    const text = raw.toString('utf8');
    const nul = text.indexOf('\0');
    const cmdText = (nul >= 0 ? text.slice(0, nul) : text).trim();
    const parts = cmdText.split(' ');
    if (parts.length >= 3 && /^[0-9a-f]{40}$/.test(parts[0]) && /^[0-9a-f]{40}$/.test(parts[1])) {
      commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts[2] });
    }
  }
  let packObjects: PackObject[] = [];
  if (parsed.rest.length > 0) {
    try {
      packObjects = parsePack(parsed.rest);
    } catch {
      packObjects = [];
    }
  }
  for (const obj of packObjects) putObject(repo, obj);
  const inner: Buffer[] = [pktLine('unpack ok\n')];
  for (const cmd of commands) {
    const current = repo.refs.get(cmd.ref);
    let ok = false;
    let reason = '';
    if (cmd.newOid === ZERO_OID) {
      if (current !== undefined && (cmd.oldOid === ZERO_OID || current === cmd.oldOid)) {
        deleteRef(repo, cmd.ref);
        ok = true;
      } else {
        reason = 'non-fast-forward';
      }
    } else if (cmd.oldOid === ZERO_OID) {
      if (current === undefined) {
        setRef(repo, cmd.ref, cmd.newOid);
        ok = true;
      } else {
        reason = 'already exists';
      }
    } else if (current === undefined || current !== cmd.oldOid) {
      reason = 'non-fast-forward';
    } else if (cmd.newOid === cmd.oldOid) {
      ok = true;
    } else if (isDescendant(repo, cmd.newOid, cmd.oldOid)) {
      setRef(repo, cmd.ref, cmd.newOid);
      ok = true;
    } else {
      reason = 'non-fast-forward';
    }
    inner.push(ok ? pktLine(`ok ${cmd.ref}\n`) : pktLine(`ng ${cmd.ref} ${reason}\n`));
  }
  const report = Buffer.concat(inner);
  const out = Buffer.concat([pktLine(Buffer.concat([Buffer.from([1]), report])), FLUSH_PKT]);
  sendBuffer(res, 200, store, out, 'application/x-git-receive-pack-result');
}

// ---------------------------------------------------------------------------
// REST v3 (/api/v3)
// ---------------------------------------------------------------------------

function repoJson(store: Store, repo: Repo): Buffer {
  if (repo.repoJsonBuf !== null) return repo.repoJsonBuf;
  const obj = {
    id: repo.id,
    node_id: encodeGlobalId('Repository', repo.id),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: repo.owner === VIEWER_LOGIN ? VIEWER_ID : 1001, type: 'User' },
    private: repo.privateRepo,
    description: repo.description,
    default_branch: repo.defaultBranch,
    has_issues: true,
    created_at: nowIso(store.trialNowSec),
    updated_at: nowIso(store.trialNowSec),
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    url: `/repos/${repo.owner}/${repo.name}`,
  };
  repo.repoJsonBuf = Buffer.from(JSON.stringify(obj), 'utf8');
  return repo.repoJsonBuf;
}

function issueJson(store: Store, repo: Repo, issue: Issue): Buffer {
  if (issue.jsonBuf !== null) return issue.jsonBuf;
  const obj = {
    id: issue.id,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((n) => {
      const l = repo.labels.get(n);
      return { name: n, color: l?.color ?? 'ededed', description: l?.description ?? '' };
    }),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID },
    created_at: nowIso(store.trialNowSec),
    updated_at: nowIso(store.trialNowSec),
    comments: issue.comments.length,
  };
  issue.jsonBuf = Buffer.from(JSON.stringify(obj), 'utf8');
  return issue.jsonBuf;
}

function pullJson(store: Store, repo: Repo, pull: Pull): Record<string, unknown> {
  const headSha = repo.refs.get(`refs/heads/${pull.headRef}`) ?? pull.headSha;
  const baseSha = repo.refs.get(`refs/heads/${pull.baseRef}`) ?? pull.baseSha;
  return {
    id: pull.id,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    // REST v3 has no "merged" state: a merged pull request reads back closed.
    state: pull.state === 'merged' ? 'closed' : pull.state,
    head: { ref: pull.headRef, sha: headSha },
    base: { ref: pull.baseRef, sha: baseSha },
    merged: pull.state === 'merged',
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID },
    created_at: nowIso(store.trialNowSec),
    updated_at: nowIso(store.trialNowSec),
  };
}

interface PageResult<T> {
  items: T[];
  link: string | null;
}

function paginate<T>(req: IncomingMessage, path: string, query: URLSearchParams, items: readonly T[]): PageResult<T> {
  const perPage = Math.max(1, Math.min(100, Number(query.get('per_page') ?? '30') || 30));
  const page = Math.max(1, Number(query.get('page') ?? '1') || 1);
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  const hasNext = start + perPage < items.length;
  let link: string | null = null;
  if (hasNext) {
    const host = req.headers.host ?? '127.0.0.1';
    link = `<http://${host}${path}?per_page=${perPage}&page=${page + 1}>; rel="next"`;
  }
  return { items: slice, link };
}

function sendJsonWithLink(res: ServerResponse, status: number, store: Store, value: unknown, link: string | null): void {
  const body = Buffer.from(JSON.stringify(value), 'utf8');
  const headers: Record<string, string | number> = {
    'content-type': 'application/json',
    'x-github-request-id': nextRequestId(store),
    'content-length': body.length,
  };
  if (link !== null) headers['link'] = link;
  res.writeHead(status, headers);
  res.end(body);
}

function sendRepoJson(res: ServerResponse, store: Store, repo: Repo): void {
  const body = repoJson(store, repo);
  res.writeHead(200, {
    'content-type': 'application/json',
    'x-github-request-id': nextRequestId(store),
    'content-length': body.length,
  });
  res.end(body);
}

function requireRepo(store: Store, res: ServerResponse, owner: string, name: string): Repo | null {
  const repo = findRepo(store, owner, name);
  if (repo === undefined) {
    sendError(res, 404, store, 'Not Found');
    return null;
  }
  return repo;
}

function parseAuthorLine(line: string): { name: string; email: string; date: string } {
  const match = /^(.*) <([^>]*)> (\d+) ([+-]\d{4})$/.exec(line);
  if (match === null) return { name: line, email: '', date: '' };
  return { name: match[1], email: match[2], date: new Date(Number(match[3]) * 1000).toISOString() };
}

function walkCommits(repo: Repo, tip: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const c = getCommit(repo, oid);
    if (c === undefined) continue;
    out.push(oid);
    for (let i = c.parents.length - 1; i >= 0; i -= 1) stack.push(c.parents[i]);
  }
  return out;
}

function resolveRefTarget(repo: Repo, ref: string | null): string | undefined {
  if (ref === null || ref === '') return repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  if (/^[0-9a-f]{40}$/.test(ref)) return repo.objects.has(ref) ? ref : undefined;
  if (ref.startsWith('refs/')) return repo.refs.get(ref);
  return repo.refs.get(`refs/heads/${ref}`);
}

export function handleRest(store: Store, req: IncomingMessage, res: ServerResponse, segments: string[], query: URLSearchParams, body: Buffer): void {
  const method = req.method ?? 'GET';

  // GET /api/v3/ — API root.
  if (segments.length === 0) {
    if (method !== 'GET') {
      sendError(res, 404, store, 'Not Found');
      return;
    }
    const value = {
      current_user_url: '/user',
      repository_url: '/repos/{owner}/{repo}',
      user_url: '/users/{user}',
      meta_url: '/meta',
    };
    const raw = Buffer.from(JSON.stringify(value), 'utf8');
    res.writeHead(200, {
      'content-type': 'application/json',
      'x-github-request-id': nextRequestId(store),
      'x-oauth-scopes': 'repo, read:org',
      'content-length': raw.length,
    });
    res.end(raw);
    return;
  }

  // GET /api/v3/meta
  if (segments.length === 1 && segments[0] === 'meta') {
    if (method !== 'GET') {
      sendError(res, 404, store, 'Not Found');
      return;
    }
    sendJson(res, 200, store, { installed_version: '1.0.0' });
    return;
  }

  // GET /api/v3/user and /api/v3/user/repos
  if (segments[0] === 'user') {
    if (segments.length === 1 && method === 'GET') {
      sendJson(res, 200, store, {
        login: VIEWER_LOGIN,
        id: VIEWER_ID,
        node_id: encodeGlobalId('User', VIEWER_ID),
        name: VIEWER_NAME,
        email: VIEWER_EMAIL,
        type: 'User',
      });
      return;
    }
    if (segments.length === 2 && segments[1] === 'repos') {
      if (method === 'GET') {
        const mine = [...store.repos.values()].filter((r) => r.owner === VIEWER_LOGIN);
        const page = paginate(req, '/api/v3/user/repos', query, mine);
        sendJsonWithLink(res, 200, store, page.items.map((r) => JSON.parse(repoJson(store, r).toString('utf8'))), page.link);
        return;
      }
      if (method === 'POST') {
        const parsed = parseJsonBody(body);
        if (!parsed.ok) {
          sendError(res, 400, store, 'Invalid JSON');
          return;
        }
        const input = isRecord(parsed.value) ? parsed.value : {};
        const name = typeof input['name'] === 'string' ? (input['name'] as string) : '';
        if (name === '') {
          sendError(res, 422, store, 'Repository name is required');
          return;
        }
        if (findRepo(store, VIEWER_LOGIN, name) !== undefined) {
          sendError(res, 422, store, 'Repository already exists');
          return;
        }
        const description = typeof input['description'] === 'string' ? (input['description'] as string) : '';
        const privateRepo = input['private'] === true;
        const repo = createRepo(store, VIEWER_LOGIN, name, description, privateRepo);
        const raw = repoJson(store, repo);
        res.writeHead(201, {
          'content-type': 'application/json',
          'x-github-request-id': nextRequestId(store),
          'content-length': raw.length,
        });
        res.end(raw);
        return;
      }
    }
    sendError(res, 404, store, 'Not Found');
    return;
  }

  // /api/v3/repos/{owner}/{name}/...
  if (segments[0] === 'repos' && segments.length >= 3) {
    const owner = segments[1];
    const name = segments[2];
    const rest = segments.slice(3);

    // /repos/{o}/{r}
    if (rest.length === 0) {
      if (method === 'GET') {
        const repo = requireRepo(store, res, owner, name);
        if (repo === null) return;
        sendRepoJson(res, store, repo);
        return;
      }
      if (method === 'PATCH') {
        const repo = requireRepo(store, res, owner, name);
        if (repo === null) return;
        const parsed = parseJsonBody(body);
        if (!parsed.ok) {
          sendError(res, 400, store, 'Invalid JSON');
          return;
        }
        const input = isRecord(parsed.value) ? parsed.value : {};
        if (typeof input['description'] === 'string') repo.description = input['description'] as string;
        if (typeof input['default_branch'] === 'string') repo.defaultBranch = input['default_branch'] as string;
        repo.repoJsonBuf = null;
        sendRepoJson(res, store, repo);
        return;
      }
      if (method === 'DELETE') {
        if (!deleteRepo(store, owner, name)) {
          sendError(res, 404, store, 'Not Found');
          return;
        }
        res.writeHead(204, { 'x-github-request-id': nextRequestId(store) });
        res.end();
        return;
      }
      sendError(res, 404, store, 'Not Found');
      return;
    }

    // /repos/{o}/{r}/branches[/{branch}]
    if (rest[0] === 'branches' && method === 'GET') {
      const repo = requireRepo(store, res, owner, name);
      if (repo === null) return;
      const branches = [...repo.refs.keys()]
        .filter((r) => r.startsWith('refs/heads/'))
        .map((r) => r.slice('refs/heads/'.length))
        .sort();
      if (rest.length === 1) {
        sendJson(res, 200, store, branches.map((b) => ({ name: b, commit: { sha: repo.refs.get(`refs/heads/${b}`) ?? '' } })));
        return;
      }
      const branch = rest.slice(1).join('/');
      const tip = repo.refs.get(`refs/heads/${branch}`);
      if (tip === undefined) {
        sendError(res, 404, store, 'Not Found');
        return;
      }
      sendJson(res, 200, store, { name: branch, commit: { sha: tip, url: `/repos/${owner}/${name}/commits/${tip}` } });
      return;
    }

    // /repos/{o}/{r}/git/refs[/heads/{branch}] and POST /git/refs
    if (rest[0] === 'git' && rest[1] === 'refs') {
      const repo = requireRepo(store, res, owner, name);
      if (repo === null) return;
      if (method === 'POST' && rest.length === 2) {
        const parsed = parseJsonBody(body);
        if (!parsed.ok) {
          sendError(res, 400, store, 'Invalid JSON');
          return;
        }
        const input = isRecord(parsed.value) ? parsed.value : {};
        const ref = typeof input['ref'] === 'string' ? (input['ref'] as string) : '';
        const sha = typeof input['sha'] === 'string' ? (input['sha'] as string) : '';
        if (ref === '' || !/^[0-9a-f]{40}$/.test(sha) || !repo.objects.has(sha)) {
          sendError(res, 422, store, 'Object does not exist');
          return;
        }
        if (repo.refs.has(ref)) {
          sendError(res, 422, store, 'Reference already exists');
          return;
        }
        setRef(repo, ref, sha);
        sendJson(res, 201, store, { ref, object: { sha, type: 'commit', url: `/repos/${owner}/${name}/git/commits/${sha}` } });
        return;
      }
      if (method === 'GET' && rest.length >= 4 && rest[2] === 'heads') {
        const branch = rest.slice(3).join('/');
        const tip = repo.refs.get(`refs/heads/${branch}`);
        if (tip === undefined) {
          sendError(res, 404, store, 'Not Found');
          return;
        }
        sendJson(res, 200, store, { ref: `refs/heads/${branch}`, object: { sha: tip, type: 'commit', url: `/repos/${owner}/${name}/git/commits/${tip}` } });
        return;
      }
      sendError(res, 404, store, 'Not Found');
      return;
    }

    // /repos/{o}/{r}/commits
    if (rest[0] === 'commits' && method === 'GET' && rest.length === 1) {
      const repo = requireRepo(store, res, owner, name);
      if (repo === null) return;
      const tip = resolveRefTarget(repo, query.get('sha'));
      if (tip === undefined) {
        sendError(res, 404, store, 'Not Found');
        return;
      }
      const oids = walkCommits(repo, tip);
      const page = paginate(req, `/api/v3/repos/${owner}/${name}/commits`, query, oids);
      const items = page.items.map((oid) => {
        const c = getCommit(repo, oid) as CommitParsed;
        return {
          sha: oid,
          commit: {
            message: c.message,
            author: parseAuthorLine(c.author),
            committer: parseAuthorLine(c.committer),
          },
          parents: c.parents.map((p) => ({ sha: p })),
        };
      });
      sendJsonWithLink(res, 200, store, items, page.link);
      return;
    }

    // /repos/{o}/{r}/contents/{path}
    if (rest[0] === 'contents') {
      const repo = requireRepo(store, res, owner, name);
      if (repo === null) return;
      const path = rest.slice(1).join('/');
      if (method === 'GET') {
        const tip = resolveRefTarget(repo, query.get('ref'));
        if (tip === undefined) {
          sendError(res, 404, store, 'Not Found');
          return;
        }
        const commit = getCommit(repo, tip);
        if (commit === undefined) {
          sendError(res, 404, store, 'Not Found');
          return;
        }
        const flat = new Map<string, { oid: string; mode: string }>();
        flattenTree(repo, commit.tree, '', flat);
        if (path === '') {
          const entries = [...flat.entries()].filter(([p]) => !p.includes('/'));
          sendJson(res, 200, store, entries.map(([p, v]) => ({ type: 'file', name: p, path: p, sha: v.oid })));
          return;
        }
        const file = flat.get(path);
        if (file !== undefined) {
          const blob = repo.objects.get(file.oid);
          const bytes = blob !== undefined ? blob.bytes : Buffer.alloc(0);
          sendJson(res, 200, store, {
            type: 'file',
            encoding: 'base64',
            content: bytes.toString('base64'),
            sha: file.oid,
            size: bytes.length,
            name: path.split('/').pop() ?? path,
            path,
          });
          return;
        }
        const prefix = `${path}/`;
        const children = new Map<string, { oid: string; mode: string; isDir: boolean }>();
        for (const [p, v] of flat) {
          if (!p.startsWith(prefix)) continue;
          const rest2 = p.slice(prefix.length);
          const slash = rest2.indexOf('/');
          if (slash === -1) children.set(rest2, { oid: v.oid, mode: v.mode, isDir: false });
          else children.set(rest2.slice(0, slash), { oid: '', mode: '40000', isDir: true });
        }
        if (children.size === 0) {
          sendError(res, 404, store, 'Not Found');
          return;
        }
        const items = [...children.entries()]
          .sort((a, b) => (a[0] < b[0] ? -1 : 1))
          .map(([childName, v]) => ({
            type: v.isDir ? 'dir' : 'file',
            name: childName,
            path: `${path}/${childName}`,
            sha: v.oid,
          }));
        sendJson(res, 200, store, items);
        return;
      }
      if (method === 'PUT' || method === 'DELETE') {
        const parsed = parseJsonBody(body);
        if (!parsed.ok) {
          sendError(res, 400, store, 'Invalid JSON');
          return;
        }
        const input = isRecord(parsed.value) ? parsed.value : {};
        const message = typeof input['message'] === 'string' ? (input['message'] as string) : 'Update';
        const branch = typeof input['branch'] === 'string' ? (input['branch'] as string) : repo.defaultBranch;
        const refname = `refs/heads/${branch}`;
        const tip = repo.refs.get(refname);
        const sha = typeof input['sha'] === 'string' ? (input['sha'] as string) : '';
        const segments = path.split('/').filter((s) => s !== '');
        if (segments.length === 0) {
          sendError(res, 422, store, 'Invalid path');
          return;
        }
        if (method === 'PUT') {
          const contentB64 = typeof input['content'] === 'string' ? (input['content'] as string) : '';
          const contentBytes = Buffer.from(contentB64, 'base64');
          const blobOid = gitObjectId('blob', contentBytes);
          putObject(repo, { oid: blobOid, type: 'blob', bytes: contentBytes });
          const currentTree = tip === undefined ? null : (getCommit(repo, tip)?.tree ?? null);
          const flat = new Map<string, { oid: string; mode: string }>();
          if (currentTree !== null) flattenTree(repo, currentTree, '', flat);
          const existing = flat.get(path);
          if (existing !== undefined) {
            if (sha === '' || sha !== existing.oid) {
              sendError(res, 409, store, 'sha does not match the current file');
              return;
            }
          } else if (sha !== '') {
            sendError(res, 409, store, 'sha does not match the current file');
            return;
          }
          const newTree = setTreePath(repo, currentTree, segments, blobOid);
          const author = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${gitTimestamp(store.trialNowSec)}`;
          const commitBytes = buildCommitBytes({
            tree: newTree,
            parents: tip === undefined ? [] : [tip],
            author,
            committer: author,
            message,
          });
          const commitOid = gitObjectId('commit', commitBytes);
          putObject(repo, { oid: commitOid, type: 'commit', bytes: commitBytes });
          setRef(repo, refname, commitOid);
          const status = existing !== undefined ? 200 : 201;
          sendJson(res, status, store, {
            content: { name: segments[segments.length - 1], path, sha: blobOid, encoding: 'base64' },
            commit: { sha: commitOid, message },
          });
          return;
        }
        // DELETE contents
        if (tip === undefined) {
          sendError(res, 404, store, 'Not Found');
          return;
        }
        const commit = getCommit(repo, tip);
        if (commit === undefined) {
          sendError(res, 404, store, 'Not Found');
          return;
        }
        const flat = new Map<string, { oid: string; mode: string }>();
        flattenTree(repo, commit.tree, '', flat);
        const existing = flat.get(path);
        if (existing === undefined) {
          sendError(res, 404, store, 'Not Found');
          return;
        }
        if (sha === '' || sha !== existing.oid) {
          sendError(res, 409, store, 'sha does not match the current file');
          return;
        }
        const newTree = setTreePath(repo, commit.tree, segments, null);
        const author = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${gitTimestamp(store.trialNowSec)}`;
        const commitBytes = buildCommitBytes({
          tree: newTree,
          parents: [tip],
          author,
          committer: author,
          message,
        });
        const commitOid = gitObjectId('commit', commitBytes);
        putObject(repo, { oid: commitOid, type: 'commit', bytes: commitBytes });
        setRef(repo, refname, commitOid);
        sendJson(res, 200, store, { commit: { sha: commitOid, message } });
        return;
      }
      sendError(res, 404, store, 'Not Found');
      return;
    }

    // /repos/{o}/{r}/labels
    if (rest[0] === 'labels') {
      const repo = requireRepo(store, res, owner, name);
      if (repo === null) return;
      if (method === 'GET' && rest.length === 1) {
        const labels = [...repo.labels.values()].sort((a, b) => (a.name < b.name ? -1 : 1));
        sendJson(res, 200, store, labels.map((l) => ({ name: l.name, color: l.color, description: l.description })));
        return;
      }
      if (method === 'POST' && rest.length === 1) {
        const parsed = parseJsonBody(body);
        if (!parsed.ok) {
          sendError(res, 400, store, 'Invalid JSON');
          return;
        }
        const input = isRecord(parsed.value) ? parsed.value : {};
        const labelName = typeof input['name'] === 'string' ? (input['name'] as string) : '';
        if (labelName === '') {
          sendError(res, 422, store, 'Label name is required');
          return;
        }
        const color = typeof input['color'] === 'string' ? (input['color'] as string) : 'ededed';
        const description = typeof input['description'] === 'string' ? (input['description'] as string) : '';
        repo.labels.set(labelName, { name: labelName, color, description });
        sendJson(res, 201, store, { name: labelName, color, description });
        return;
      }
      sendError(res, 404, store, 'Not Found');
      return;
    }

    // /repos/{o}/{r}/issues[/{n}[/comments]]
    if (rest[0] === 'issues') {
      const repo = requireRepo(store, res, owner, name);
      if (repo === null) return;
      if (rest.length === 1 && method === 'GET') {
        let list = [...repo.issues];
        const state = query.get('state') ?? 'open';
        if (state !== 'all') list = list.filter((i) => i.state === state);
        const direction = query.get('direction') ?? 'desc';
        list.sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
        const page = paginate(req, `/api/v3/repos/${owner}/${name}/issues`, query, list);
        sendJsonWithLink(res, 200, store, page.items.map((i) => JSON.parse(issueJson(store, repo, i).toString('utf8'))), page.link);
        return;
      }
      if (rest.length === 1 && method === 'POST') {
        const parsed = parseJsonBody(body);
        if (!parsed.ok) {
          sendError(res, 400, store, 'Invalid JSON');
          return;
        }
        const input = isRecord(parsed.value) ? parsed.value : {};
        const title = typeof input['title'] === 'string' ? (input['title'] as string) : '';
        if (title === '') {
          sendError(res, 422, store, 'Issue title is required');
          return;
        }
        const labelsInput: string[] = Array.isArray(input['labels']) ? (input['labels'] as unknown[]).filter((l): l is string => typeof l === 'string') : [];
        for (const labelName of labelsInput) {
          if (!repo.labels.has(labelName)) {
            sendError(res, 422, store, `Label "${labelName}" does not exist`);
            return;
          }
        }
        store.seq += 1;
        const issue: Issue = {
          id: store.nextIssueId++,
          number: ++repo.issueSeq,
          repoId: repo.id,
          title,
          body: typeof input['body'] === 'string' ? (input['body'] as string) : '',
          state: 'open',
          labels: labelsInput,
          createdSeq: store.seq,
          updatedSeq: store.seq,
          comments: [],
          jsonBuf: null,
        };
        repo.issues.push(issue);
        const raw = issueJson(store, repo, issue);
        res.writeHead(201, {
          'content-type': 'application/json',
          'x-github-request-id': nextRequestId(store),
          'content-length': raw.length,
        });
        res.end(raw);
        return;
      }
      if (rest.length >= 2) {
        const number = Number(rest[1]);
        const issue = repo.issues.find((i) => i.number === number);
        if (issue === undefined) {
          sendError(res, 404, store, 'Not Found');
          return;
        }
        if (rest.length === 2 && method === 'GET') {
          const raw = issueJson(store, repo, issue);
          res.writeHead(200, {
            'content-type': 'application/json',
            'x-github-request-id': nextRequestId(store),
            'content-length': raw.length,
          });
          res.end(raw);
          return;
        }
        if (rest.length === 2 && method === 'PATCH') {
          const parsed = parseJsonBody(body);
          if (!parsed.ok) {
            sendError(res, 400, store, 'Invalid JSON');
            return;
          }
          const input = isRecord(parsed.value) ? parsed.value : {};
          if (typeof input['title'] === 'string') issue.title = input['title'] as string;
          if (typeof input['body'] === 'string') issue.body = input['body'] as string;
          if (input['state'] === 'open' || input['state'] === 'closed') issue.state = input['state'] as 'open' | 'closed';
          store.seq += 1;
          issue.updatedSeq = store.seq;
          issue.jsonBuf = null;
          const raw = issueJson(store, repo, issue);
          res.writeHead(200, {
            'content-type': 'application/json',
            'x-github-request-id': nextRequestId(store),
            'content-length': raw.length,
          });
          res.end(raw);
          return;
        }
        if (rest.length === 3 && rest[2] === 'comments' && method === 'GET') {
          sendJson(res, 200, store, issue.comments.map((c) => ({ id: c.id, body: c.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID }, created_at: nowIso(store.trialNowSec) })));
          return;
        }
        if (rest.length === 3 && rest[2] === 'comments' && method === 'POST') {
          const parsed = parseJsonBody(body);
          if (!parsed.ok) {
            sendError(res, 400, store, 'Invalid JSON');
            return;
          }
          const input = isRecord(parsed.value) ? parsed.value : {};
          const commentBody = typeof input['body'] === 'string' ? (input['body'] as string) : '';
          store.seq += 1;
          const comment: IssueComment = { id: store.nextCommentId++, body: commentBody, createdSeq: store.seq };
          issue.comments.push(comment);
          issue.jsonBuf = null;
          sendJson(res, 201, store, { id: comment.id, body: comment.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID }, created_at: nowIso(store.trialNowSec) });
          return;
        }
      }
      sendError(res, 404, store, 'Not Found');
      return;
    }

    // /repos/{o}/{r}/pulls[/{n}[/files|/merge]]
    if (rest[0] === 'pulls') {
      const repo = requireRepo(store, res, owner, name);
      if (repo === null) return;
      if (rest.length === 1 && method === 'GET') {
        let list = [...repo.pulls];
        const state = query.get('state') ?? 'open';
        // A merged pull request reads back as closed on REST v3.
        if (state === 'open') list = list.filter((p) => p.state === 'open');
        else if (state === 'closed') list = list.filter((p) => p.state === 'closed' || p.state === 'merged');
        list.sort((a, b) => b.createdSeq - a.createdSeq);
        const page = paginate(req, `/api/v3/repos/${owner}/${name}/pulls`, query, list);
        sendJsonWithLink(res, 200, store, page.items.map((p) => pullJson(store, repo, p)), page.link);
        return;
      }
      if (rest.length === 1 && method === 'POST') {
        const parsed = parseJsonBody(body);
        if (!parsed.ok) {
          sendError(res, 400, store, 'Invalid JSON');
          return;
        }
        const input = isRecord(parsed.value) ? parsed.value : {};
        const title = typeof input['title'] === 'string' ? (input['title'] as string) : '';
        const head = typeof input['head'] === 'string' ? (input['head'] as string) : '';
        const base = typeof input['base'] === 'string' ? (input['base'] as string) : '';
        if (title === '' || head === '' || base === '') {
          sendError(res, 422, store, 'A pull request needs a title, head and base');
          return;
        }
        const headSha = repo.refs.get(`refs/heads/${head}`);
        const baseSha = repo.refs.get(`refs/heads/${base}`);
        if (headSha === undefined || baseSha === undefined) {
          sendError(res, 422, store, 'Head or base branch does not exist');
          return;
        }
        const duplicate = repo.pulls.find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
        if (duplicate !== undefined) {
          sendError(res, 422, store, 'A pull request already exists for this head and base');
          return;
        }
        store.seq += 1;
        const pull: Pull = {
          id: store.nextPullId++,
          number: ++repo.pullSeq,
          repoId: repo.id,
          title,
          body: typeof input['body'] === 'string' ? (input['body'] as string) : '',
          state: 'open',
          headRef: head,
          baseRef: base,
          headSha,
          baseSha,
          createdSeq: store.seq,
          mergedAt: null,
          mergeCommitSha: null,
        };
        repo.pulls.push(pull);
        const raw = Buffer.from(JSON.stringify(pullJson(store, repo, pull)), 'utf8');
        res.writeHead(201, {
          'content-type': 'application/json',
          'x-github-request-id': nextRequestId(store),
          'content-length': raw.length,
        });
        res.end(raw);
        return;
      }
      if (rest.length >= 2) {
        const number = Number(rest[1]);
        const pull = repo.pulls.find((p) => p.number === number);
        if (pull === undefined) {
          sendError(res, 404, store, 'Not Found');
          return;
        }
        if (rest.length === 2 && method === 'GET') {
          sendJson(res, 200, store, pullJson(store, repo, pull));
          return;
        }
        if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
          const headCommit = getCommit(repo, pull.headSha);
          const baseCommit = getCommit(repo, pull.baseSha);
          const headTree = headCommit?.tree ?? EMPTY_TREE_OID;
          const mergeBaseOid = mergeBase(repo, pull.headSha, pull.baseSha);
          const baseTree = mergeBaseOid === null ? headTree : (getCommit(repo, mergeBaseOid)?.tree ?? EMPTY_TREE_OID);
          void baseCommit;
          const files = diffTrees(repo, baseTree, headTree);
          sendJson(res, 200, store, files.map((f) => ({ filename: f.path, status: f.status, additions: f.additions, deletions: f.deletions, changes: f.additions + f.deletions })));
          return;
        }
        if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
          if (pull.state !== 'open') {
            sendError(res, 405, store, 'Pull request is not open');
            return;
          }
          const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
          const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
          if (baseTip === undefined || headTip === undefined) {
            sendError(res, 404, store, 'Not Found');
            return;
          }
          const merged = threeWayMerge(repo, baseTip, headTip, baseTip);
          if (merged.conflict) {
            sendError(res, 405, store, 'Merge conflict');
            return;
          }
          const author = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${gitTimestamp(store.trialNowSec)}`;
          const commitBytes = buildCommitBytes({
            tree: merged.treeOid,
            parents: [baseTip],
            author,
            committer: author,
            message: pull.title,
          });
          const mergeOid = gitObjectId('commit', commitBytes);
          putObject(repo, { oid: mergeOid, type: 'commit', bytes: commitBytes });
          setRef(repo, `refs/heads/${pull.baseRef}`, mergeOid);
          pull.state = 'merged';
          pull.mergedAt = nowIso(store.trialNowSec);
          pull.mergeCommitSha = mergeOid;
          sendJson(res, 200, store, { sha: mergeOid, merged: true, message: pull.title });
          return;
        }
      }
      sendError(res, 404, store, 'Not Found');
      return;
    }

    sendError(res, 404, store, 'Not Found');
    return;
  }

  sendError(res, 404, store, 'Not Found');
}

// ---------------------------------------------------------------------------
// GraphQL (/api/graphql)
// ---------------------------------------------------------------------------

type GqlValue =
  | string
  | number
  | boolean
  | null
  | { kind: 'var'; name: string }
  | { kind: 'list'; items: GqlValue[] }
  | { kind: 'object'; fields: Record<string, GqlValue> }
  | { kind: 'enum'; value: string };

interface GqlSelection {
  alias: string | null;
  name: string;
  args: Record<string, GqlValue>;
  selections: GqlSelection[] | null;
  typeCondition: string | null;
  spread: string | null;
}

interface GqlDocument {
  kind: 'query' | 'mutation';
  selections: GqlSelection[];
  fragments: Map<string, { typeCondition: string; selections: GqlSelection[] }>;
}

interface GqlToken {
  type: 'punct' | 'name' | 'string' | 'int' | 'float';
  value: string;
}

function gqlLex(input: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  while (i < input.length) {
    const ch = input[i];
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i++;
      continue;
    }
    if (ch === '#') {
      while (i < input.length && input[i] !== '\n') i++;
      continue;
    }
    if (ch === '.' && input.slice(i, i + 3) === '...') {
      tokens.push({ type: 'punct', value: '...' });
      i += 3;
      continue;
    }
    if ('{}()[]:!=$=@'.includes(ch)) {
      tokens.push({ type: 'punct', value: ch });
      i++;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let out = '';
      while (j < input.length && input[j] !== '"') {
        if (input[j] === '\\' && j + 1 < input.length) {
          const esc = input[j + 1];
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += input[j];
          j++;
        }
      }
      tokens.push({ type: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      while (j < input.length && /[0-9.]/.test(input[j])) j++;
      const text = input.slice(i, j);
      tokens.push({ type: text.includes('.') ? 'float' : 'int', value: text });
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(ch)) {
      let j = i;
      while (j < input.length && /[_A-Za-z0-9]/.test(input[j])) j++;
      tokens.push({ type: 'name', value: input.slice(i, j) });
      i = j;
      continue;
    }
    i++;
  }
  return tokens;
}

class GqlParser {
  private pos = 0;
  private readonly tokens: GqlToken[];

  constructor(tokens: GqlToken[]) {
    this.tokens = tokens;
  }

  private peek(): GqlToken | undefined {
    return this.tokens[this.pos];
  }

  private next(): GqlToken {
    const token = this.tokens[this.pos];
    this.pos++;
    return token as GqlToken;
  }

  private expect(value: string): GqlToken {
    const token = this.next();
    if (token.value !== value) throw new Error(`expected ${value}, got ${token.value}`);
    return token;
  }

  private skipDirectives(): void {
    while (this.peek()?.value === '@') {
      this.next();
      this.next();
      if (this.peek()?.value === '(') this.parseArguments();
    }
  }

  parseDocument(): GqlDocument {
    let kind: 'query' | 'mutation' = 'query';
    const fragments = new Map<string, { typeCondition: string; selections: GqlSelection[] }>();
    let selections: GqlSelection[] = [];
    while (this.pos < this.tokens.length) {
      const token = this.next();
      if (token.value === 'query' || token.value === 'mutation') {
        kind = token.value as 'query' | 'mutation';
        if (this.peek()?.type === 'name') this.next();
        if (this.peek()?.value === '(') this.parseVariableDefinitions();
        selections = this.parseSelectionSet();
      } else if (token.value === 'fragment') {
        const name = this.next().value;
        this.expect('on');
        const typeCondition = this.next().value;
        const sels = this.parseSelectionSet();
        fragments.set(name, { typeCondition, selections: sels });
      } else if (token.value === '{') {
        selections = this.parseSelectionSetBody();
      }
    }
    return { kind, selections, fragments };
  }

  private parseVariableDefinitions(): void {
    this.expect('(');
    let depth = 1;
    while (this.pos < this.tokens.length && depth > 0) {
      const token = this.next();
      if (token.value === '(') depth++;
      else if (token.value === ')') depth--;
    }
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expect('{');
    return this.parseSelectionSetBody();
  }

  private parseSelectionSetBody(): GqlSelection[] {
    const out: GqlSelection[] = [];
    while (this.pos < this.tokens.length && this.peek()?.value !== '}') {
      const token = this.peek() as GqlToken;
      if (token.value === '...') {
        this.next();
        const nextToken = this.peek() as GqlToken;
        if (nextToken.value === 'on') {
          this.next();
          const typeCondition = this.next().value;
          const sels = this.parseSelectionSet();
          out.push({ alias: null, name: '', args: {}, selections: sels, typeCondition, spread: null });
        } else {
          const name = this.next().value;
          this.skipDirectives();
          out.push({ alias: null, name: '', args: {}, selections: null, typeCondition: null, spread: name });
        }
        continue;
      }
      const first = this.next();
      let alias: string | null = null;
      let name = first.value;
      if (this.peek()?.value === ':') {
        this.next();
        alias = name;
        name = this.next().value;
      }
      let args: Record<string, GqlValue> = {};
      if (this.peek()?.value === '(') args = this.parseArguments();
      this.skipDirectives();
      let sels: GqlSelection[] | null = null;
      if (this.peek()?.value === '{') sels = this.parseSelectionSet();
      out.push({ alias, name, args, selections: sels, typeCondition: null, spread: null });
    }
    this.expect('}');
    return out;
  }

  private parseArguments(): Record<string, GqlValue> {
    const args: Record<string, GqlValue> = {};
    this.expect('(');
    while (this.pos < this.tokens.length && this.peek()?.value !== ')') {
      const name = this.next().value;
      this.expect(':');
      args[name] = this.parseValue();
    }
    this.expect(')');
    return args;
  }

  private parseValue(): GqlValue {
    const token = this.next();
    if (token.value === '$') return { kind: 'var', name: this.next().value };
    if (token.value === '[') {
      const items: GqlValue[] = [];
      while (this.peek()?.value !== ']') items.push(this.parseValue());
      this.expect(']');
      return { kind: 'list', items };
    }
    if (token.value === '{') {
      const fields: Record<string, GqlValue> = {};
      while (this.peek()?.value !== '}') {
        const name = this.next().value;
        this.expect(':');
        fields[name] = this.parseValue();
      }
      this.expect('}');
      return { kind: 'object', fields };
    }
    if (token.type === 'string') return token.value;
    if (token.type === 'int') return Number.parseInt(token.value, 10);
    if (token.type === 'float') return Number.parseFloat(token.value);
    if (token.value === 'true') return true;
    if (token.value === 'false') return false;
    if (token.value === 'null') return null;
    return { kind: 'enum', value: token.value };
  }
}

function gqlResolveValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  if (value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
  if (value.kind === 'var') return variables[value.name] ?? null;
  if (value.kind === 'list') return value.items.map((item) => gqlResolveValue(item, variables));
  if (value.kind === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value.fields)) out[k] = gqlResolveValue(v, variables);
    return out;
  }
  return value.value;
}

const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'body', 'state', 'createdAt', 'updatedAt', 'author', 'labels', 'comments', 'url', 'repository'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'headRefName', 'baseRefName', 'headRefOid', 'baseRefOid', 'mergeable', 'merged', 'mergedAt', 'files', 'author', 'createdAt', 'updatedAt'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'private', 'createdAt', 'updatedAt', 'url'],
  User: ['id', 'login', 'name', 'email'],
  SearchType: [],
};

const GQL_ENUM_VALUES: Record<string, string[]> = {
  SearchType: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE'],
};

type GqlObject =
  | { __typename: 'Query' }
  | { __typename: 'User'; login: string; id: number; name: string; email: string }
  | { __typename: 'Repository'; repo: Repo }
  | { __typename: 'Issue'; repo: Repo; issue: Issue }
  | { __typename: 'PullRequest'; repo: Repo; pull: Pull }
  | { __typename: 'IssueComment'; repo: Repo; issue: Issue; comment: IssueComment }
  | { __typename: 'IssueConnection'; repo: Repo; nodes: Issue[]; pageInfo: { hasNextPage: boolean; endCursor: string | null } }
  | { __typename: 'PullRequestConnection'; repo: Repo; nodes: Pull[]; pageInfo: { hasNextPage: boolean; endCursor: string | null } }
  | { __typename: 'PullRequestFileConnection'; repo: Repo; nodes: { path: string }[] }
  | { __typename: 'Ref'; name: string }
  | { __typename: '__Type'; name: string }
  | { __typename: '__Field'; name: string }
  | { __typename: '__EnumValue'; name: string }
  | { __typename: 'CommentEdge'; repo: Repo; issue: Issue; comment: IssueComment };

interface GqlContext {
  store: Store;
  errors: { message: string }[];
}

function gqlIssueId(repo: Repo, issue: Issue): string {
  return encodeGlobalId('Issue', repo.id, issue.number);
}

function gqlPullId(repo: Repo, pull: Pull): string {
  return encodeGlobalId('PullRequest', repo.id, pull.number);
}

function gqlRepoId(repo: Repo): string {
  return encodeGlobalId('Repository', repo.id);
}

function gqlCommentId(repo: Repo, issue: Issue, comment: IssueComment): string {
  return encodeGlobalId('IssueComment', repo.id, issue.number, comment.id);
}

function gqlSelect(
  ctx: GqlContext,
  obj: GqlObject,
  selections: GqlSelection[] | null,
  fragments: Map<string, { typeCondition: string; selections: GqlSelection[] }>,
  variables: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (selections === null) return out;
  for (const sel of selections) {
    if (sel.spread !== null) {
      const frag = fragments.get(sel.spread);
      if (frag === undefined) continue;
      if (frag.typeCondition !== obj.__typename) continue;
      Object.assign(out, gqlSelect(ctx, obj, frag.selections, fragments, variables));
      continue;
    }
    if (sel.typeCondition !== null) {
      if (sel.typeCondition !== obj.__typename) continue;
      Object.assign(out, gqlSelect(ctx, obj, sel.selections, fragments, variables));
      continue;
    }
    const key = sel.alias ?? sel.name;
    const args: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(sel.args)) args[k] = gqlResolveValue(v, variables);
    out[key] = gqlResolveField(ctx, obj, sel.name, args, sel.selections, fragments, variables);
  }
  return out;
}

function gqlUnknownField(ctx: GqlContext, typeName: string, field: string): null {
  ctx.errors.push({ message: `Cannot query field "${field}" on type "${typeName}".` });
  return null;
}

function gqlListIssues(repo: Repo, args: Record<string, unknown>): { nodes: Issue[]; pageInfo: { hasNextPage: boolean; endCursor: string | null } } {
  let list = [...repo.issues];
  const states = args['states'];
  if (Array.isArray(states) && states.length > 0) {
    const wanted = new Set(states.map((s) => String(s).toLowerCase()));
    list = list.filter((i) => wanted.has(i.state));
  }
  const orderBy = args['orderBy'];
  if (isRecord(orderBy)) {
    const direction = String(orderBy['direction'] ?? 'ASC').toUpperCase();
    list.sort((a, b) => (direction === 'DESC' ? b.number - a.number : a.number - b.number));
  } else {
    list.sort((a, b) => a.number - b.number);
  }
  const after = args['after'];
  if (typeof after === 'string' && after !== '') {
    try {
      const decoded = Buffer.from(after, 'base64').toString('utf8');
      const n = Number(decoded.split(':')[1]);
      if (Number.isFinite(n)) list = list.filter((i) => i.number > n);
    } catch {
      // Ignore a bad cursor.
    }
  }
  const first = typeof args['first'] === 'number' ? (args['first'] as number) : list.length;
  const page = list.slice(0, first);
  const hasNextPage = list.length > first;
  const endCursor = page.length > 0 ? Buffer.from(`cursor:${page[page.length - 1].number}`, 'utf8').toString('base64') : null;
  return { nodes: page, pageInfo: { hasNextPage, endCursor } };
}

function gqlResolveField(
  ctx: GqlContext,
  obj: GqlObject,
  field: string,
  args: Record<string, unknown>,
  selections: GqlSelection[] | null,
  fragments: Map<string, { typeCondition: string; selections: GqlSelection[] }>,
  variables: Record<string, unknown>,
): unknown {
  const store = ctx.store;
  switch (obj.__typename) {
    case 'Query': {
      if (field === 'viewer') {
        return gqlSelect(ctx, { __typename: 'User', login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL }, selections, fragments, variables);
      }
      if (field === 'repository') {
        const owner = String(args['owner'] ?? '');
        const name = String(args['name'] ?? '');
        const repo = findRepo(store, owner, name);
        if (repo === undefined) return null;
        return gqlSelect(ctx, { __typename: 'Repository', repo }, selections, fragments, variables);
      }
      if (field === 'node') {
        const id = String(args['id'] ?? '');
        const decoded = decodeGlobalId(id);
        if (decoded === null) return null;
        if (decoded.kind === 'Repository') {
          const repo = store.reposById.get(Number(decoded.parts[0]));
          if (repo === undefined) return null;
          return gqlSelect(ctx, { __typename: 'Repository', repo }, selections, fragments, variables);
        }
        if (decoded.kind === 'Issue') {
          const repo = store.reposById.get(Number(decoded.parts[0]));
          const issue = repo?.issues.find((i) => i.number === Number(decoded.parts[1]));
          if (repo === undefined || issue === undefined) return null;
          return gqlSelect(ctx, { __typename: 'Issue', repo, issue }, selections, fragments, variables);
        }
        if (decoded.kind === 'PullRequest') {
          const repo = store.reposById.get(Number(decoded.parts[0]));
          const pull = repo?.pulls.find((p) => p.number === Number(decoded.parts[1]));
          if (repo === undefined || pull === undefined) return null;
          return gqlSelect(ctx, { __typename: 'PullRequest', repo, pull }, selections, fragments, variables);
        }
        return null;
      }
      if (field === '__type') {
        const name = String(args['name'] ?? '');
        if (GQL_TYPE_FIELDS[name] === undefined && GQL_ENUM_VALUES[name] === undefined) return null;
        return gqlSelect(ctx, { __typename: '__Type', name }, selections, fragments, variables);
      }
      if (field === 'createIssue') return gqlMutateCreateIssue(ctx, args, selections, fragments, variables);
      if (field === 'closeIssue') return gqlMutateCloseIssue(ctx, args, selections, fragments, variables);
      if (field === 'createPullRequest') return gqlMutateCreatePullRequest(ctx, args, selections, fragments, variables);
      if (field === 'mergePullRequest') return gqlMutateMergePullRequest(ctx, args, selections, fragments, variables);
      if (field === 'addComment') return gqlMutateAddComment(ctx, args, selections, fragments, variables);
      return gqlUnknownField(ctx, 'Query', field);
    }
    case 'User': {
      if (field === 'login') return obj.login;
      if (field === 'id') return encodeGlobalId('User', obj.id);
      if (field === 'name') return obj.name;
      if (field === 'email') return obj.email;
      return gqlUnknownField(ctx, 'User', field);
    }
    case 'Repository': {
      const repo = obj.repo;
      if (field === 'id') return gqlRepoId(repo);
      if (field === 'databaseId') return repo.id;
      if (field === 'name') return repo.name;
      if (field === 'nameWithOwner') return `${repo.owner}/${repo.name}`;
      if (field === 'description') return repo.description;
      if (field === 'private') return repo.privateRepo;
      if (field === 'owner') {
        return gqlSelect(ctx, { __typename: 'User', login: repo.owner, id: repo.owner === VIEWER_LOGIN ? VIEWER_ID : 1001, name: repo.owner, email: `${repo.owner}@example.invalid` }, selections, fragments, variables);
      }
      if (field === 'defaultBranchRef') {
        const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
        if (tip === undefined) return null;
        return gqlSelect(ctx, { __typename: 'Ref', name: repo.defaultBranch }, selections, fragments, variables);
      }
      if (field === 'viewerPermission') return 'ADMIN';
      if (field === 'hasIssuesEnabled') return true;
      if (field === 'createdAt' || field === 'updatedAt') return nowIso(store.trialNowSec);
      if (field === 'url') return `https://github.com/${repo.owner}/${repo.name}`;
      if (field === 'issue') {
        const issue = repo.issues.find((i) => i.number === Number(args['number']));
        if (issue === undefined) return null;
        return gqlSelect(ctx, { __typename: 'Issue', repo, issue }, selections, fragments, variables);
      }
      if (field === 'issues') {
        const page = gqlListIssues(repo, args);
        return gqlSelect(ctx, { __typename: 'IssueConnection', repo, nodes: page.nodes, pageInfo: page.pageInfo }, selections, fragments, variables);
      }
      if (field === 'pullRequests') {
        const first = typeof args['first'] === 'number' ? (args['first'] as number) : repo.pulls.length;
        const nodes = [...repo.pulls].sort((a, b) => a.number - b.number).slice(0, first);
        const hasNextPage = repo.pulls.length > first;
        return gqlSelect(
          ctx,
          { __typename: 'PullRequestConnection', repo, nodes, pageInfo: { hasNextPage, endCursor: null } },
          selections,
          fragments,
          variables,
        );
      }
      if (field === 'pullRequest') {
        const pull = repo.pulls.find((p) => p.number === Number(args['number']));
        if (pull === undefined) return null;
        return gqlSelect(ctx, { __typename: 'PullRequest', repo, pull }, selections, fragments, variables);
      }
      return gqlUnknownField(ctx, 'Repository', field);
    }
    case 'Issue': {
      const issue = obj.issue;
      if (field === 'id') return gqlIssueId(obj.repo, issue);
      if (field === 'number') return issue.number;
      if (field === 'title') return issue.title;
      if (field === 'body') return issue.body;
      if (field === 'state') return issue.state.toUpperCase();
      if (field === 'createdAt' || field === 'updatedAt') return nowIso(store.trialNowSec);
      return gqlUnknownField(ctx, 'Issue', field);
    }
    case 'PullRequest': {
      const pull = obj.pull;
      const repo = obj.repo;
      if (field === 'id') return gqlPullId(repo, pull);
      if (field === 'number') return pull.number;
      if (field === 'title') return pull.title;
      if (field === 'body') return pull.body;
      if (field === 'state') return pull.state.toUpperCase();
      if (field === 'headRefName') return pull.headRef;
      if (field === 'baseRefName') return pull.baseRef;
      if (field === 'headRefOid') return repo.refs.get(`refs/heads/${pull.headRef}`) ?? pull.headSha;
      if (field === 'baseRefOid') return repo.refs.get(`refs/heads/${pull.baseRef}`) ?? pull.baseSha;
      if (field === 'merged') return pull.state === 'merged';
      if (field === 'mergedAt') return pull.mergedAt;
      if (field === 'mergeable') {
        const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
        const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
        if (baseTip === undefined || headTip === undefined) return 'UNKNOWN';
        const merged = threeWayMerge(repo, baseTip, headTip, baseTip);
        return merged.conflict ? 'CONFLICTING' : 'MERGEABLE';
      }
      if (field === 'files') {
        const first = typeof args['first'] === 'number' ? (args['first'] as number) : 100;
        const headCommit = getCommit(repo, pull.headSha);
        const mergeBaseOid = mergeBase(repo, pull.headSha, pull.baseSha);
        const baseTree = mergeBaseOid === null ? (headCommit?.tree ?? EMPTY_TREE_OID) : (getCommit(repo, mergeBaseOid)?.tree ?? EMPTY_TREE_OID);
        const files = diffTrees(repo, baseTree, headCommit?.tree ?? EMPTY_TREE_OID).slice(0, first);
        return gqlSelect(ctx, { __typename: 'PullRequestFileConnection', repo, nodes: files.map((f) => ({ path: f.path })) }, selections, fragments, variables);
      }
      if (field === 'createdAt' || field === 'updatedAt') return nowIso(store.trialNowSec);
      return gqlUnknownField(ctx, 'PullRequest', field);
    }
    case 'IssueConnection': {
      if (field === 'nodes') {
        return obj.nodes.map((issue) => gqlSelect(ctx, { __typename: 'Issue', repo: obj.repo, issue }, selections, fragments, variables));
      }
      if (field === 'pageInfo') {
        return { hasNextPage: obj.pageInfo.hasNextPage, endCursor: obj.pageInfo.endCursor };
      }
      if (field === 'totalCount') return obj.nodes.length;
      return gqlUnknownField(ctx, 'IssueConnection', field);
    }
    case 'PullRequestConnection': {
      if (field === 'nodes') {
        return obj.nodes.map((pull) => gqlSelect(ctx, { __typename: 'PullRequest', repo: obj.repo, pull }, selections, fragments, variables));
      }
      if (field === 'pageInfo') {
        return { hasNextPage: obj.pageInfo.hasNextPage, endCursor: obj.pageInfo.endCursor };
      }
      if (field === 'totalCount') return obj.nodes.length;
      return gqlUnknownField(ctx, 'PullRequestConnection', field);
    }
    case 'PullRequestFileConnection': {
      if (field === 'nodes') return obj.nodes.map((n) => ({ path: n.path }));
      return gqlUnknownField(ctx, 'PullRequestFileConnection', field);
    }
    case 'Ref': {
      if (field === 'name') return obj.name;
      return gqlUnknownField(ctx, 'Ref', field);
    }
    case '__Type': {
      if (field === 'name') return obj.name;
      if (field === 'kind') return GQL_ENUM_VALUES[obj.name] !== undefined ? 'ENUM' : 'OBJECT';
      if (field === 'fields') {
        const names = GQL_TYPE_FIELDS[obj.name] ?? [];
        return names.map((n) => ({ name: n }));
      }
      if (field === 'enumValues') {
        const names = GQL_ENUM_VALUES[obj.name] ?? [];
        return names.map((n) => ({ name: n }));
      }
      return gqlUnknownField(ctx, '__Type', field);
    }
    case '__Field':
    case '__EnumValue': {
      if (field === 'name') return obj.name;
      return gqlUnknownField(ctx, obj.__typename, field);
    }
    case 'IssueComment': {
      if (field === 'id') return gqlCommentId(obj.repo, obj.issue, obj.comment);
      if (field === 'body') return obj.comment.body;
      return gqlUnknownField(ctx, 'IssueComment', field);
    }
    case 'CommentEdge': {
      if (field === 'node') {
        return gqlSelect(ctx, { __typename: 'IssueComment', repo: obj.repo, issue: obj.issue, comment: obj.comment }, selections, fragments, variables);
      }
      return gqlUnknownField(ctx, 'CommentEdge', field);
    }
  }
}

function gqlMutateCreateIssue(
  ctx: GqlContext,
  args: Record<string, unknown>,
  selections: GqlSelection[] | null,
  fragments: Map<string, { typeCondition: string; selections: GqlSelection[] }>,
  variables: Record<string, unknown>,
): unknown {
  const store = ctx.store;
  const input = isRecord(args['input']) ? (args['input'] as Record<string, unknown>) : {};
  const repo = store.reposById.get(Number(decodeGlobalId(String(input['repositoryId'] ?? ''))?.parts[0]));
  const title = typeof input['title'] === 'string' ? (input['title'] as string) : '';
  if (repo === undefined || title === '') {
    ctx.errors.push({ message: 'createIssue: the repository does not exist or the title is empty' });
    return null;
  }
  store.seq += 1;
  const issue: Issue = {
    id: store.nextIssueId++,
    number: ++repo.issueSeq,
    repoId: repo.id,
    title,
    body: typeof input['body'] === 'string' ? (input['body'] as string) : '',
    state: 'open',
    labels: [],
    createdSeq: store.seq,
    updatedSeq: store.seq,
    comments: [],
    jsonBuf: null,
  };
  repo.issues.push(issue);
  const out: Record<string, unknown> = {};
  for (const sel of selections ?? []) {
    if (sel.name === 'issue') {
      out[sel.alias ?? sel.name] = gqlSelect(ctx, { __typename: 'Issue', repo, issue }, sel.selections, fragments, variables);
    }
  }
  return out;
}

function gqlMutateCloseIssue(
  ctx: GqlContext,
  args: Record<string, unknown>,
  selections: GqlSelection[] | null,
  fragments: Map<string, { typeCondition: string; selections: GqlSelection[] }>,
  variables: Record<string, unknown>,
): unknown {
  const store = ctx.store;
  const input = isRecord(args['input']) ? (args['input'] as Record<string, unknown>) : {};
  const decoded = decodeGlobalId(String(input['issueId'] ?? ''));
  const repo = decoded?.kind === 'Issue' ? store.reposById.get(Number(decoded.parts[0])) : undefined;
  const issue = repo?.issues.find((i) => i.number === Number(decoded?.parts[1]));
  if (repo === undefined || issue === undefined) {
    ctx.errors.push({ message: 'closeIssue: the issue does not exist' });
    return null;
  }
  issue.state = 'closed';
  store.seq += 1;
  issue.updatedSeq = store.seq;
  issue.jsonBuf = null;
  const out: Record<string, unknown> = {};
  for (const sel of selections ?? []) {
    if (sel.name === 'issue') {
      out[sel.alias ?? sel.name] = gqlSelect(ctx, { __typename: 'Issue', repo, issue }, sel.selections, fragments, variables);
    }
  }
  return out;
}

function gqlMutateCreatePullRequest(
  ctx: GqlContext,
  args: Record<string, unknown>,
  selections: GqlSelection[] | null,
  fragments: Map<string, { typeCondition: string; selections: GqlSelection[] }>,
  variables: Record<string, unknown>,
): unknown {
  const store = ctx.store;
  const input = isRecord(args['input']) ? (args['input'] as Record<string, unknown>) : {};
  const repo = store.reposById.get(Number(decodeGlobalId(String(input['repositoryId'] ?? ''))?.parts[0]));
  const title = typeof input['title'] === 'string' ? (input['title'] as string) : '';
  const head = typeof input['headRefName'] === 'string' ? (input['headRefName'] as string) : '';
  const base = typeof input['baseRefName'] === 'string' ? (input['baseRefName'] as string) : '';
  const headSha = repo?.refs.get(`refs/heads/${head}`);
  const baseSha = repo?.refs.get(`refs/heads/${base}`);
  if (repo === undefined || title === '' || headSha === undefined || baseSha === undefined) {
    ctx.errors.push({ message: 'createPullRequest: the repository or a branch does not exist' });
    return null;
  }
  const duplicate = repo.pulls.find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
  if (duplicate !== undefined) {
    ctx.errors.push({ message: 'createPullRequest: a pull request already exists for this head and base' });
    return null;
  }
  store.seq += 1;
  const pull: Pull = {
    id: store.nextPullId++,
    number: ++repo.pullSeq,
    repoId: repo.id,
    title,
    body: '',
    state: 'open',
    headRef: head,
    baseRef: base,
    headSha,
    baseSha,
    createdSeq: store.seq,
    mergedAt: null,
    mergeCommitSha: null,
  };
  repo.pulls.push(pull);
  const out: Record<string, unknown> = {};
  for (const sel of selections ?? []) {
    if (sel.name === 'pullRequest') {
      out[sel.alias ?? sel.name] = gqlSelect(ctx, { __typename: 'PullRequest', repo, pull }, sel.selections, fragments, variables);
    }
  }
  return out;
}

function gqlMutateMergePullRequest(
  ctx: GqlContext,
  args: Record<string, unknown>,
  selections: GqlSelection[] | null,
  fragments: Map<string, { typeCondition: string; selections: GqlSelection[] }>,
  variables: Record<string, unknown>,
): unknown {
  const store = ctx.store;
  const input = isRecord(args['input']) ? (args['input'] as Record<string, unknown>) : {};
  const decoded = decodeGlobalId(String(input['pullRequestId'] ?? ''));
  const repo = decoded?.kind === 'PullRequest' ? store.reposById.get(Number(decoded.parts[0])) : undefined;
  const pull = repo?.pulls.find((p) => p.number === Number(decoded?.parts[1]));
  if (repo === undefined || pull === undefined) {
    ctx.errors.push({ message: 'mergePullRequest: the pull request does not exist' });
    return null;
  }
  if (pull.state !== 'open') {
    ctx.errors.push({ message: 'mergePullRequest: the pull request is not open' });
    return null;
  }
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  if (baseTip === undefined || headTip === undefined) {
    ctx.errors.push({ message: 'mergePullRequest: a branch does not exist' });
    return null;
  }
  const merged = threeWayMerge(repo, baseTip, headTip, baseTip);
  if (merged.conflict) {
    ctx.errors.push({ message: 'mergePullRequest: merge conflict' });
    return null;
  }
  const author = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${gitTimestamp(store.trialNowSec)}`;
  const commitBytes = buildCommitBytes({
    tree: merged.treeOid,
    parents: [baseTip],
    author,
    committer: author,
    message: pull.title,
  });
  const mergeOid = gitObjectId('commit', commitBytes);
  putObject(repo, { oid: mergeOid, type: 'commit', bytes: commitBytes });
  setRef(repo, `refs/heads/${pull.baseRef}`, mergeOid);
  pull.state = 'merged';
  pull.mergedAt = nowIso(store.trialNowSec);
  pull.mergeCommitSha = mergeOid;
  const out: Record<string, unknown> = {};
  for (const sel of selections ?? []) {
    if (sel.name === 'pullRequest') {
      out[sel.alias ?? sel.name] = gqlSelect(ctx, { __typename: 'PullRequest', repo, pull }, sel.selections, fragments, variables);
    }
  }
  return out;
}

function gqlMutateAddComment(
  ctx: GqlContext,
  args: Record<string, unknown>,
  selections: GqlSelection[] | null,
  fragments: Map<string, { typeCondition: string; selections: GqlSelection[] }>,
  variables: Record<string, unknown>,
): unknown {
  const store = ctx.store;
  const input = isRecord(args['input']) ? (args['input'] as Record<string, unknown>) : {};
  const decoded = decodeGlobalId(String(input['subjectId'] ?? ''));
  const body = typeof input['body'] === 'string' ? (input['body'] as string) : '';
  let repo: Repo | undefined;
  let issue: Issue | undefined;
  if (decoded?.kind === 'Issue') {
    repo = store.reposById.get(Number(decoded.parts[0]));
    issue = repo?.issues.find((i) => i.number === Number(decoded.parts[1]));
  }
  if (repo === undefined || issue === undefined) {
    ctx.errors.push({ message: 'addComment: the subject does not exist' });
    return null;
  }
  store.seq += 1;
  const comment: IssueComment = { id: store.nextCommentId++, body, createdSeq: store.seq };
  issue.comments.push(comment);
  issue.jsonBuf = null;
  const out: Record<string, unknown> = {};
  for (const sel of selections ?? []) {
    if (sel.name === 'commentEdge') {
      out[sel.alias ?? sel.name] = gqlSelect(ctx, { __typename: 'CommentEdge', repo, issue, comment }, sel.selections, fragments, variables);
    }
  }
  return out;
}

export function executeGraphQL(store: Store, query: string, variables: Record<string, unknown>): Record<string, unknown> {
  const ctx: GqlContext = { store, errors: [] };
  let doc: GqlDocument;
  try {
    doc = new GqlParser(gqlLex(query)).parseDocument();
  } catch (err) {
    return { errors: [{ message: err instanceof Error ? err.message : 'GraphQL parse error' }] };
  }
  const data = gqlSelect(ctx, { __typename: 'Query' }, doc.selections, doc.fragments, variables);
  const result: Record<string, unknown> = { data };
  if (ctx.errors.length > 0) result['errors'] = ctx.errors;
  return result;
}

export function handleGraphQL(store: Store, req: IncomingMessage, res: ServerResponse, body: Buffer): void {
  const parsed = parseJsonBody(body);
  if (!parsed.ok) {
    sendJson(res, 400, store, { errors: [{ message: 'Invalid JSON' }] });
    return;
  }
  const runOne = (entry: unknown): Record<string, unknown> => {
    if (!isRecord(entry) || typeof entry['query'] !== 'string') {
      return { errors: [{ message: 'GraphQL query is required' }] };
    }
    const variables = isRecord(entry['variables']) ? (entry['variables'] as Record<string, unknown>) : {};
    return executeGraphQL(store, entry['query'] as string, variables);
  };
  if (Array.isArray(parsed.value)) {
    sendJson(res, 200, store, parsed.value.map(runOne));
    return;
  }
  sendJson(res, 200, store, runOne(parsed.value));
}

// ---------------------------------------------------------------------------
// MCP (/mcp, JSON-RPC 2.0)
// ---------------------------------------------------------------------------

const MCP_SERVER_NAME = 'github-core-clone';
const MCP_SERVER_VERSION = '1.0.0';
const MCP_SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25'];

const MCP_TOOLS: readonly Record<string, unknown>[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the viewer.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        name: { type: 'string', description: 'The repository name.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'Filter by state: open, closed or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The pull request title.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
        body: { type: 'string', description: 'The pull request body.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash commit.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        pull_number: { type: 'integer', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpToolResult(obj: unknown): Record<string, unknown> {
  const text = JSON.stringify(obj);
  return { content: [{ type: 'text', text }], structuredContent: obj };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function mcpCallTool(store: Store, name: string, args: Record<string, unknown>): Record<string, unknown> {
  const owner = typeof args['owner'] === 'string' && args['owner'] !== '' ? (args['owner'] as string) : VIEWER_LOGIN;
  if (name === 'create_repo') {
    const repoName = typeof args['name'] === 'string' ? (args['name'] as string) : '';
    if (repoName === '') return mcpToolError('create_repo: name is required');
    const existing = findRepo(store, owner, repoName);
    if (existing !== undefined) {
      return mcpToolResult(JSON.parse(repoJson(store, existing).toString('utf8')));
    }
    const description = typeof args['description'] === 'string' ? (args['description'] as string) : '';
    const privateRepo = args['private'] === true;
    const repo = createRepo(store, owner, repoName, description, privateRepo);
    return mcpToolResult(JSON.parse(repoJson(store, repo).toString('utf8')));
  }
  if (name === 'get_repo') {
    const repoName = typeof args['repo'] === 'string' ? (args['repo'] as string) : '';
    const repo = findRepo(store, owner, repoName);
    if (repo === undefined) return mcpToolError(`get_repo: repository ${owner}/${repoName} does not exist`);
    return mcpToolResult(JSON.parse(repoJson(store, repo).toString('utf8')));
  }
  if (name === 'create_issue') {
    const repoName = typeof args['repo'] === 'string' ? (args['repo'] as string) : '';
    const repo = findRepo(store, owner, repoName);
    if (repo === undefined) return mcpToolError(`create_issue: repository ${owner}/${repoName} does not exist`);
    const title = typeof args['title'] === 'string' ? (args['title'] as string) : '';
    if (title === '') return mcpToolError('create_issue: title is required');
    store.seq += 1;
    const issue: Issue = {
      id: store.nextIssueId++,
      number: ++repo.issueSeq,
      repoId: repo.id,
      title,
      body: typeof args['body'] === 'string' ? (args['body'] as string) : '',
      state: 'open',
      labels: [],
      createdSeq: store.seq,
      updatedSeq: store.seq,
      comments: [],
      jsonBuf: null,
    };
    repo.issues.push(issue);
    return mcpToolResult(JSON.parse(issueJson(store, repo, issue).toString('utf8')));
  }
  if (name === 'list_issues') {
    const repoName = typeof args['repo'] === 'string' ? (args['repo'] as string) : '';
    const repo = findRepo(store, owner, repoName);
    if (repo === undefined) return mcpToolError(`list_issues: repository ${owner}/${repoName} does not exist`);
    const state = typeof args['state'] === 'string' ? (args['state'] as string) : 'open';
    let list = [...repo.issues];
    if (state !== 'all') list = list.filter((i) => i.state === state);
    list.sort((a, b) => b.createdSeq - a.createdSeq);
    return mcpToolResult(list.map((i) => JSON.parse(issueJson(store, repo, i).toString('utf8'))));
  }
  if (name === 'create_pull_request') {
    const repoName = typeof args['repo'] === 'string' ? (args['repo'] as string) : '';
    const repo = findRepo(store, owner, repoName);
    if (repo === undefined) return mcpToolError(`create_pull_request: repository ${owner}/${repoName} does not exist`);
    const title = typeof args['title'] === 'string' ? (args['title'] as string) : '';
    const head = typeof args['head'] === 'string' ? (args['head'] as string) : '';
    const base = typeof args['base'] === 'string' ? (args['base'] as string) : '';
    if (title === '' || head === '' || base === '') return mcpToolError('create_pull_request: title, head and base are required');
    const headSha = repo.refs.get(`refs/heads/${head}`);
    const baseSha = repo.refs.get(`refs/heads/${base}`);
    if (headSha === undefined || baseSha === undefined) return mcpToolError('create_pull_request: head or base branch does not exist');
    const duplicate = repo.pulls.find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
    if (duplicate !== undefined) return mcpToolError('create_pull_request: a pull request already exists for this head and base');
    store.seq += 1;
    const pull: Pull = {
      id: store.nextPullId++,
      number: ++repo.pullSeq,
      repoId: repo.id,
      title,
      body: typeof args['body'] === 'string' ? (args['body'] as string) : '',
      state: 'open',
      headRef: head,
      baseRef: base,
      headSha,
      baseSha,
      createdSeq: store.seq,
      mergedAt: null,
      mergeCommitSha: null,
    };
    repo.pulls.push(pull);
    return mcpToolResult(pullJson(store, repo, pull));
  }
  if (name === 'merge_pull_request') {
    const repoName = typeof args['repo'] === 'string' ? (args['repo'] as string) : '';
    const repo = findRepo(store, owner, repoName);
    if (repo === undefined) return mcpToolError(`merge_pull_request: repository ${owner}/${repoName} does not exist`);
    const number = Number(args['pull_number']);
    const pull = repo.pulls.find((p) => p.number === number);
    if (pull === undefined) return mcpToolError(`merge_pull_request: pull request ${number} does not exist`);
    if (pull.state !== 'open') return mcpToolError('merge_pull_request: the pull request is not open');
    const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
    const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
    if (baseTip === undefined || headTip === undefined) return mcpToolError('merge_pull_request: a branch does not exist');
    const merged = threeWayMerge(repo, baseTip, headTip, baseTip);
    if (merged.conflict) return mcpToolError('merge_pull_request: merge conflict');
    const author = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${gitTimestamp(store.trialNowSec)}`;
    const commitBytes = buildCommitBytes({
      tree: merged.treeOid,
      parents: [baseTip],
      author,
      committer: author,
      message: pull.title,
    });
    const mergeOid = gitObjectId('commit', commitBytes);
    putObject(repo, { oid: mergeOid, type: 'commit', bytes: commitBytes });
    setRef(repo, `refs/heads/${pull.baseRef}`, mergeOid);
    pull.state = 'merged';
    pull.mergedAt = nowIso(store.trialNowSec);
    pull.mergeCommitSha = mergeOid;
    return mcpToolResult({ number: pull.number, merged: true, state: 'merged', sha: mergeOid });
  }
  return mcpToolError(`unknown tool: ${name}`);
}

function handleMcp(store: Store, req: IncomingMessage, res: ServerResponse, body: Buffer, sessionId: string): void {
  const parsed = parseJsonBody(body);
  if (!parsed.ok) {
    const raw = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }), 'utf8');
    res.writeHead(400, { 'content-type': 'application/json', 'mcp-session-id': sessionId, 'content-length': raw.length });
    res.end(raw);
    return;
  }
  const runOne = (entry: unknown): Record<string, unknown> | null => {
    if (!isRecord(entry) || typeof entry['method'] !== 'string') {
      return { jsonrpc: '2.0', id: isRecord(entry) ? (entry['id'] ?? null) : null, error: { code: -32600, message: 'Invalid Request' } };
    }
    const id = 'id' in entry ? entry['id'] : undefined;
    const method = entry['method'] as string;
    const params = isRecord(entry['params']) ? (entry['params'] as Record<string, unknown>) : {};
    // A request without an id is a notification: no JSON-RPC answer.
    if (id === undefined) return null;
    const serverInfo = { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION };
    if (method === 'server/discover') {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          supportedVersions: MCP_SUPPORTED_VERSIONS,
          protocolVersion: MCP_SUPPORTED_VERSIONS[0],
          capabilities: { tools: {} },
          serverInfo,
          _meta: { 'io.modelcontextprotocol/serverInfo': serverInfo },
        },
      };
    }
    if (method === 'initialize') {
      const requested = typeof params['protocolVersion'] === 'string' ? (params['protocolVersion'] as string) : '';
      const protocolVersion = MCP_SUPPORTED_VERSIONS.includes(requested) ? requested : (MCP_SUPPORTED_VERSIONS[0] as string);
      return {
        jsonrpc: '2.0',
        id,
        result: { protocolVersion, capabilities: { tools: {} }, serverInfo },
      };
    }
    if (method === 'ping') {
      return { jsonrpc: '2.0', id, result: {} };
    }
    if (method === 'tools/list') {
      return { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } };
    }
    if (method === 'tools/call') {
      const toolName = typeof params['name'] === 'string' ? (params['name'] as string) : '';
      const tool = MCP_TOOLS.find((t) => t['name'] === toolName);
      if (tool === undefined) {
        return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${toolName}` } };
      }
      const args = isRecord(params['arguments']) ? (params['arguments'] as Record<string, unknown>) : {};
      const schema = tool['inputSchema'] as Record<string, unknown>;
      const required = Array.isArray(schema['required']) ? (schema['required'] as unknown[]).filter((r): r is string => typeof r === 'string') : [];
      const missing = required.filter((r) => args[r] === undefined || args[r] === null || args[r] === '');
      if (missing.length > 0) {
        return { jsonrpc: '2.0', id, result: mcpToolError(`tools/call ${toolName}: missing required argument(s): ${missing.join(', ')}`) };
      }
      return { jsonrpc: '2.0', id, result: mcpCallTool(store, toolName, args) };
    }
    return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
  };
  if (Array.isArray(parsed.value)) {
    const results = parsed.value.map(runOne).filter((r) => r !== null);
    const raw = Buffer.from(JSON.stringify(results), 'utf8');
    res.writeHead(200, { 'content-type': 'application/json', 'mcp-session-id': sessionId, 'content-length': raw.length });
    res.end(raw);
    return;
  }
  const result = runOne(parsed.value);
  if (result === null) {
    res.writeHead(202, { 'mcp-session-id': sessionId });
    res.end();
    return;
  }
  const raw = Buffer.from(JSON.stringify(result), 'utf8');
  res.writeHead(200, { 'content-type': 'application/json', 'mcp-session-id': sessionId, 'content-length': raw.length });
  res.end(raw);
}

// ---------------------------------------------------------------------------
// Router + server
// ---------------------------------------------------------------------------

export function createForge(options: ForgeOptions): ReturnType<typeof createServer> {
  const store = createStore(options.token, options.trialNowSec);
  const sessionId = randomUUID();
  const server = createServer((req, res) => {
    void (async () => {
      try {
        // Fast URL split: the paths this forge serves are plain ASCII, so skip
        // the URL constructor and only percent-decode segments that need it.
        const rawUrl = req.url ?? '/';
        const qIndex = rawUrl.indexOf('?');
        const pathname = qIndex === -1 ? rawUrl : rawUrl.slice(0, qIndex);
        const query = qIndex === -1 ? new URLSearchParams() : new URLSearchParams(rawUrl.slice(qIndex + 1));
        const segments = pathname
          .split('/')
          .filter((s) => s !== '')
          .map((s) => (s.includes('%') ? decodeURIComponent(s) : s));

        if (pathname === '/healthz') {
          res.writeHead(200, { 'content-type': 'text/plain' });
          res.end('ok');
          return;
        }

        // Git smart HTTP: /{owner}/{repo}.git/info/refs, git-upload-pack,
        // git-receive-pack. The git client appends ".git" to the repo name
        // in the URL; the repository itself is stored without it.
        const gitRepoName = (raw: string): string => (raw.endsWith('.git') ? raw.slice(0, -4) : raw);
        if (segments.length === 4 && segments[2] === 'info' && segments[3] === 'refs' && req.method === 'GET') {
          if (!isAuthorized(store, req)) {
            sendError(res, 401, store, 'Bad credentials');
            return;
          }
          handleGitInfoRefs(store, req, res, segments[0], gitRepoName(segments[1]), query.get('service') ?? '');
          return;
        }
        if (segments.length === 3 && segments[2] === 'git-upload-pack' && req.method === 'POST') {
          if (!isAuthorized(store, req)) {
            sendError(res, 401, store, 'Bad credentials');
            return;
          }
          const body = await readBody(req);
          handleUploadPack(store, req, res, segments[0], gitRepoName(segments[1]), body);
          return;
        }
        if (segments.length === 3 && segments[2] === 'git-receive-pack' && req.method === 'POST') {
          if (!isAuthorized(store, req)) {
            sendError(res, 401, store, 'Bad credentials');
            return;
          }
          const body = await readBody(req);
          handleReceivePack(store, req, res, segments[0], gitRepoName(segments[1]), body);
          return;
        }

        // REST v3.
        if (segments[0] === 'api' && segments[1] === 'v3') {
          if (!isAuthorized(store, req)) {
            sendError(res, 401, store, 'Bad credentials');
            return;
          }
          // GET requests in this suite never carry a body.
          const body = req.method === 'GET' ? Buffer.alloc(0) : await readBody(req);
          handleRest(store, req, res, segments.slice(2), query, body);
          return;
        }

        // GraphQL.
        if (segments[0] === 'api' && segments[1] === 'graphql' && req.method === 'POST') {
          if (!isAuthorized(store, req)) {
            sendError(res, 401, store, 'Bad credentials');
            return;
          }
          const body = await readBody(req);
          handleGraphQL(store, req, res, body);
          return;
        }

        // MCP.
        if (segments[0] === 'mcp' && segments.length === 1) {
          if (req.method === 'GET' || req.method === 'DELETE') {
            res.writeHead(405, { 'mcp-session-id': sessionId });
            res.end();
            return;
          }
          if (req.method === 'POST') {
            if (!isAuthorized(store, req)) {
              sendError(res, 401, store, 'Bad credentials');
              return;
            }
            const body = await readBody(req);
            handleMcp(store, req, res, body, sessionId);
            return;
          }
          res.writeHead(405, { 'mcp-session-id': sessionId });
          res.end();
          return;
        }

        sendError(res, 404, store, 'Not Found');
      } catch {
        try {
          if (!res.headersSent) sendError(res, 500, store, 'Internal Server Error');
          else res.end();
        } catch {
          // The socket is already gone.
        }
      }
    })();
  });
  // Small request/response pairs on a keep-alive socket must not wait on Nagle.
  server.on('connection', (socket) => socket.setNoDelay(true));
  return server;
}
