#!/usr/bin/env node
// Migrate old hill YAML files in WRECK-d/form-submissions to the triples format.
// Old: track_points = [[lat,lng], ...], ele_profile = [ele, ...] (different length)
// New: track_points = [[lat,lng,ele], ...], ele_profile = ""

import { execSync } from "node:child_process";

const REPO = "WRECK-d/form-submissions";
const DIR = "vertday/hills";

const TOKEN = execSync("gh auth token", { encoding: "utf8" }).trim();
if (!TOKEN) { console.error("No GitHub token from gh auth"); process.exit(1); }

const headers = {
  Authorization: `Bearer ${TOKEN}`,
  Accept: "application/vnd.github+json",
  "User-Agent": "vertday-migrate",
};

// Match worker.js exactly: each line is `key: "value"` with `"` escaped as `\"`.
function parseYaml(text) {
  const obj = {};
  for (const line of text.split("\n")) {
    const m = line.match(/^(\w+):\s*"(.*)"$/);
    if (m) obj[m[1]] = m[2].replace(/\\"/g, '"');
  }
  return obj;
}

function toYaml(obj) {
  return Object.entries(obj)
    .map(([k, v]) => `${k}: "${String(v).replace(/"/g, '\\"')}"`)
    .join("\n");
}

async function gh(path, init = {}) {
  const res = await fetch(`https://api.github.com/repos/${REPO}/${path}`, {
    ...init,
    headers: { ...headers, ...(init.headers || {}) },
  });
  if (!res.ok) throw new Error(`GitHub ${path}: ${res.status} ${await res.text()}`);
  return res.json();
}

async function listHills() {
  return gh(`contents/${DIR}`);
}

async function readFile(path) {
  const data = await gh(`contents/${path}`);
  const content = Buffer.from(data.content, "base64").toString("utf8");
  return { content, sha: data.sha };
}

async function writeFile(path, content, sha, message) {
  return gh(`contents/${path}`, {
    method: "PUT",
    body: JSON.stringify({
      message,
      content: Buffer.from(content, "utf8").toString("base64"),
      sha,
    }),
  });
}

// Linear-interpolate `eles` (length M) to a new array of length N.
function resample(eles, n) {
  if (eles.length === n) return eles.slice();
  if (eles.length === 0) return new Array(n).fill(0);
  if (eles.length === 1) return new Array(n).fill(eles[0]);
  const out = new Array(n);
  for (let i = 0; i < n; i++) {
    const t = (i / (n - 1)) * (eles.length - 1);
    const lo = Math.floor(t);
    const hi = Math.min(lo + 1, eles.length - 1);
    const f = t - lo;
    out[i] = eles[lo] * (1 - f) + eles[hi] * f;
  }
  return out;
}

async function main() {
  const dryRun = process.argv.includes("--dry-run");
  const files = await listHills();
  console.log(`Found ${files.length} hill files`);

  for (const f of files) {
    if (!f.name.endsWith(".yml")) continue;
    const { content, sha } = await readFile(f.path);
    const hill = parseYaml(content);

    let tp, ep;
    try { tp = JSON.parse(hill.track_points || "[]"); } catch { tp = []; }
    try { ep = JSON.parse(hill.ele_profile || "[]"); } catch { ep = []; }

    if (!tp.length) {
      console.log(`  ${f.name}: empty track_points, skipping`);
      continue;
    }
    if (tp[0].length >= 3) {
      console.log(`  ${f.name}: already triples, skipping`);
      continue;
    }
    if (!ep.length) {
      console.log(`  ${f.name}: no ele_profile, would write zero-elevation triples`);
      // proceed — better to have triples format with zero ele than mismatched
    }

    const eleMatched = resample(ep.length ? ep : new Array(tp.length).fill(0), tp.length);
    const triples = tp.map((p, i) => [p[0], p[1], Math.round(eleMatched[i] * 10) / 10]);

    const updated = { ...hill, track_points: JSON.stringify(triples), ele_profile: "" };
    const newYaml = toYaml(updated);

    console.log(`  ${f.name}: converting (${tp.length} pts, ${ep.length} ele → ${triples.length} triples)`);
    if (!dryRun) {
      await writeFile(f.path, newYaml, sha, `Migrate ${hill.name || f.name} to triples format`);
      console.log(`    ✓ written`);
    }
  }
  console.log(dryRun ? "Dry run complete (no changes)" : "Migration complete");
}

main().catch((e) => { console.error(e); process.exit(1); });
