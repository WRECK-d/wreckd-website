#!/usr/bin/env node
// One-off edits to hill YAML files.
//   - Reverse "base-camp-to-everest" (GPX was recorded going down)
//   - Trim "frith-from-boulders" and "mt-climie" to longest-climb only
// Usage: node edit-hills.mjs [--dry-run]

import { execSync } from "node:child_process";

const REPO = "WRECK-d/form-submissions";
const DIR = "vertday/hills";

const TOKEN = execSync("gh auth token", { encoding: "utf8" }).trim();
if (!TOKEN) { console.error("No GitHub token from gh auth"); process.exit(1); }

const headers = {
  Authorization: `Bearer ${TOKEN}`,
  Accept: "application/vnd.github+json",
  "User-Agent": "vertday-edit",
};

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
async function listHills() { return gh(`contents/${DIR}`); }
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

function haversine(a, b) {
  const R = 6371;
  const dLat = (b[0] - a[0]) * Math.PI / 180;
  const dLng = (b[1] - a[1]) * Math.PI / 180;
  const x = Math.sin(dLat/2)**2 + Math.cos(a[0]*Math.PI/180) * Math.cos(b[0]*Math.PI/180) * Math.sin(dLng/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(x), Math.sqrt(1 - x));
}

function computeStats(triples) {
  let gain = 0, dist = 0;
  for (let i = 1; i < triples.length; i++) {
    const dEle = triples[i][2] - triples[i - 1][2];
    if (dEle > 0) gain += dEle;
    dist += haversine(triples[i - 1], triples[i]);
  }
  return { gain: Math.round(gain), dist: Math.round(dist * 100) / 100 };
}

function centroid(triples) {
  if (!triples.length) return { lat: "", lng: "" };
  return {
    lat: triples.reduce((s, p) => s + p[0], 0) / triples.length,
    lng: triples.reduce((s, p) => s + p[1], 0) / triples.length,
  };
}

// Same algorithm as worker.js: longest sustained climb allowing ≤2m drops as noise.
function findLongestClimb(triples) {
  if (triples.length < 2) return { start: 0, end: triples.length - 1 };
  const NOISE = 2;
  let bestStart = 0, bestEnd = triples.length - 1, bestGain = -Infinity;
  let curStart = 0, curMin = triples[0][2], curPeak = triples[0][2], curPeakIdx = 0;
  for (let i = 1; i < triples.length; i++) {
    const ele = triples[i][2];
    if (ele >= curPeak - NOISE) {
      if (ele > curPeak) { curPeak = ele; curPeakIdx = i; }
    } else {
      const gain = curPeak - curMin;
      if (gain > bestGain) { bestGain = gain; bestStart = curStart; bestEnd = curPeakIdx; }
      curStart = i; curMin = ele; curPeak = ele; curPeakIdx = i;
    }
  }
  const gain = curPeak - curMin;
  if (gain > bestGain) { bestStart = curStart; bestEnd = curPeakIdx; }
  return { start: bestStart, end: bestEnd };
}

const ACTIONS = {
  "base-camp-to-everest": { op: "reverse" },
  "frith-from-boulders": { op: "trim-to-climb" },
  "mt-climie": { op: "trim-to-climb" },
};

async function main() {
  const dryRun = process.argv.includes("--dry-run");
  const files = await listHills();
  for (const f of files) {
    if (!f.name.endsWith(".yml")) continue;
    const slug = f.name.replace(/^\d+-/, "").replace(/\.yml$/, "");
    const action = ACTIONS[slug];
    if (!action) continue;

    const { content, sha } = await readFile(f.path);
    const hill = parseYaml(content);
    let triples;
    try { triples = JSON.parse(hill.track_points); } catch { triples = []; }
    if (!triples.length || triples[0].length < 3) {
      console.log(`  ${slug}: not in triples format, skipping`);
      continue;
    }

    const beforeStats = computeStats(triples);
    let newTriples;
    let msg;
    if (action.op === "reverse") {
      newTriples = [...triples].reverse();
      msg = `Reverse ${hill.name} (climb instead of descent)`;
    } else if (action.op === "trim-to-climb") {
      const { start, end } = findLongestClimb(triples);
      newTriples = triples.slice(start, end + 1);
      msg = `Trim ${hill.name} to longest climb [${start}..${end}]`;
    }

    const stats = computeStats(newTriples);
    const c = centroid(newTriples);
    const updated = {
      ...hill,
      track_points: JSON.stringify(newTriples),
      elevation_gain_m: stats.gain,
      distance_km: stats.dist,
      centroid_lat: c.lat,
      centroid_lng: c.lng,
    };
    const newYaml = toYaml(updated);

    console.log(`  ${slug}: ${action.op}`);
    console.log(`    before: ${triples.length} pts, ${beforeStats.gain}m / ${beforeStats.dist}km`);
    console.log(`    after:  ${newTriples.length} pts, ${stats.gain}m / ${stats.dist}km`);
    if (!dryRun) {
      await writeFile(f.path, newYaml, sha, msg);
      console.log(`    ✓ written`);
    }
  }
  console.log(dryRun ? "Dry run complete (no changes)" : "Done");
}

main().catch((e) => { console.error(e); process.exit(1); });
