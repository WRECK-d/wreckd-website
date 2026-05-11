#!/usr/bin/env node
// Backfill the `region` field on existing hill YAML files.
// Mapping is hard-coded; pass --dry-run to preview without writing.

import { execSync } from "node:child_process";

const REPO = "WRECK-d/form-submissions";
const DIR = "vertday/hills";

const TOKEN = execSync("gh auth token", { encoding: "utf8" }).trim();
if (!TOKEN) { console.error("No GitHub token from gh auth"); process.exit(1); }

const headers = {
  Authorization: `Bearer ${TOKEN}`,
  Accept: "application/vnd.github+json",
  "User-Agent": "vertday-region",
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

const REGION_MAP = {
  "base-camp-to-everest": "Nepal",
  "crawford-prison": "Wellington",
  "dawn-wall-te-whiti-gate-to-pole": "Hutt",
  "frith-from-boulders": "Wairarapa",
  "mount-victoria-winter-solstice-route": "Wellington",
  "mt-climie": "Hutt",
  "remutaka-trig": "Wairarapa",
  "tip-track": "Wellington",
  "waimapihi-turbine": "Wellington",
};

async function main() {
  const dryRun = process.argv.includes("--dry-run");
  const files = await listHills();
  for (const f of files) {
    if (!f.name.endsWith(".yml")) continue;
    const slug = f.name.replace(/^\d+-/, "").replace(/\.yml$/, "");
    const region = REGION_MAP[slug];
    if (!region) {
      console.log(`  ${slug}: no mapping, skipping`);
      continue;
    }

    const { content, sha } = await readFile(f.path);
    const hill = parseYaml(content);
    if (hill.region === region) {
      console.log(`  ${slug}: already ${region}, skipping`);
      continue;
    }

    const updated = { ...hill, region };
    const newYaml = toYaml(updated);
    console.log(`  ${slug}: ${hill.region || "(unset)"} → ${region}`);
    if (!dryRun) {
      await writeFile(f.path, newYaml, sha, `Set region for ${hill.name || slug} to ${region}`);
      console.log(`    ✓ written`);
    }
  }
  console.log(dryRun ? "Dry run complete (no changes)" : "Done");
}

main().catch((e) => { console.error(e); process.exit(1); });
