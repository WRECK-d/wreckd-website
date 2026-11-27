const ALLOWED_ORIGINS = [
  "https://wreckd.org.nz",
  "http://wreckd.org.nz",
];
const GITHUB_REPO = "WRECK-d/form-submissions";

// ---------------------------------------------------------------------------
// EVENT SETTINGS
// Events are NOT set in this file. Each event is a small text file in the
// public website repo: data/fixtures/<event-slug>.yaml
// The worker reads those files live (cached ~60 seconds), so adding, editing,
// opening or closing an event never needs a redeploy. Files whose names start
// with "_" (e.g. _template.yaml) are ignored.
// ---------------------------------------------------------------------------
const SITE_REPO = "WRECK-d/wreckd-website";
const SITE_BRANCH = "main";
const EVENTS_DIR = "data/fixtures";
const TIME_ZONE = "Pacific/Auckland";
const CACHE_SECONDS = 60;

const REQUIRED_FIELDS = [
  "type", "fixture", "name", "email", "dob", "gender",
  "address", "mobile", "emergency_name", "emergency_phone", "plb",
];

function isAllowedOrigin(origin) {
  return ALLOWED_ORIGINS.includes(origin);
}

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": isAllowedOrigin(origin) ? origin : "",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function normalizeTeamName(name) {
  if (!name) return "";
  return String(name)
    .replace(/[^A-Za-z0-9\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .split(" ")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join(" ");
}

async function fetchRegistry(env) {
  const response = await fetch(
    `https://api.github.com/repos/${GITHUB_REPO}/contents/fixtures-registry.json`,
    {
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "wreckd-fixtures-worker",
      },
    }
  );
  if (!response.ok) return { refs: [], teams: [] };
  const { content } = await response.json();
  return JSON.parse(atob(content.replace(/\n/g, "")));
}

async function fetchExistingTeams(env) {
  const reg = await fetchRegistry(env);
  return Array.from(new Set(reg.teams || [])).sort();
}

// Public participant list, built by build-fixtures-registry.py in the private
// repo. Already deduped, withdrawn-excluded, opt-outs dropped, and limited to
// public-safe fields (name, team, type). We serve it verbatim — no private
// data is present in the file to begin with.
async function fetchParticipants(env) {
  const response = await fetch(
    `https://api.github.com/repos/${GITHUB_REPO}/contents/fixtures-participants.json`,
    {
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "wreckd-fixtures-worker",
      },
    }
  );
  if (!response.ok) return { fixtures: {} };
  const { content } = await response.json();
  return JSON.parse(atob(content.replace(/\n/g, "")));
}

function toYaml(obj) {
  return Object.entries(obj)
    .map(([key, value]) => `${key}: "${String(value).replace(/"/g, '\\"')}"`)
    .join("\n");
}

function baseRef(event, lastName) {
  const prefix = event.prefix || "FX";
  const suffix = lastName.replace(/[^a-zA-Z]/g, "").slice(0, 4).toUpperCase();
  return `${prefix}-${suffix}`;
}

async function generateRef(event, lastName, env) {
  const base = baseRef(event, lastName);
  const reg = await fetchRegistry(env);
  const usedRefs = new Set(reg.refs || []);
  if (!usedRefs.has(base)) return base;
  for (let i = 2; i <= 99; i++) {
    const candidate = `${base}-${String(i).padStart(2, "0")}`;
    if (!usedRefs.has(candidate)) return candidate;
  }
  return base; // fallback, shouldn't happen
}

function generateFilename(ref, type) {
  const now = new Date();
  const ts = now.toISOString().replace(/[-:T]/g, "").slice(0, 14);
  const slug = ref.replace(/[^a-zA-Z0-9]/g, "-").toLowerCase();
  // The "-race" / "-volunteer" ending lets the worker count race entries
  // against an event's spot limit without opening every file.
  return `fixtures/${ts}-${slug}-${type}.yml`;
}

function base64Encode(str) {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);
  const binString = Array.from(bytes, (b) => String.fromCodePoint(b)).join("");
  return btoa(binString);
}

async function fetchListEmails(listName, env, seen = new Set()) {
  if (seen.has(listName)) return new Set();
  seen.add(listName);
  const response = await fetch(
    `https://api.github.com/repos/${GITHUB_REPO}/contents/email/lists/${listName}.yml`,
    {
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "wreckd-fixtures-worker",
      },
    }
  );
  if (!response.ok) return new Set();
  const { content } = await response.json();
  const yaml = atob(content.replace(/\n/g, ""));
  const emails = new Set();
  for (const line of yaml.split("\n")) {
    const includeMatch = line.match(/^\s*-\s+include:\s+(\S+)/);
    if (includeMatch) {
      const nested = await fetchListEmails(includeMatch[1], env, seen);
      for (const e of nested) emails.add(e);
      continue;
    }
    const emailMatch = line.match(/^\s+email:\s+"?([^"]+)"?\s*$/);
    if (emailMatch) emails.add(emailMatch[1].trim().toLowerCase());
  }
  return emails;
}

async function isMember(email, env) {
  const emails = await fetchListEmails("all-members", env);
  return emails.has(email.trim().toLowerCase());
}

async function saveToGitHub(submission, env) {
  const filename = generateFilename(submission.ref, submission.type);
  const yamlContent = toYaml(submission);
  const response = await fetch(
    `https://api.github.com/repos/${GITHUB_REPO}/contents/${filename}`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "wreckd-fixtures-worker",
      },
      body: JSON.stringify({
        message: `New fixture registration: ${submission.ref} — ${submission.fixture}`,
        content: base64Encode(yamlContent),
      }),
    }
  );
  if (!response.ok) {
    const err = await response.text();
    console.error("GitHub API error:", err);
    throw new Error("Failed to save submission");
  }
}


// ---------------------------------------------------------------------------
// Event settings: loading, parsing, open/closed status, spot counting
// ---------------------------------------------------------------------------

function githubHeaders(env) {
  return {
    Authorization: `Bearer ${env.GITHUB_TOKEN}`,
    Accept: "application/vnd.github+json",
    "User-Agent": "wreckd-fixtures-worker",
  };
}

// Reads the simple "key: value" format used by the event files. One setting
// per line; "#" starts a comment; quotes around values are optional.
function parseEventFile(text) {
  const out = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/^﻿/, "");
    if (!line.trim() || line.trim().startsWith("#")) continue;
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$/);
    if (!m) continue;
    let value = m[2].trim();
    if (/^["']/.test(value)) {
      const q = value[0];
      const end = value.indexOf(q, 1);
      value = end > 0 ? value.slice(1, end) : value.slice(1);
    } else {
      value = value.replace(/\s+#.*$/, "").trim();
    }
    out[m[1].toLowerCase()] = value;
  }
  return out;
}

function yesNo(value, fallback) {
  if (value === undefined || value === "") return fallback;
  return /^(yes|true|y|1|on)$/i.test(String(value).trim());
}

function toNumberOrNull(value) {
  if (value === undefined || value === null || String(value).trim() === "") return null;
  const n = Number(String(value).replace(/[$,\s]/g, ""));
  return Number.isFinite(n) ? n : null;
}

// Offset (ms) between UTC and NZ time at a given instant (handles daylight saving).
function tzOffsetMs(timestamp) {
  const parts = new Intl.DateTimeFormat("en-NZ", {
    timeZone: TIME_ZONE, hourCycle: "h23",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  }).formatToParts(new Date(timestamp));
  const get = (t) => Number(parts.find((p) => p.type === t).value);
  const asUtc = Date.UTC(get("year"), get("month") - 1, get("day"), get("hour"), get("minute"), get("second"));
  return asUtc - Math.floor(timestamp / 1000) * 1000;
}

// "2027-02-10" or "2027-02-10 18:00" (NZ time) -> timestamp.
// A date with no time means start of day for "opens", end of day for "closes".
function parseNzTime(value, endOfDay) {
  if (!value) return null;
  const m = String(value).trim().match(/^(\d{4})-(\d{1,2})-(\d{1,2})(?:[ T](\d{1,2}):(\d{2}))?$/);
  if (!m) return NaN;
  const [, y, mo, d, h, mi] = m;
  const hour = h !== undefined ? Number(h) : (endOfDay ? 23 : 0);
  const minute = mi !== undefined ? Number(mi) : (endOfDay ? 59 : 0);
  const wallClock = Date.UTC(Number(y), Number(mo) - 1, Number(d), hour, minute, endOfDay && h === undefined ? 59 : 0);
  let ts = wallClock - tzOffsetMs(wallClock);
  const second = wallClock - tzOffsetMs(ts);
  if (second !== ts) ts = second;
  return ts;
}

function normaliseEvent(slug, raw) {
  const problems = [];
  const opens = parseNzTime(raw.opens, false);
  const closes = parseNzTime(raw.closes, true);
  if (Number.isNaN(opens)) problems.push("opens is not a valid date (use YYYY-MM-DD or YYYY-MM-DD HH:MM)");
  if (Number.isNaN(closes)) problems.push("closes is not a valid date (use YYYY-MM-DD or YYYY-MM-DD HH:MM)");
  if (!raw.closes) problems.push("closes is missing");
  const prefix = String(raw.prefix || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (!prefix) problems.push("prefix is missing");
  return {
    slug,
    name: raw.name || slug,
    prefix,
    date: raw.date || "",
    location: raw.location || "",
    info_link: raw.info_link || "",
    fee: toNumberOrNull(raw.fee) || 0,
    race_spots: toNumberOrNull(raw.race_spots),
    volunteers: yesNo(raw.volunteers, true),
    teams: yesNo(raw.teams, true),
    open: yesNo(raw.open, true),
    opens: Number.isNaN(opens) ? null : opens,
    closes: Number.isNaN(closes) ? null : closes,
    problems,
  };
}

async function cached(key, loader) {
  const cache = typeof caches !== "undefined" ? caches.default : null;
  const cacheKey = new Request(`https://wreckd-fixtures-cache.internal/${key}`);
  if (cache) {
    const hit = await cache.match(cacheKey);
    if (hit) return hit.json();
  }
  const value = await loader();
  if (cache) {
    await cache.put(cacheKey, new Response(JSON.stringify(value), {
      headers: { "Cache-Control": `public, max-age=${CACHE_SECONDS}` },
    }));
  }
  return value;
}

async function loadEventsFresh(env) {
  const listing = await fetch(
    `https://api.github.com/repos/${SITE_REPO}/contents/${EVENTS_DIR}?ref=${SITE_BRANCH}`,
    { headers: githubHeaders(env) }
  );
  if (!listing.ok) {
    console.error("Could not list event files:", listing.status, await listing.text());
    return {};
  }
  const files = (await listing.json()).filter(
    (f) => f.type === "file" && /\.ya?ml$/i.test(f.name) && !f.name.startsWith("_")
  );
  const events = {};
  await Promise.all(files.map(async (f) => {
    const res = await fetch(f.download_url, { headers: { "User-Agent": "wreckd-fixtures-worker" } });
    if (!res.ok) return;
    const slug = f.name.replace(/\.ya?ml$/i, "").toLowerCase();
    events[slug] = normaliseEvent(slug, parseEventFile(await res.text()));
  }));
  return events;
}

async function loadEvents(env) {
  return cached("events-v1", () => loadEventsFresh(env));
}

// Counts race entries already saved for an event, by file name.
async function countRaceEntriesFresh(event, env) {
  const res = await fetch(
    `https://api.github.com/repos/${GITHUB_REPO}/git/trees/HEAD:fixtures`,
    { headers: githubHeaders(env) }
  );
  if (!res.ok) return 0;
  const { tree } = await res.json();
  const marker = `-${event.prefix.toLowerCase()}-`;
  return (tree || []).filter(
    (f) => f.type === "blob" && f.path.includes(marker) && f.path.endsWith("-race.yml")
  ).length;
}

// status: "open" | "not_yet_open" | "closed" | "full" | "misconfigured"
async function eventStatus(event, env, { fresh = false } = {}) {
  const now = Date.now();
  if (event.problems.length) return { status: "misconfigured", spots_left: null };
  if (!event.open) return { status: "closed", spots_left: null };
  if (event.opens && now < event.opens) return { status: "not_yet_open", spots_left: null };
  if (event.closes && now > event.closes) return { status: "closed", spots_left: null };
  if (event.race_spots === null) return { status: "open", spots_left: null };
  const used = fresh
    ? await countRaceEntriesFresh(event, env)
    : await cached(`count-${event.slug}`, () => countRaceEntriesFresh(event, env));
  const left = Math.max(0, event.race_spots - used);
  return { status: left > 0 ? "open" : "full", spots_left: left };
}

function formatNz(ts) {
  if (!ts) return "";
  return new Intl.DateTimeFormat("en-NZ", {
    timeZone: TIME_ZONE, weekday: "short", day: "numeric", month: "short",
    year: "numeric", hour: "numeric", minute: "2-digit",
  }).format(new Date(ts));
}

async function publicEventList(env) {
  const events = await loadEvents(env);
  const list = [];
  for (const event of Object.values(events)) {
    const { status, spots_left } = await eventStatus(event, env);
    const item = {
      slug: event.slug,
      name: event.name,
      date: event.date,
      location: event.location,
      info_link: event.info_link,
      fee: event.fee,
      race_spots: event.race_spots,
      spots_left,
      volunteers: event.volunteers,
      teams: event.teams,
      status,
      opens: event.opens ? new Date(event.opens).toISOString() : null,
      closes: event.closes ? new Date(event.closes).toISOString() : null,
      opens_text: formatNz(event.opens),
      closes_text: formatNz(event.closes),
    };
    if (status === "misconfigured") item.problems = event.problems;
    list.push(item);
  }
  list.sort((a, b) => (a.closes || "").localeCompare(b.closes || ""));
  return list;
}

async function handleRegister(request, env) {
  const origin = request.headers.get("Origin") || "";

  let data;
  const contentType = request.headers.get("Content-Type") || "";
  if (contentType.includes("application/json")) {
    data = await request.json();
  } else {
    return new Response(JSON.stringify({ error: "Unsupported content type" }), {
      status: 400,
      headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
    });
  }

  const missing = REQUIRED_FIELDS.filter((f) => !data[f] || !String(data[f]).trim());
  if (missing.length > 0) {
    return new Response(JSON.stringify({ error: `Missing required fields: ${missing.join(", ")}` }), {
      status: 400,
      headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
    });
  }

  const reject = (msg) => new Response(JSON.stringify({ error: msg }), {
    status: 400,
    headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
  });

  const events = await loadEvents(env);
  const fixture = events[String(data.fixture).toLowerCase()];
  if (!fixture) return reject("Invalid fixture");

  if (!["race", "volunteer"].includes(data.type)) {
    return reject("Invalid registration type");
  }
  if (data.type === "volunteer" && !fixture.volunteers) {
    return reject(`${fixture.name} is not taking volunteer sign-ups.`);
  }

  // Check open/close dates and, for racers, spots left (fresh count, no cache).
  const { status } = await eventStatus(fixture, env, { fresh: data.type === "race" });
  if (status === "not_yet_open") return reject(`Registration for ${fixture.name} opens ${formatNz(fixture.opens)}.`);
  if (status === "closed" || status === "misconfigured") return reject(`Registration for ${fixture.name} is closed.`);
  if (status === "full" && data.type === "race") return reject(`Sorry, ${fixture.name} is full.`);

  const memberCheck = await isMember(data.email, env);
  if (!memberCheck) {
    return new Response(JSON.stringify({
      error: "You must be a paid WREC\u2019kd member to register for a fixture. Please join at wreckd.org.nz/join before registering.",
    }), {
      status: 400,
      headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
    });
  }

  const nameParts = data.name.trim().split(/\s+/);
  const lastName = nameParts[nameParts.length - 1];
  const ref = await generateRef(fixture, lastName, env);

  // Normalize team name; if a team with the same canonical name already exists,
  // use the existing canonical spelling so registrants are grouped consistently.
  let team = "";
  if (data.type === "race" && fixture.teams) {
    const normalized = normalizeTeamName(data.team);
    if (normalized) {
      const existingTeams = await fetchExistingTeams(env);
      const match = existingTeams.find((t) => t.toLowerCase() === normalized.toLowerCase());
      team = match || normalized;
    }
  }

  const submission = {
    ref,
    type: data.type,
    fixture: fixture.slug,
    fixture_title: fixture.name,
    team,
    name: data.name.trim(),
    publish_name: data.publish_name === "no" ? "no" : "yes",
    email: data.email.trim(),
    dob: data.dob,
    gender: data.gender,
    address: data.address.trim(),
    mobile: data.mobile.trim(),
    alt_contact: data.alt_contact || "",
    emergency_name: data.emergency_name.trim(),
    emergency_phone: data.emergency_phone.trim(),
    medical: data.medical || "",
    experience: data.experience || "",
    experience_detail: data.experience_detail || "",
    plb: data.plb,
    ...(data.type === "volunteer" ? {
      volunteer_roles: data.volunteer_roles || "",
      volunteer_declaration_name: data.volunteer_declaration_name || "",
    } : {
      race_declaration_name: data.race_declaration_name || "",
      fee: String(fixture.fee),
      payment_status: "pending",
    }),
    submitted_at: new Date().toISOString(),
  };

  try {
    await saveToGitHub(submission, env);
  } catch (err) {
    return new Response(JSON.stringify({ error: "Failed to save registration" }), {
      status: 500,
      headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
    });
  }

  return new Response(JSON.stringify({
    ref,
    type: data.type,
    fee: data.type === "race" ? fixture.fee : 0,
  }), {
    status: 200,
    headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (url.pathname === "/register" && request.method === "POST") {
      if (origin && !isAllowedOrigin(origin)) {
        return new Response(JSON.stringify({ error: "Forbidden" }), {
          status: 403, headers: { "Content-Type": "application/json" },
        });
      }
      return handleRegister(request, env);
    }

    if (url.pathname === "/fixtures" && request.method === "GET") {
      if (origin && !isAllowedOrigin(origin)) {
        return new Response(JSON.stringify({ error: "Forbidden" }), {
          status: 403, headers: { "Content-Type": "application/json" },
        });
      }
      const fixtures = await publicEventList(env);
      return new Response(JSON.stringify({ fixtures }), {
        status: 200,
        headers: {
          ...corsHeaders(origin),
          "Content-Type": "application/json",
          "Cache-Control": "public, max-age=30",
        },
      });
    }

    if (url.pathname === "/teams" && request.method === "GET") {
      if (origin && !isAllowedOrigin(origin)) {
        return new Response(JSON.stringify({ error: "Forbidden" }), {
          status: 403, headers: { "Content-Type": "application/json" },
        });
      }
      const teams = await fetchExistingTeams(env);
      return new Response(JSON.stringify({ teams }), {
        status: 200,
        headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
      });
    }

    if (url.pathname === "/participants" && request.method === "GET") {
      if (origin && !isAllowedOrigin(origin)) {
        return new Response(JSON.stringify({ error: "Forbidden" }), {
          status: 403, headers: { "Content-Type": "application/json" },
        });
      }
      const data = await fetchParticipants(env);
      const fixture = url.searchParams.get("fixture") || "";
      const body = fixture
        ? { fixture, participants: data.fixtures[fixture] || [] }
        : { fixtures: data.fixtures };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: {
          ...corsHeaders(origin),
          "Content-Type": "application/json",
          "Cache-Control": "public, max-age=60",
        },
      });
    }

    if (url.pathname === "/check-member" && request.method === "GET") {
      if (origin && !isAllowedOrigin(origin)) {
        return new Response(JSON.stringify({ error: "Forbidden" }), {
          status: 403, headers: { "Content-Type": "application/json" },
        });
      }
      const email = url.searchParams.get("email") || "";
      const member = email ? await isMember(email, env) : false;
      return new Response(JSON.stringify({ member }), {
        status: 200,
        headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "Not found" }), {
      status: 404, headers: { "Content-Type": "application/json" },
    });
  },
};
