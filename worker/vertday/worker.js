const ALLOWED_ORIGINS = [
  "https://vertday.wreckd.org.nz",
  "http://localhost",
  "http://localhost:8080",
  "http://127.0.0.1:8080",
];
const GITHUB_REPO = "WRECK-d/form-submissions";

function isAllowedOrigin(origin) {
  if (!origin) return true;
  if (ALLOWED_ORIGINS.includes(origin)) return true;
  if (/^http:\/\/localhost(:\d+)?$/.test(origin)) return true;
  if (/^https:\/\/[a-z0-9-]+\.vertday\.pages\.dev$/.test(origin)) return true;
  return false;
}

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": isAllowedOrigin(origin) ? (origin || "*") : "",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function json(data, status = 200, origin = "", cacheSeconds = 0) {
  const headers = { ...corsHeaders(origin), "Content-Type": "application/json" };
  if (cacheSeconds > 0) headers["Cache-Control"] = `public, max-age=${cacheSeconds}`;
  return new Response(JSON.stringify(data), { status, headers });
}

function toYaml(obj) {
  return Object.entries(obj)
    .map(([key, value]) => `${key}: "${String(value).replace(/"/g, '\\"')}"`)
    .join("\n");
}

function parseYaml(text) {
  const obj = {};
  for (const line of text.split("\n")) {
    const m = line.match(/^(\w+):\s*"(.*)"$/);
    if (m) {
      obj[m[1]] = m[2].replace(/\\"/g, '"');
    }
  }
  return obj;
}

function base64Encode(str) {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);
  const binString = Array.from(bytes, (b) => String.fromCodePoint(b)).join("");
  return btoa(binString);
}

function base64Decode(b64) {
  const binString = atob(b64.replace(/\n/g, ""));
  const bytes = Uint8Array.from(binString, (c) => c.codePointAt(0));
  return new TextDecoder().decode(bytes);
}

function generateTimestamp() {
  return new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
}

function generateSlug(name, existingSlugs) {
  let base = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (!base) base = "athlete";
  let slug = base;
  let n = 2;
  while (existingSlugs.has(slug)) {
    slug = `${base}-${n}`;
    n++;
  }
  return slug;
}

async function githubGet(path, env) {
  const res = await fetch(
    `https://api.github.com/repos/${GITHUB_REPO}/contents/${path}`,
    {
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "vertday-worker",
      },
    }
  );
  if (!res.ok) {
    const err = await res.text();
    throw Object.assign(new Error(`GitHub GET ${path} failed: ${err}`), { status: res.status });
  }
  return res.json();
}

async function githubList(path, env) {
  try {
    const data = await githubGet(path, env);
    return Array.isArray(data) ? data : [];
  } catch (e) {
    if (e.status === 404) return [];
    throw e;
  }
}

async function githubPut(path, content, message, env) {
  const res = await fetch(
    `https://api.github.com/repos/${GITHUB_REPO}/contents/${path}`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "vertday-worker",
      },
      body: JSON.stringify({ message, content: base64Encode(content) }),
    }
  );
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`GitHub PUT ${path} failed: ${err}`);
  }
  return res.json();
}

async function getExistingSlugs(env) {
  const files = await githubList("vertday/signups", env);
  const slugs = new Set();
  for (const f of files) {
    // filename: TIMESTAMP-slug.yml — strip 15-char prefix (14 digits + hyphen)
    const slug = f.name.slice(15).replace(/\.yml$/, "");
    if (slug) slugs.add(slug);
  }
  return slugs;
}

async function findSignupFile(slug, env) {
  const files = await githubList("vertday/signups", env);
  return files.find((f) => f.name.endsWith(`-${slug}.yml`)) || null;
}

async function fetchYaml(file, env) {
  const data = await githubGet(file.path, env);
  return parseYaml(base64Decode(data.content));
}

// Reads vertday/leaderboard.json (precomputed by the form-submissions Action).
// Single subrequest; falls back to an empty stub when the file isn't there yet.
async function loadPrecomputed(env) {
  try {
    const data = await githubGet("vertday/leaderboard.json", env);
    return JSON.parse(base64Decode(data.content));
  } catch (e) {
    if (e.status === 404) {
      return { entries: [], by_category: {}, hills: [], per_hill: {}, per_athlete: {}, updated_at: null };
    }
    throw e;
  }
}

// ── Haversine distance in km ────────────────────────────────────────────────

function haversine(lat1, lng1, lat2, lng2) {
  const R = 6371;
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLng = ((lng2 - lng1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// ── GPX parsing ─────────────────────────────────────────────────────────────

function parseGpx(text) {
  const eles = [...text.matchAll(/<ele>([\d.]+)<\/ele>/g)].map((m) =>
    parseFloat(m[1])
  );
  const trkpts = [
    ...text.matchAll(/<trkpt\s+lat="([\d.-]+)"\s+lon="([\d.-]+)"/g),
  ].map((m) => [parseFloat(m[1]), parseFloat(m[2])]);

  // Also try lon before lat ordering
  const trkpts2 = trkpts.length
    ? trkpts
    : [...text.matchAll(/<trkpt\s+lon="([\d.-]+)"\s+lat="([\d.-]+)"/g)].map(
        (m) => [parseFloat(m[2]), parseFloat(m[1])]
      );

  const pts = trkpts2;

  // Build [lat, lng, ele] triples (pad missing elevations with 0)
  const triples = pts.map((p, i) => [p[0], p[1], eles[i] != null ? eles[i] : 0]);

  let elevation_gain_m = 0;
  for (let i = 1; i < triples.length; i++) {
    const diff = triples[i][2] - triples[i - 1][2];
    if (diff > 0) elevation_gain_m += diff;
  }

  let distance_km = 0;
  for (let i = 1; i < triples.length; i++) {
    distance_km += haversine(
      triples[i - 1][0], triples[i - 1][1],
      triples[i][0], triples[i][1]
    );
  }

  const centroid =
    triples.length > 0
      ? {
          lat: triples.reduce((s, p) => s + p[0], 0) / triples.length,
          lng: triples.reduce((s, p) => s + p[1], 0) / triples.length,
        }
      : null;

  // Downsample to max 500 triples
  let track_points = triples;
  if (triples.length > 500) {
    const step = Math.ceil(triples.length / 500);
    track_points = triples.filter((_, i) => i % step === 0);
  }

  // Auto-detect longest sustained climb (allow ≤2m drops as noise)
  const climbRange = findLongestClimb(track_points);

  return {
    elevation_gain_m: Math.round(elevation_gain_m),
    distance_km: Math.round(distance_km * 100) / 100,
    track_points,
    centroid,
    climb_start: climbRange.start,
    climb_end: climbRange.end,
  };
}

// Find longest run of net-positive elevation in downsampled triples.
// Allows small drops (<= 2m) as noise within a climb.
function findLongestClimb(triples) {
  if (triples.length < 2) return { start: 0, end: triples.length - 1 };
  const NOISE = 2;
  let bestStart = 0, bestEnd = triples.length - 1, bestGain = -Infinity;
  let curStart = 0, curMin = triples[0][2], curPeak = triples[0][2], curPeakIdx = 0;

  for (let i = 1; i < triples.length; i++) {
    const ele = triples[i][2];
    if (ele >= curPeak - NOISE) {
      // still climbing (within noise)
      if (ele > curPeak) { curPeak = ele; curPeakIdx = i; }
    } else {
      // descended past noise threshold — close out current climb
      const gain = curPeak - curMin;
      if (gain > bestGain) {
        bestGain = gain;
        bestStart = curStart;
        bestEnd = curPeakIdx;
      }
      // start new candidate climb from here
      curStart = i;
      curMin = ele;
      curPeak = ele;
      curPeakIdx = i;
    }
  }
  // close out final climb
  const gain = curPeak - curMin;
  if (gain > bestGain) {
    bestStart = curStart;
    bestEnd = curPeakIdx;
  }
  return { start: bestStart, end: bestEnd };
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async function handleSignUp(request, env, origin) {
  let data;
  try {
    data = await request.json();
  } catch {
    return json({ error: "Invalid JSON" }, 400, origin);
  }

  const name = String(data.name || "").trim();
  const email = String(data.email || "").trim();
  const category = String(data.category || "").trim();

  if (!name || !email || !category) {
    return json({ error: "Missing required fields: name, email, category" }, 400, origin);
  }

  const validCategories = ["Male", "Female", "Machine", "Dog", "Tiny Human"];
  if (!validCategories.includes(category)) {
    return json({ error: `Invalid category. Must be one of: ${validCategories.join(", ")}` }, 400, origin);
  }

  const existingSlugs = await getExistingSlugs(env);
  const slug = generateSlug(name, existingSlugs);
  const ts = generateTimestamp();

  const signup = {
    slug,
    name,
    email,
    strava: String(data.strava || "").trim(),
    location: String(data.location || "").trim(),
    club: String(data.club || "").trim(),
    category,
    registered_at: new Date().toISOString(),
  };

  await githubPut(
    `vertday/signups/${ts}-${slug}.yml`,
    toYaml(signup),
    `New Vert Day signup: ${name}`,
    env
  );

  return json(
    { slug, entry_url: `https://vertday.wreckd.org.nz/${slug}` },
    200,
    origin
  );
}

async function handleGetEntry(slug, env, origin) {
  const data = await loadPrecomputed(env);
  const entry = data.per_athlete && data.per_athlete[slug];
  if (!entry) return json({ error: "Not found" }, 404, origin);
  return json(entry, 200, origin, 30);
}

async function handlePostWorkout(slug, request, env, origin) {
  const signupFile = await findSignupFile(slug, env);
  if (!signupFile) return json({ error: "Athlete not found" }, 404, origin);

  let data;
  try {
    data = await request.json();
  } catch {
    return json({ error: "Invalid JSON" }, 400, origin);
  }

  const name = String(data.name || "").trim();
  const elevation_gain_m = parseFloat(data.elevation_gain_m);

  if (!name || isNaN(elevation_gain_m)) {
    return json({ error: "Missing required fields: name, elevation_gain_m" }, 400, origin);
  }

  const ts = generateTimestamp();
  const id = `${ts}-${Math.random().toString(36).slice(2, 8)}`;

  const workout = {
    id,
    slug,
    name,
    elevation_gain_m: Math.round(elevation_gain_m),
    distance_km: Math.round(parseFloat(data.distance_km || 0) * 100) / 100,
    location_lat: String(data.location_lat || ""),
    location_lng: String(data.location_lng || ""),
    location_name: String(data.location_name || "").trim(),
    gpx_track: String(data.gpx_track || ""),
    hill_id: String(data.hill_id || ""),
    laps: String(parseInt(data.laps) || 1),
    source: ["manual", "gpx"].includes(data.source) ? data.source : "manual",
    added_at: new Date().toISOString(),
  };

  await githubPut(
    `vertday/workouts/${slug}/${ts}.yml`,
    toYaml(workout),
    `Vert Day workout for ${slug}: ${name}`,
    env
  );

  return json(workout, 201, origin);
}

async function handleParseGpx(request, origin) {
  let gpxText;
  const contentType = request.headers.get("Content-Type") || "";

  if (contentType.includes("multipart/form-data")) {
    const formData = await request.formData();
    const file = formData.get("gpx");
    if (!file) return json({ error: "No GPX file provided" }, 400, origin);
    gpxText = typeof file === "string" ? file : await file.text();
  } else {
    gpxText = await request.text();
  }

  if (!gpxText || !gpxText.includes("<gpx")) {
    return json({ error: "Invalid GPX file" }, 400, origin);
  }

  const result = parseGpx(gpxText);
  return json(result, 200, origin);
}

async function handleLeaderboard(env, origin) {
  const data = await loadPrecomputed(env);
  return json(
    { entries: data.entries, by_category: data.by_category, updated_at: data.updated_at },
    200,
    origin,
    30
  );
}

async function handleGetHill(hillSlug, env, origin) {
  const data = await loadPrecomputed(env);
  const entry = data.per_hill && data.per_hill[hillSlug];
  if (!entry) return json({ error: "Hill not found" }, 404, origin);
  return json(entry, 200, origin, 30);
}

async function handleGetHills(env, origin) {
  const data = await loadPrecomputed(env);
  const hills = (data.hills || []).slice().sort((a, b) => a.name.localeCompare(b.name));
  return json(hills, 200, origin, 30);
}

async function handlePostHill(request, env, origin) {
  let data;
  try {
    data = await request.json();
  } catch {
    return json({ error: "Invalid JSON" }, 400, origin);
  }

  const name = String(data.name || "").trim();
  if (!name) return json({ error: "Missing required field: name" }, 400, origin);
  if (!data.track_points || !data.elevation_gain_m) {
    return json({ error: "Missing GPX data — parse a GPX file first" }, 400, origin);
  }

  const ALLOWED_REGIONS = [
    "Wellington", "Porirua", "Hutt", "Kapiti", "Eastbourne", "Wairarapa",
    "Christchurch", "North Island (other)", "South Island (other)",
    "Nepal", "Anywhere Else",
  ];
  const requestedRegion = String(data.region || "").trim();
  const region = ALLOWED_REGIONS.includes(requestedRegion) ? requestedRegion : "Anywhere Else";

  const ts = generateTimestamp();
  const id = `${ts}-${Math.random().toString(36).slice(2, 8)}`;
  const slug = generateSlug(name, new Set());

  const hill = {
    id,
    slug,
    name,
    region,
    elevation_gain_m: Math.round(parseFloat(data.elevation_gain_m)),
    distance_km: Math.round(parseFloat(data.distance_km || 0) * 100) / 100,
    track_points: String(data.track_points),
    centroid_lat: String(data.centroid_lat || ""),
    centroid_lng: String(data.centroid_lng || ""),
    added_by: String(data.added_by || "").trim(),
    added_at: new Date().toISOString(),
  };

  await githubPut(
    `vertday/hills/${ts}-${slug}.yml`,
    toYaml(hill),
    `Add hill: ${name}`,
    env
  );

  return json(hill, 201, origin);
}

async function handleDeleteWorkout(slug, workoutId, env, origin) {
  const files = await githubList(`vertday/workouts/${slug}`, env);
  const tsPrefix = workoutId.slice(0, 14);
  const file = files.find((f) => f.name === `${tsPrefix}.yml`);
  if (!file) return json({ error: "Workout not found" }, 404, origin);

  const res = await fetch(
    `https://api.github.com/repos/${GITHUB_REPO}/contents/${file.path}`,
    {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "vertday-worker",
      },
      body: JSON.stringify({
        message: `Delete workout ${workoutId} for ${slug}`,
        sha: file.sha,
      }),
    }
  );

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`GitHub DELETE failed: ${err}`);
  }

  return json({ deleted: true }, 200, origin);
}

// ── Router ────────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname;
    const origin = request.headers.get("Origin") || "";

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (origin && !isAllowedOrigin(origin)) {
      return json({ error: "Forbidden" }, 403, "");
    }

    try {
      if (path === "/sign-up" && method === "POST") {
        return handleSignUp(request, env, origin);
      }

      if (path === "/parse-gpx" && method === "POST") {
        return handleParseGpx(request, origin);
      }

      if (path === "/leaderboard" && method === "GET") {
        return handleLeaderboard(env, origin);
      }

      const entryMatch = path.match(/^\/entries\/([^/]+)$/);
      if (entryMatch && method === "GET") {
        return handleGetEntry(entryMatch[1], env, origin);
      }

      const workoutMatch = path.match(/^\/entries\/([^/]+)\/workouts$/);
      if (workoutMatch && method === "POST") {
        return handlePostWorkout(workoutMatch[1], request, env, origin);
      }

      const deleteMatch = path.match(/^\/entries\/([^/]+)\/workouts\/([^/]+)$/);
      if (deleteMatch && method === "DELETE") {
        return handleDeleteWorkout(deleteMatch[1], deleteMatch[2], env, origin);
      }

      if (path === "/hills" && method === "GET") {
        return handleGetHills(env, origin);
      }

      const hillSlugMatch = path.match(/^\/hills\/([^/]+)$/);
      if (hillSlugMatch && method === "GET") {
        return handleGetHill(hillSlugMatch[1], env, origin);
      }

      if (path === "/hills" && method === "POST") {
        return handlePostHill(request, env, origin);
      }

      return json({ error: "Not found" }, 404, origin);
    } catch (err) {
      console.error(err);
      return json({ error: "Internal server error" }, 500, origin);
    }
  },
};
