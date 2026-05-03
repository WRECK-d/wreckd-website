const ALLOWED_ORIGINS = [
  "https://wreckd.org.nz",
  "http://wreckd.org.nz",
];
const GITHUB_REPO = "WRECK-d/form-submissions";

const FIXTURES = {
  "mukamuka-munter": { label: "Mukamuka Munter", fee: 10 },
  "aorangi-undulator": { label: "Aorangi Undulator", fee: 20 },
};

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

function toYaml(obj) {
  return Object.entries(obj)
    .map(([key, value]) => `${key}: "${String(value).replace(/"/g, '\\"')}"`)
    .join("\n");
}

const FIXTURE_PREFIX = {
  "mukamuka-munter": "MM",
  "aorangi-undulator": "AU",
};

function baseRef(fixture, lastName) {
  const prefix = FIXTURE_PREFIX[fixture] || "FX";
  const suffix = lastName.replace(/[^a-zA-Z]/g, "").slice(0, 4).toUpperCase();
  return `${prefix}-${suffix}`;
}

async function generateRef(fixture, lastName, env) {
  const base = baseRef(fixture, lastName);
  const reg = await fetchRegistry(env);
  const usedRefs = new Set(reg.refs || []);
  if (!usedRefs.has(base)) return base;
  for (let i = 2; i <= 99; i++) {
    const candidate = `${base}-${String(i).padStart(2, "0")}`;
    if (!usedRefs.has(candidate)) return candidate;
  }
  return base; // fallback, shouldn't happen
}

function generateFilename(ref) {
  const now = new Date();
  const ts = now.toISOString().replace(/[-:T]/g, "").slice(0, 14);
  const slug = ref.replace(/[^a-zA-Z0-9]/g, "-").toLowerCase();
  return `fixtures/${ts}-${slug}.yml`;
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
  const filename = generateFilename(submission.ref);
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
        message: `New fixture registration: ${submission.name} — ${submission.fixture}`,
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

  if (!FIXTURES[data.fixture]) {
    return new Response(JSON.stringify({ error: "Invalid fixture" }), {
      status: 400,
      headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
    });
  }

  if (!["race", "volunteer"].includes(data.type)) {
    return new Response(JSON.stringify({ error: "Invalid registration type" }), {
      status: 400,
      headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
    });
  }

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
  const ref = await generateRef(data.fixture, lastName, env);
  const fixture = FIXTURES[data.fixture];

  // Normalize team name; if a team with the same canonical name already exists,
  // use the existing canonical spelling so registrants are grouped consistently.
  let team = "";
  if (data.type === "race") {
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
    fixture: data.fixture,
    team,
    name: data.name.trim(),
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
