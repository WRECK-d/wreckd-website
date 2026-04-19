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
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function toYaml(obj) {
  return Object.entries(obj)
    .map(([key, value]) => `${key}: "${String(value).replace(/"/g, '\\"')}"`)
    .join("\n");
}

function generateRef() {
  const now = new Date();
  const date = now.toISOString().slice(0, 10).replace(/-/g, "");
  const rand = Math.random().toString(36).slice(2, 8);
  return `FIX-${date}-${rand}`;
}

function generateFilename(ref) {
  const now = new Date();
  const ts = now.toISOString().replace(/[-:T]/g, "").slice(0, 14);
  return `fixtures/${ts}-${ref.slice(-6)}.yml`;
}

function base64Encode(str) {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);
  const binString = Array.from(bytes, (b) => String.fromCodePoint(b)).join("");
  return btoa(binString);
}

async function isMember(email, env) {
  const response = await fetch(
    `https://api.github.com/repos/${GITHUB_REPO}/contents/submissions.csv`,
    {
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "wreckd-fixtures-worker",
      },
    }
  );
  if (!response.ok) return false;
  const { content } = await response.json();
  const csv = atob(content.replace(/\n/g, ""));
  const normalised = email.trim().toLowerCase();
  for (const line of csv.split("\n").slice(1)) {
    const cols = line.split(",").map((c) => c.replace(/^"|"$/g, "").trim().toLowerCase());
    // cols: name, email, membership, payment_status, amount_total, currency, submitted_at
    if (cols[1] === normalised && cols[3] === "paid") return true;
  }
  return false;
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

  const ref = generateRef();
  const fixture = FIXTURES[data.fixture];

  const submission = {
    ref,
    type: data.type,
    fixture: data.fixture,
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

    return new Response(JSON.stringify({ error: "Not found" }), {
      status: 404, headers: { "Content-Type": "application/json" },
    });
  },
};
