const ALLOWED_ORIGINS = [
  "https://wreckd.org.nz",
  "http://wreckd.org.nz",
];
const GITHUB_REPO = "WRECK-d/form-submissions";
const STRIPE_API_BASE = "https://api.stripe.com/v1";

const FIXTURES = {
  "mukamuka-munter": { label: "Mukamuka Munter", amount: 1000, currency: "nzd" },
  "aorangi-undulator": { label: "Aorangi Undulator", amount: 2000, currency: "nzd" },
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

async function stripeRequest(endpoint, params, stripeSecretKey) {
  const response = await fetch(`${STRIPE_API_BASE}${endpoint}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${stripeSecretKey}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(params).toString(),
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(`Stripe API error: ${data.error?.message || response.statusText}`);
  }
  return data;
}

async function verifyStripeWebhook(payload, signatureHeader, secret) {
  const parts = {};
  for (const part of signatureHeader.split(",")) {
    const [key, ...rest] = part.split("=");
    parts[key.trim()] = rest.join("=").trim();
  }
  const timestamp = parts["t"];
  const expectedSignature = parts["v1"];
  if (!timestamp || !expectedSignature) return null;

  const currentTime = Math.floor(Date.now() / 1000);
  if (Math.abs(currentTime - parseInt(timestamp)) > 300) return null;

  const signedPayload = `${timestamp}.${payload}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signatureBytes = await crypto.subtle.sign("HMAC", key, encoder.encode(signedPayload));
  const computedSignature = Array.from(new Uint8Array(signatureBytes))
    .map((b) => b.toString(16).padStart(2, "0")).join("");

  if (computedSignature.length !== expectedSignature.length) return null;

  const compareKey = await crypto.subtle.importKey(
    "raw", encoder.encode("webhook-compare"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig1 = new Uint8Array(await crypto.subtle.sign("HMAC", compareKey, encoder.encode(computedSignature)));
  const sig2 = new Uint8Array(await crypto.subtle.sign("HMAC", compareKey, encoder.encode(expectedSignature)));

  let equal = true;
  for (let i = 0; i < sig1.length; i++) {
    if (sig1[i] !== sig2[i]) equal = false;
  }
  if (!equal) return null;
  return JSON.parse(payload);
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
  const base = {
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
    plb: data.plb,
    submitted_at: new Date().toISOString(),
  };

  if (data.type === "volunteer") {
    const submission = {
      ...base,
      volunteer_roles: data.volunteer_roles || "",
      volunteer_declaration_name: data.volunteer_declaration_name || "",
    };
    try {
      await saveToGitHub(submission, env);
    } catch (err) {
      return new Response(JSON.stringify({ error: "Failed to save registration" }), {
        status: 500,
        headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ ref, type: "volunteer" }), {
      status: 200,
      headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
    });
  }

  // Racer — create Stripe checkout
  if (!data.race_declaration_name) {
    return new Response(JSON.stringify({ error: "Race declaration signature is required" }), {
      status: 400,
      headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
    });
  }

  const fixture = FIXTURES[data.fixture];
  const priceId = data.fixture === "mukamuka-munter" ? env.STRIPE_PRICE_MUKAMUKA : env.STRIPE_PRICE_UNDULATOR;

  try {
    const session = await stripeRequest(
      "/checkout/sessions",
      {
        mode: "payment",
        "line_items[0][price]": priceId,
        "line_items[0][quantity]": "1",
        customer_email: data.email.trim(),
        success_url: `https://wreckd.org.nz/fixtures/register/success/?ref=${ref}&fixture=${data.fixture}`,
        cancel_url: `https://wreckd.org.nz/fixtures/register/`,
        "metadata[ref]": ref,
        "metadata[type]": "race",
        "metadata[fixture]": data.fixture,
        "metadata[name]": data.name.trim(),
        "metadata[email]": data.email.trim(),
        "metadata[dob]": data.dob,
        "metadata[gender]": data.gender,
        "metadata[address]": data.address.trim(),
        "metadata[mobile]": data.mobile.trim(),
        "metadata[alt_contact]": data.alt_contact || "",
        "metadata[emergency_name]": data.emergency_name.trim(),
        "metadata[emergency_phone]": data.emergency_phone.trim(),
        "metadata[medical]": data.medical || "",
        "metadata[experience]": data.experience || "",
        "metadata[plb]": data.plb,
        "metadata[race_declaration_name]": data.race_declaration_name,
      },
      env.STRIPE_SECRET_KEY
    );
    return new Response(JSON.stringify({ url: session.url }), {
      status: 200,
      headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error("Stripe error:", err.message);
    return new Response(JSON.stringify({ error: "Failed to create payment session" }), {
      status: 500,
      headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
    });
  }
}

async function handleWebhook(request, env) {
  const body = await request.text();
  const signature = request.headers.get("stripe-signature");
  if (!signature) {
    return new Response(JSON.stringify({ error: "Missing signature" }), {
      status: 400, headers: { "Content-Type": "application/json" },
    });
  }

  const event = await verifyStripeWebhook(body, signature, env.STRIPE_WEBHOOK_SECRET_FIXTURES);
  if (!event) {
    return new Response(JSON.stringify({ error: "Invalid signature" }), {
      status: 400, headers: { "Content-Type": "application/json" },
    });
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const m = session.metadata;
    const submission = {
      ref: m.ref,
      type: "race",
      fixture: m.fixture,
      name: m.name,
      email: m.email,
      dob: m.dob,
      gender: m.gender,
      address: m.address,
      mobile: m.mobile,
      alt_contact: m.alt_contact,
      emergency_name: m.emergency_name,
      emergency_phone: m.emergency_phone,
      medical: m.medical,
      experience: m.experience,
      plb: m.plb,
      race_declaration_name: m.race_declaration_name,
      payment_status: session.payment_status,
      stripe_session_id: session.id,
      amount_total: String(session.amount_total),
      currency: session.currency,
      submitted_at: new Date().toISOString(),
    };
    try {
      await saveToGitHub(submission, env);
    } catch (err) {
      console.error("Failed to save:", err.message);
      return new Response(JSON.stringify({ error: "Failed to save" }), {
        status: 500, headers: { "Content-Type": "application/json" },
      });
    }
  }

  return new Response(JSON.stringify({ received: true }), {
    status: 200, headers: { "Content-Type": "application/json" },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (url.pathname === "/webhook" && request.method === "POST") {
      return handleWebhook(request, env);
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
