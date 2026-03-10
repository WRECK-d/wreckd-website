const ALLOWED_ORIGINS = [
  "https://wreckd.runs.nz",
  "http://wreckd.runs.nz",
];
const GITHUB_REPO = "WRECK-d/form-submissions";
const REQUIRED_FIELDS = ["name", "email", "membership"];
const STRIPE_API_BASE = "https://api.stripe.com/v1";

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

function generateFilename() {
  const now = new Date();
  const ts = now.toISOString().replace(/[-:T]/g, "").slice(0, 14);
  const rand = Math.random().toString(36).slice(2, 8);
  return `submissions/${ts}-${rand}.yml`;
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
    throw new Error(
      `Stripe API error: ${data.error?.message || response.statusText}`
    );
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

  if (!timestamp || !expectedSignature) {
    return null;
  }

  // Reject events older than 5 minutes to prevent replay attacks
  const currentTime = Math.floor(Date.now() / 1000);
  if (Math.abs(currentTime - parseInt(timestamp)) > 300) {
    return null;
  }

  // Compute HMAC-SHA256 of "timestamp.payload"
  const signedPayload = `${timestamp}.${payload}`;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signatureBytes = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(signedPayload)
  );
  const computedSignature = Array.from(new Uint8Array(signatureBytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  // Constant-time comparison via double-HMAC
  if (computedSignature.length !== expectedSignature.length) {
    return null;
  }

  const compareKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode("webhook-compare"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig1 = new Uint8Array(
    await crypto.subtle.sign("HMAC", compareKey, encoder.encode(computedSignature))
  );
  const sig2 = new Uint8Array(
    await crypto.subtle.sign("HMAC", compareKey, encoder.encode(expectedSignature))
  );

  let equal = true;
  for (let i = 0; i < sig1.length; i++) {
    if (sig1[i] !== sig2[i]) equal = false;
  }

  if (!equal) {
    return null;
  }

  return JSON.parse(payload);
}

async function saveToGitHub(submission, env) {
  const filename = generateFilename();
  const yamlContent = toYaml(submission);

  const githubResponse = await fetch(
    `https://api.github.com/repos/${GITHUB_REPO}/contents/${filename}`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "wreckd-form-worker",
      },
      body: JSON.stringify({
        message: `New paid membership from ${submission.name}`,
        content: base64Encode(yamlContent),
      }),
    }
  );

  if (!githubResponse.ok) {
    const err = await githubResponse.text();
    console.error("GitHub API error:", err);
    throw new Error("Failed to save submission");
  }
}

async function handleCreateCheckoutSession(request, env) {
  const origin = request.headers.get("Origin") || "";

  let data;
  const contentType = request.headers.get("Content-Type") || "";
  if (contentType.includes("application/json")) {
    data = await request.json();
  } else if (contentType.includes("application/x-www-form-urlencoded")) {
    const formData = await request.formData();
    data = Object.fromEntries(formData.entries());
  } else {
    return new Response(
      JSON.stringify({ error: "Unsupported content type" }),
      {
        status: 400,
        headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
      }
    );
  }

  const missing = REQUIRED_FIELDS.filter(
    (f) => !data[f] || !String(data[f]).trim()
  );
  if (missing.length > 0) {
    return new Response(
      JSON.stringify({
        error: `Missing required fields: ${missing.join(", ")}`,
      }),
      {
        status: 400,
        headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
      }
    );
  }

  if (!["adult", "youth"].includes(data.membership)) {
    return new Response(
      JSON.stringify({ error: "Invalid membership type" }),
      {
        status: 400,
        headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
      }
    );
  }

  const priceId =
    data.membership === "adult"
      ? env.STRIPE_PRICE_ADULT
      : env.STRIPE_PRICE_YOUTH;

  try {
    const session = await stripeRequest(
      "/checkout/sessions",
      {
        mode: "payment",
        "line_items[0][price]": priceId,
        "line_items[0][quantity]": "1",
        customer_email: data.email.trim(),
        success_url: "https://wreckd.runs.nz/join/success/",
        cancel_url: "https://wreckd.runs.nz/join/cancelled/",
        "metadata[name]": data.name.trim(),
        "metadata[email]": data.email.trim(),
        "metadata[membership]": data.membership.trim(),
      },
      env.STRIPE_SECRET_KEY
    );

    return new Response(JSON.stringify({ url: session.url }), {
      status: 200,
      headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error("Stripe error:", err.message);
    return new Response(
      JSON.stringify({ error: "Failed to create payment session" }),
      {
        status: 500,
        headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
      }
    );
  }
}

async function handleWebhook(request, env) {
  const body = await request.text();
  const signature = request.headers.get("stripe-signature");

  if (!signature) {
    return new Response(JSON.stringify({ error: "Missing signature" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const event = await verifyStripeWebhook(
    body,
    signature,
    env.STRIPE_WEBHOOK_SECRET
  );
  if (!event) {
    return new Response(JSON.stringify({ error: "Invalid signature" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const metadata = session.metadata;

    const submission = {
      name: metadata.name,
      email: metadata.email,
      membership: metadata.membership,
      payment_status: session.payment_status,
      stripe_session_id: session.id,
      amount_total: String(session.amount_total),
      currency: session.currency,
      submitted_at: new Date().toISOString(),
    };

    try {
      await saveToGitHub(submission, env);
    } catch (err) {
      console.error("Failed to save to GitHub:", err.message);
      return new Response(JSON.stringify({ error: "Failed to save" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  return new Response(JSON.stringify({ received: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    // CORS preflight for any route
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // Stripe webhook — no CORS, no origin check; signature is the auth
    if (url.pathname === "/webhook" && request.method === "POST") {
      return handleWebhook(request, env);
    }

    // Create Checkout Session
    if (url.pathname === "/create-checkout-session" && request.method === "POST") {
      if (origin && !isAllowedOrigin(origin)) {
        return new Response(JSON.stringify({ error: "Forbidden" }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        });
      }
      return handleCreateCheckoutSession(request, env);
    }

    return new Response(JSON.stringify({ error: "Not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  },
};
