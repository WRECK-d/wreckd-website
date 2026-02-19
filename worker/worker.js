const ALLOWED_ORIGINS = [
  "https://wreckd.runs.nz",
  "http://wreckd.runs.nz",
];
const GITHUB_REPO = "WRECK-d/form-submissions";
const REQUIRED_FIELDS = ["name", "email", "membership"];

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

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "Method not allowed" }), {
        status: 405,
        headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
      });
    }

    if (origin && !isAllowedOrigin(origin)) {
      return new Response(JSON.stringify({ error: "Forbidden" }), {
        status: 403,
        headers: { "Content-Type": "application/json" },
      });
    }

    let data;
    const contentType = request.headers.get("Content-Type") || "";
    if (contentType.includes("application/json")) {
      data = await request.json();
    } else if (contentType.includes("application/x-www-form-urlencoded")) {
      const formData = await request.formData();
      data = Object.fromEntries(formData.entries());
    } else {
      return new Response(JSON.stringify({ error: "Unsupported content type" }), {
        status: 400,
        headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
      });
    }

    const missing = REQUIRED_FIELDS.filter((f) => !data[f] || !String(data[f]).trim());
    if (missing.length > 0) {
      return new Response(
        JSON.stringify({ error: `Missing required fields: ${missing.join(", ")}` }),
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

    const submission = {
      name: data.name.trim(),
      email: data.email.trim(),
      membership: data.membership.trim(),
      submitted_at: new Date().toISOString(),
    };

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
          message: `New submission from ${submission.name}`,
          content: btoa(yamlContent),
        }),
      }
    );

    if (!githubResponse.ok) {
      const err = await githubResponse.text();
      console.error("GitHub API error:", err);
      return new Response(JSON.stringify({ error: "Failed to save submission" }), {
        status: 500,
        headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { ...corsHeaders(origin), "Content-Type": "application/json" },
    });
  },
};
