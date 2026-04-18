---
title: "Registration Submitted"
description: "Fixture registration received — WREC'kd"
---

<div id="success-content">
  <p>Loading your registration details...</p>
</div>

<script>
(function() {
  const params = new URLSearchParams(window.location.search);
  const ref = params.get("ref") || "";
  const fixture = params.get("fixture") || "";
  const fees = { "mukamuka-munter": 10, "aorangi-undulator": 20 };
  const amount = fees[fixture] || "—";

  const el = document.getElementById("success-content");
  el.innerHTML = `
    <p>Your entry will be confirmed once payment is received.</p>
    <table style="font-family:monospace; border-collapse:collapse; margin:24px 0; font-size:0.9rem; line-height:2;">
      <tr><td style="padding-right:24px; font-weight:bold;">Reference</td><td>${ref}</td></tr>
      <tr><td style="padding-right:24px; font-weight:bold;">Amount</td><td>$${amount} NZD</td></tr>
      <tr><td style="padding-right:24px; font-weight:bold;">Bank</td><td>BNZ</td></tr>
      <tr><td style="padding-right:24px; font-weight:bold;">Account name</td><td>WRECkd</td></tr>
      <tr><td style="padding-right:24px; font-weight:bold;">Account number</td><td>02-0688-0269592-000</td></tr>
      <tr><td style="padding-right:24px; font-weight:bold;">Reference</td><td>${ref}</td></tr>
    </table>
    <p>Questions? Email <a href="mailto:office@runs.nz">office@runs.nz</a>.</p>
  `;
})();
</script>
