/*
 * Reusable fixture participant list.
 *
 * Renders the published entrants for a fixture into a container element.
 * Data comes live from the fixtures Worker, which reads the (private)
 * form-submissions repo server-side and returns only public-safe fields
 * (name, team, type). Withdrawals and name opt-outs are already applied
 * upstream, so this script just displays what it receives.
 *
 * Usage: add a container with data-fixture set to the fixture slug, then
 * load this script:
 *
 *   <div class="wreckd-participants" data-fixture="mukamuka-munter"></div>
 *   <script src="/fixtures/participant-list.js" defer></script>
 *
 * Every matching container on the page is populated independently.
 */
(function () {
  var WORKER_URL = "https://wreckd-fixtures-worker.wreckd.workers.dev";

  var FIXTURE_TITLES = {
    "mukamuka-munter": "Mukamuka Munter",
    "aorangi-undulator": "Aorangi Undulator",
  };

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function injectStyles() {
    if (document.getElementById("wreckd-participants-styles")) return;
    var style = document.createElement("style");
    style.id = "wreckd-participants-styles";
    style.textContent = [
      ".wreckd-participants { font-family: 'Courier New', Courier, monospace; margin: 1.5rem 0; }",
      ".wreckd-participants .wp-status { color: #555; font-style: italic; }",
      ".wreckd-participants .wp-count { margin: 0 0 0.75rem; font-weight: bold; }",
      ".wreckd-participants table { border-collapse: collapse; width: 100%; max-width: 640px; }",
      ".wreckd-participants th, .wreckd-participants td { text-align: left; padding: 0.35rem 0.75rem 0.35rem 0; border-bottom: 1px solid #ddd; vertical-align: top; }",
      ".wreckd-participants th { border-bottom: 2px solid #cc0000; text-transform: uppercase; font-size: 0.8rem; letter-spacing: 0.05em; }",
      ".wreckd-participants td.wp-num { color: #999; text-align: right; padding-right: 0.75rem; width: 2.5rem; }",
      ".wreckd-participants .wp-vol { color: #cc0000; font-size: 0.8rem; text-transform: uppercase; }",
    ].join("\n");
    document.head.appendChild(style);
  }

  function render(container, participants) {
    var racers = participants.filter(function (p) { return p.type !== "volunteer"; });
    var volunteers = participants.filter(function (p) { return p.type === "volunteer"; });

    var html = "";
    var countBits = [racers.length + " entrant" + (racers.length === 1 ? "" : "s")];
    if (volunteers.length) {
      countBits.push(volunteers.length + " volunteer" + (volunteers.length === 1 ? "" : "s"));
    }
    html += '<p class="wp-count">' + countBits.join(" &middot; ") + "</p>";

    if (!participants.length) {
      html += '<p class="wp-status">No entrants yet &mdash; be the first to register.</p>';
      container.innerHTML = html;
      return;
    }

    html += "<table><thead><tr><th></th><th>Name</th><th>Team</th></tr></thead><tbody>";
    var i = 1;
    participants.forEach(function (p) {
      var isVol = p.type === "volunteer";
      var teamCell = escapeHtml(p.team || "");
      if (isVol) teamCell = '<span class="wp-vol">volunteer</span>';
      html += "<tr>" +
        '<td class="wp-num">' + (isVol ? "" : i++) + "</td>" +
        "<td>" + escapeHtml(p.name) + "</td>" +
        "<td>" + teamCell + "</td>" +
        "</tr>";
    });
    html += "</tbody></table>";

    container.innerHTML = html;
  }

  function load(container) {
    var fixture = container.getAttribute("data-fixture");
    if (!fixture) return;

    injectStyles();
    container.innerHTML = '<p class="wp-status">Loading entrants&hellip;</p>';

    fetch(WORKER_URL + "/participants?fixture=" + encodeURIComponent(fixture))
      .then(function (res) {
        if (!res.ok) throw new Error("Failed to load");
        return res.json();
      })
      .then(function (data) {
        render(container, data.participants || []);
      })
      .catch(function () {
        var title = FIXTURE_TITLES[fixture] || "this fixture";
        container.innerHTML =
          '<p class="wp-status">Could not load the entrants list for ' +
          escapeHtml(title) + " right now. Please refresh.</p>";
      });
  }

  function init() {
    var containers = document.querySelectorAll(".wreckd-participants[data-fixture]");
    Array.prototype.forEach.call(containers, load);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
