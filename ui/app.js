/* Sentinel Suite Phase D0 — tiny SPA (no build step). */
(function () {
  const $ = (sel) => document.querySelector(sel);

  async function api(path, opts) {
    const res = await fetch(path, {
      headers: { Accept: "application/json", ...(opts && opts.body ? { "Content-Type": "application/json" } : {}) },
      ...opts,
    });
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { raw: text }; }
    if (!res.ok) {
      const err = new Error((data && data.error) || res.statusText || "request failed");
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  function showView(name) {
    document.querySelectorAll(".view").forEach((el) => el.classList.add("hidden"));
    const view = document.getElementById("view-" + name);
    if (view) view.classList.remove("hidden");
    document.querySelectorAll("nav button.nav").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.view === name);
    });
  }

  document.querySelectorAll("nav button.nav").forEach((btn) => {
    btn.addEventListener("click", () => showView(btn.dataset.view));
  });

  function renderList(el, items, primary, secondary) {
    el.innerHTML = "";
    if (!items.length) {
      el.innerHTML = '<li class="muted">None yet — <code>sentinel program init demo</code></li>';
      return;
    }
    for (const item of items) {
      const li = document.createElement("li");
      const left = document.createElement("span");
      left.textContent = primary(item);
      const right = document.createElement("span");
      right.className = "muted";
      right.textContent = secondary ? secondary(item) : "";
      li.appendChild(left);
      li.appendChild(right);
      el.appendChild(li);
    }
  }

  async function loadHome() {
    const [doctor, programs, packs] = await Promise.all([
      api("/api/doctor"),
      api("/api/programs"),
      api("/api/packs"),
    ]);
    const out = $("#doctor-out");
    out.textContent = (doctor.lines || []).join("\n");
    out.classList.toggle("status-pass", !!doctor.ok);
    out.classList.toggle("status-fail", !doctor.ok);
    $("#program-count").textContent = String(programs.count || 0);
    $("#pack-count").textContent = String(packs.count || 0);
    renderList($("#home-programs"), programs.programs || [], (p) => p.id, (p) => p.platform || "");
    renderList($("#home-packs"), packs.packs || [], (p) => p.id, (p) => "roles:" + p.needs_roles);

    // fill selects
    const progSel = $("#findings-program");
    const runProg = $("#run-program");
    progSel.innerHTML = "";
    for (const p of programs.programs || []) {
      const opt = document.createElement("option");
      opt.value = p.id;
      opt.textContent = p.id + (p.name && p.name !== p.id ? " — " + p.name : "");
      progSel.appendChild(opt);
    }
    if (!(programs.programs || []).length) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "(no programs)";
      progSel.appendChild(opt);
    }

    const packSel = $("#run-pack");
    packSel.innerHTML = "";
    for (const p of packs.packs || []) {
      const opt = document.createElement("option");
      opt.value = p.id;
      opt.textContent = p.id + " (roles:" + p.needs_roles + ")";
      packSel.appendChild(opt);
    }

    // programs table
    const pt = $("#programs-table");
    if (!(programs.programs || []).length) {
      pt.innerHTML = "<p class='muted'>No programs under SENTINEL_HOME/programs.</p>";
    } else {
      pt.innerHTML =
        "<table><thead><tr><th>id</th><th>name</th><th>platform</th><th>graph</th><th>scope</th></tr></thead><tbody>" +
        (programs.programs || [])
          .map(
            (p) =>
              "<tr><td>" +
              esc(p.id) +
              "</td><td>" +
              esc(p.name) +
              "</td><td>" +
              esc(p.platform) +
              "</td><td>" +
              (p.has_graph ? "yes" : "no") +
              "</td><td>" +
              (p.has_scope ? "yes" : "no") +
              "</td></tr>"
          )
          .join("") +
        "</tbody></table>";
    }

    // packs table
    const pk = $("#packs-table");
    pk.innerHTML =
      "<table><thead><tr><th>id</th><th>class</th><th>roles</th><th>noise</th><th>description</th></tr></thead><tbody>" +
      (packs.packs || [])
        .map(
          (p) =>
            "<tr><td>" +
            esc(p.id) +
            "</td><td>" +
            esc(p.class) +
            "</td><td>" +
            p.needs_roles +
            "</td><td>" +
            esc(p.noise_class) +
            "</td><td>" +
            esc(p.description || "") +
            "</td></tr>"
        )
        .join("") +
      "</tbody></table>";
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  async function loadFindings() {
    const pid = $("#findings-program").value;
    const status = $("#findings-status").value || "all";
    const box = $("#findings-table");
    if (!pid) {
      box.innerHTML = "<p class='muted'>Select a program.</p>";
      return;
    }
    box.innerHTML = "<p class='muted'>Loading…</p>";
    try {
      const data = await api(
        "/api/programs/" + encodeURIComponent(pid) + "/findings?status=" + encodeURIComponent(status)
      );
      const rows = data.findings || [];
      if (!rows.length) {
        box.innerHTML = "<p class='muted'>No findings for this filter.</p>";
        return;
      }
      box.innerHTML =
        "<table><thead><tr><th>id</th><th>title</th><th>verification</th><th>pack</th><th>host</th></tr></thead><tbody>" +
        rows
          .map((f) => {
            const p = f.payload || f;
            return (
              "<tr><td class='mono'>" +
              esc(f.id || f.event_id || "") +
              "</td><td>" +
              esc(p.title || p.summary || "") +
              "</td><td>" +
              esc(p.verification || p.verification_status || "") +
              "</td><td>" +
              esc(p.pack_id || "") +
              "</td><td>" +
              esc(p.host || "") +
              "</td></tr>"
            );
          })
          .join("") +
        "</tbody></table>";
    } catch (e) {
      box.innerHTML = "<p class='status-fail'>" + esc(e.message) + "</p>";
    }
  }

  $("#findings-refresh").addEventListener("click", loadFindings);
  $("#findings-program").addEventListener("change", loadFindings);
  $("#findings-status").addEventListener("change", loadFindings);

  $("#run-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    const body = {
      program_id: String(fd.get("program_id") || "").trim(),
      pack_id: String(fd.get("pack_id") || "").trim(),
      scope_path: String(fd.get("scope_path") || "").trim() || null,
      i_own_this: $("#run-own").checked,
      i_understand_lab: $("#run-lab").checked,
    };
    const out = $("#run-out");
    out.classList.remove("hidden");
    out.textContent = "Running…";
    if (!body.i_own_this) {
      out.textContent = "Refused: check i_own_this (ownership acknowledgment required).";
      return;
    }
    if (!window.confirm(
      "Run pack " + body.pack_id + " on program " + body.program_id + "?\n\n" +
      "This uses your ownership acknowledgment. Lab packs stay gated server-side."
    )) {
      out.textContent = "Cancelled.";
      return;
    }
    try {
      const data = await api("/api/pack/run", { method: "POST", body: JSON.stringify(body) });
      out.textContent = JSON.stringify(data, null, 2);
    } catch (e) {
      out.textContent = "Error: " + e.message + (e.data ? "\n" + JSON.stringify(e.data, null, 2) : "");
    }
  });

  $("#run-clear").addEventListener("click", () => {
    const out = $("#run-out");
    out.textContent = "";
    out.classList.add("hidden");
  });

  loadHome()
    .then(() => {
      if ($("#findings-program").value) return loadFindings();
    })
    .catch((e) => {
      $("#doctor-out").textContent = "Failed to load: " + e.message;
    });
})();
