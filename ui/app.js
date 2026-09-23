/* Sentinel Suite Phase D2 — tiny SPA (no build step). */
(function () {
  const $ = (sel) => document.querySelector(sel);
  const TOKEN_KEY = "sentinel_ui_token";

  function getToken() {
    try { return sessionStorage.getItem(TOKEN_KEY) || ""; } catch { return ""; }
  }
  function setToken(t) {
    try {
      if (t) sessionStorage.setItem(TOKEN_KEY, t);
      else sessionStorage.removeItem(TOKEN_KEY);
    } catch { /* ignore */ }
  }

  async function api(path, opts) {
    const headers = {
      Accept: "application/json",
      ...(opts && opts.body ? { "Content-Type": "application/json" } : {}),
      ...(opts && opts.headers ? opts.headers : {}),
    };
    const tok = getToken();
    if (tok) {
      headers["Authorization"] = "Bearer " + tok;
      headers["X-Sentinel-UI-Token"] = tok;
    }
    const res = await fetch(path, { ...opts, headers });
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { raw: text }; }
    if (!res.ok) {
      const err = new Error((data && data.error) || res.statusText || "request failed");
      err.status = res.status;
      err.data = data;
      err.code = data && data.code;
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
    if (name === "scope") loadScope();
    if (name === "reports") syncReportSelects();
    if (name === "auth") refreshAuthStatus();
    if (name === "findings" && $("#findings-program").value) loadFindings();
    if (name === "assets") loadAssets();
    if (name === "changes") loadChanges();
    if (name === "modules") loadModules();
  }

  document.querySelectorAll("nav button.nav").forEach((btn) => {
    btn.addEventListener("click", () => showView(btn.dataset.view));
  });

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

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

  function fillProgramSelects(programs) {
    const ids = [
      "findings-program",
      "scope-program",
      "report-program",
      "assets-program",
      "changes-program",
    ];
    const list = $("#program-list");
    list.innerHTML = "";
    for (const p of programs) {
      const o = document.createElement("option");
      o.value = p.id;
      list.appendChild(o);
    }
    for (const sid of ids) {
      const sel = $("#" + sid);
      if (!sel) continue;
      const cur = sel.value;
      sel.innerHTML = "";
      if (!programs.length) {
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "(no programs)";
        sel.appendChild(opt);
        continue;
      }
      for (const p of programs) {
        const opt = document.createElement("option");
        opt.value = p.id;
        opt.textContent = p.id + (p.name && p.name !== p.id ? " — " + p.name : "");
        sel.appendChild(opt);
      }
      if (cur) sel.value = cur;
    }
    if (programs[0] && !$("#run-program").value) {
      $("#run-program").value = programs[0].id;
    }
  }

  let PACKS_CACHE = [];

  function fillPackSelects(packs) {
    PACKS_CACHE = packs || [];
    for (const sid of ["run-pack", "report-pack"]) {
      const sel = $("#" + sid);
      if (!sel) continue;
      const keepAll = sid === "report-pack";
      sel.innerHTML = keepAll ? '<option value="">(all packs)</option>' : "";
      for (const p of PACKS_CACHE) {
        const opt = document.createElement("option");
        opt.value = p.id;
        opt.textContent =
          p.id +
          " · roles:" +
          p.needs_roles +
          " · " +
          (p.noise_class || "?");
        sel.appendChild(opt);
      }
    }
    updatePackMeta();
  }

  function updatePackMeta() {
    const id = $("#run-pack").value;
    const p = PACKS_CACHE.find((x) => x.id === id);
    const el = $("#pack-meta");
    if (!p) {
      el.textContent = "";
      return;
    }
    el.textContent =
      (p.description || "") +
      " · class=" +
      p.class +
      " · needs_roles=" +
      p.needs_roles +
      " · role paths: roles/a.json" +
      (p.needs_roles >= 2 ? " + roles/b.json" : "");
  }

  $("#run-pack").addEventListener("change", updatePackMeta);

  async function refreshAuthBanner() {
    const banner = $("#auth-banner");
    try {
      const st = await api("/api/auth/status");
      if (st.need_first_run) {
        banner.classList.remove("hidden");
        banner.innerHTML =
          'First-run required before pack run / scope edit / confirm — open <button type="button" id="goto-auth">Auth</button> to set password or skip for lab.';
        $("#goto-auth").onclick = () => showView("auth");
      } else if (st.mode === "password" && !getToken()) {
        banner.classList.remove("hidden");
        banner.textContent =
          "Password mode — login on Auth tab for mutating actions (run / scope / confirm).";
      } else {
        banner.classList.add("hidden");
        banner.textContent = "";
      }
    } catch {
      banner.classList.add("hidden");
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
    renderList(
      $("#home-packs"),
      packs.packs || [],
      (p) => p.id,
      (p) => "roles:" + p.needs_roles + " · " + (p.noise_class || "")
    );

    fillProgramSelects(programs.programs || []);
    fillPackSelects(packs.packs || []);

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

    await refreshAuthBanner();
  }

  function formatLogLines(lines) {
    if (!lines || !lines.length) return "";
    return lines
      .map((L) => {
        if (typeof L === "string") return L;
        const extra = Object.keys(L)
          .filter((k) => !["ts", "level", "msg"].includes(k))
          .map((k) => k + "=" + JSON.stringify(L[k]))
          .join(" ");
        return (
          "[" +
          (L.ts || "") +
          "] " +
          (L.level || "info").toUpperCase() +
          "  " +
          (L.msg || "") +
          (extra ? "  " + extra : "")
        );
      })
      .join("\n");
  }

  let pollTimer = null;
  let currentRunId = null;

  function setRunStatus(s) {
    $("#run-status").textContent = s;
  }

  async function pollRun(runId) {
    try {
      const data = await api("/api/pack/run/" + encodeURIComponent(runId));
      $("#run-out").textContent = formatLogLines(data.log_lines || []);
      if (data.error) {
        $("#run-out").textContent += "\nERROR: " + data.error;
      }
      setRunStatus("run_id=" + runId + " · status=" + data.status);
      if (["done", "error", "stopped"].includes(data.status)) {
        currentRunId = null;
        if (pollTimer) {
          clearInterval(pollTimer);
          pollTimer = null;
        }
        if (data.result) {
          $("#run-out").textContent +=
            "\n\n--- result summary ---\n" +
            JSON.stringify(
              {
                findings_emitted: data.result.findings_emitted,
                roles_loaded: data.result.roles_loaded,
                scoped: data.result.scoped,
                human_gate: data.result.human_gate,
              },
              null,
              2
            );
        }
      }
    } catch (e) {
      setRunStatus("poll error: " + e.message);
    }
  }

  $("#run-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    const body = {
      program_id: String(fd.get("program_id") || "").trim(),
      pack_id: String(fd.get("pack_id") || "").trim(),
      scope_path: String(fd.get("scope_path") || "").trim() || null,
      role_a_path: String(fd.get("role_a_path") || "").trim() || null,
      role_b_path: String(fd.get("role_b_path") || "").trim() || null,
      i_own_this: $("#run-own").checked,
      i_understand_lab: $("#run-lab").checked,
      async: $("#run-async").checked,
    };
    const out = $("#run-out");
    out.textContent = "";
    if (!body.i_own_this) {
      out.textContent = "Refused: check i_own_this (ownership acknowledgment required).";
      setRunStatus("refused");
      return;
    }
    if (
      !window.confirm(
        "Run pack " +
          body.pack_id +
          " on program " +
          body.program_id +
          "?\n\nOwnership acknowledged. Lab packs stay gated server-side. Never auto-VERIFIED."
      )
    ) {
      out.textContent = "Cancelled.";
      setRunStatus("cancelled");
      return;
    }
    setRunStatus("starting…");
    try {
      const data = await api("/api/pack/run", {
        method: "POST",
        body: JSON.stringify(body),
      });
      if (data.run_id) {
        currentRunId = data.run_id;
        out.textContent = formatLogLines([]);
        setRunStatus("run_id=" + data.run_id + " · polling");
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = setInterval(() => pollRun(data.run_id), 400);
        pollRun(data.run_id);
      } else {
        const result = data.result || data;
        out.textContent = formatLogLines(result.log_lines || []);
        out.textContent +=
          "\n\n" +
          JSON.stringify(
            {
              findings_emitted: result.findings_emitted,
              roles_loaded: result.roles_loaded,
              human_gate: result.human_gate,
            },
            null,
            2
          );
        setRunStatus("done (sync)");
      }
    } catch (e) {
      out.textContent =
        "Error: " +
        e.message +
        (e.data ? "\n" + JSON.stringify(e.data, null, 2) : "");
      setRunStatus("error");
      if (e.code === "need_first_run" || e.code === "auth_required") {
        refreshAuthBanner();
        showView("auth");
      }
    }
  });

  $("#run-stop").addEventListener("click", async () => {
    try {
      const data = await api("/api/pack/stop", {
        method: "POST",
        body: JSON.stringify({ run_id: currentRunId }),
      });
      $("#run-out").textContent +=
        "\n" + formatLogLines([{ ts: "", level: "warn", msg: data.message || "stop" }]);
      setRunStatus("stop signaled");
    } catch (e) {
      setRunStatus("stop error: " + e.message);
    }
  });

  $("#run-clear").addEventListener("click", () => {
    $("#run-out").textContent = "";
    setRunStatus("Idle");
  });

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
        "/api/programs/" +
          encodeURIComponent(pid) +
          "/findings?status=" +
          encodeURIComponent(status)
      );
      const rows = data.findings || [];
      if (!rows.length) {
        box.innerHTML = "<p class='muted'>No findings for this filter.</p>";
        return;
      }
      box.innerHTML =
        "<table><thead><tr><th></th><th>id</th><th>title</th><th>verification</th><th>pack</th><th>host</th></tr></thead><tbody>" +
        rows
          .map((f) => {
            const id = f.id || f.event_id || "";
            return (
              "<tr><td><button type='button' class='ghost pick-finding' data-id='" +
              esc(id) +
              "'>Use</button></td><td class='mono'>" +
              esc(id) +
              "</td><td>" +
              esc(f.title || "") +
              "</td><td>" +
              esc(f.verification || "") +
              "</td><td>" +
              esc(f.pack_id || "") +
              "</td><td>" +
              esc(f.host || "") +
              "</td></tr>"
            );
          })
          .join("") +
        "</tbody></table>";
      box.querySelectorAll(".pick-finding").forEach((btn) => {
        btn.addEventListener("click", () => {
          $("#confirm-id").value = btn.dataset.id;
        });
      });
    } catch (e) {
      box.innerHTML = "<p class='status-fail'>" + esc(e.message) + "</p>";
    }
  }

  $("#findings-refresh").addEventListener("click", loadFindings);
  $("#findings-program").addEventListener("change", loadFindings);
  $("#findings-status").addEventListener("change", loadFindings);

  $("#confirm-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const pid = $("#findings-program").value;
    const body = {
      program_id: pid,
      finding_id: $("#confirm-id").value.trim(),
      status: $("#confirm-status").value,
      note: $("#confirm-note").value,
      who: $("#confirm-who").value.trim() || null,
    };
    const out = $("#confirm-out");
    try {
      const data = await api("/api/confirm-finding", {
        method: "POST",
        body: JSON.stringify(body),
      });
      out.textContent = JSON.stringify(data, null, 2);
      loadFindings();
    } catch (e) {
      out.textContent =
        "Error: " + e.message + (e.data ? "\n" + JSON.stringify(e.data, null, 2) : "");
      if (e.code === "need_first_run" || e.code === "auth_required") showView("auth");
    }
  });

  async function loadScope() {
    const pid = $("#scope-program").value;
    if (!pid) return;
    try {
      const data = await api("/api/programs/" + encodeURIComponent(pid) + "/scope");
      $("#scope-text").value = data.text || "";
      $("#scope-meta").textContent =
        data.path +
        " · allow=" +
        data.allow_count +
        " deny=" +
        data.deny_count +
        " · hard_kill=" +
        data.hard_kill;
      $("#scope-out").classList.add("hidden");
    } catch (e) {
      $("#scope-meta").textContent = e.message;
    }
  }

  $("#scope-program").addEventListener("change", loadScope);
  $("#scope-reload").addEventListener("click", loadScope);

  async function saveScope(dryRun) {
    const pid = $("#scope-program").value;
    const out = $("#scope-out");
    out.classList.remove("hidden");
    try {
      const data = await api(
        "/api/programs/" + encodeURIComponent(pid) + "/scope",
        {
          method: "PUT",
          body: JSON.stringify({ text: $("#scope-text").value, dry_run: !!dryRun }),
        }
      );
      out.textContent = JSON.stringify(data, null, 2);
      if (!dryRun) loadScope();
    } catch (e) {
      out.textContent =
        "Error: " + e.message + (e.data ? "\n" + JSON.stringify(e.data, null, 2) : "");
      if (e.code === "need_first_run" || e.code === "auth_required") showView("auth");
    }
  }

  $("#scope-save").addEventListener("click", () => saveScope(false));
  $("#scope-dry").addEventListener("click", () => saveScope(true));

  $("#hk-probe").addEventListener("click", async () => {
    const pid = $("#scope-program").value;
    const out = $("#hk-out");
    try {
      const data = await api(
        "/api/programs/" + encodeURIComponent(pid) + "/scope/hard-kill",
        {
          method: "POST",
          body: JSON.stringify({ target: $("#hk-target").value }),
        }
      );
      out.textContent = JSON.stringify(data, null, 2);
      out.classList.toggle("status-fail", !!(data.result && data.result.hard_kill));
      out.classList.toggle("status-pass", !!(data.result && data.result.allowed));
    } catch (e) {
      out.textContent = "Error: " + e.message;
    }
  });

  async function briefImport(write) {
    const pid = $("#scope-program").value;
    const out = $("#brief-out");
    try {
      const data = await api(
        "/api/programs/" + encodeURIComponent(pid) + "/scope/brief",
        {
          method: "POST",
          body: JSON.stringify({
            brief: $("#brief-text").value,
            platform: $("#brief-platform").value,
            dry_run: !write,
          }),
        }
      );
      out.textContent = JSON.stringify(data, null, 2);
      if (write) loadScope();
    } catch (e) {
      out.textContent =
        "Error: " + e.message + (e.data ? "\n" + JSON.stringify(e.data, null, 2) : "");
    }
  }

  $("#brief-dry").addEventListener("click", () => briefImport(false));
  $("#brief-write").addEventListener("click", () => {
    if (window.confirm("Write parsed brief into scope.txt?")) briefImport(true);
  });

  function syncReportSelects() {
    /* already filled from loadHome */
  }

  async function loadReport() {
    const pid = $("#report-program").value;
    const pack = $("#report-pack").value;
    const out = $("#report-out");
    if (!pid) {
      out.textContent = "Select a program.";
      return;
    }
    let url =
      "/api/programs/" + encodeURIComponent(pid) + "/report?format=json";
    if (pack) url += "&pack_id=" + encodeURIComponent(pack);
    else url += "&all_packs=1";
    try {
      const data = await api(url);
      out.textContent = data.markdown || JSON.stringify(data, null, 2);
      out.dataset.markdown = data.markdown || "";
      out.dataset.filename =
        "sentinel-report-" + pid + (pack ? "-" + pack : "-all") + ".md";
    } catch (e) {
      out.textContent = "Error: " + e.message;
    }
  }

  $("#report-load").addEventListener("click", loadReport);
  $("#report-download").addEventListener("click", () => {
    const md = $("#report-out").dataset.markdown || $("#report-out").textContent;
    const blob = new Blob([md], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = $("#report-out").dataset.filename || "sentinel-report.md";
    a.click();
    URL.revokeObjectURL(a.href);
  });

  async function refreshAuthStatus() {
    try {
      const st = await api("/api/auth/status");
      $("#auth-status-out").textContent =
        JSON.stringify(st, null, 2) +
        "\n\nsession_token_present=" +
        !!getToken();
    } catch (e) {
      $("#auth-status-out").textContent = e.message;
    }
  }

  $("#auth-set").addEventListener("click", async () => {
    const out = $("#auth-action-out");
    try {
      const data = await api("/api/auth/setup", {
        method: "POST",
        body: JSON.stringify({
          action: "set_password",
          password: $("#auth-password").value,
        }),
      });
      out.textContent = JSON.stringify(data, null, 2);
      await refreshAuthStatus();
      await refreshAuthBanner();
    } catch (e) {
      out.textContent =
        "Error: " + e.message + (e.data ? "\n" + JSON.stringify(e.data, null, 2) : "");
    }
  });

  $("#auth-skip").addEventListener("click", async () => {
    const out = $("#auth-action-out");
    try {
      const data = await api("/api/auth/setup", {
        method: "POST",
        body: JSON.stringify({ action: "skip_lab" }),
      });
      out.textContent = JSON.stringify(data, null, 2);
      await refreshAuthStatus();
      await refreshAuthBanner();
    } catch (e) {
      out.textContent =
        "Error: " + e.message + (e.data ? "\n" + JSON.stringify(e.data, null, 2) : "");
    }
  });

  $("#auth-login").addEventListener("click", async () => {
    const out = $("#auth-action-out");
    try {
      const data = await api("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ password: $("#auth-password").value }),
      });
      setToken(data.token || "");
      out.textContent = JSON.stringify({ ok: data.ok, token_type: data.token_type }, null, 2);
      await refreshAuthStatus();
      await refreshAuthBanner();
    } catch (e) {
      out.textContent = "Error: " + e.message;
    }
  });

  $("#auth-logout").addEventListener("click", async () => {
    try {
      await api("/api/auth/logout", { method: "POST", body: "{}" });
    } catch { /* ignore */ }
    setToken("");
    refreshAuthStatus();
    refreshAuthBanner();
    $("#auth-action-out").textContent = "Logged out.";
  });

  loadHome()
    .then(() => {
      if ($("#findings-program").value) return loadFindings();
    })
    .catch((e) => {
      $("#doctor-out").textContent = "Failed to load: " + e.message;
    });

  async function loadAssets() {
    const pid = $("#assets-program").value;
    const kind = $("#assets-kind").value;
    const q = $("#assets-q").value.trim();
    const box = $("#assets-table");
    const meta = $("#assets-meta");
    if (!pid) {
      box.innerHTML = '<p class="empty-state">Select a program.</p>';
      meta.textContent = "";
      return;
    }
    box.innerHTML = '<p class="muted">Loading…</p>';
    try {
      const qs = new URLSearchParams({ kind, q });
      const data = await api("/api/programs/" + encodeURIComponent(pid) + "/assets?" + qs);
      meta.textContent =
        (data.count || 0) + " assets" +
        (data.counts
          ? " · domain " + data.counts.domain +
            " · dns " + data.counts.dns +
            " · ip " + data.counts.ip +
            " · port " + data.counts.port +
            " · url " + data.counts.url
          : "");
      if (data.empty) {
        box.innerHTML = '<p class="empty-state">' + esc(data.message || "No assets.") + "</p>";
        return;
      }
      let html = "<table><thead><tr><th>Score</th><th>Kind</th><th>Name</th><th>Reasons</th><th>First seen</th></tr></thead><tbody>";
      for (const a of data.assets || []) {
        html +=
          "<tr><td><span class='score-pill'>" +
          esc(a.score) +
          "</span></td><td>" +
          esc(a.kind) +
          "</td><td class='mono'>" +
          esc(a.name) +
          "</td><td class='muted small'>" +
          esc((a.reasons || []).join(", ")) +
          "</td><td class='muted small'>" +
          esc(a.first_seen || "") +
          "</td></tr>";
      }
      html += "</tbody></table>";
      box.innerHTML = html;
    } catch (e) {
      box.innerHTML = '<p class="empty-state">' + esc(e.message || e) + "</p>";
    }
  }

  $("#assets-refresh").addEventListener("click", loadAssets);
  $("#assets-kind").addEventListener("change", loadAssets);
  $("#assets-program").addEventListener("change", loadAssets);
  $("#assets-q").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") loadAssets();
  });

  async function loadChanges() {
    const pid = $("#changes-program").value;
    const window_ = $("#changes-window").value;
    const box = $("#changes-table");
    const meta = $("#changes-meta");
    if (!pid) {
      box.innerHTML = '<p class="empty-state">Select a program.</p>';
      meta.textContent = "";
      return;
    }
    box.innerHTML = '<p class="muted">Loading…</p>';
    try {
      const qs = new URLSearchParams({ window: window_ });
      const data = await api(
        "/api/programs/" + encodeURIComponent(pid) + "/changes?" + qs
      );
      meta.textContent =
        "window=" +
        esc(data.window) +
        " · " +
        (data.count || 0) +
        " deltas" +
        (data.baseline_ts ? " · baseline " + data.baseline_ts : "") +
        (data.current_ts ? " · current " + data.current_ts : "");
      if (data.empty) {
        box.innerHTML =
          '<p class="empty-state">' + esc(data.message || "No changes.") + "</p>";
        return;
      }
      let html =
        "<table><thead><tr><th>Score</th><th>Change</th><th>Kind</th><th>Name</th><th>Reasons</th></tr></thead><tbody>";
      for (const d of data.deltas || []) {
        const cls = d.change === "added" ? "delta-added" : "delta-removed";
        html +=
          "<tr><td><span class='score-pill'>" +
          esc(d.score) +
          "</span></td><td class='" +
          cls +
          "'>" +
          esc(d.change) +
          "</td><td>" +
          esc(d.kind) +
          "</td><td class='mono'>" +
          esc(d.name) +
          "</td><td class='muted small'>" +
          esc((d.reasons || []).join(", ")) +
          "</td></tr>";
      }
      html += "</tbody></table>";
      box.innerHTML = html;
    } catch (e) {
      box.innerHTML = '<p class="empty-state">' + esc(e.message || e) + "</p>";
    }
  }

  $("#changes-refresh").addEventListener("click", loadChanges);
  $("#changes-window").addEventListener("change", loadChanges);
  $("#changes-program").addEventListener("change", loadChanges);

  async function loadModules() {
    const box = $("#modules-table");
    const meta = $("#modules-meta");
    box.innerHTML = '<p class="muted">Loading…</p>';
    try {
      const data = await api("/api/modules");
      meta.textContent =
        (data.count || 0) +
        " modules · installable=" +
        String(data.installable) +
        (data.message ? " — " + data.message : "");
      let html =
        "<table><thead><tr><th>Id</th><th>Type</th><th>Class</th><th>Roles</th><th>Noise</th><th>Version</th><th>Description</th></tr></thead><tbody>";
      for (const m of data.modules || []) {
        html +=
          "<tr><td class='mono'>" +
          esc(m.id) +
          "</td><td>" +
          esc(m.type) +
          "</td><td>" +
          esc(m.class) +
          "</td><td>" +
          esc(m.needs_roles) +
          "</td><td>" +
          esc(m.noise_class) +
          "</td><td>" +
          esc(m.version) +
          "</td><td class='muted small'>" +
          esc(m.description || "") +
          "</td></tr>";
      }
      html += "</tbody></table>";
      box.innerHTML = html;
    } catch (e) {
      box.innerHTML = '<p class="empty-state">' + esc(e.message || e) + "</p>";
    }
  }


})();