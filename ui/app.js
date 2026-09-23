/* Sentinel Suite Phase D4 — tiny SPA (no build step). */
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
    if (name === "labs") loadLabs();
    if (name === "coach") loadCoach();
    if (name === "settings") loadSettings();
    if (name === "osint") loadOsint();
    if (name === "surface") loadSurface();
    if (name === "authlab") loadAuthLab();
    if (name === "workbench") loadWorkbench();
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
      "coach-program",
      "labs-program",
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



  function renderCoachCard(h, labProminent) {
    const isLab = String(h.kind || "").indexOf("lab_") === 0;
    const cls = "coach-card" + (labProminent && isLab ? " lab-kind" : "");
    let html =
      '<article class="' +
      cls +
      '"><span class="kind">' +
      esc(h.kind) +
      "</span><h3>" +
      esc(h.title) +
      '</h3><p class="body">' +
      esc(h.body) +
      "</p>";
    if (h.evidence_counts) {
      html +=
        '<div class="evidence">evidence: ' +
        esc(JSON.stringify(h.evidence_counts)) +
        "</div>";
    }
    html += "</article>";
    return html;
  }

  async function loadCoach() {
    const pid = $("#coach-program").value;
    const box = $("#coach-hints");
    const meta = $("#coach-meta");
    const disc = $("#coach-disclaimer");
    const labSec = $("#coach-lab-section");
    const labBox = $("#coach-lab-hints");
    const labMeta = $("#coach-lab-meta");
    const methodHead = $("#coach-method-heading");
    if (!pid) {
      box.innerHTML = '<p class="empty-state">Select a program.</p>';
      meta.textContent = "";
      disc.textContent = "";
      if (labSec) labSec.classList.add("hidden");
      if (methodHead) methodHead.classList.add("hidden");
      return;
    }
    box.innerHTML = '<p class="muted">Loading…</p>';
    if (labBox) labBox.innerHTML = "";
    try {
      const data = await api("/api/programs/" + encodeURIComponent(pid) + "/coach");
      disc.textContent = data.disclaimer || "";
      const ec = data.evidence_counts || {};
      const lp = data.lab_progress || {};
      meta.textContent =
        (data.count || 0) +
        " hints · urls=" +
        (ec.url || 0) +
        " · interesting_api=" +
        (ec.interesting_api || 0) +
        " · auth_surface=" +
        (ec.auth_surface || 0) +
        " · findings=" +
        (ec.findings_total || 0) +
        " · llm=" +
        String(!!data.llm) +
        " · lab_bound=" +
        String(!!data.lab_bound);
      const all = data.hints || [];
      const labHints = all.filter(function (h) {
        return String(h.kind || "").indexOf("lab_") === 0;
      });
      const methodHints = all.filter(function (h) {
        return String(h.kind || "").indexOf("lab_") !== 0;
      });
      if (data.lab_bound && labSec && labBox) {
        labSec.classList.remove("hidden");
        if (methodHead) methodHead.classList.remove("hidden");
        const counts = (lp && lp.counts) || {};
        labMeta.textContent =
          "lab=" +
          (lp.lab_id || "?") +
          " · stage=" +
          (lp.lab_stage || "?") +
          " · attempted=" +
          (counts.attempted || 0) +
          "/" +
          (counts.objectives || 0) +
          " · unlocked=" +
          (counts.hints_unlocked || 0) +
          " · completed=" +
          (counts.completed || 0) +
          " · kinds=" +
          ((data.lab_kinds || []).join(",") || "—");
        if (!labHints.length) {
          labBox.innerHTML = '<p class="empty-state">No lab hints yet.</p>';
        } else {
          labBox.innerHTML = labHints
            .map(function (h) {
              return renderCoachCard(h, true);
            })
            .join("");
        }
        if (!methodHints.length) {
          box.innerHTML = '<p class="empty-state">No methodology hints.</p>';
        } else {
          box.innerHTML = methodHints
            .map(function (h) {
              return renderCoachCard(h, false);
            })
            .join("");
        }
      } else {
        if (labSec) labSec.classList.add("hidden");
        if (methodHead) methodHead.classList.add("hidden");
        if (!all.length) {
          box.innerHTML = '<p class="empty-state">No hints.</p>';
          return;
        }
        box.innerHTML = all
          .map(function (h) {
            return renderCoachCard(h, false);
          })
          .join("");
      }
    } catch (e) {
      box.innerHTML = '<p class="empty-state">' + esc(e.message || e) + "</p>";
      if (labSec) labSec.classList.add("hidden");
    }
  }

  $("#coach-refresh").addEventListener("click", loadCoach);
  $("#coach-program").addEventListener("change", loadCoach);

  const THEME_KEY = "sentinel_ui_theme";
  function applyTheme(mode) {
    const m = mode === "light" ? "light" : "dark";
    document.body.classList.toggle("theme-light", m === "light");
    try { localStorage.setItem(THEME_KEY, m); } catch { /* ignore */ }
    const st = $("#theme-status");
    if (st) st.textContent = "theme=" + m + " (localStorage stub)";
  }
  function initTheme() {
    let m = "dark";
    try { m = localStorage.getItem(THEME_KEY) || "dark"; } catch { /* ignore */ }
    applyTheme(m);
  }
  $("#theme-dark").addEventListener("click", () => applyTheme("dark"));
  $("#theme-light").addEventListener("click", () => applyTheme("light"));
  initTheme();

  async function loadSettings() {
    try {
      const data = await api("/api/settings");
      $("#settings-env").textContent = JSON.stringify(
        {
          SENTINEL_HOME: data.SENTINEL_HOME,
          bind: data.bind,
          phase: data.phase,
          license: data.license,
          fences: data.fences,
          theme: data.theme,
        },
        null,
        2
      );
      $("#settings-auth").textContent = JSON.stringify(
        {
          auth: data.auth,
          doctor: data.doctor,
          engines: data.engines,
        },
        null,
        2
      );
      const fp = $("#settings-free-promise");
      if (fp) {
        fp.textContent = JSON.stringify(data.free_promise || {}, null, 2);
      }
      const tel = $("#settings-telemetry");
      if (tel) {
        tel.textContent = JSON.stringify(data.telemetry || {}, null, 2);
      }
      if (data.rates_present) {
        $("#settings-rates").textContent = JSON.stringify(data.rates, null, 2);
      } else {
        $("#settings-rates").textContent =
          "No rates.json under SENTINEL_HOME — rates display absent (honest empty).";
      }
    } catch (e) {
      $("#settings-env").textContent = "Error: " + e.message;
    }
  }

  $("#settings-goto-auth").addEventListener("click", () => showView("auth"));
  $("#settings-clear-auth").addEventListener("click", async () => {
    const out = $("#settings-action-out");
    if (
      !window.confirm(
        "Clear local UI auth (delete ui_auth.json)? You will need first-run again."
      )
    ) {
      out.textContent = "Cancelled.";
      return;
    }
    try {
      const data = await api("/api/auth/clear", {
        method: "POST",
        body: JSON.stringify({ confirm: true }),
      });
      setToken("");
      out.textContent = JSON.stringify(data, null, 2);
      await loadSettings();
      await refreshAuthBanner();
    } catch (e) {
      out.textContent =
        "Error: " +
        e.message +
        (e.data ? "\n" + JSON.stringify(e.data, null, 2) : "");
      if (e.code === "need_first_run" || e.code === "auth_required") showView("auth");
    }
  });



  // --- Phase D4: OSINT / Surface / Auth lab / Workbench / Ctrl+K ---

  async function fillProgramSelect(sel) {
    const data = await api("/api/programs");
    const programs = data.programs || [];
    sel.innerHTML = programs
      .map((p) => "<option value=\"" + esc(p.id) + "\">" + esc(p.id) + "</option>")
      .join("");
    if (!programs.length) {
      sel.innerHTML = "<option value=\"\">(no programs)</option>";
    }
    return programs;
  }

  async function loadOsint() {
    const sel = $("#osint-program");
    if (!sel.options.length) await fillProgramSelect(sel);
    const pid = sel.value;
    const box = $("#osint-table");
    const svgBox = $("#osint-svg");
    const counts = $("#osint-counts");
    if (!pid) {
      box.innerHTML = "<p class=\"empty-state\">No programs yet.</p>";
      svgBox.innerHTML = "";
      return;
    }
    const kinds = $("#osint-kinds").value;
    const q = $("#osint-q").value.trim();
    const qs =
      "?kinds=" + encodeURIComponent(kinds) + "&q=" + encodeURIComponent(q);
    try {
      const data = await api("/api/programs/" + encodeURIComponent(pid) + "/osint-graph" + qs);
      counts.textContent = data.empty
        ? data.message || "Empty graph"
        : "nodes=" +
          data.counts.nodes +
          " edges=" +
          data.counts.edges +
          " · " +
          Object.keys(data.tables)
            .map((k) => k + "=" + data.counts[k])
            .join(" · ");
      if (data.empty) {
        box.innerHTML = "<p class=\"empty-state\">" + esc(data.message) + "</p>";
        svgBox.innerHTML = "<p class=\"empty-state\">No nodes to draw.</p>";
        return;
      }
      // SVG from layout
      const layout = data.layout || [];
      const edges = data.edges || [];
      const idPos = {};
      layout.forEach((n) => {
        idPos[n.id] = n;
      });
      let maxX = 400,
        maxY = 200;
      layout.forEach((n) => {
        maxX = Math.max(maxX, n.x + 120);
        maxY = Math.max(maxY, n.y + 40);
      });
      let svg =
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 " +
        maxX +
        " " +
        maxY +
        "\">";
      edges.forEach((e) => {
        const a = idPos[e.from];
        const b = idPos[e.to];
        if (!a || !b) return;
        svg +=
          "<line class=\"viz-edge\" x1=\"" +
          (a.x + 40) +
          "\" y1=\"" +
          (a.y + 12) +
          "\" x2=\"" +
          (b.x + 40) +
          "\" y2=\"" +
          (b.y + 12) +
          "\" />";
      });
      layout.forEach((n) => {
        svg +=
          "<rect class=\"viz-node\" x=\"" +
          n.x +
          "\" y=\"" +
          n.y +
          "\" width=\"100\" height=\"28\" rx=\"6\" />";
        svg +=
          "<text class=\"viz-label\" x=\"" +
          (n.x + 6) +
          "\" y=\"" +
          (n.y + 18) +
          "\">" +
          esc(n.label) +
          "</text>";
      });
      svg += "</svg>";
      svgBox.innerHTML = svg;

      let html = "";
      Object.keys(data.tables).forEach((bucket) => {
        const rows = data.tables[bucket] || [];
        if (!rows.length) return;
        html += "<h3>" + esc(bucket) + " (" + rows.length + ")</h3>";
        html +=
          "<table><thead><tr><th>Label</th><th>Type</th><th>Confidence</th></tr></thead><tbody>";
        rows.forEach((r) => {
          html +=
            "<tr><td>" +
            esc(r.label) +
            "</td><td>" +
            esc(r.type) +
            "</td><td>" +
            esc(r.confidence) +
            "</td></tr>";
        });
        html += "</tbody></table>";
      });
      box.innerHTML = html || "<p class=\"empty-state\">No rows match filters.</p>";
    } catch (e) {
      box.innerHTML = "<p class=\"empty-state\">Error: " + esc(e.message) + "</p>";
    }
  }
  $("#osint-refresh").addEventListener("click", loadOsint);
  $("#osint-kinds").addEventListener("change", loadOsint);
  $("#osint-program").addEventListener("change", loadOsint);
  $("#osint-q").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") loadOsint();
  });

  async function loadSurface() {
    const sel = $("#surface-program");
    if (!sel.options.length) await fillProgramSelect(sel);
    const pid = sel.value;
    const box = $("#surface-table");
    const counts = $("#surface-counts");
    if (!pid) {
      box.innerHTML = "<p class=\"empty-state\">No programs yet.</p>";
      return;
    }
    const kind = $("#surface-kind").value;
    const q = $("#surface-q").value.trim();
    const qs =
      "?kind=" + encodeURIComponent(kind) + "&q=" + encodeURIComponent(q);
    try {
      const data = await api(
        "/api/programs/" + encodeURIComponent(pid) + "/surface" + qs
      );
      counts.textContent = data.empty
        ? data.message || "Empty"
        : "count=" +
          data.count +
          " · " +
          Object.keys(data.counts)
            .map((k) => k + "=" + data.counts[k])
            .join(" · ");
      if (data.empty) {
        box.innerHTML = "<p class=\"empty-state\">" + esc(data.message) + "</p>";
        return;
      }
      let html =
        "<table><thead><tr><th>Kind</th><th>Name</th><th>Detail</th></tr></thead><tbody>";
      (data.items || []).forEach((it) => {
        const detail = [it.method, it.host, it.path, it.in, it.url]
          .filter(Boolean)
          .join(" · ");
        html +=
          "<tr><td>" +
          esc(it.kind) +
          "</td><td>" +
          esc(it.name) +
          "</td><td class=\"small\">" +
          esc(detail) +
          "</td></tr>";
      });
      html += "</tbody></table>";
      box.innerHTML = html;
    } catch (e) {
      box.innerHTML = "<p class=\"empty-state\">Error: " + esc(e.message) + "</p>";
    }
  }
  $("#surface-refresh").addEventListener("click", loadSurface);
  $("#surface-kind").addEventListener("change", loadSurface);
  $("#surface-program").addEventListener("change", loadSurface);
  $("#surface-q").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") loadSurface();
  });

  async function loadAuthLab() {
    const sel = $("#authlab-program");
    if (!sel.options.length) await fillProgramSelect(sel);
    const pid = sel.value;
    const box = $("#authlab-body");
    if (!pid) {
      box.innerHTML = "<p class=\"empty-state\">No programs yet.</p>";
      return;
    }
    try {
      const data = await api(
        "/api/programs/" + encodeURIComponent(pid) + "/auth-lab"
      );
      if (data.empty) {
        box.innerHTML =
          "<p class=\"empty-state\">" + esc(data.message || "Empty vault") + "</p>";
        return;
      }
      let html = "";
      ["a", "b"].forEach((letter) => {
        const r = (data.roles || {})[letter] || {};
        html += "<article class=\"card auth-role-card\">";
        html += "<h3>Role " + letter.toUpperCase() + "</h3>";
        html +=
          "<p class=\"muted small\">" +
          esc(r.rel) +
          " · exists=" +
          !!r.exists +
          " · usable=" +
          !!r.usable +
          "</p>";
        if (r.message) html += "<p class=\"empty-state\">" + esc(r.message) + "</p>";
        if (r.error) html += "<p class=\"status-fail\">" + esc(r.error) + "</p>";
        html +=
          "<pre class=\"mono\">" +
          esc(
            JSON.stringify(
              {
                cookie_keys: r.cookie_keys,
                header_keys: r.header_keys,
                has_bearer: r.has_bearer,
                bearer_preview: r.bearer_preview,
                replay_stub: r.replay_stub,
              },
              null,
              2
            )
          ) +
          "</pre>";
        html += "</article>";
      });
      html +=
        "<p class=\"muted small\">" + esc(data.disclaimer || "") + "</p>";
      box.innerHTML = html;
    } catch (e) {
      box.innerHTML = "<p class=\"empty-state\">Error: " + esc(e.message) + "</p>";
    }
  }
  $("#authlab-refresh").addEventListener("click", loadAuthLab);
  $("#authlab-program").addEventListener("change", loadAuthLab);

  async function loadWorkbench() {
    const sel = $("#wb-program");
    if (!sel.options.length) await fillProgramSelect(sel);
  }

  function wbPayload(extra) {
    let headers = {};
    try {
      headers = JSON.parse($("#wb-headers").value || "{}");
    } catch (e) {
      throw new Error("headers must be valid JSON object");
    }
    const bodyRaw = $("#wb-body").value;
    const out = {
      program_id: $("#wb-program").value,
      method: $("#wb-method").value,
      url: $("#wb-url").value.trim(),
      headers: headers,
      body: bodyRaw || null,
      i_own_this: $("#wb-own").checked,
      format: $("#wb-format").value,
    };
    return Object.assign(out, extra || {});
  }

  $("#wb-export").addEventListener("click", async () => {
    const out = $("#wb-out");
    try {
      const data = await api("/api/workbench/export", {
        method: "POST",
        body: JSON.stringify(wbPayload()),
      });
      out.textContent = JSON.stringify(data, null, 2);
    } catch (e) {
      out.textContent =
        "Error: " + e.message + (e.data ? "\n" + JSON.stringify(e.data, null, 2) : "");
    }
  });

  $("#wb-send").addEventListener("click", async () => {
    const out = $("#wb-out");
    try {
      const body = wbPayload();
      if (!body.i_own_this) {
        out.textContent =
          "Refused: check i_own_this (ownership acknowledgment required for live send).";
        return;
      }
      if (
        !window.confirm(
          "Live workbench send to " +
            body.url +
            "?\nRequires in-scope host + ownership. Not a finding."
        )
      ) {
        out.textContent = "Cancelled.";
        return;
      }
      const data = await api("/api/workbench/send", {
        method: "POST",
        body: JSON.stringify(body),
      });
      out.textContent = JSON.stringify(data, null, 2);
    } catch (e) {
      out.textContent =
        "Error: " +
        e.message +
        (e.data ? "\n" + JSON.stringify(e.data, null, 2) : "");
      if (e.code === "need_first_run" || e.code === "auth_required") showView("auth");
    }
  });


  // --- Phase E0: Open Lab ---
  let _labsCatalogCache = [];

  function showCatalogStartDocs() {
    const sel = $("#labs-catalog");
    const docs = $("#labs-start-docs");
    if (!sel || !docs || !sel.options.length) return;
    const labId = sel.value;
    const L = (_labsCatalogCache || []).find((x) => x.lab_id === labId);
    if (L && L.start_docs) {
      docs.textContent = L.start_docs;
      return;
    }
    const o = sel.options[sel.selectedIndex];
    docs.textContent =
      "Select Open Lab to write LAB_START.md into the program.\n" +
      "Default base: " +
      (o && o.dataset.base ? o.dataset.base : "http://127.0.0.1:3000");
  }

  async function loadLabsCatalog() {
    const sel = $("#labs-catalog");
    const meta = $("#labs-catalog-meta");
    try {
      const data = await api("/api/labs");
      _labsCatalogCache = data.labs || [];
      sel.innerHTML = "";
      for (const L of _labsCatalogCache) {
        const opt = document.createElement("option");
        opt.value = L.lab_id;
        opt.textContent = L.name + " (" + L.lab_id + ")";
        opt.dataset.defaultProgram = L.default_program_id || "";
        opt.dataset.base = L.default_base_url || "";
        sel.appendChild(opt);
      }
      meta.textContent = JSON.stringify(
        {
          count: data.count,
          phase: data.phase,
          progress_schema_version: data.progress_schema_version,
          labs: (_labsCatalogCache || []).map((L) => L.lab_id),
          note: data.note,
        },
        null,
        2
      );
      if (sel.options.length) {
        const o = sel.options[sel.selectedIndex];
        if (!$("#labs-program-id").value) {
          $("#labs-program-id").value = o.dataset.defaultProgram || "lab-juice-shop";
        }
        showCatalogStartDocs();
      }
    } catch (e) {
      meta.textContent = String(e.message || e);
    }
  }

  async function loadLabs() {
    await loadLabsCatalog();
    const sel = $("#labs-program");
    if (sel && !sel.options.length) {
      try {
        const progs = await api("/api/programs");
        fillProgramSelects(progs.programs || []);
      } catch { /* ignore */ }
    }
    if ($("#labs-program").value) await refreshLabStatus();
  }

  function fillLabObjectiveSelect(objectives) {
    const sel = $("#labs-objective-select");
    if (!sel) return;
    const prev = sel.value || ($("#labs-objective-id") && $("#labs-objective-id").value) || "";
    sel.innerHTML = '<option value="">— select objective —</option>';
    for (const o of objectives || []) {
      const opt = document.createElement("option");
      opt.value = o.id;
      const flags = [];
      if (o.attempted) flags.push("tried");
      if (o.hints_unlocked) flags.push("hints");
      if (o.completed) flags.push("done");
      opt.textContent =
        o.id + " — " + (o.title || "") + (flags.length ? " [" + flags.join(",") + "]" : "");
      sel.appendChild(opt);
    }
    if (prev) {
      sel.value = prev;
      if ($("#labs-objective-id")) $("#labs-objective-id").value = prev;
    }
  }

  function pickLabObjective(oid) {
    if (!oid) return;
    if ($("#labs-objective-id")) $("#labs-objective-id").value = oid;
    const sel = $("#labs-objective-select");
    if (sel) sel.value = oid;
  }

  async function refreshLabStatus() {
    const pid = $("#labs-program").value;
    const box = $("#labs-objectives");
    const meta = $("#labs-status-meta");
    const schemaEl = $("#labs-progress-schema");
    if (!pid) {
      box.innerHTML = '<p class="empty-state">Open a lab or select a lab-bound program.</p>';
      meta.textContent = "";
      if (schemaEl) schemaEl.textContent = "";
      fillLabObjectiveSelect([]);
      return;
    }
    box.innerHTML = '<p class="muted">Loading…</p>';
    try {
      const data = await api("/api/programs/" + encodeURIComponent(pid) + "/lab");
      const c = data.counts || {};
      meta.textContent =
        data.lab_id +
        " @ " +
        data.base_url +
        " · attempted=" +
        (c.attempted || 0) +
        "/" +
        (c.objectives || 0) +
        " · hints_unlocked=" +
        (c.hints_unlocked || 0) +
        " · completed=" +
        (c.completed || 0) +
        " · invent_findings=" +
        String(!!data.invent_findings);
      if (schemaEl) {
        const p = data.progress || {};
        schemaEl.textContent =
          "progress schema_version=" +
          (data.progress_schema_version || p.schema_version || "?") +
          (p.updated_at ? " · updated_at=" + p.updated_at : "") +
          " · shared attempt/hint/complete UX";
      }
      if (data.start_docs) $("#labs-start-docs").textContent = data.start_docs;
      fillLabObjectiveSelect(data.objectives || []);
      let html = "";
      for (const o of data.objectives || []) {
        const cardClass =
          "coach-card" +
          (o.completed ? " lab-obj-done" : o.attempted ? " lab-obj-tried" : "");
        html +=
          '<article class="' +
          cardClass +
          '"><span class="kind">' +
          esc(o.category) +
          "</span><h3>" +
          esc(o.id) +
          " — " +
          esc(o.title) +
          "</h3><p class="body">" +
          esc(o.summary || "") +
          "</p><div class="evidence">" +
          "attempted=" +
          o.attempted +
          " · hints_unlocked=" +
          o.hints_unlocked +
          " · completed=" +
          o.completed +
          " · packs=" +
          esc((o.suggested_packs || []).join(",") || "(none)") +
          "</div>";
        if (o.hints_unlocked && (o.hints_preview || []).length) {
          html += "<ol>";
          for (const h of o.hints_preview) {
            html += "<li>" + esc(h.body || h) + "</li>";
          }
          html += "</ol>";
        } else {
          html +=
            '<p class="muted small">Hints locked — record an attempt to unlock.</p>';
        }
        html +=
          '<div class="labs-obj-actions">' +
          '<button type="button" class="ghost labs-pick" data-oid="' +
          esc(o.id) +
          '">Use</button>' +
          '<button type="button" class="labs-obj-attempt" data-oid="' +
          esc(o.id) +
          '">Attempt</button>' +
          '<button type="button" class="ghost labs-obj-complete" data-oid="' +
          esc(o.id) +
          '">Complete</button>' +
          '<button type="button" class="ghost labs-obj-hints" data-oid="' +
          esc(o.id) +
          '">Hints</button>' +
          "</div></article>";
      }
      box.innerHTML = html || '<p class="empty-state">No objectives.</p>';
      box.querySelectorAll(".labs-pick").forEach((btn) => {
        btn.addEventListener("click", () => pickLabObjective(btn.dataset.oid));
      });
      box.querySelectorAll(".labs-obj-attempt").forEach((btn) => {
        btn.addEventListener("click", () => {
          pickLabObjective(btn.dataset.oid);
          postLabAttempt(false);
        });
      });
      box.querySelectorAll(".labs-obj-complete").forEach((btn) => {
        btn.addEventListener("click", () => {
          pickLabObjective(btn.dataset.oid);
          postLabAttempt(true);
        });
      });
      box.querySelectorAll(".labs-obj-hints").forEach((btn) => {
        btn.addEventListener("click", async () => {
          pickLabObjective(btn.dataset.oid);
          const oid = btn.dataset.oid;
          const program = $("#labs-program").value;
          try {
            const hints = await api(
              "/api/programs/" +
                encodeURIComponent(program) +
                "/lab/hints/" +
                encodeURIComponent(oid)
            );
            $("#labs-hints-out").textContent = JSON.stringify(hints, null, 2);
          } catch (e) {
            $("#labs-hints-out").textContent = String(e.message || e);
          }
        });
      });
      renderLabTutorial(data.tutorial || null);
    } catch (e) {
      box.innerHTML =
        '<p class="empty-state">' +
        esc(e.message || e) +
        " — open a lab first.</p>";
      renderLabTutorial(null);
    }
  }

  function renderLabTutorial(tutorial) {
    const box = $("#labs-tutorial-checklist");
    const meta = $("#labs-tutorial-meta");
    if (!box) return;
    if (!tutorial) {
      box.innerHTML =
        '<p class="muted">Open a lab-bound program to load the checklist.</p>';
      if (meta) meta.textContent = "";
      return;
    }
    let html = "";
    for (const s of tutorial.steps || []) {
      const mark = s.done ? "✓" : "○";
      const cls = "coach-card" + (s.done ? " lab-obj-done" : "");
      html +=
        '<article class="' +
        cls +
        '"><span class="kind">' +
        esc(s.id) +
        "</span><h3>" +
        esc(mark + " " + (s.title || "")) +
        '</h3><p class="body">' +
        esc(s.detail || "") +
        "</p></article>";
    }
    box.innerHTML = html || '<p class="empty-state">No tutorial steps.</p>';
    if (meta) {
      meta.textContent =
        "tutorial " +
        (tutorial.done_count || 0) +
        "/" +
        (tutorial.total || 0) +
        (tutorial.complete ? " · DONE" : "") +
        " · lab1_exit=" +
        String(!!tutorial.lab1_exit) +
        " · confirmed_findings=" +
        ((tutorial.counts && tutorial.counts.confirmed_findings) || 0) +
        " · invent_findings=" +
        String(!!tutorial.invent_findings);
    }
  }

  async function refreshLabTutorial() {
    const pid = $("#labs-program") && $("#labs-program").value;
    if (!pid) {
      renderLabTutorial(null);
      return;
    }
    try {
      const data = await api(
        "/api/programs/" + encodeURIComponent(pid) + "/lab/tutorial"
      );
      renderLabTutorial(data);
    } catch (e) {
      const box = $("#labs-tutorial-checklist");
      if (box) box.innerHTML = '<p class="empty-state">' + esc(e.message || e) + "</p>";
    }
  }

  $("#labs-refresh-catalog").addEventListener("click", loadLabsCatalog);
  $("#labs-refresh").addEventListener("click", refreshLabStatus);
  $("#labs-program").addEventListener("change", refreshLabStatus);
  $("#labs-catalog").addEventListener("change", () => {
    const o = $("#labs-catalog").options[$("#labs-catalog").selectedIndex];
    if (o) $("#labs-program-id").value = o.dataset.defaultProgram || "";
    showCatalogStartDocs();
  });
  const objSel = $("#labs-objective-select");
  if (objSel) {
    objSel.addEventListener("change", () => {
      if (objSel.value) pickLabObjective(objSel.value);
    });
  }

  $("#labs-open").addEventListener("click", async () => {
    const lab_id = $("#labs-catalog").value;
    const program_id = ($("#labs-program-id").value || "").trim();
    try {
      const data = await api("/api/labs/open", {
        method: "POST",
        body: JSON.stringify({
          lab_id,
          program_id: program_id || undefined,
        }),
      });
      const result = data.result || data;
      $("#labs-hints-out").textContent = JSON.stringify(
        { opened: true, program_id: result.program_id, counts: result.counts },
        null,
        2
      );
      if (result.start_docs) $("#labs-start-docs").textContent = result.start_docs;
      // refresh programs + select
      const progs = await api("/api/programs");
      fillProgramSelects(progs.programs || []);
      if (result.program_id) {
        $("#labs-program").value = result.program_id;
        if ($("#coach-program")) $("#coach-program").value = result.program_id;
        if ($("#run-program")) $("#run-program").value = result.program_id;
      }
      await refreshLabStatus();
    } catch (e) {
      $("#labs-hints-out").textContent =
        e.message + (e.data ? "\n" + JSON.stringify(e.data, null, 2) : "");
      if (e.code === "need_first_run" || e.code === "auth_required") showView("auth");
    }
  });

  async function postLabAttempt(complete) {
    const pid = $("#labs-program").value;
    const oid = ($("#labs-objective-id").value || "").trim();
    const note = ($("#labs-attempt-note").value || "").trim();
    if (!pid || !oid) {
      $("#labs-hints-out").textContent = "Select program + objective id.";
      return;
    }
    try {
      const data = await api(
        "/api/programs/" + encodeURIComponent(pid) + "/lab/attempt",
        {
          method: "POST",
          body: JSON.stringify({
            objective_id: oid,
            note: note || undefined,
            complete: !!complete,
          }),
        }
      );
      $("#labs-hints-out").textContent = JSON.stringify(data.result || data, null, 2);
      await refreshLabStatus();
      // show unlocked hints
      const hints = await api(
        "/api/programs/" +
          encodeURIComponent(pid) +
          "/lab/hints/" +
          encodeURIComponent(oid)
      );
      $("#labs-hints-out").textContent = JSON.stringify(hints, null, 2);
    } catch (e) {
      $("#labs-hints-out").textContent =
        e.message + (e.data ? "\n" + JSON.stringify(e.data, null, 2) : "");
      if (e.code === "need_first_run" || e.code === "auth_required") showView("auth");
    }
  }

  $("#labs-attempt").addEventListener("click", () => postLabAttempt(false));
  $("#labs-complete").addEventListener("click", () => postLabAttempt(true));

  if ($("#labs-tutorial-refresh")) {
    $("#labs-tutorial-refresh").addEventListener("click", refreshLabTutorial);
  }
  if ($("#labs-goto-confirm")) {
    $("#labs-goto-confirm").addEventListener("click", () => {
      const pid = $("#labs-program") && $("#labs-program").value;
      if (pid && $("#findings-program")) $("#findings-program").value = pid;
      if (pid && $("#report-program")) $("#report-program").value = pid;
      showView("findings");
    });
  }
  if ($("#labs-export-report")) {
    $("#labs-export-report").addEventListener("click", async () => {
      const pid = $("#labs-program") && $("#labs-program").value;
      const out = $("#labs-report-out");
      if (!pid) {
        if (out) out.textContent = "Select a lab-bound program first.";
        return;
      }
      try {
        const data = await api(
          "/api/programs/" + encodeURIComponent(pid) + "/lab/report",
          { method: "POST", body: JSON.stringify({}) }
        );
        const result = data.result || data;
        if (out) {
          out.textContent = JSON.stringify(
            {
              ok: result.ok,
              output: result.output,
              tutorial_complete: result.tutorial_complete,
              confirmed_findings: result.confirmed_findings,
              invent_findings: result.invent_findings,
              markdown_preview: (result.markdown || "").slice(0, 1200),
            },
            null,
            2
          );
          out.dataset.markdown = result.markdown || "";
          out.dataset.filename = "report.md";
        }
        // Also offer download
        if (result.markdown) {
          const a = document.createElement("a");
          a.href = URL.createObjectURL(
            new Blob([result.markdown], { type: "text/markdown" })
          );
          a.download = "report.md";
          a.click();
          URL.revokeObjectURL(a.href);
        }
        if (pid && $("#report-program")) $("#report-program").value = pid;
        await refreshLabStatus();
        await refreshLabTutorial();
      } catch (e) {
        if (out)
          out.textContent =
            e.message + (e.data ? "\n" + JSON.stringify(e.data, null, 2) : "");
        if (e.code === "need_first_run" || e.code === "auth_required") showView("auth");
      }
    });
  }

  $("#labs-show-hints").addEventListener("click", async () => {
    const pid = $("#labs-program").value;
    const oid = ($("#labs-objective-id").value || "").trim();
    if (!pid || !oid) {
      $("#labs-hints-out").textContent = "Select program + objective id.";
      return;
    }
    try {
      const hints = await api(
        "/api/programs/" +
          encodeURIComponent(pid) +
          "/lab/hints/" +
          encodeURIComponent(oid)
      );
      $("#labs-hints-out").textContent = JSON.stringify(hints, null, 2);
    } catch (e) {
      $("#labs-hints-out").textContent = String(e.message || e);
    }
  });


  // Ctrl/Cmd+K command palette
  const TABS = [
    { id: "home", label: "Home", kind: "tab" },
    { id: "programs", label: "Programs", kind: "tab" },
    { id: "packs", label: "Packs", kind: "tab" },
    { id: "hunt", label: "Hunt", kind: "tab" },
    { id: "scope", label: "Scope", kind: "tab" },
    { id: "findings", label: "Findings", kind: "tab" },
    { id: "reports", label: "Reports", kind: "tab" },
    { id: "assets", label: "Assets", kind: "tab" },
    { id: "changes", label: "Changes", kind: "tab" },
    { id: "modules", label: "Modules", kind: "tab" },
    { id: "osint", label: "OSINT graph", kind: "tab" },
    { id: "surface", label: "Surface map", kind: "tab" },
    { id: "authlab", label: "Auth lab", kind: "tab" },
    { id: "workbench", label: "Workbench", kind: "tab" },
    { id: "labs", label: "Open Lab", kind: "tab" },
    { id: "coach", label: "Coach", kind: "tab" },
    { id: "settings", label: "Settings", kind: "tab" },
    { id: "auth", label: "Auth", kind: "tab" },
  ];
  let cmdItems = TABS.slice();
  let cmdActive = 0;

  async function refreshCmdCatalog() {
    cmdItems = TABS.slice();
    try {
      const [progs, packs] = await Promise.all([
        api("/api/programs"),
        api("/api/packs"),
      ]);
      (progs.programs || []).forEach((p) => {
        cmdItems.push({
          id: "programs",
          label: "Program " + p.id,
          kind: "program",
          hint: p.name || p.id,
        });
      });
      (packs.packs || []).forEach((pk) => {
        cmdItems.push({
          id: "hunt",
          label: "Pack " + pk.id,
          kind: "pack",
          hint: pk.pack_class || "",
        });
      });
    } catch {
      /* ignore */
    }
  }

  function renderCmd(q) {
    const ql = (q || "").trim().toLowerCase();
    const filtered = cmdItems.filter((it) => {
      if (!ql) return it.kind === "tab";
      return (
        it.label.toLowerCase().includes(ql) ||
        (it.hint || "").toLowerCase().includes(ql) ||
        it.kind.includes(ql)
      );
    });
    const ul = $("#cmd-results");
    cmdActive = 0;
    ul.innerHTML = filtered
      .slice(0, 40)
      .map(
        (it, i) =>
          "<li data-idx=\"" +
          i +
          "\" data-view=\"" +
          esc(it.id) +
          "\" class=\"" +
          (i === 0 ? "active" : "") +
          "\"><span>" +
          esc(it.label) +
          "</span><span class=\"hint\">" +
          esc(it.kind + (it.hint ? " · " + it.hint : "")) +
          "</span></li>"
      )
      .join("");
    ul._filtered = filtered.slice(0, 40);
  }

  function openCmd() {
    const pal = $("#cmd-palette");
    pal.classList.remove("hidden");
    $("#cmd-input").value = "";
    refreshCmdCatalog().then(() => {
      renderCmd("");
      $("#cmd-input").focus();
    });
  }
  function closeCmd() {
    $("#cmd-palette").classList.add("hidden");
  }
  function runCmdSelected() {
    const list = $("#cmd-results")._filtered || [];
    const it = list[cmdActive];
    if (!it) return;
    closeCmd();
    showView(it.id);
  }

  document.addEventListener("keydown", (ev) => {
    const meta = ev.ctrlKey || ev.metaKey;
    if (meta && (ev.key === "k" || ev.key === "K")) {
      ev.preventDefault();
      if ($("#cmd-palette").classList.contains("hidden")) openCmd();
      else closeCmd();
      return;
    }
    if ($("#cmd-palette").classList.contains("hidden")) return;
    if (ev.key === "Escape") {
      ev.preventDefault();
      closeCmd();
    } else if (ev.key === "ArrowDown") {
      ev.preventDefault();
      const list = $("#cmd-results")._filtered || [];
      cmdActive = Math.min(cmdActive + 1, Math.max(0, list.length - 1));
      renderCmdHighlight();
    } else if (ev.key === "ArrowUp") {
      ev.preventDefault();
      cmdActive = Math.max(0, cmdActive - 1);
      renderCmdHighlight();
    } else if (ev.key === "Enter") {
      ev.preventDefault();
      runCmdSelected();
    }
  });

  function renderCmdHighlight() {
    document.querySelectorAll("#cmd-results li").forEach((li, i) => {
      li.classList.toggle("active", i === cmdActive);
    });
  }

  $("#cmd-input").addEventListener("input", (ev) => renderCmd(ev.target.value));
  $("#cmd-results").addEventListener("click", (ev) => {
    const li = ev.target.closest("li");
    if (!li) return;
    cmdActive = Number(li.getAttribute("data-idx") || 0);
    runCmdSelected();
  });
  $("#cmd-palette").addEventListener("click", (ev) => {
    if (ev.target.id === "cmd-palette") closeCmd();
  });


})();
