(() => {
  const moves = { draft: ["open"], open: ["doing"], doing: ["open", "review"], review: ["done", "rework"], rework: ["doing", "review"] };
  const names = { draft: "草稿", open: "可领取", doing: "进行中", review: "待验收", rework: "返修中", done: "已完成" };
  let dragged = null;

  let toastTimer = 0;
  const say = text => {
    let box = document.querySelector(".wb-toast:not(.wb-refresh-notice)");
    if (!box) {
      box = document.createElement("div");
      box.className = "wb-toast";
      box.setAttribute("role", "status");
      document.body.append(box);
    }
    box.textContent = text;
    box.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { box.hidden = true; }, 2800);
  };

  const stateContext = document.querySelector?.("[data-workspace-revision]");
  if (stateContext?.dataset.workspaceRevision) {
    const initialRevision = stateContext.dataset.workspaceRevision;
    const stateUrl = new URL("/workspace-state", location.origin);
    if (stateContext.dataset.workspaceProject) stateUrl.searchParams.set("project", stateContext.dataset.workspaceProject);
    // A held request (GET /workspace-state?revision=&timeout=) answers the moment the visible state changes.
    // The plain check on a timer stays as the fallback whenever holding is refused, fails or is not honoured.
    const HOLD = 45, POLL = 20000, HELD_AT_LEAST = 2000;
    let refreshTimer = null, active = null, dirty = false, reloading = false, changed = false, notice = null;
    const clearRefreshTimer = () => { if (refreshTimer !== null) clearTimeout(refreshTimer); refreshTimer = null; };
    const scheduleRefresh = () => {
      clearRefreshTimer();
      if (!document.hidden && !reloading) refreshTimer = setTimeout(checkWorkspace, POLL);
    };
    const reloadWorkspace = () => { reloading = true; clearRefreshTimer(); location.reload(); };
    const showRefreshNotice = (text, update) => {
      changed = update;
      if (!notice) {
        notice = document.createElement("div");
        notice.className = "wb-toast wb-refresh-notice";
        notice.setAttribute("role", "status");
        const message = document.createElement("span"), button = document.createElement("button");
        button.type = "button"; button.className = "secondary btn-sm";
        button.addEventListener("click", () => { if (changed) reloadWorkspace(); else checkWorkspace(); });
        notice.append(message, button);
        document.body.append(notice);
      }
      notice.children[0].textContent = text;
      notice.children[1].textContent = update ? "刷新状态" : "重新检查";
    };
    const canRefresh = () => ["/", "/board", "/list"].includes(location.pathname) && !dirty &&
      !document.activeElement?.matches?.("input, textarea, select, [contenteditable='true']") &&
      !document.querySelector(".wb-panel, .wb-scrim, dialog[open], [role='dialog']:not([hidden]), form[data-post-pending]");
    async function checkWorkspace(hold) {
      clearRefreshTimer();
      if (document.hidden || active || reloading) return;
      // Once a change is known but cannot be applied yet, a held request would answer at once every time.
      const held = hold === true && !changed, url = new URL(stateUrl.href);
      if (held) { url.searchParams.set("revision", initialRevision); url.searchParams.set("timeout", String(HOLD)); }
      const controller = new AbortController(), request = active = {controller};
      const timeout = setTimeout(() => controller.abort(), held ? (HOLD + 8) * 1000 : 8000), started = Date.now();
      let waitNext = false;
      try {
        const response = await fetch(url.href, {method: "GET", cache: "no-store", credentials: "same-origin",
          redirect: "error", headers: {Accept: "application/json"}, signal: controller.signal});
        if (!response.ok) throw new Error("unavailable");
        const result = await response.json();
        if (typeof result.revision !== "string" || !/^[a-f0-9]{64}$/.test(result.revision)) throw new Error("invalid revision");
        if (request !== active || document.hidden) return;
        if (result.revision !== initialRevision) {
          if (canRefresh()) reloadWorkspace();
          // The page's own submission wakes its held request too; it leaves by itself, so the timer decides later.
          else if (held && document.querySelector("form[data-post-pending]")) changed = true;
          else showRefreshNotice("任务状态已有更新；当前输入和详情保留，处理完成后可刷新。", true);
        } else {
          if (notice) { notice.remove(); notice = null; }
          changed = false;
          // An unchanged answer that came back early was not held: keep to the timer instead of asking in a loop.
          waitNext = !held || Date.now() - started >= HELD_AT_LEAST;
        }
      } catch {
        // A refused or broken held request only falls back to the timer; the plain check reports a lost connection.
        if (request === active && !document.hidden && !held) {
          showRefreshNotice("暂时无法同步状态，当前内容保留；连接恢复后可重新检查。", false);
        }
      } finally {
        clearTimeout(timeout);
        if (request === active) {
          active = null;
          if (waitNext) checkWorkspace(true); else scheduleRefresh();
        }
      }
    }
    document.addEventListener("input", () => { dirty = true; });
    document.addEventListener("change", () => { dirty = true; });
    document.addEventListener("visibilitychange", () => {
      clearRefreshTimer();
      if (document.hidden) {
        if (active) { const request = active; active = null; request.controller.abort(); }
      } else checkWorkspace(true);
    });
    checkWorkspace(true);
  }

  // Actual POSTs stay on this page until a matching terminal receipt is verified.
  // Frozen bodies/File references live only with their form; never in browser storage.
  const checkingForms = new WeakSet(), formRequests = new WeakMap();
  const submissionMessage = (form, text) => {
    let message = form.querySelector("[data-submit-readiness]");
    if (!message) {
      message = document.createElement("p");
      message.dataset.submitReadiness = "";
      message.className = "muted-text";
      message.setAttribute("role", "status");
      message.setAttribute("aria-live", "polite");
      form.prepend(message);
    }
    message.textContent = text;
    return message;
  };
  const newRequestId = () => "web-" + crypto.randomUUID().replaceAll("-", "");
  const formPayload = (form, submitter) => {
    const values = new FormData(form);
    if (submitter?.name && !submitter.disabled) values.append(submitter.name, submitter.value);
    return values;
  };
  const samePayload = (first, second) => {
    const left = [...first.entries()].filter(([key]) => key !== "csrf"), right = [...second.entries()].filter(([key]) => key !== "csrf");
    return left.length === right.length && left.every(([key, value], index) => key === right[index][0] && value === right[index][1]);
  };
  const responseJson = async response => {
    const limit = 8 * 1024 * 1024;
    if (!response.headers.get("Content-Type")?.startsWith("application/json")) throw new Error("unconfirmed receipt");
    if (Number(response.headers.get("Content-Length")) > limit) throw new Error("receipt too large");
    let text = "";
    if (response.body?.getReader) {
      const reader = response.body.getReader(), decoder = new TextDecoder(); let size = 0;
      while (true) {
        const part = await reader.read(); if (part.done) break;
        size += part.value.byteLength;
        if (size > limit) { await reader.cancel(); throw new Error("receipt too large"); }
        text += decoder.decode(part.value, {stream: true});
      }
      text += decoder.decode();
    } else {
      text = await response.text();
      if (new TextEncoder().encode(text).length > limit) throw new Error("receipt too large");
    }
    return JSON.parse(text);
  };
  const receiptMatches = (value, request) => value && value.request_id === request.id &&
    ["completed", "pending", "rejected", "not_received"].includes(value.state);
  const updateCsrf = (form, request, value) => {
    if (typeof value.csrf === "string" && /^[a-f0-9]{64}$/.test(value.csrf)) {
      request.values.set("csrf", value.csrf);
      const field = form.querySelector('input[name="csrf"]'); if (field) field.value = value.csrf;
    }
  };
  const completeForm = (form, request, value) => {
    request.phase = "completed";
    if (value.redirect_url) {
      const url = new URL(value.redirect_url, location.origin);
      if (url.origin !== location.origin) throw new Error("untrusted redirect");
      location.assign(url.href); return;
    }
    submissionMessage(form, "本次页面操作已得到成功回执。当前输入仍保留；请按结果确认下一步，一次性资料请妥善保存。");
    if (typeof value.html === "string") {
      const page = new DOMParser().parseFromString(value.html, "text/html");
      const content = page.querySelector("main > .wb-page, main > .task-panel") || page.querySelector("main") || page.body;
      content.querySelectorAll("script, iframe, object, embed, header, nav").forEach(item => item.remove());
      request.resultNode?.remove();
      const result = document.createElement("section"); result.dataset.postResult = "";
      result.setAttribute("aria-label", "已确认的操作结果");
      result.append(document.importNode(content, true)); form.after(result); request.resultNode = result; setupPickers(result);
    }
    request.values = null;
  };
  const requestControls = (form, request, text) => {
    const box = submissionMessage(form, text + "（请求编号：" + request.id + "）");
    const check = document.createElement("button"); check.type = "button"; check.className = "secondary";
    check.textContent = "查询／恢复原请求";
    check.addEventListener("click", () => recoverForm(form, request)); box.append(check);
    if (request.phase === "rejected" && typeof request.received === "boolean" || request.phase === "not_received") {
      const correct = document.createElement("button"); correct.type = "button"; correct.className = "secondary";
      correct.textContent = "将当前修正作为新请求";
      correct.addEventListener("click", () => {
        if (checkingForms.has(form)) return;
        const field = form.querySelector('input[name="request_id"]');
        if (!field) return submissionMessage(form, "请按此专用表单的受控流程修正后提交，当前输入保留。");
        field.value = newRequestId();
        if (request.received === true) {
          let link = form.querySelector('input[name="supersedes_request_id"]');
          if (!link) { link = document.createElement("input"); link.type = "hidden"; link.name = "supersedes_request_id"; form.append(link); }
          link.value = request.id;
        }
        formRequests.delete(form); form.requestSubmit(request.submitter || undefined);
      }); box.append(correct);
    }
    if (request.phase === "auth") {
      const login = document.createElement("a"); login.href = "/login"; login.target = "_blank"; login.rel = "noopener";
      login.textContent = "在新页面登录（保留当前输入）"; box.append(login);
    }
  };
  const fetchFormResult = async (form, request, lookup) => {
    if (checkingForms.has(form) || !form.isConnected) return;
    if (request.retryAt && Date.now() < request.retryAt) {
      requestControls(form, request, "服务建议稍后恢复，请在 " + Math.ceil((request.retryAt - Date.now()) / 1000) + " 秒后再查询；当前输入保留。"); return;
    }
    const priorPhase = request.phase;
    checkingForms.add(form); form.setAttribute("data-post-pending", "");
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 30000);
    const status = submissionMessage(form, lookup ? "正在查询原请求，当前输入保留。" : "正在提交原请求，请等待回执；当前输入保留。");
    const cancel = document.createElement("button"); cancel.type = "button"; cancel.textContent = "取消等待";
    cancel.addEventListener("click", () => controller.abort()); status.append(cancel);
    try {
      let url, options;
      if (lookup) {
        url = new URL("/workspace-receipt", location.origin); url.searchParams.set("request", request.id);
        options = {method: "GET", credentials: "same-origin", cache: "no-store", redirect: "error", signal: controller.signal};
      } else {
        url = request.url;
        const body = request.multipart ? request.values : new URLSearchParams([...request.values.entries()]);
        options = {method: "POST", body, credentials: "same-origin", cache: "no-store", redirect: "error", signal: controller.signal,
          headers: {"X-TaskPool-Response": "json", "X-TaskPool-Request-ID": request.id}};
      }
      const response = await fetch(String(url), options);
      const suggestedDelay = Number(response.headers.get("Retry-After"));
      if ([429, 503].includes(response.status) && Number.isFinite(suggestedDelay) && suggestedDelay > 0)
        request.retryAt = Date.now() + Math.min(suggestedDelay, 120) * 1000;
      if (response.status === 401 || response.status === 403) {
        request.phase = "auth";
        requestControls(form, request, "登录或授权已变化。当前输入和原编号保留；重新登录后再查询原请求，不降低认证要求。"); return;
      }
      const value = await responseJson(response);
      if (!receiptMatches(value, request)) throw new Error("unmatched receipt");
      updateCsrf(form, request, value);
      if (value.state === "completed" && response.ok && Number(value.status) >= 200 && Number(value.status) < 300) {
        if (lookup) {
          request.phase = "confirmed"; request.received = true;
          const message = submissionMessage(form, "原请求已确认完成。需要一次性结果时可重新读取原回执；当前输入保留，不新建请求。");
          const read = document.createElement("button"); read.type = "button"; read.className = "secondary"; read.textContent = "读取原操作回执";
          read.addEventListener("click", () => fetchFormResult(form, request, false)); message.append(read); return;
        }
        completeForm(form, request, value); return;
      }
      request.phase = value.state; request.received = value.received;
      if (lookup && ["pending", "not_received"].includes(value.state) && response.status < 400) {
        if (priorPhase === "rejected" && value.state === "not_received") {
          requestControls(form, request, "原请求未受理，当前修正可作为新请求提交；原输入仍保留。"); return;
        }
        checkingForms.delete(form);
        clearTimeout(timer);
        return await fetchFormResult(form, request, false);
      }
      const retry = Number(response.headers.get("Retry-After"));
      const wait = Number.isInteger(retry) && retry > 0 && retry <= 120 ? `建议 ${retry} 秒后再查询。` : "";
      requestControls(form, request, (value.message || "请求尚未确认完成，保留原编号及首次提交内容。") + wait + " 刷新或重新登录可能需要重选文件；重新选择不能冒充原摘要已核验。");
    } catch {
      request.phase = "unknown";
      requestControls(form, request, "本次提交结果未知（网络、维护或取消等待）。当前输入、原请求编号和文件引用仍保留；先查询原结果，再恢复原内容，勿另建重复请求。");
    } finally {
      clearTimeout(timer); checkingForms.delete(form);
    }
  };
  const recoverForm = (form, request) => {
    if (!request.values) return submissionMessage(form, "原请求已完成，请查看已确认结果。");
    return fetchFormResult(form, request, true);
  };
  document.addEventListener("submit", async event => {
    const form = event.target, submitter = event.submitter;
    if (!(form instanceof HTMLFormElement) || event.defaultPrevented || form.hasAttribute("data-async-submit")) return;
    const method = submitter?.getAttribute("formmethod") || form.method;
    if (method.toLowerCase() !== "post") return;
    const action = submitter?.getAttribute("formaction") || form.action;
    if (new URL(action, location.href).origin !== location.origin) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    if (checkingForms.has(form)) return;
    const previous = formRequests.get(form);
    let values;
    try { values = formPayload(form, submitter); }
    catch { return submissionMessage(form, "浏览器未能读取表单或文件，当前输入保留；请核对文件后重试。"); }
    if (previous) {
      if (previous.phase === "completed") return submissionMessage(form, "原请求已完成，勿重复提交；请查看结果或重新打开操作。");
      if (!samePayload(values, previous.values)) {
        requestControls(form, previous, "当前内容已经修改。原请求尚未确认时不能用同一编号发送不同内容；查询／恢复只使用首次提交内容，当前修正仍保留。"); return;
      }
      return recoverForm(form, previous);
    }
    const request = {id: String(values.get("request_id") || newRequestId()), values, submitter,
      url: new URL(action, location.href).href, multipart: form.enctype === "multipart/form-data", phase: "new"};
    formRequests.set(form, request);
    return fetchFormResult(form, request, false);
  }, true);

  function setupPickers(root) {
    root.querySelectorAll("[data-identity-picker]").forEach(picker => {
      const search = picker.querySelector("[data-picker-search]"), select = picker.querySelector("select");
      if (!search || !select || picker.dataset.ready) return;
      picker.dataset.ready = "1";
      search.addEventListener("input", () => {
        const query = search.value.trim().toLocaleLowerCase();
        let matched = 0;
        Array.from(select.options).forEach(option => {
          const show = !option.value || option.selected || (option.textContent + " " + option.value).toLocaleLowerCase().includes(query);
          option.hidden = !show;
          if (option.value && show) matched += 1;
        });
        search.setAttribute("aria-description", matched ? `${matched} 个匹配身份，打开下方选择框选择。` : "没有匹配身份，请修改搜索词。");
      });
    });
  }
  setupPickers(document);

  // Persist only task-view filters. Never serialize forms, tokens, URLs or page data.
  document.querySelectorAll("[data-saved-views]").forEach(box => {
    const actor = document.querySelector("[data-view-actor]")?.dataset.viewActor;
    const picker = box.querySelector("[data-view-picker]"), input = box.querySelector("[data-view-name]");
    const status = box.querySelector("[data-view-status]");
    if (!actor) return;
    const project = new URLSearchParams(location.search).get("project") || "";
    const key = JSON.stringify(["taskpool-views-v1", actor, project, location.pathname]);
    const allowed = ["project", "q", "lane", "mine", "sort", "stage", "window", "receiver", "owner", "matching"];
    let views = [];
    const sensitiveView = value => [value.name, ...Object.values(value.filters || {})].some(item => typeof item === "string" && /\bBearer\s+[A-Za-z0-9._~+/-]{25,}|\b(?:ghp_|github_pat_|sk-proj-|sk-ant-)[A-Za-z0-9_-]{24,}|\/ai\/join\/[^\s#]+#[^\s]+/i.test(item));
    const clean = row => row && typeof row.name === "string" && row.name.length > 0 && row.name.length <= 60 &&
      row.filters && typeof row.filters === "object" && !Array.isArray(row.filters) &&
      Object.entries(row.filters).every(([name, value]) => allowed.includes(name) && typeof value === "string" && value.length <= 200) &&
      (row.filters.project || "") === project && !sensitiveView(row);
    try {
      const saved = JSON.parse(localStorage.getItem(key) || "[]");
      views = Array.isArray(saved) ? saved.filter(clean) : [];
    } catch { status.textContent = "无法读取已保存视图，当前筛选仍可使用。"; }
    const render = () => {
      picker.replaceChildren(new Option("选择视图", ""));
      views.forEach((view, index) => picker.add(new Option(view.name, String(index))));
    };
    const persist = () => {
      try { localStorage.setItem(key, JSON.stringify(views)); return true; }
      catch { status.textContent = "浏览器未允许保存视图；当前筛选仍然保留。"; return false; }
    };
    render();
    picker.addEventListener("change", () => {
      if (picker.value !== "") input.value = views[Number(picker.value)]?.name || "";
    });
    box.querySelector("[data-view-open]").addEventListener("click", () => {
      if (picker.value === "") return;
      const view = views[Number(picker.value)];
      if (!clean(view)) return;
      location.assign(location.pathname + "?" + new URLSearchParams(view.filters).toString());
    });
    box.querySelector("[data-view-save]").addEventListener("click", () => {
      const name = input.value.trim();
      if (!name) { status.textContent = "请填写视图名称。"; input.focus(); return; }
      const filters = {};
      const params = new URLSearchParams(location.search);
      allowed.forEach(key => { const value = params.get(key); if (value) filters[key] = value; });
      const view = {name, filters};
      if (sensitiveView(view)) { status.textContent = "视图条件疑似含访问凭据，请移除后保存；当前输入保留。"; return; }
      if (!clean(view)) { status.textContent = "筛选内容过长，未保存。"; return; }
      const found = views.findIndex(row => row.name === name);
      const old = views.slice();
      if (found < 0) views.push(view); else views[found] = view;
      if (!persist()) { views = old; return; }
      render(); status.textContent = "当前筛选已保存到本浏览器。";
    });
    box.querySelector("[data-view-delete]").addEventListener("click", () => {
      if (picker.value === "") { status.textContent = "请先选择要删除的视图。"; return; }
      const old = views.slice();
      views.splice(Number(picker.value), 1);
      if (!persist()) { views = old; return; }
      render(); status.textContent = "已删除所选视图。";
    });
  });

  document.addEventListener("dragstart", event => {
    const card = event.target.closest && event.target.closest(".card[data-task]");
    if (!card) return;
    dragged = card;
    card.classList.add("dragging");
    event.dataTransfer.setData("text/plain", card.dataset.task);
  });
  document.addEventListener("dragend", () => {
    if (dragged) dragged.classList.remove("dragging");
    dragged = null;
    document.querySelectorAll(".drop").forEach(item => item.classList.remove("drop"));
  });
  document.addEventListener("dragover", event => {
    const column = event.target.closest && event.target.closest("[data-col]");
    if (!column || !dragged) return;
    event.preventDefault();
    document.querySelectorAll(".drop").forEach(item => item !== column && item.classList.remove("drop"));
    column.classList.add("drop");
  });
  document.addEventListener("drop", event => {
    const column = event.target.closest && event.target.closest("[data-col]");
    if (!column || !dragged) return;
    event.preventDefault();
    const from = dragged.dataset.column, to = column.dataset.col;
    if (from === to) return;
    if (!(moves[from] || []).includes(to)) return say(`不能从「${names[from]}」直接到「${names[to]}」。`);
    const form = dragged.querySelector(`form[data-move="${to}"]`);
    if (form) return form.requestSubmit();
    if (dragged.dataset.why && (from === "draft" || from === "open")) return say(dragged.dataset.why);
    openTask(dragged.querySelector(".card-link").href);
  });

  const closePanel = () => document.querySelectorAll(".wb-panel,.wb-scrim").forEach(item => item.remove());

  const openTask = url => openLayer(url, "wb-panel", "task-sheet", "任务详情", "正在打开任务…");
  const openNew = url => openLayer(url, "wb-panel wb-modal", "new-task", "新建任务", "正在打开表单…");

  async function openLayer(url, className, target, label, waiting) {
    closePanel();
    const scrim = document.createElement("div");
    scrim.className = "wb-scrim";
    scrim.addEventListener("click", closePanel);
    const panel = document.createElement("aside");
    panel.className = className;
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-label", label);
    const close = document.createElement("button");
    close.type = "button";
    close.className = "secondary wb-close";
    close.textContent = "关闭";
    close.addEventListener("click", closePanel);
    const loading = document.createElement("p");
    loading.className = "wb-loading";
    loading.setAttribute("role", "status");
    loading.textContent = waiting;
    panel.append(close, loading);
    document.body.append(scrim, panel);
    close.focus();
    try {
      const response = await fetch(url, { credentials: "same-origin" });
      if (!response.ok) throw new Error("load");
      const page = new DOMParser().parseFromString(await response.text(), "text/html");
      const content = page.getElementById(target);
      if (!content) throw new Error("content");
      if (!panel.isConnected) return;
      loading.replaceWith(document.importNode(content, true));
      setupPickers(panel);
      const first = panel.querySelector("input[name=title]");
      if (first) first.focus();
    } catch (error) {
      location.href = url;
    }
  }

  document.addEventListener("click", event => {
    if (!event.target.closest || event.ctrlKey || event.metaKey || event.shiftKey || event.button !== 0) return;
    const create = event.target.closest("a[data-new-task]");
    if (create) {
      event.preventDefault();
      return openNew(create.href);
    }
    const direct = event.target.closest("a.card-link, a[data-task-link]");
    const holder = direct ? null : event.target.closest(".card, tr[data-task-row]");
    if (!direct && (!holder || event.target.closest("a, button, input, select, textarea, form"))) return;
    const link = direct || holder.querySelector("a.card-link");
    if (!link) return;
    event.preventDefault();
    if (window.matchMedia("(max-width: 760px)").matches) location.href = link.href;
    else openTask(link.href);
  });
  document.addEventListener("change", event => {
    const form = event.target.closest && event.target.closest("form[data-auto]");
    if (form) form.requestSubmit();
  });
  document.addEventListener("keydown", event => { if (event.key === "Escape") closePanel(); });
})();
