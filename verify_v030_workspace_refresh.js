"use strict";
// Execute actual polling code with synthetic DOM, clock and replies. No service or storage.
const assert = require("node:assert/strict"), fs = require("node:fs"), vm = require("node:vm");
const original = "a".repeat(64), updated = "b".repeat(64);
const reply = (revision = updated, ok = true) => ({ok, json: async () => ({revision, version: "fixture"})});
const tick = async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); };

function fixture(response = () => reply()) {
  const state = {reloads: 0, calls: 0, dirtyText: "unfinished input", panel: false, focus: false, storage: 0};
  const listeners = {}, timers = new Map(), notices = [];
  let nextTimer = 1;
  class Element {
    constructor() { this.children = []; this.dataset = {}; this.events = {}; this.removed = false; }
    setAttribute() {}
    append(...items) { this.children.push(...items); }
    addEventListener(name, callback) { this.events[name] = callback; }
    remove() { this.removed = true; }
  }
  const context = {dataset: {workspaceRevision: original, workspaceProject: "p"}};
  const document = {
    hidden: false, activeElement: {matches: () => state.focus},
    querySelector: selector => selector === "[data-workspace-revision]" ? context : state.panel ? {} : null,
    querySelectorAll: () => [], createElement: () => new Element(), body: {append: item => notices.push(item)},
    addEventListener(name, callback) { (listeners[name] ||= []).push(callback); }
  };
  const storage = new Proxy({}, {get() { state.storage++; throw Error("storage forbidden"); }});
  const env = {document, URL, URLSearchParams, AbortController,
    location: {origin: "https://fixture.test", href: "https://fixture.test/", pathname: "/", reload() { state.reloads++; }},
    localStorage: storage, sessionStorage: storage,
    setTimeout(callback, delay) { const id = nextTimer++; timers.set(id, {callback, delay}); return id; },
    clearTimeout(id) { timers.delete(id); },
    fetch: async (url, options) => {
      state.calls++;
      assert.equal(url, "https://fixture.test/workspace-state?project=p");
      assert.equal(options.method, "GET"); assert.equal(options.cache, "no-store");
      assert.equal(options.credentials, "same-origin"); assert.equal(options.body, undefined);
      return response();
    }};
  vm.runInNewContext(fs.readFileSync("pool/workbench.js", "utf8"), env);
  return {state, document, timers, notices, emit: name => (listeners[name] || []).forEach(callback => callback({})),
    async poll() {
      const timer = [...timers].find(([, item]) => item.delay === 20000);
      assert.ok(timer, "expected one polling timer"); timers.delete(timer[0]); await timer[1].callback();
    }};
}

(async () => {
  const automatic = fixture(); await automatic.poll();
  assert.equal(automatic.state.reloads, 1); assert.equal(automatic.timers.size, 0);

  const editing = fixture(); editing.emit("input"); await editing.poll();
  assert.equal(editing.state.reloads, 0); assert.equal(editing.state.dirtyText, "unfinished input");
  assert.equal(editing.notices.length, 1); assert.equal(editing.notices[0].children[1].textContent, "刷新状态");
  assert.equal(editing.state.storage, 0);
  const focused = fixture(); focused.state.focus = true; await focused.poll(); assert.equal(focused.state.reloads, 0);

  const panel = fixture(); panel.state.panel = true; await panel.poll();
  assert.equal(panel.state.reloads, 0); assert.equal(panel.state.panel, true);
  assert.match(panel.notices[0].children[0].textContent, /详情保留/);

  for (const response of [() => reply(updated, false), () => { throw Error("offline"); }]) {
    const unavailable = fixture(response); await unavailable.poll();
    assert.equal(unavailable.state.reloads, 0); assert.equal(unavailable.state.dirtyText, "unfinished input");
    assert.match(unavailable.notices[0].children[0].textContent, /当前内容保留/);
    assert.equal(unavailable.notices[0].children[1].textContent, "重新检查");
  }

  const hidden = fixture(); hidden.document.hidden = true; hidden.emit("visibilitychange");
  assert.equal(hidden.timers.size, 0); assert.equal(hidden.state.calls, 0);
  hidden.document.hidden = false; hidden.emit("visibilitychange"); await tick();
  assert.equal(hidden.state.calls, 1); assert.equal(hidden.state.reloads, 1);

  let resolve;
  const single = fixture(() => new Promise(done => { resolve = done; }));
  single.emit("visibilitychange"); single.emit("visibilitychange");
  assert.equal(single.state.calls, 1);
  resolve(reply(original)); await tick();
  assert.equal([...single.timers.values()].filter(timer => timer.delay === 20000).length, 1);
  assert.equal(single.state.reloads, 0); assert.equal(single.state.storage, 0);
  console.log("PASS 6 refresh scenarios: automatic, edit/focus, panel/dialog guard, maintenance/network, visibility, single timer/inflight");
})().catch(error => { console.error(error); process.exitCode = 1; });
