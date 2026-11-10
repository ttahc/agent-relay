"use strict";
// Execute actual refresh code with synthetic DOM, clock and replies. No service or storage.
// The page first holds a request open (event-driven); the 20 s timer with a plain check is its fallback.
const assert = require("node:assert/strict"), fs = require("node:fs"), vm = require("node:vm");
const original = "a".repeat(64), updated = "b".repeat(64);
const PLAIN = "https://fixture.test/workspace-state?project=p";
const HELD = PLAIN + "&revision=" + original + "&timeout=45";
const reply = (revision = updated, ok = true) => ({ok, json: async () => ({revision, version: "fixture"})});
const refused = () => reply(original, false);  // e.g. 429: every waiting place is taken
const tick = async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); };

// `response` answers the plain timer check, `held` the request that is kept open.
function fixture(response = () => reply(), held = refused) {
  const state = {reloads: 0, calls: 0, plain: 0, held: 0, dirtyText: "unfinished input", panel: false, focus: false,
    pending: false, storage: 0, now: 1000000, signals: []};
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
    querySelector: selector => selector === "[data-workspace-revision]" ? context :
      selector === "form[data-post-pending]" ? (state.pending ? {} : null) : state.panel || state.pending ? {} : null,
    querySelectorAll: () => [], createElement: () => new Element(), body: {append: item => notices.push(item)},
    addEventListener(name, callback) { (listeners[name] ||= []).push(callback); }
  };
  const storage = new Proxy({}, {get() { state.storage++; throw Error("storage forbidden"); }});
  const env = {document, URL, URLSearchParams, AbortController, Date: {now: () => state.now},
    location: {origin: "https://fixture.test", href: "https://fixture.test/", pathname: "/", reload() { state.reloads++; }},
    localStorage: storage, sessionStorage: storage,
    setTimeout(callback, delay) { const id = nextTimer++; timers.set(id, {callback, delay}); return id; },
    clearTimeout(id) { timers.delete(id); },
    fetch: async (url, options) => {
      state.calls++;
      assert.ok(url === PLAIN || url === HELD, "unexpected request " + url);
      assert.equal(options.method, "GET"); assert.equal(options.cache, "no-store");
      assert.equal(options.credentials, "same-origin"); assert.equal(options.body, undefined);
      assert.equal(options.redirect, "error");
      state.signals.push(options.signal);
      if (url === HELD) { state.held++; return held(); }
      state.plain++; return response();
    }};
  vm.runInNewContext(fs.readFileSync("pool/workbench.js", "utf8"), env);
  const delays = delay => [...timers.values()].filter(timer => timer.delay === delay).length;
  return {state, document, timers, notices, delays, emit: name => (listeners[name] || []).forEach(callback => callback({})),
    async poll() {
      const timer = [...timers].find(([, item]) => item.delay === 20000);
      assert.ok(timer, "expected one polling timer"); timers.delete(timer[0]); await timer[1].callback(); await tick();
    }};
}
// A page whose held request was refused at load: it is on the timer, as before event-driven refresh existed.
async function onTimer(response, held) {
  const page = fixture(response, held); await tick();
  assert.equal(page.state.held, 1, "the page asks to be held first"); assert.equal(page.state.plain, 0);
  assert.equal(page.notices.length, 0, "a refused held request is not reported"); assert.equal(page.delays(20000), 1);
  return page;
}
// A held request the test answers when it chooses.
function parked() {
  const waiting = [];
  return {waiting, held: () => new Promise((resolve, reject) => waiting.push({resolve, reject}))};
}

(async () => {
  // --- The timer fallback: the six scenarios that held before, now reached after a refused held request.
  const automatic = await onTimer(); await automatic.poll();
  assert.equal(automatic.state.reloads, 1); assert.equal(automatic.timers.size, 0);

  const editing = await onTimer(); editing.emit("input"); await editing.poll();
  assert.equal(editing.state.reloads, 0); assert.equal(editing.state.dirtyText, "unfinished input");
  assert.equal(editing.notices.length, 1); assert.equal(editing.notices[0].children[1].textContent, "刷新状态");
  assert.equal(editing.state.storage, 0);
  const focused = await onTimer(); focused.state.focus = true; await focused.poll(); assert.equal(focused.state.reloads, 0);

  const panel = await onTimer(); panel.state.panel = true; await panel.poll();
  assert.equal(panel.state.reloads, 0); assert.equal(panel.state.panel, true);
  assert.match(panel.notices[0].children[0].textContent, /详情保留/);

  for (const response of [() => reply(updated, false), () => { throw Error("offline"); }]) {
    const unavailable = await onTimer(response); await unavailable.poll();
    assert.equal(unavailable.state.reloads, 0); assert.equal(unavailable.state.dirtyText, "unfinished input");
    assert.match(unavailable.notices[0].children[0].textContent, /当前内容保留/);
    assert.equal(unavailable.notices[0].children[1].textContent, "重新检查");
    assert.equal(unavailable.delays(20000), 1, "the timer keeps checking while the service is away");
  }

  let asked = 0;
  const hidden = await onTimer(undefined, () => asked++ ? reply() : refused()); hidden.document.hidden = true; hidden.emit("visibilitychange");
  assert.equal(hidden.timers.size, 0); assert.equal(hidden.state.calls, 1);
  hidden.document.hidden = false; hidden.emit("visibilitychange"); await tick();
  assert.equal(hidden.state.calls, 2); assert.equal(hidden.state.reloads, 1);

  const one = parked(), single = fixture(undefined, one.held);
  single.emit("visibilitychange"); single.emit("visibilitychange");
  assert.equal(single.state.calls, 1, "one request at a time");
  one.waiting[0].resolve(reply(original)); await tick();
  assert.equal(single.delays(20000), 1); assert.equal(single.state.calls, 1);
  assert.equal(single.state.reloads, 0); assert.equal(single.state.storage, 0);

  // --- Event-driven refresh: the held request.
  const wake = parked(), live = fixture(undefined, wake.held); await tick();
  assert.equal(live.state.held, 1); assert.equal(live.delays(20000), 0, "no polling timer while a request is held");
  assert.equal(live.delays(53000), 1, "the held request has its own, longer limit");
  live.state.now += 7000; wake.waiting[0].resolve(reply()); await tick();
  assert.equal(live.state.reloads, 1, "a change reloads the page when it arrives, not at the next poll");
  assert.equal(live.state.calls, 1); assert.equal(live.timers.size, 0);

  const quiet = parked(), idle = fixture(undefined, quiet.held); await tick();
  idle.state.now += 45000; quiet.waiting[0].resolve(reply(original)); await tick();
  assert.equal(idle.state.held, 2, "an unchanged answer after the hold is followed by the next held request");
  assert.equal(idle.state.plain, 0); assert.equal(idle.delays(20000), 0); assert.equal(idle.notices.length, 0);
  idle.state.now += 3000; quiet.waiting[1].resolve(reply()); await tick();
  assert.equal(idle.state.reloads, 1);

  // A service or proxy that answers "unchanged" at once is not holding: no request loop, back to the timer.
  const eager = fixture(() => reply(original), () => reply(original)); await tick();
  assert.equal(eager.state.calls, 1); assert.equal(eager.delays(20000), 1); assert.equal(eager.notices.length, 0);
  await eager.poll();
  assert.equal(eager.state.plain, 1, "the timer check is the plain one");
  assert.equal(eager.state.held, 2, "a successful plain check tries holding again");
  assert.equal(eager.delays(20000), 1); assert.equal(eager.state.reloads, 0);

  // A held request that breaks (network, upgrade, timeout) falls back quietly; the plain check reports trouble.
  const broken = fixture(() => { throw Error("offline"); }, () => { throw Error("reset"); }); await tick();
  assert.equal(broken.notices.length, 0); assert.equal(broken.delays(20000), 1);
  await broken.poll();
  assert.match(broken.notices[0].children[0].textContent, /当前内容保留/); assert.equal(broken.state.held, 1);

  // A change that cannot be applied yet is announced once and then followed by the timer, never by held requests.
  const busy = parked(), typing = fixture(() => reply(), busy.held); await tick();
  typing.emit("input"); typing.state.now += 4000; busy.waiting[0].resolve(reply()); await tick();
  assert.equal(typing.state.reloads, 0); assert.equal(typing.notices.length, 1);
  assert.equal(typing.notices[0].children[1].textContent, "刷新状态");
  assert.equal(typing.state.calls, 1); assert.equal(typing.delays(20000), 1);
  await typing.poll(); await typing.poll();
  assert.equal(typing.state.held, 1, "a known change is not asked for with held requests");
  assert.equal(typing.state.plain, 2); assert.equal(typing.state.reloads, 0);
  typing.notices[0].children[1].events.click();
  assert.equal(typing.state.reloads, 1, "the notice's button applies the change");

  // The page's own submission wakes its held request too: no notice while it is still being confirmed.
  const own = parked(), sending = fixture(() => reply(), own.held); await tick();
  sending.state.pending = true; sending.state.now += 500; own.waiting[0].resolve(reply()); await tick();
  assert.equal(sending.state.reloads, 0); assert.equal(sending.notices.length, 0); assert.equal(sending.delays(20000), 1);
  sending.state.pending = false; await sending.poll();
  assert.equal(sending.state.plain, 1); assert.equal(sending.state.reloads, 1);

  // A hidden page gives its held request up; coming back asks again and the stale answer is ignored.
  const away = parked(), tab = fixture(undefined, away.held); await tick();
  tab.document.hidden = true; tab.emit("visibilitychange");
  assert.equal(tab.state.signals[0].aborted, true, "the held request is closed with the page hidden");
  assert.equal(tab.delays(20000), 0);
  tab.document.hidden = false; tab.emit("visibilitychange"); await tick();
  assert.equal(tab.state.held, 2, "a visible page asks again at once");
  away.waiting[0].reject(Error("aborted")); await tick();
  assert.equal(tab.state.held, 2); assert.equal(tab.notices.length, 0); assert.equal(tab.delays(20000), 0);
  tab.state.now += 9000; away.waiting[1].resolve(reply()); await tick();
  assert.equal(tab.state.reloads, 1); assert.equal(tab.state.storage, 0);

  console.log("PASS 6 timer-fallback scenarios: automatic, edit/focus, panel/dialog guard, maintenance/network, visibility, single inflight");
  console.log("PASS 7 held-request scenarios: change at once, re-hold, not-held guard, quiet fallback, known change, own submission, hidden tab");
})().catch(error => { console.error(error); process.exitCode = 1; });
