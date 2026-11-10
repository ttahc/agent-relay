"use strict";
const assert = require("node:assert/strict"), fs = require("node:fs"), vm = require("node:vm"), crypto = require("node:crypto");
const response = (status, value, type = "application/json") => ({status, ok: status >= 200 && status < 300,
  headers: {get: name => name.toLowerCase() === "content-type" ? type : null},
  text: async () => type === "application/json" ? JSON.stringify(value) : String(value)});
const complete = (id, extra = {}) => response(200, {state: "completed", status: 200, request_id: id, redirect_url: "/tasks/T1", ...extra});

function fixture(reply, multipart = false) {
  const handlers = [], calls = [], navigated = [], timers = new Map(), selectors = []; let serial = 0, storage = 0, nativePosts = 0;
  class Node {
    constructor() { this.children = []; this.dataset = {}; this.events = {}; this._text = ""; }
    set textContent(value) { this._text = value; this.children = []; }
    get textContent() { return this._text; }
    append(...items) { this.children.push(...items); }
    setAttribute() {}
    addEventListener(name, callback) { this.events[name] = callback; }
    remove() {}
    querySelectorAll(selector) { selectors.push(selector); return []; }
  }
  class Form extends Node {
    constructor() {
      super(); this.method = "post"; this.enctype = multipart ? "multipart/form-data" : "application/x-www-form-urlencoded";
      this.action = "https://fixture.test/actions/example"; this.isConnected = true; this.attributes = new Map();
      this.values = [["request_id", "original-request"], ["csrf", "a".repeat(64)], ["body", "original text"], ["password", "private-input"]];
      this.results = [];
    }
    hasAttribute(name) { return this.attributes.has(name); }
    getAttribute(name) { return this.attributes.get(name) ?? null; }
    setAttribute(name, value) { this.attributes.set(name, value); }
    field(name) {
      const row = this.values.find(item => item[0] === name); if (!row) return null;
      return {get value() { return row[1]; }, set value(value) { row[1] = value; }};
    }
    querySelector(selector) {
      if (selector === "[data-submit-readiness]") return this.message;
      const match = selector.match(/^input\[name="([^"]+)"\]$/); return match ? this.field(match[1]) : null;
    }
    prepend(item) { this.message = item; }
    after(item) { this.results.push(item); }
    append(item) {
      if (item.name) { const row = [item.name]; Object.defineProperty(row, "1", {get: () => item.value, set: value => { item.value = value; }, enumerable: true}); row.length = 2; this.values.push(row); }
      else super.append(item);
    }
    requestSubmit(button) { return emit(this, button); }
  }
  class FormValues {
    constructor(form) { this.values = form.values.map(row => row.slice()); }
    entries() { return this.values[Symbol.iterator](); }
    append(key, value) { this.values.push([key, value]); }
    get(key) { return this.values.find(row => row[0] === key)?.[1] ?? null; }
    set(key, value) { this.values = this.values.filter(row => row[0] !== key); this.values.push([key, value]); }
  }
  const document = {querySelector: () => null, querySelectorAll: () => [], createElement: () => new Node(), importNode: node => node,
    addEventListener(type, callback, capture) { if (type === "submit") handlers.push({callback, capture}); }};
  const forbidden = new Proxy({}, {get() { storage++; throw Error("credential storage forbidden"); }});
  const env = {document, window: {addEventListener() {}}, HTMLFormElement: Form, FormData: FormValues,
    URL, URLSearchParams, AbortController, TextEncoder, TextDecoder, crypto,
    DOMParser: class { parseFromString() { const content = new Node(); content.confirmationForm = true; return {querySelector: () => content, body: content}; } },
    location: {href: "https://fixture.test/", origin: "https://fixture.test", pathname: "/", assign: value => navigated.push(value)},
    localStorage: forbidden, sessionStorage: forbidden,
    setTimeout(callback, delay) { const id = ++serial; timers.set(id, {callback, delay}); return id; }, clearTimeout: id => timers.delete(id),
    fetch: async (url, options) => { calls.push({url, options}); return reply(url, options, calls.length); }};
  const context = vm.createContext(env);
  vm.runInContext(fs.readFileSync("pool/round_web.py", "utf8").match(/SCRIPT = """([\s\S]*?)"""\.encode/)[1], context);
  vm.runInContext(fs.readFileSync("pool/workbench.js", "utf8"), context);
  async function emit(form, button) {
    const event = {target: form, submitter: button, defaultPrevented: false, stopped: false,
      preventDefault() { this.defaultPrevented = true; }, stopImmediatePropagation() { this.stopped = true; }};
    const pending = [];
    for (const handler of [...handlers].sort((a, b) => Number(Boolean(b.capture)) - Number(Boolean(a.capture)))) {
      pending.push(handler.callback(event)); if (event.stopped) break;
    }
    if (!event.defaultPrevented) nativePosts++;
    await Promise.all(pending);
  }
  const button = {name: "decision", value: "save", disabled: false, getAttribute: () => null, after() {}};
  const form = new Form();
  return {form, button, emit: () => emit(form, button), calls, navigated, selectors, storage: () => storage, nativePosts: () => nativePosts,
    control: text => form.message.children.find(item => item.textContent === text)};
}

(async () => {
  const ok = fixture((url, options) => complete(options.headers["X-TaskPool-Request-ID"])); await ok.emit();
  assert.equal(ok.nativePosts(), 0); assert.equal(ok.calls[0].options.method, "POST");
  assert.equal(ok.calls[0].options.body.get("request_id"), "original-request");
  assert.equal(ok.calls[0].options.body.get("decision"), "save"); assert.equal(ok.form.field("body").value, "original text");
  assert.equal(ok.navigated.length, 1); assert.equal(ok.storage(), 0); assert.equal(ok.button.disabled, false);
  const preview = fixture(() => complete("original-request", {redirect_url: null, html: "<main><form>confirm</form></main>"}));
  await preview.emit(); assert.equal(preview.navigated.length, 0); assert.equal(preview.form.results.length, 1);
  assert.equal(preview.form.results[0].children[0].confirmationForm, true);
  assert.ok(preview.selectors.every(selector => !selector.split(/,\s*/).includes("form")));
  assert.equal(preview.form.children.length, 0);

  const lost = fixture((url, options, n) => { if (n === 1) throw Error("lost acknowledgement"); return complete("original-request"); });
  await lost.emit(); lost.form.field("body").value = "corrected text"; await lost.emit();
  assert.equal(lost.calls.length, 1); assert.match(lost.form.message.textContent, /内容已经修改/);
  await lost.control("查询／恢复原请求").events.click();
  assert.equal(lost.calls[1].options.method, "GET"); assert.equal(lost.calls.length, 2); assert.equal(lost.navigated.length, 0);
  await lost.control("读取原操作回执").events.click();
  assert.equal(lost.calls.length, 3); assert.equal(lost.navigated.length, 1);
  assert.equal(lost.calls[2].options.body.get("body"), "original text");
  assert.equal(lost.form.field("body").value, "corrected text");

  const file = {name: "output.txt", size: 4};
  const files = fixture((url, options, n) => n === 1 ? response(503, "maintenance", "text/html") :
    n === 2 ? response(200, {state: "not_received", status: 200, request_id: "original-request", received: false}) : complete("original-request"), true);
  files.form.values.push(["artifact", file]); await files.emit();
  assert.equal(files.navigated.length, 0); assert.equal(files.form.values.at(-1)[1], file);
  await files.control("查询／恢复原请求").events.click();
  assert.equal(files.calls[2].options.body.get("artifact"), file); assert.equal(files.calls[2].options.body.get("decision"), "save");

  const pending = fixture((url, options, n) => n < 3 ? response(202, {state: "pending", status: 202, request_id: "original-request", received: true}) : complete("original-request"));
  await pending.emit(); await pending.control("查询／恢复原请求").events.click();
  assert.deepEqual(pending.calls.map(call => call.options.method), ["POST", "GET", "POST"]);
  assert.equal(String(pending.calls[0].options.body), String(pending.calls[2].options.body));

  const rejected = fixture((url, options, n) => n === 1 ? response(409, {state: "rejected", status: 409, request_id: "original-request", received: true, message: "fix"}) : complete(options.headers["X-TaskPool-Request-ID"]));
  await rejected.emit(); rejected.form.field("body").value = "fixed";
  await rejected.control("将当前修正作为新请求").events.click();
  const corrected = rejected.calls[1].options.body;
  assert.notEqual(corrected.get("request_id"), "original-request"); assert.equal(corrected.get("supersedes_request_id"), "original-request");
  assert.equal(corrected.get("body"), "fixed"); assert.equal(rejected.form.field("password").value, "private-input");

  const auth = fixture(() => response(401, "expired", "text/html")); await auth.emit();
  assert.equal(auth.navigated.length, 0); assert.ok(auth.control("在新页面登录（保留当前输入）")); assert.equal(auth.storage(), 0);
  const resumed = fixture((url, options, n) => n === 1 ? response(401, "expired", "text/html") :
    n === 2 ? response(202, {state: "pending", status: 202, request_id: "original-request", received: true, csrf: "b".repeat(64)}) : complete("original-request"));
  await resumed.emit(); await resumed.control("查询／恢复原请求").events.click();
  assert.equal(resumed.calls[2].options.body.get("csrf"), "b".repeat(64));
  assert.equal(resumed.calls[2].options.body.get("request_id"), "original-request"); assert.equal(resumed.form.field("password").value, "private-input");
  const wrong = fixture(() => complete("wrong-request")); await wrong.emit(); assert.equal(wrong.navigated.length, 0);
  const foreign = fixture(() => complete("original-request", {redirect_url: "https://other.test/"})); await foreign.emit(); assert.equal(foreign.navigated.length, 0);

  let resolve;
  const concurrent = fixture(() => new Promise(done => { resolve = done; }));
  const first = concurrent.emit(); await concurrent.emit(); assert.equal(concurrent.calls.length, 1);
  resolve(complete("original-request")); await first; assert.equal(concurrent.nativePosts(), 0);
  console.log("PASS actual POST receipt verification, lost acknowledgements, frozen File/submitter/RID recovery, pending continuation, linked correction, auth, duplicate suppression and no storage");
})().catch(error => { console.error(error); process.exitCode = 1; });
