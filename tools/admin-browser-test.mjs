#!/usr/bin/env node
// Execute the shipped browser script with a minimal DOM and controlled fetch.
// This deterministic lifecycle regression is not a replacement for browser QA.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createContext, runInContext } from "node:vm";

const source = readFileSync(
  new URL("../components/admin/web/app.js", import.meta.url),
  "utf8",
);
const html = readFileSync(
  new URL("../components/admin/web/index.html", import.meta.url),
  "utf8",
);

class DOMNode {
  constructor() {
    this.children = [];
    this.parent = null;
    this.ownText = "";
  }
  append(...children) {
    for (let child of children) {
      if (!(child instanceof DOMNode)) {
        const text = new DOMNode();
        text.ownText = String(child);
        child = text;
      }
      child.parent = this;
      this.children.push(child);
    }
  }
  replaceChildren(...children) {
    for (const child of this.children) child.parent = null;
    this.children = [];
    this.ownText = "";
    this.append(...children);
  }
  get textContent() {
    return this.ownText + this.children.map((child) => child.textContent).join("");
  }
  set textContent(value) {
    this.replaceChildren();
    this.ownText = String(value);
  }
}
class Element extends DOMNode {
  constructor(tag) {
    super();
    this.tagName = tag;
    this.attributes = new Map();
    this.dataset = {};
    this.events = new Map();
    this.hidden = false;
    this.open = false;
    this.disabled = false;
    this.value = "";
    this.className = "";
    this.classList = {add: (...names) => {this.className = [...new Set([...this.className.split(/\s+/).filter(Boolean), ...names])].join(" ");}};
    this.style = {};
  }
  setAttribute(key, value) {
    this.attributes.set(key, String(value));
    if (key === "value") this.value = String(value);
    if (key.startsWith("data-")) this.dataset[key.slice(5)] = String(value);
  }
  removeAttribute(key) {
    this.attributes.delete(key);
  }
  addEventListener(type, callback) {
    if (!this.events.has(type)) this.events.set(type, []);
    this.events.get(type).push(callback);
  }
  dispatch(type, event = {}) {
    return Promise.all(
      (this.events.get(type) || []).map((callback) =>
        callback({ target: this, preventDefault() {}, ...event }),
      ),
    );
  }
  focus() {}
  close() {
    this.open = false;
  }
  showModal() {
    this.open = true;
  }
  querySelectorAll(selector) {
    const result = [];
    const visit = (parent) => {
      for (const child of parent.children) {
        if (!(child instanceof Element)) continue;
        if (matches(child, selector)) result.push(child);
        visit(child);
      }
    };
    visit(this);
    return result;
  }
  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }
}
function matches(element, selector) {
  const pieces = selector.split(/\s+/);
  const last = pieces.pop();
  const simple = (node, pattern) => {
    const tag = pattern.match(/^[a-z]+/);
    if (tag && node.tagName !== tag[0]) return false;
    const id = pattern.match(/#([\w-]+)/);
    if (id && node.attributes.get("id") !== id[1]) return false;
    const cls = pattern.match(/\.([\w-]+)/);
    if (cls && !node.className.split(/\s+/).includes(cls[1])) return false;
    const attr = pattern.match(/\[([\w-]+)(?:=["']?([^"'\]]+)["']?)?\]/);
    if (attr) {
      if (attr[1] === "open") return node.open;
      if (!node.attributes.has(attr[1])) return false;
      if (attr[2] !== undefined && node.attributes.get(attr[1]) !== attr[2])
        return false;
    }
    return true;
  };
  if (!simple(element, last)) return false;
  for (const piece of pieces.reverse()) {
    do {
      element = element.parent;
    } while (element && !simple(element, piece));
    if (!element) return false;
  }
  return true;
}
const settle = () => new Promise((resolve) => setImmediate(resolve));
function harness() {
  const root = new Element("body");
  const header = new Element("header"), footer = new Element("footer");
  header.setAttribute("id", "console-header");
  footer.setAttribute("id", "console-footer");
  // Model the hard-hidden attributes from the shipped document, before JS runs.
  for (const node of [header, footer]) {
    const tag = html.match(new RegExp(`<${node.tagName}[^>]*id="${node.attributes.get("id")}"[^>]*>`))?.[0];
    node.hidden = !!tag && /\bhidden\b/.test(tag);
  }
  root.append(header);
  for (const id of [
    "main", "modal", "drawer", "toast", "signout", "network-name",
    "mode-badge", "updated", "public-links",
  ]) {
    const element = new Element(id === "modal" ? "dialog" : "div");
    element.setAttribute("id", id);
    if (["signout", "network-name", "mode-badge"].includes(id)) header.append(element);
    else if (["updated", "public-links"].includes(id)) footer.append(element);
    else root.append(element);
  }
  root.append(footer);
  for (const page of ["machines", "users", "access", "dns", "settings"]) {
    const link = new Element("a");
    link.setAttribute("data-page", page);
    header.append(link);
  }
  const document = {
    title: "Tailgate",
    querySelector: (selector) => root.querySelector(selector),
    querySelectorAll: (selector) => root.querySelectorAll(selector),
    createElement: (tag) => new Element(tag),
    createTextNode: (text) => {
      const node = new DOMNode();
      node.textContent = text;
      return node;
    },
    addEventListener() {},
  };
  const requests = [];
  const navigations = [];
  const context = createContext({
    document,
    Node: DOMNode,
    window: { addEventListener() {} },
    location: { hash: "#settings", assign(path) { navigations.push(path); }, reload() {} },
    navigator: { clipboard: { writeText: async () => {} } },
    AbortController,
    setTimeout,
    clearTimeout,
    innerWidth: 1200,
    innerHeight: 800,
    fetch: (path, options) => new Promise((resolve, reject) => {
      // Deliberately allow replies after abort: the epoch guard must still work.
      requests.push({
        path,
        options,
        fail: reject,
        reply: (value, status = 200) => resolve({
          status,
          ok: status >= 200 && status < 300,
          json: async () => value,
        }),
      });
    }),
  });
  runInContext(source, context, { filename: "app.js" });
  return {
    document,
    requests,
    navigations,
    element: (id) => document.querySelector(`#${id}`),
    run: (code) => runInContext(code, context),
    take(path) {
      const index = requests.findIndex((request) => request.path === path);
      assert.notEqual(index, -1, `Expected ${path} request`);
      return requests.splice(index, 1)[0];
    },
  };
}
const privateSnapshot = {
  demo: false,
  writes: true,
  nodes: [{
    id: "1", name: "private-device", givenName: "private-device",
    ipAddresses: ["100.64.0.2"], online: true,
    user: { id: "1", email: "alice@example.com" }, tags: [], approvedRoutes: [],
  }],
  users: [{ id: "1", name: "alice", email: "alice@example.com" }],
  settings: { deviceDomain: "private.mesh.example.com" },
  updatedAt: "2026-01-01T12:00:00Z",
};
function visible(element) {
  for (let node = element; node; node = node.parent) {
    if (node.hidden) return false;
  }
  return true;
}
function assertConsoleHidden(h) {
  assert.equal(visible(h.element("console-header")), false);
  assert.equal(visible(h.element("console-footer")), false);
  for (const link of h.document.querySelectorAll("[data-page]"))
    assert.equal(visible(link), false, "Console navigation is hidden");
  for (const id of ["mode-badge", "network-name", "signout", "updated", "public-links"])
    assert.equal(visible(h.element(id)), false, `${id} is hidden`);
}
function assertConsoleVisible(h) {
  assert.equal(visible(h.element("console-header")), true);
  assert.equal(visible(h.element("console-footer")), true);
  for (const link of h.document.querySelectorAll("[data-page]"))
    assert.equal(visible(link), true, "Authenticated navigation is visible");
}
async function signedIn() {
  const h = harness();
  h.take("/api/session").reply({ authenticated: true, demo: false, csrf: "original-csrf", authMode: "token" });
  await settle();
  h.take("/api/snapshot").reply(JSON.parse(JSON.stringify(privateSnapshot)));
  await settle();
  assert.ok(h.element("main").textContent.includes("Private administrator session"));
  assertConsoleVisible(h);
  return h;
}
function assertSignedOut(h) {
  assertConsoleHidden(h);
  assert.ok(h.document.querySelector(".login"));
  assert.equal(h.run("data"), null);
  assert.equal(h.run("csrf"), "");
  assert.equal(h.element("drawer").hidden, true);
  assert.equal(h.element("drawer").textContent, "");
  assert.equal(h.element("modal").open, false);
  assert.equal(h.element("modal").textContent, "");
  assert.equal(h.element("toast").hidden, true);
  assert.equal(h.element("toast").textContent, "");
  assert.equal(h.element("network-name").textContent, "Your network");
  assert.equal(h.element("updated").textContent, "");
  assert.equal(h.element("signout").hidden, true);
  assert.equal(h.document.title, "Sign in · Tailgate");
  assert.equal(h.document.querySelectorAll("[aria-current]").length, 0);
}

test("logout clears protected UI immediately and rejects a delayed snapshot", async () => {
  const h = await signedIn();
  h.run("showDevice(data.nodes[0]); showDialog('Private dialog', el('p', {}, 'private details'))");
  const pending = h.run("refresh()");
  const snapshot = h.take("/api/snapshot");
  const logout = h.element("signout").dispatch("click");
  assertSignedOut(h);
  assert.equal(snapshot.options.signal.aborted, true);
  const revocation = h.take("/api/logout");
  assert.equal(revocation.options.headers["X-CSRF-Token"], "original-csrf");
  assert.equal(revocation.options.signal.aborted, false);
  assert.equal(h.document.querySelector('.login button[type="submit"]').disabled, true);
  h.document.querySelector("#login-token").value = "fictitious-login-token";
  await h.document.querySelector(".login").dispatch("submit");
  assert.equal(h.requests.length, 0, "No new login while old logout is pending");
  snapshot.reply(privateSnapshot);
  await pending;
  assertSignedOut(h);
  revocation.reply({ ok: true });
  await logout;
  assertSignedOut(h);
  assert.equal(h.document.querySelector('.login button[type="submit"]').disabled, false);
});

test("logout rejects a snapshot whose body finishes after its headers", async () => {
  const h = await signedIn();
  const pending = h.run("refresh()");
  const snapshot = h.take("/api/snapshot");
  let finishBody;
  snapshot.reply(new Promise((resolve) => { finishBody = resolve; }));
  await settle();
  const logout = h.element("signout").dispatch("click");
  const revocation = h.take("/api/logout");
  finishBody(privateSnapshot);
  await pending;
  assertSignedOut(h);
  revocation.reply({ ok: true });
  await logout;
  assertSignedOut(h);
});

test("401 clears CSRF, private data and overlays", async () => {
  const h = await signedIn();
  h.run("showDevice(data.nodes[0]); showDialog('Private dialog', el('p', {}, 'private details'))");
  const pending = h.run("refresh()");
  h.take("/api/snapshot").reply({ error: "Sign in to continue" }, 401);
  await pending;
  assertSignedOut(h);
});

test("a late login result cannot restore a cleared session", async () => {
  const h = harness();
  h.take("/api/session").reply({ authenticated: false, demo: false, csrf: "", authMode: "token" });
  await settle();
  const form = h.document.querySelector(".login");
  h.document.querySelector("#login-token").value = "fictitious-login-token";
  const pending = form.dispatch("submit");
  const login = h.take("/api/login");
  await h.run("showLogin()");
  assert.equal(login.options.signal.aborted, true);
  login.reply({ csrf: "stale-login-csrf" });
  await pending;
  assertSignedOut(h);
  assert.equal(h.requests.length, 0);
});

test("a late initial session result cannot restore a cleared session", async () => {
  const h = harness();
  const session = h.take("/api/session");
  await h.run("showLogin()");
  session.reply({ authenticated: true, demo: false, csrf: "stale-session-csrf", authMode: "token" });
  await settle();
  assertSignedOut(h);
  assert.equal(h.requests.length, 0);
});

test("a late mutation result cannot reopen inventory or display a success notice", async () => {
  const h = await signedIn();
  h.run("changeDevice(data.nodes[0], 'rename')");
  h.document.querySelector("#device-change").value = "renamed-device";
  const save = h.element("modal").querySelectorAll("button")
    .find((button) => button.textContent === "Save name");
  const pending = save.dispatch("click");
  const mutation = h.take("/api/machines/1/rename");
  await h.run("showLogin()");
  assert.equal(mutation.options.signal.aborted, true);
  mutation.reply({ ok: true });
  await pending;
  assertSignedOut(h);
  assert.equal(h.requests.length, 0);
});

test("an old 401 cannot sign out a newer successful login", async () => {
  const h = await signedIn();
  const oldRefresh = h.run("refresh()");
  const oldSnapshot = h.take("/api/snapshot");
  await h.run("showLogin()");
  h.document.querySelector("#login-token").value = "fictitious-new-token";
  const newLogin = h.document.querySelector(".login").dispatch("submit");
  h.take("/api/login").reply({ csrf: "new-csrf" });
  await settle();
  h.take("/api/snapshot").reply(privateSnapshot);
  await newLogin;
  oldSnapshot.reply({ error: "old session expired" }, 401);
  await oldRefresh;
  assert.equal(h.run("csrf"), "new-csrf");
  assert.equal(h.document.querySelector(".login"), null);
  assert.equal(h.element("network-name").textContent, "private.mesh.example.com");
});

test("failed server logout clears private views and reports unconfirmed revocation", async () => {
  const h = await signedIn();
  const logout = h.element("signout").dispatch("click");
  h.take("/api/logout").reply({ error: "Temporary upstream failure" }, 502);
  await logout;
  assertSignedOut(h);
  assert.ok(h.document.querySelector(".login-error").textContent
    .includes("Server sign-out could not be confirmed"));
  assert.equal(h.document.querySelector('.login button[type="submit"]').disabled, false);
});

test("Google mode exposes only the Google sign-in flow, never a token form", async () => {
  const h = harness();
  h.take("/api/session").reply({ authenticated: false, demo: false, csrf: "", authMode: "google" });
  await settle();
  assertConsoleHidden(h);
  assert.equal(h.document.querySelector("#login-token"), null);
  assert.ok(h.document.querySelector(".login").textContent.includes("Sign in with Google"));
  await h.document.querySelector(".login .primary").dispatch("click");
  assert.equal(h.requests.length, 0, "Google navigation never uses token login API");
  assert.deepEqual(h.navigations, ["/auth/google/start"]);
  assertConsoleHidden(h);
});

test("missing authentication metadata does not offer token fallback", async () => {
  const h = harness();
  h.take("/api/session").reply({ authenticated: false, demo: false, csrf: "" });
  await settle();
  assert.equal(h.document.querySelector("#login-token"), null);
  assert.ok(h.element("main").textContent.includes("service is unavailable"));
  assertConsoleHidden(h);
});
test("Google sign-in uses the locally served official button with an accessible name", async () => {
  const h=harness();h.take("/api/session").reply({authenticated:false,authMode:"google",publicSiteURL:"https://control.example.com"});await settle();
  const button=h.document.querySelector('.google-signin'), image=h.document.querySelector('.google-signin img');
  assert.equal(button.attributes.get('aria-label'),'Sign in with Google');
  assert.equal(image.attributes.get('src'),'/google-sign-in.png');
  assert.equal(image.attributes.get('width'),'177');assert.equal(image.attributes.get('height'),'40');
  assert.ok(h.document.querySelector('.login').textContent.includes('Privacy'));
  assertConsoleHidden(h);
  assert.deepEqual(h.document.querySelector('.information-links').querySelectorAll('a').map(a=>a.textContent),['Privacy','Terms','Support']);
  const privacy=h.document.querySelector('.information-links').querySelectorAll('a').find(a=>a.textContent==='Privacy');
  assert.equal(privacy.attributes.get('href'),'https://control.example.com/privacy');
});
test("public policy links survive sign-out while protected inventory is cleared", async () => {
  const h=await signedIn();h.run("setInformationSite('https://control.example.com')");await h.run('showLogin()');assertSignedOut(h);
  assert.ok(h.element('public-links').textContent.includes('Privacy'));
  assert.equal(visible(h.element('public-links')),false);
  assert.ok(h.document.querySelector('.login').textContent.includes('Support'));
  h.run("setInformationSite('javascript:alert(1)')");assert.equal(h.element('public-links').hidden,true);
});

test("the served document hides console chrome before authentication JavaScript executes", () => {
  const h = harness();
  assertConsoleHidden(h);
  assert.equal(h.requests.length, 1, "Initial session request is still pending");
  const initialMain = html.match(/<main\b[^>]*>[\s\S]*?<\/main>/)?.[0];
  assert.ok(initialMain?.includes('class="wrap login-shell"'));
  assert.ok(initialMain?.includes('class="brand login-brand"'));
  assert.ok(initialMain?.includes("Checking sign-in…"));
  assert.ok(!initialMain?.includes("Loading your network"));
});

test("session failure retains a login-only screen and never reveals console navigation", async () => {
  for (const failure of ["http", "network"]) {
    const h = harness();
    assertConsoleHidden(h);
    const session = h.take("/api/session");
    if (failure === "http") session.reply({ error: "Temporarily unavailable" }, 503);
    else session.fail(new Error("Network unavailable"));
    await settle();
    assertSignedOut(h);
    assert.ok(h.document.querySelector(".login-brand"));
    assert.equal(h.document.querySelector("#login-token"), null);
    assert.ok(h.document.querySelector(".login").textContent.includes("Reload sign-in"));
    h.run("location.hash = '#machines'; render()");
    assertConsoleHidden(h);
  }
});

test("an authenticated session reveals chrome only after its current snapshot arrives", async () => {
  const h = harness();
  h.take("/api/session").reply({ authenticated: true, demo: false, csrf: "current-csrf", authMode: "google" });
  await settle();
  assertConsoleHidden(h);
  h.take("/api/snapshot").reply(privateSnapshot);
  await settle();
  assertConsoleVisible(h);
  const logout = h.element("signout").dispatch("click");
  assertSignedOut(h);
  h.take("/api/logout").reply({ ok: true });
  await logout;
  assertSignedOut(h);
});

test("a failed initial snapshot returns to login without exposing authenticated chrome", async () => {
  const h = harness();
  h.take("/api/session").reply({ authenticated: true, demo: false, csrf: "current-csrf", authMode: "google" });
  await settle();
  assertConsoleHidden(h);
  h.take("/api/snapshot").reply({ error: "Network data is unavailable" }, 503);
  await settle();
  assertSignedOut(h);
  assert.ok(h.document.querySelector(".login-error").textContent.includes("Network data is unavailable"));
  assert.equal(h.document.querySelector("#login-token"), null);
});

test("a failed token sign-in leaves all console controls hidden", async () => {
  const h = harness();
  h.take("/api/session").reply({ authenticated: false, demo: false, authMode: "token" });
  await settle();
  assertSignedOut(h);
  h.document.querySelector("#login-token").value = "fictitious-invalid-token";
  const attempt = h.document.querySelector(".login").dispatch("submit");
  h.take("/api/login").reply({ error: "Sign-in was not accepted" }, 401);
  await attempt;
  assertSignedOut(h);
  assert.ok(h.document.querySelector(".login-error").textContent.includes("not accepted"));
});

const workflowFixture = {
  revision: 4, inventory: "test-only-inventory-fingerprint", writes: true,
  blocked: "", denial_verified: false,
  plan: { device_ids: ["1"], teams: [], grants: [] },
  devices: [{ id: "1", name: "private-device", email: "alice@example.com", eligible: true, approved: true }],
  proposals: [{ id: "test-only-proposal", revision: 4, actor: "alice@example.com", status: "pending", created_at: "2026-01-01T12:00:00Z", plan: { device_ids: ["1"], teams: [], grants: [] } }],
  audit: [], original_owners: {},
};
test("access proposals require a separate review before an approval request", async () => {
  const h = await signedIn();
  h.run(`data.workflow = ${JSON.stringify(workflowFixture)}; location.hash = '#access'; render();`);
  const review = h.element("main").querySelectorAll("button").find(b => b.textContent === "Review and approve");
  assert.ok(review, "pending proposal has a review action");
  await review.dispatch("click");
  assert.equal(h.requests.length, 0, "opening review never applies a policy");
  assert.ok(h.element("modal").textContent.includes("personal Taildrop"));
  const approve = h.element("modal").querySelectorAll("button").find(b => b.textContent === "Approve and apply");
  const action = approve.dispatch("click");
  const request = h.take("/api/workflow/approve");
  assert.deepEqual(JSON.parse(request.options.body), { id: "test-only-proposal" });
  assert.equal(request.options.headers["X-CSRF-Token"], "original-csrf");
  request.reply({ ok: true });
  await settle();
  h.take("/api/snapshot").reply(privateSnapshot);
  await action;
});
test("company requests reach the administrator and require explicit review", async () => {
  const h = await signedIn();
  const w = { ...workflowFixture, requests: [{id:"company-request",email:"bob@example.com",reason:"Need work tools",status:"pending",created_at:"2026-01-01T12:00:00Z"}] };
  h.run(`data.workflow=${JSON.stringify(w)};location.hash='#access';render();`);
  assert.ok(h.element("main").textContent.includes("Company access requested"));
  await h.element("main").querySelectorAll("button").find(b=>b.textContent==="Review request").dispatch("click");
  assert.equal(h.requests.length,0);
  assert.ok(h.element("modal").textContent.includes("Devices enrolled with this verified Google account will be approved automatically"));
  h.element("modal").querySelector("select").value = "1";
  h.element("modal").querySelectorAll("input").find(i=>i.attributes.get("aria-label")==="Service name").value = "Work dashboard";
  h.element("modal").querySelectorAll("input").find(i=>i.attributes.get("aria-label")==="Service port").value = "tcp:8443";
  const action = h.element("modal").querySelectorAll("button").find(b=>b.textContent==="Approve company access").dispatch("click");
  const request = h.take("/api/requests/review");
  assert.deepEqual(JSON.parse(request.options.body),{id:"company-request",decision:"approved",note:"",auto_access:{service:"Work dashboard",destination_id:"1",port:"tcp:8443"}});
  assert.equal(request.options.headers["X-CSRF-Token"],"original-csrf");
  await h.run("showLogin()");
  request.reply({ok:true}); await action;
  assertSignedOut(h);assert.equal(h.requests.length,0);
});
test("a pending company request remains reviewable when proposal and audit lists are null", async () => {
  const h = await signedIn();
  const w = {...workflowFixture, proposals:null, audit:null, requests:[{id:"company-request",email:"bob@example.com",reason:"Need work tools",status:"pending",created_at:"2026-01-01T12:00:00Z"}], blocked:"An earlier access check needs reconciliation", denial_verified:true};
  h.run(`data.workflow=${JSON.stringify(w)};location.hash='#access';render();`);
  assertConsoleVisible(h);
  const review = h.element("main").querySelectorAll("button").find(b=>b.textContent==="Review request");
  assert.ok(review,"company requests remain reviewable while network grants are blocked");
  await review.dispatch("click");
  assert.equal(h.requests.length,0);
  const action = h.element("modal").querySelectorAll("button").find(b=>b.textContent==="Approve company access").dispatch("click");
  const request = h.take("/api/requests/review");
  assert.deepEqual(JSON.parse(request.options.body),{id:"company-request",decision:"approved",note:""});
  request.reply({ok:true});await settle();
  h.take("/api/snapshot").reply({...privateSnapshot, workflow:{...w,requests:[{...w.requests[0],status:"approved"}]}});
  await action;
  assert.ok(h.element("main").textContent.includes("approved"));
});
test("all console pages tolerate null or omitted empty approval collections", async () => {
  const h = await signedIn();
  for(const empty of [null,undefined]) {
    const w={...workflowFixture,proposals:empty,audit:empty,requests:empty};
    for(const page of ['machines','users','access','dns','settings']) {
      h.run(`data.workflow=${JSON.stringify(w)};location.hash='#${page}';render();`);
      assertConsoleVisible(h);
      assert.ok(!h.element("main").textContent.includes("Cannot read properties"));
    }
  }
});
test("a delayed access approval cannot restore protected views after logout", async () => {
  const h = await signedIn();
  h.run(`data.workflow = ${JSON.stringify(workflowFixture)}; location.hash = '#access'; render(); planEditor();`);
  const action = h.run("workflowAction('approve', {id:'test-only-proposal'})");
  const approval = h.take("/api/workflow/approve");
  await h.run("showLogin()");
  approval.reply({ ok: true });
  await action;
  assertSignedOut(h);
  assert.equal(h.requests.length, 0);
});
test("every administrator page distinguishes unverified denial from successful enforcement", async () => {
  const h = await signedIn();
  h.run(`data.workflow = ${JSON.stringify({ ...workflowFixture, blocked: "Controller unavailable", denial_verified: false })}; data.operations = {checks:[{name:'Backup',status:'warning',message:'Recovery point old'}]}; location.hash='#settings'; render();`);
  assert.ok(h.element("main").textContent.includes("denial unverified; existing connectivity may remain"));
  assert.ok(h.element("main").textContent.includes("Recovery point old"));
  assert.ok(h.element("main").textContent.includes("Email alerts are not enabled"));
  h.run("data.workflow.denial_verified=true; render();");
  assert.ok(h.element("main").textContent.toLowerCase().includes("deny-all verified"));
  assert.ok(!h.element("main").textContent.includes("denial unverified"));
});
test("healthy checks stay out of the machine view and remain available in Settings", async () => {
  const h = await signedIn();
  h.run(`data.operations={checks:[{name:'controller_https',status:'pass',message:'Controller public HTTPS'},{name:'off_host_backup',status:'pass',message:'Verified encrypted backup'}]}; location.hash='#machines'; render();`);
  assert.equal(h.element("mode-badge").textContent, "System healthy");
  assert.equal(h.element("main").querySelector(".notices"), null);
  assert.ok(!h.element("main").textContent.includes("Controller public HTTPS"));
  h.run("location.hash='#settings'; render();");
  assert.ok(h.element("main").textContent.includes("2 of 2 checks passed"));
  assert.ok(h.element("main").textContent.includes("Verified encrypted backup"));
  assert.equal(h.element("main").querySelector(".health-details").open, false);
});
test("warnings and paused approvals stay actionable without claiming healthy status", async () => {
  const h = await signedIn();
  h.run(`data.workflow=${JSON.stringify({...workflowFixture,blocked:'Earlier inventory verification failed',denial_verified:true})}; data.operations={checks:[{name:'Status freshness',status:'warning',message:'Status is stale'}]}; location.hash='#machines'; render();`);
  assert.equal(h.element("mode-badge").textContent, "Access paused");
  const notices=h.element("main").querySelector(".notices");
  assert.ok(notices.textContent.includes("Access approvals paused"));
  assert.ok(notices.textContent.includes("System needs attention"));
  assert.deepEqual(notices.querySelectorAll("a").map(a=>a.attributes.get("href")),["#access","#settings","#access"]);
  assert.ok(notices.textContent.includes("Awaiting approval"));
  h.run("data.operations=null; data.workflow=null; render();");
  assert.equal(h.element("mode-badge").textContent,"Health unknown");
});
test("unverified denial overrides passing operations and never promises blocked access", async () => {
  const h=await signedIn();
  h.run(`data.nodes=[];data.users=[];data.workflow=${JSON.stringify({...workflowFixture,blocked:'Controller unavailable',denial_verified:false,devices:[],proposals:[]})};data.operations={checks:[{name:'controller_https',status:'pass',message:'Controller HTTPS'}]};location.hash='#machines';render();`);
  const link=h.element("mode-badge");
  assert.equal(link.textContent,"Access unverified");
  assert.ok(!link.className.split(/\s+/).includes("healthy"));
  assert.ok(link.attributes.get("aria-label").includes("Access unverified"));
  assert.equal(link.attributes.get("href"),"#access");
  assert.ok(h.element("main").textContent.includes("Access enforcement is unverified"));
  assert.ok(!h.element("main").textContent.includes("Devices of approved company members receive their assigned access after enrollment"));
});
test("DNS distinguishes public resolvers from automatic private search suffixes", async () => {
  const h=await signedIn();
  h.run("data.configAvailable=true;data.settings.magicDNS=true;data.settings.searchDomains=['corp.example.com'];location.hash='#dns';render();");
  const text=h.element("main").textContent;
  assert.ok(text.includes("Use device’s existing DNS for internet names"));
  assert.ok(text.includes("private.mesh.example.com, corp.example.com"));
  assert.ok(text.includes("private.mesh.example.com (MagicDNS)"));
  assert.ok(text.includes("machine → machine.private.mesh.example.com"));
  h.run("data.settings.magicDNS=false;render();");
  assert.ok(h.element("main").textContent.includes("MagicDNS short names are not enabled"));
  assert.ok(!h.element("main").textContent.includes("private.mesh.example.com (MagicDNS)"));
});
test("empty networks show enrollment guidance without irrelevant search controls", async () => {
  const h=await signedIn();
  h.run(`data.nodes=[]; data.users=[]; data.workflow=${JSON.stringify({...workflowFixture,blocked:'',devices:[],proposals:[]})}; location.hash='#machines'; render();`);
  assert.ok(h.element("main").textContent.includes("Connect your first device"));
  assert.ok(h.element("main").textContent.includes("Devices of approved company members receive their assigned access after enrollment"));
  assert.equal(h.element("main").querySelector(".toolbar"),null);
  const add=h.element("main").querySelectorAll("button").find(b=>b.textContent==="Add device");
  // No controller URL must still fail safely rather than issuing credentials.
  await add.dispatch("click");
  assert.ok(h.element("toast").textContent.includes("Controller configuration is unavailable"));
});

const bridgeFixture = {version:1,revision:7,writes:true,gateways:{migration:{enabled:false,allowed_users:[]}},audit:[]};
test("bridge changes send revision and exact accounts with CSRF, and preserve a conflict draft", async () => {
  const h=await signedIn();
  h.run(`data.bridge=${JSON.stringify(bridgeFixture)};location.hash='#bridge';render();`);
  h.element('bridge-users-migration').value='alice@example.com\nbob@example.com';
  h.element('bridge-enabled-migration').checked=true;
  const save=h.element('main').querySelectorAll('button').find(b=>b.textContent==='Save bridge rules');
  const action=save.dispatch('click');const req=h.take('/api/bridge-config');
  assert.deepEqual(JSON.parse(req.options.body),{id:'migration',revision:7,enabled:true,allowed_users:['alice@example.com','bob@example.com']});
  assert.equal(req.options.headers['X-CSRF-Token'],'original-csrf');
  req.reply({error:'Configuration changed; reload before saving'},409);await action;
  assert.match(h.element('main').textContent,/reload before saving/);
  assert.equal(h.element('bridge-users-migration').value,'alice@example.com\nbob@example.com');
});
test("late bridge saves cannot expose a success notification after logout", async () => {
  const h=await signedIn();
  h.run(`data.bridge=${JSON.stringify(bridgeFixture)};location.hash='#bridge';render();`);
  const save=h.element('main').querySelectorAll('button').find(b=>b.textContent==='Save bridge rules');
  const action=save.dispatch('click');const req=h.take('/api/bridge-config');
  h.run('clearProtectedState()');req.reply({saved:true,revision:8});await action;
  assertConsoleHidden(h);assert.equal(h.element('toast').hidden,true);assert.equal(h.run('data'),null);
});

test("machine metadata is visible, searchable and kept separate from its DNS name", async () => {
  const h = await signedIn();
  h.run(`data.nodes[0].givenName = "localhost"; data.nodes[0].name = "localhost";
    Object.assign(data.nodes[0], {model: "iPhone14,7", os: "iOS", osVersion: "18.0", architecture: "arm64", version: "1.0"});
    location.hash = "#machines"; render();`);
  assert.match(h.element("main").textContent, /iPhone14,7 · iOS 18.0/);
  h.run('query = "iphone14,7"; render();');
  assert.match(h.element("main").textContent, /1 device/);
  h.run('showDevice(data.nodes[0]);');
  assert.match(h.element("drawer").textContent, /localhost.private.mesh.example.com/);
  assert.match(h.element("drawer").textContent, /ModeliPhone14,7/);
  assert.match(h.element("drawer").textContent, /Architecturearm64/);
  h.run('data.nodes[0].model = "<img src=x onerror=alert(1)>"; showDevice(data.nodes[0]);');
  assert.equal(h.element("drawer").querySelectorAll("img").length, 0);
});

const permissionsFixture = {
  ...workflowFixture,
  users: [
    {id:"person-alice", name:"Alice Example", email:"alice@example.com", device_ids:["1","2"], services:[{name:"Dashboard",destination_id:"3",port:"tcp:8443"}]},
    {id:"person-bob", name:"Bob Example", email:"bob@example.com", device_ids:[], services:[]},
  ],
  devices:[...workflowFixture.devices,{id:"3",name:"Service server",eligible:true,approved:true}],
  services:[{name:"Dashboard",destination_id:"3",port:"tcp:8443"}],
  service_access:[{destination_id:"3",port:"tcp:8443",user_ids:["person-alice"]}],
  // Machine-only infrastructure access must not be presented as a user grant.
  plan:{device_ids:["1","2","3"],teams:[{name:"infra",device_ids:["3"]}],grants:[{team:"infra",destination_ids:["3"],ports:["tcp:8443"]}]},
};
test("Services shows people and user detail shows their exact assigned services", async () => {
  const h=await signedIn();
  h.run(`data.workflow=${JSON.stringify(permissionsFixture)};location.hash="#services";render();`);
  assert.match(h.element("main").textContent,/1 person has access/);
  const person=h.element("main").querySelectorAll("button").find(b=>b.textContent==="Alice Example");
  await person.dispatch("click");
  assert.equal(h.element("drawer").hidden,false);
  assert.match(h.element("drawer").textContent,/Service permissions/);
  assert.match(h.element("drawer").textContent,/Dashboard/);
  assert.match(h.element("drawer").textContent,/TCP 8443/);
  h.run('location.hash="#users";render();');
  await h.element("main").querySelectorAll("button").find(b=>b.textContent==="Bob Example").dispatch("click");
  assert.match(h.element("drawer").textContent,/No service permissions assigned/);
  assert.match(h.element("drawer").textContent,/No enrolled devices/);
  h.run('data.workflow.service_access=[];location.hash="#services";render();');
  assert.match(h.element("main").textContent,/0 people have access/);
});
test("service changes submit user identities and require separate apply confirmation", async () => {
  const h=await signedIn();
  h.run(`data.workflow=${JSON.stringify(permissionsFixture)};manageService(data.workflow.services[0]);`);
  const checks=h.element("modal").querySelectorAll('input').filter(i=>i.attributes.get('type')==='checkbox');
  assert.equal(checks.length,2,"one choice per person, including a member without devices");
  checks[0].checked=false;await checks[0].dispatch('change');
  checks[1].checked=true;await checks[1].dispatch('change');
  const review=h.element("modal").querySelectorAll('button').find(b=>b.textContent==='Review changes');
  const action=review.dispatch('click'), req=h.take('/api/workflow/service-propose');
  assert.deepEqual(JSON.parse(req.options.body),{destination_id:'3',port:'tcp:8443',user_ids:['person-bob'],revision:4,inventory:'test-only-inventory-fingerprint',comment:'Service access: Dashboard (tcp:8443)'});
  assert.equal(req.options.headers['X-CSRF-Token'],'original-csrf');
  assert.equal(h.requests.length,0);
  req.reply({ok:true,proposal_id:'review-users'});await settle();
  h.take('/api/snapshot').reply({...privateSnapshot,workflow:permissionsFixture});await action;
  assert.match(h.element('modal').textContent,/Grant accessBob Example/);
  assert.match(h.element('modal').textContent,/Remove accessAlice Example/);
  assert.equal(h.requests.length,0,'proposal does not apply permissions');
  const apply=h.element('modal').querySelectorAll('button').find(b=>b.textContent==='Apply access').dispatch('click');
  const approval=h.take('/api/workflow/approve');assert.deepEqual(JSON.parse(approval.options.body),{id:'review-users'});
  approval.reply({ok:true});await settle();h.take('/api/snapshot').reply({...privateSnapshot,workflow:permissionsFixture});await apply;
});
test("service search, unchanged selections and conflict errors preserve a reviewable draft", async () => {
  const h=await signedIn();h.run(`data.workflow=${JSON.stringify(permissionsFixture)};manageService(data.workflow.services[0]);`);
  const review=h.element('modal').querySelectorAll('button').find(b=>b.textContent==='Review changes');
  await review.dispatch('click');assert.equal(h.requests.length,0);assert.match(h.element('modal').textContent,/Select a change/);
  const search=h.element('modal').querySelectorAll('input').find(i=>i.attributes.get('type')==='search');
  search.value='bob';await search.dispatch('input');
  const rows=h.element('modal').querySelector('.service-picker').querySelectorAll('label');
  assert.equal(rows[0].hidden,true);assert.equal(rows[1].hidden,false);
  const bob=rows[1].querySelector('input');bob.checked=true;await bob.dispatch('change');
  const action=review.dispatch('click');h.take('/api/workflow/service-propose').reply({error:'Inventory changed; refresh and review again'},409);await action;
  assert.match(h.element('modal').textContent,/Inventory changed/);assert.equal(bob.checked,true);assert.equal(review.disabled,false);
});
test("blocked services hide mutation controls and a delayed proposal cannot restore signed-out state", async () => {
  const h=await signedIn();h.run(`data.workflow=${JSON.stringify({...permissionsFixture,blocked:'Review required'})};location.hash='#services';render();`);
  assert.doesNotMatch(h.element('main').textContent,/Manage access|Add service/);
  h.run('data.workflow.blocked="";manageService(data.workflow.services[0]);');
  const bob=h.element('modal').querySelectorAll('input').find(i=>i.value==='person-bob');bob.checked=true;await bob.dispatch('change');
  const action=h.element('modal').querySelectorAll('button').find(b=>b.textContent==='Review changes').dispatch('click');
  const req=h.take('/api/workflow/service-propose');await h.run('showLogin()');req.reply({ok:true,proposal_id:'stale'});await action;
  assertSignedOut(h);assert.equal(h.requests.length,0);assert.equal(h.element('modal').open,false);
});
