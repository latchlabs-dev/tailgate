"use strict";
const main = document.querySelector("#main"),
  modal = document.querySelector("#modal"),
  drawer = document.querySelector("#drawer");
let data = null,
  csrf = "",
  query = "",
  filter = "all",
  owner = "all",
  timer,
  authEpoch = 0,
  signingOut = false,
  authMode = "unknown",
  publicSiteURL = "";
const pendingRequests = new Set();
const el = (tag, attrs = {}, ...children) => {
  const n = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") n.className = value;
    else if (key.startsWith("on")) n.addEventListener(key.slice(2), value);
    else n.setAttribute(key, value);
  }
  for (const c of children.flat()) {
    if (c !== null && c !== undefined)
      n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
};
const button = (label, cls, fn) =>
  el("button", { class: cls, type: "button", onclick: fn }, label);
const humanDate = (value) => {
  if (!value || value.startsWith("0001-")) return "Not reported";
  const d = new Date(value);
  return Number.isNaN(d.valueOf())
    ? "Not reported"
    : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
};
const age = (value) => {
  if (!value) return "Not reported";
  const d = new Date(value);
  if (Number.isNaN(d.valueOf()) || d.getFullYear() < 2000)
    return "Not reported";
  const mins = Math.max(0, Math.floor((Date.now() - d) / 60000));
  return mins < 1
    ? "Just now"
    : mins < 60
      ? `${mins}m ago`
      : mins < 1440
        ? `${Math.floor(mins / 60)}h ago`
        : `${Math.floor(mins / 1440)}d ago`;
};
const deviceName = (n) => n.givenName || n.name || "Unnamed device";
const devicePlatform = (n) => [n.model, [n.os, n.osVersion].filter(Boolean).join(" ")].filter(Boolean).join(" · ") || "Device details not reported";
const noExpiry = (n) => !n.expiry || n.expiry.startsWith("0001-");
const expired = (n) => !noExpiry(n) && new Date(n.expiry) < new Date();
const isExit = (n) =>
  (n.approvedRoutes || []).some((r) => r === "0.0.0.0/0" || r === "::/0");
const toast = (message) => {
  const t = document.querySelector("#toast");
  t.textContent = message;
  t.hidden = false;
  clearTimeout(timer);
  timer = setTimeout(() => {
    t.hidden = true;
  }, 3000);
};
class StaleRequest extends Error {}
function setConsoleVisible(visible) {
  document.querySelector("#console-header").hidden = !visible;
  document.querySelector("#console-footer").hidden = !visible;
  main.className = visible ? "wrap" : "wrap login-shell";
}
function clearProtectedState() {
  setConsoleVisible(false);
  authEpoch++;
  for (const controller of pendingRequests) controller.abort();
  pendingRequests.clear();
  data = null;
  csrf = "";
  query = "";
  filter = "all";
  owner = "all";
  drawer.hidden = true;
  drawer.replaceChildren();
  modal.close();
  modal.replaceChildren();
  clearTimeout(timer);
  const notice = document.querySelector("#toast");
  notice.hidden = true;
  notice.textContent = "";
  document.querySelector("#signout").hidden = true;
  document.querySelector("#network-name").textContent = "Your network";
  document.querySelector("#mode-badge").textContent = "Private console";
  document.querySelector("#mode-badge").className = "local-badge health-summary";
  document.querySelector("#mode-badge").setAttribute("href", "#settings");
  document.querySelector("#mode-badge").setAttribute("aria-label", "System health");
  document.querySelector("#updated").textContent = "";
  document.querySelectorAll("[data-page]").forEach((a) =>
    a.removeAttribute("aria-current"),
  );
  document.title = "Sign in · Tailgate";
}
async function request(path, body, { revokeSession = false } = {}) {
  const epoch = authEpoch,
    controller = new AbortController();
  // The sign-out request must revoke its original cookie after local clearing.
  // All other pending results belong to the current authentication epoch.
  if (!revokeSession) pendingRequests.add(controller);
  try {
    const response = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      credentials: "same-origin",
      headers:
        body === undefined
          ? {}
          : { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    if (!revokeSession && epoch !== authEpoch) throw new StaleRequest();
    const value = await response.json();
    if (!revokeSession && epoch !== authEpoch) throw new StaleRequest();
    if (response.status === 401 && path !== "/api/login") {
      if (!revokeSession) await showLogin();
      throw new Error("Sign in to continue");
    }
    if (!response.ok) throw new Error(value.error || "The request failed");
    return value;
  } finally {
    pendingRequests.delete(controller);
  }
}
async function copy(text) {
  const epoch = authEpoch;
  try {
    await navigator.clipboard.writeText(text);
    if (epoch !== authEpoch) return;
    toast("Copied to clipboard");
  } catch {
    if (epoch !== authEpoch) return;
    toast("Clipboard unavailable. Select and copy the text.");
  }
}
function preview() {
  return data.demo
    ? el(
        "div",
        { class: "preview" },
        el("strong", {}, "Local preview"),
        el(
          "span",
          {},
          "Fictitious devices and users. Try the controls safely.",
        ),
        el("span", {}, "Changes reset on restart"),
      )
    : null;
}
function heading(title, subtitle, action) {
  return el(
    "div",
    { class: "page-head" },
    el(
      "div",
      {},
      el("h1", {}, title),
      el("p", { class: "subtitle" }, subtitle),
    ),
    action || null,
  );
}
function badges(n) {
  const values = (n.tags || []).map((t) =>
    el("span", { class: "badge purple" }, t),
  );
  if (isExit(n)) values.push(el("span", { class: "badge blue" }, "Exit node"));
  if ((n.approvedRoutes || []).some((r) => r !== "0.0.0.0/0" && r !== "::/0"))
    values.push(el("span", { class: "badge blue" }, "Subnet router"));
  if (noExpiry(n)) values.push(el("span", { class: "badge" }, "No expiry"));
  if (expired(n)) values.push(el("span", { class: "badge" }, "Expired"));
  return values.length ? el("div", { class: "badges" }, values) : null;
}
function status(n) {
  const online = n.online && !expired(n);
  return el(
    "div",
    { class: "status" + (online ? "" : " offline") },
    el("span", { class: "dot" + (online ? "" : " offline") }),
    online ? "Connected" : expired(n) ? "Expired" : age(n.lastSeen),
  );
}
function icon(n) {
  const symbol =
    { macOS: "⌘", Linux: ">_", Windows: "⊞", iOS: "▯", Android: "▯" }[n.os] ||
    "▣";
  return el("span", { class: "os-icon", "aria-hidden": "true" }, symbol);
}
function showDialog(title, ...content) {
  modal.replaceChildren(
    button("×", "close", () => modal.close()),
    el("h2", { id: "modal-title" }, title),
    ...content.filter(node => node !== null && node !== undefined),
  );
  modal.showModal();
}
function informationLinks() {
  if (!publicSiteURL) return null;
  return el("nav", {class:"information-links", "aria-label":"Tailgate information"},
    ...[["Privacy","/privacy"],["Terms","/terms"],["Support","/support"]].map(([label,path]) =>
      el("a", {href:publicSiteURL+path},label)));
}
function loginBrand() {
  return el("div", {class:"brand login-brand"},
    el("img", {src:"/favicon.svg",alt:"",width:"32",height:"32"}), "tailgate");
}
function setInformationSite(value) {
  publicSiteURL = typeof value === "string" && /^https:\/\/[a-z0-9.-]+$/.test(value) ? value : "";
  const footer = document.querySelector("#public-links");
  if (footer) {
    footer.hidden = !publicSiteURL;
    footer.replaceChildren();
    if (publicSiteURL) footer.append(...[["Home","/"],["Privacy","/privacy"],["Terms","/terms"],["Support","/support"]].map(([label,path]) => el("a",{href:publicSiteURL+path},label)));
  }
}
function closeActions(details) {
  document.querySelectorAll(".row-action[open]").forEach((d) => {
    if (d !== details) d.open = false;
  });
}
function actions(n) {
  const details = el(
    "details",
    { class: "row-action" },
    el("summary", { "aria-label": "Actions for " + deviceName(n) }, "⋯"),
  );
  details.addEventListener("toggle", () => {
    if (details.open) {
      closeActions(details);
      const rect = details.querySelector("summary").getBoundingClientRect();
      menu.style.top = `${Math.max(8, Math.min(innerHeight - 160, rect.bottom + 6))}px`;
      menu.style.right = `${Math.max(16, innerWidth - rect.right)}px`;
    }
  });
  const menu = el(
    "div",
    { class: "menu" },
    button("View details", "", () => {
      details.open = false;
      showDevice(n);
    }),
  );
  if (data.writes)
    for (const [title, action] of [
      ["Rename…", "rename"],
      ["Expire access…", "expire"],
      ["Remove…", "delete"],
    ])
      menu.append(
        button(title, action === "delete" ? "remove" : "", () => {
          details.open = false;
          changeDevice(n, action);
        }),
      );
  details.append(menu);
  return details;
}
function showDevice(n) {
  drawer.hidden = false;
  drawer.replaceChildren(
    button("×", "close", () => (drawer.hidden = true)),
    icon(n),
    el("h2", { id: "drawer-title" }, deviceName(n)),
    status(n),
    badges(n),
  );
  const rows = [
    ["Address", (n.ipAddresses || []).join("\n") || "Not reported"],
    [
      "DNS name",
      data.settings.deviceDomain
        ? deviceName(n) + "." + data.settings.deviceDomain
        : "Not available",
    ],
    ["Owner", n.user.email || n.user.name || "Tagged device"],
    ["Reported hostname", n.name || "Not reported"],
    ["Model", n.model || "Not reported"],
    ["Operating system", [n.os, n.osVersion].filter(Boolean).join(" ") || "Not reported"],
    ["Architecture", n.architecture || "Not reported"],
    ["Metadata collected", n.metadataCollectedAt ? humanDate(n.metadataCollectedAt) : "Not reported"],
    ["Client version", n.version || "Not reported"],
    ["Created", humanDate(n.createdAt)],
    ["Last seen", n.online ? "Connected" : humanDate(n.lastSeen)],
    ["Key expires", noExpiry(n) ? "No expiry" : humanDate(n.expiry)],
    ["Routes", (n.approvedRoutes || []).join(", ") || "None"],
  ];
  const dl = el("dl", { class: "definition" });
  for (const [k, v] of rows) dl.append(el("dt", {}, k), el("dd", {}, v));
  drawer.append(dl);
  if (n.ipAddresses?.length)
    drawer.append(
      button("Copy address", "secondary", () => copy(n.ipAddresses[0])),
    );
  drawer.querySelector(".close").focus();
}
function changeDevice(n, action) {
  const name = deviceName(n),
    input = el("input", {
      id: "device-change",
      autocomplete: "off",
      maxlength: 63,
      value: action === "rename" ? name : "",
    }),
    error = el("div", { class: "login-error", role: "alert" }),
    title = {
      rename: "Rename device",
      expire: "Expire device access",
      delete: "Remove device",
    }[action];
  const explanation = {
    rename:
      "Use a short, descriptive name. This also changes its private DNS name.",
    expire: "The device will need to authenticate again to regain access.",
    delete:
      "Remove this device from the network. It must enroll again to reconnect.",
  }[action];
  const save = button(
    action === "rename"
      ? "Save name"
      : action === "expire"
        ? "Expire access"
        : "Remove device",
    action === "rename" ? "primary" : "danger",
    async () => {
      const epoch = authEpoch;
      save.disabled = true;
      error.textContent = "";
      try {
        await request(
          `/api/machines/${n.id}/${action}`,
          action === "rename"
            ? { name: input.value }
            : { confirmation: input.value },
        );
        if (epoch !== authEpoch) return;
        modal.close();
        drawer.hidden = true;
        await refresh();
        if (epoch !== authEpoch || !data) return;
        toast(data.demo ? "Sample device updated" : "Device updated");
      } catch (e) {
        if (epoch !== authEpoch || e instanceof StaleRequest) return;
        error.textContent = e.message;
      } finally {
        save.disabled = false;
      }
    },
  );
  showDialog(
    title,
    el("p", {}, explanation),
    el(
      "label",
      { for: "device-change" },
      action === "rename" ? "Device name" : `Type ${name} to confirm`,
    ),
    input,
    error,
    el(
      "div",
      { class: "dialog-actions" },
      button("Cancel", "secondary", () => modal.close()),
      save,
    ),
  );
  input.focus();
}
function addDevice() {
  if (!data.settings.controlURL) {
    toast("Controller configuration is unavailable");
    return;
  }
  const command = el("code", { class: "code" }),
    hint = el("p", {}),
    tabs = el("div", { class: "platforms" });
  const select = (platform) => {
    tabs
      .querySelectorAll("button")
      .forEach((b) =>
        b.setAttribute("aria-pressed", String(b.textContent === platform)),
      );
    command.textContent =
      (platform === "macOS"
        ? "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
        : "tailscale") +
      " login --login-server=" +
      data.settings.controlURL;
    hint.textContent =
      platform === "macOS"
        ? "Run this command with the standard Tailscale app open."
        : "Install the standard Tailscale client, then run this command.";
  };
  for (const p of ["macOS", "Windows", "Linux"])
    tabs.append(button(p, "secondary", () => select(p)));
  select("macOS");
  showDialog(
    "Connect a device",
    el(
      "p",
      {},
      "Keep the standard Tailscale client. Sign in to this network through its configured identity provider.",
    ),
    tabs,
    hint,
    command,
    el(
      "p",
      {},
      "Joining the network does not grant access to other devices. Access is governed by your network policy.",
    ),
    el(
      "div",
      { class: "dialog-actions" },
      button("Close", "secondary", () => modal.close()),
      button("Copy command", "primary", () => copy(command.textContent)),
    ),
  );
}
function machines() {
  const section = el(
    "section",
    {},
    preview(),
    heading(
      "Machines",
      "Manage the devices connected to your network.",
      button("Add device", "primary", addDevice),
    ),
  );
  if (!data.nodes.length) {
    section.append(el("div", {class: "empty empty-network"},
      el("div", {class: "empty-icon", "aria-hidden": "true"}, el("img", {src: "/favicon.svg", alt: "", width: "32", height: "32"})),
      el("h2", {}, "Connect your first device"),
      el("p", {}, data.workflow ? "Connect with the standard Tailscale client, then review and approve its access." : "Connect with the standard Tailscale client to start using your private network."),
      button("Add device", "primary", addDevice),
      el("p", {class: "empty-note"}, data.workflow?.blocked && !data.workflow.denial_verified ? "Access enforcement is unverified. Review access before relying on this network." : data.workflow ? "Devices of approved company members receive their assigned access after enrollment." : "Access is governed by your network policy.")));
    return section;
  }
  const search = el("input", {
    type: "search",
    placeholder: "Search devices, models, OS, owners…",
    "aria-label": "Search machines",
    maxlength: 200,
    value: query,
  });
  const state = el("select", { "aria-label": "Connection status" });
  for (const [v, t] of [
    ["all", "All statuses"],
    ["online", "Connected"],
    ["offline", "Not connected"],
    ["expired", "Expired"],
  ])
    state.append(el("option", { value: v }, t));
  state.value = filter;
  const ownerSelect = el(
    "select",
    { "aria-label": "Device owner" },
    el("option", { value: "all" }, "All owners"),
  );
  for (const u of data.users)
    ownerSelect.append(
      el("option", { value: u.id }, u.displayName || u.email || u.name),
    );
  ownerSelect.value = owner;
  const counts = el("div", { class: "counts" }),
    list = el("div", { class: "table-scroll" });
  const fill = () => {
    const matching = data.nodes.filter(
      (n) =>
        [
          deviceName(n),
          n.name, n.model, n.os, n.osVersion, n.architecture, n.version,
          ...(n.ipAddresses || []),
          n.user?.email,
          n.user?.name,
          ...(n.tags || []),
        ]
          .join(" ")
          .toLowerCase()
          .includes(query.toLowerCase()) &&
        (owner === "all" || n.user.id === owner) &&
        (filter === "all" ||
          (filter === "online" && n.online && !expired(n)) ||
          (filter === "offline" && !n.online) ||
          (filter === "expired" && expired(n))),
    );
    counts.replaceChildren(
      `${matching.length} ${matching.length === 1 ? "device" : "devices"}`,
      el(
        "span",
        { class: "connected" },
        el("span", { class: "dot" }),
        `${data.nodes.filter((n) => n.online && !expired(n)).length} connected`,
      ),
    );
    list.replaceChildren();
    if (!matching.length) {
      list.append(
        el(
          "div",
          { class: "empty" },
          el(
            "h2",
            {},
            data.nodes.length
              ? "No matching devices"
              : "Your network starts here",
          ),
          el(
            "p",
            {},
            data.nodes.length
              ? "Try another search or clear the filters."
              : "Connect your first device to see it here.",
          ),
        ),
      );
      return;
    }
    const table = el(
      "table",
      {},
      el(
        "thead",
        {},
        el(
          "tr",
          {},
          el("th", {}, "Machine"),
          el("th", {}, "Address"),
          el("th", { class: "owner-col" }, "Managed by"),
          el("th", {}, "Last seen"),
          el("th", {}, ""),
        ),
      ),
    );
    const body = el("tbody");
    for (const n of matching)
      body.append(
        el(
          "tr",
          {},
          el(
            "td",
            {},
            el(
              "div",
              { class: "device-cell" },
              icon(n),
              el(
                "div",
                {},
                button(deviceName(n), "device-link", () => showDevice(n)),
                el(
                  "div",
                  { class: "secondary-text" },
                  devicePlatform(n),
                ),
                badges(n),
              ),
            ),
          ),
          el(
            "td",
            {},
            (n.ipAddresses || []).length
              ? button(
                  [
                    el("span", { class: "mono" }, n.ipAddresses[0]),
                    el(
                      "span",
                      { class: "copy-mark", "aria-hidden": "true" },
                      "⧉",
                    ),
                  ],
                  "copy-ip",
                  () => copy(n.ipAddresses[0]),
                )
              : "—",
            el("div", { class: "secondary-text mono" }, n.version || ""),
          ),
          el(
            "td",
            { class: "owner-col" },
            el(
              "div",
              { class: "owner" },
              n.tags?.length
                ? "Tagged device"
                : n.user.displayName || n.user.name || "—",
            ),
            el(
              "div",
              { class: "owner-email" },
              n.tags?.length ? "Managed by policy" : n.user.email || "",
            ),
          ),
          el("td", {}, status(n)),
          el("td", {}, actions(n)),
        ),
      );
    table.append(body);
    list.append(table);
  };
  search.addEventListener("input", () => {
    query = search.value;
    fill();
  });
  state.addEventListener("change", () => {
    filter = state.value;
    fill();
  });
  ownerSelect.addEventListener("change", () => {
    owner = ownerSelect.value;
    fill();
  });
  fill();
  section.append(
    el(
      "div",
      { class: "toolbar" },
      el(
        "div",
        { class: "search" },
        el("span", { "aria-hidden": "true" }, "⌕"),
        search,
      ),
      state,
      ownerSelect,
      button("↻ Refresh", "secondary refresh", refresh),
    ),
    counts,
    list,
    el(
      "div",
      { class: "table-note" },
      el("span", {}, "Connected devices are governed by your access policy."),
      data.demo ? el("span", {}, "Sample network · 2 people") : null,
    ),
  );
  return section;
}
function permissionUsers() {
  return data.workflow?.users || [];
}
const personName = u => u.name || u.displayName || u.email || "Unnamed user";
function personButton(u) {
  return button(personName(u), "person-link", () => showUser(u));
}
function showUser(u) {
  const permissions = u.services || [];
  const devices = (u.device_ids || []).map(id => data.nodes.find(n => String(n.id) === String(id))).filter(Boolean);
  drawer.hidden = false;
  drawer.replaceChildren(...[button("×", "close", () => (drawer.hidden = true)),
    el("h2", {id:"drawer-title"}, personName(u)), el("p", {class:"secondary-text"}, u.email || "Email not reported"),
    el("h3", {}, "Service permissions"),
    el("p", {class:"secondary-text"}, "Assigned access through this person’s approved devices."),
    ...permissions.map(service => el("div", {class:"permission-item"}, el("strong", {}, service.name),
      el("p", {}, serviceDevice(service.destination_id)), el("span", {class:"badge blue"}, service.port.toUpperCase().replace(":", " ")))),
    !permissions.length ? el("p", {class:"permission-empty"}, data.workflow ? "No service permissions assigned." : "Service permissions are managed by your network policy.") : null,
    data.workflow ? el("a", {href:"#services", onclick:() => (drawer.hidden = true)}, "Manage permissions in Services") : null,
    el("h3", {}, "Devices"), ...devices.map(n => el("p", {}, deviceName(n))),
    !devices.length ? el("p", {class:"secondary-text"}, "No enrolled devices.") : null].filter(node => node !== null));
  drawer.querySelector(".close").focus();
}
function users() {
  const people = data.workflow ? permissionUsers() : data.users;
  const section = el("section", {}, preview(), heading("Users", "See each person’s devices and assigned service permissions."));
  const table = el("table", {}, el("thead", {}, el("tr", {}, el("th", {}, "User"), el("th", {}, "Devices"), el("th", {}, "Service permissions"))));
  const body = el("tbody");
  for (const original of people) {
    const u = data.workflow ? original : {...original, device_ids:data.nodes.filter(n => n.user?.id === original.id).map(n => n.id)};
    body.append(el("tr", {},
      el("td", {}, personButton(u), el("div", {class:"secondary-text"}, u.email || "Email not reported")),
      el("td", {}, String((u.device_ids || []).length)),
      el("td", {}, data.workflow ? `${(u.services || []).length} ${(u.services || []).length === 1 ? "service" : "services"}` : "Policy managed separately")));
  }
  table.append(body);
  section.append(people.length ? el("div", {class:"table-scroll"}, table) : el("div", {class:"empty"}, el("h2", {}, "No users yet"), el("p", {}, "Approved members appear here.")));
  return section;
}
function card(title, ...content) {
  return el("article", { class: "card" }, el("h2", {}, title), ...content);
}
function access() {
  if (data.workflow) return approvals();
  const source =
    data.settings.policyMode === "file"
      ? "Deployment file"
      : data.settings.policyMode === "database"
        ? "Headscale database"
        : "Not available";
  return el(
    "section",
    {},
    preview(),
    heading(
      "Access controls",
      "Define who can reach the devices and services in your network.",
    ),
    el(
      "div",
      { class: "card" },
      el(
        "div",
        { class: "card-header" },
        el("h2", {}, "Network policy"),
        el("span", { class: "pill muted" }, "Read-only"),
      ),
      el(
        "div",
        { class: "policy-tools" },
        el("span", {}, "Source: " + source),
        button("Copy policy", "secondary", () => copy(data.policy)),
      ),
      el("pre", { class: "code" }, data.policy || "Policy is not available."),
      el(
        "p",
        {},
        "Policy changes are reviewed and applied through deployment configuration.",
      ),
      el(
        "div",
        { class: "rule-line" },
        el("span", {}, "Explicit grants control connectivity"),
        el("span", {}, "Membership alone grants no access"),
      ),
    ),
  );
}
async function workflowAction(action, payload) {
  const epoch = authEpoch;
  try {
    await request("/api/workflow/" + action, payload);
    if (epoch !== authEpoch) return;
    modal.close();
    await refresh();
    if (epoch === authEpoch) toast("Access workflow updated");
  } catch (e) {
    if (epoch !== authEpoch || e instanceof StaleRequest) return;
    toast(e.message);
    await refresh();
  }
}
function planEditor() {
  const w = data.workflow;
  const selected = new Set(w.plan.device_ids || []);
  const sources = new Set(), destinations = new Set();
  const picker = (set) => el("div", {class: "card approval-picker"}, ...w.devices.filter(n => n.eligible).map(n => {
    const input = el("input", {type: "checkbox", value: n.id, onchange: () => input.checked ? set.add(n.id) : set.delete(n.id)});
    input.checked = set.has(n.id);
    return el("label", {}, input, " " + n.name + " · " + (n.email || "No owner") + " (#" + n.id + ")");
  }));
  const name = el("input", {type: "text", placeholder: "developers", "aria-label": "Team name", maxlength: "32"});
  const ports = el("input", {type: "text", placeholder: "tcp:443, tcp:22", "aria-label": "Allowed ports"});
  const draft = el("textarea", {rows: "18", cols: "75", "aria-label": "Complete proposed access plan"});
  draft.value = JSON.stringify(w.plan, null, 2);
  const comment = el("input", {type: "text", placeholder: "Reason for this change", maxlength: "512", "aria-label": "Change reason"});
  const build = () => {
    try {
      const plan = JSON.parse(draft.value);
      plan.device_ids = Array.from(selected);
      if (name.value.trim()) {
        const team = name.value.trim();
        plan.teams = (plan.teams || []).filter(t => t.name !== team);
        plan.teams.push({name: team, device_ids: Array.from(sources)});
        plan.grants = (plan.grants || []).filter(g => g.team !== team);
        if (destinations.size) plan.grants.push({team, destination_ids: Array.from(destinations), ports: ports.value.split(",").map(p => p.trim()).filter(Boolean)});
      }
      draft.value = JSON.stringify(plan, null, 2);
    } catch { toast("The draft must be valid JSON"); }
  };
  showDialog("Propose access changes",
    el("p", {}, "Choose exact devices. Enrollment alone grants no access. Each approved device receives a unique protected tag and retains its original Google owner in Tailgate's approval ledger."),
    el("h3", {}, "Approved device set"), picker(selected),
    el("h3", {}, "Add or replace a team"), name,
    el("p", {}, "Select that team's source devices, then the destination devices and concrete TCP/UDP ports."),
    el("h4", {}, "Team source devices"), picker(sources),
    el("h4", {}, "Destination devices"), picker(destinations), ports,
    button("Update draft from selections", "secondary", build),
    el("h3", {}, "Complete desired plan"),
    el("p", {}, "Review this entire plan. Removing a device, team or grant withdraws that access. Advanced edits may be made directly below; wildcards, IP selectors and port ranges are rejected."), draft, comment,
    button("Submit for review", "primary", () => {
      try { const plan = JSON.parse(draft.value); workflowAction("propose", {revision: w.revision, inventory: w.inventory, plan, comment: comment.value}); }
      catch { toast("The draft must be valid JSON"); }
    }));
}
function approvals() {
  const w = data.workflow;
  const section = el("section", {}, heading("Access approvals", "Approve devices, select team members and grant exact services. Revision " + w.revision,
    w.writes && !w.blocked ? button("Propose changes", "primary", planEditor) : null));
  if (w.blocked) section.append(card("Access changes blocked", el("p", {class: "error"}, w.blocked), el("p", {}, "Reconciliation installs and verifies deny-all. Recreate and review a fresh plan before restoring access."), w.writes ? button("Reconcile to deny-all", "danger", () => showDialog("Reconcile access", el("p", {}, "This withdraws all network grants. It does not restore personal ownership of tagged devices."), button("Verify deny-all and reconcile", "danger", () => workflowAction("reconcile", {})))) : null));
  const review = (entry, decision) => {
    const note = el("textarea", {rows:"3", maxlength:"1000", "aria-label":"Note for the requester", placeholder:"Optional note for the requester"});
    const destination = el("select", {"aria-label":"Service device"}, el("option", {value:""}, "No service grant"), ...w.devices.filter(n => n.approved).map(n => el("option", {value:n.id}, n.name + " (#" + n.id + ")")));
    const service = el("input", {type:"text", maxlength:"64", placeholder:"Service name (for example, Satellite)", "aria-label":"Service name"});
    const port = el("input", {type:"text", placeholder:"tcp:8443", "aria-label":"Service port"});
    const error = el("p", {class:"error", role:"alert"});
    error.hidden = true;
    const submit = button(decision === "approved" ? "Approve company access" : decision === "revoked" ? "Revoke company access" : "Decline request", decision === "approved" ? "primary" : "danger", async () => {
      const epoch = authEpoch;
      submit.disabled = true;
      try {
        const auto_access = decision === "approved" && destination.value ? {service:service.value.trim(), destination_id:destination.value, port:port.value.trim()} : undefined;
        await request("/api/requests/review", {id:entry.id, decision, note:note.value, auto_access});
        if (epoch !== authEpoch) return;
        modal.close(); await refresh();
        if (epoch === authEpoch) toast("Company request reviewed");
      } catch (e) { if (epoch === authEpoch && !(e instanceof StaleRequest)) { error.hidden=false; error.textContent=e.message; submit.disabled=false; } }
    });
    showDialog(decision === "approved" ? "Approve company access" : decision === "revoked" ? "Revoke company access" : "Decline company access", el("p", {}, entry.email), el("p", {}, entry.reason), el("p", {}, decision === "approved" ? "Devices enrolled with this verified Google account will be approved automatically. Choose an exact service and port if they should receive one." : decision === "revoked" ? "This stops future automatic device admission and withdraws this person's approved device and service grants. It does not disable their Google account." : "This request will be declined."), decision === "approved" ? el("div", {}, el("label", {}, "Service device (optional)", destination), el("label", {}, "Service name", service), el("label", {}, "Service port", port)) : null, note, error, submit);
  };
  const company = w.requests || [];
  section.append(card("Company access requests", el("p", {}, "Review new users before they begin device setup."),
    ...company.filter(r => r.status === "pending").map(r => el("div", {class:"card"}, el("strong", {}, r.email), el("p", {}, r.reason), el("p", {}, humanDate(r.created_at)),
      w.writes ? button("Review request", "primary", () => review(r, "approved")) : null,
      w.writes ? button("Decline", "secondary", () => review(r, "rejected")) : null)),
    !company.some(r => r.status === "pending") ? el("p", {}, "No requests awaiting review.") : null,
    ...company.filter(r => r.status !== "pending").slice(-5).reverse().map(r => el("div", {class:"rule-line"}, el("span", {}, r.email + " · " + r.status + " · " + humanDate(r.reviewed_at)), r.status === "approved" && w.writes ? button("Revoke", "secondary", () => review(r, "revoked")) : null))));
  section.append(card("Devices", el("p", {}, "Devices of approved company members are admitted after their verified Google identity is matched. Existing tagged servers still need a separate administrator enrollment process."), ...w.devices.map(n => el("div", {class:"rule-line"},
    el("span", {}, n.name + " · " + (n.email || "No original owner") + " (#" + n.id + ")"),
    el("span", {}, n.approved ? "Approved" : n.eligible ? "Pending approval" : n.reason),
    n.approved && w.writes ? button("Revoke access", "secondary", () => showDialog("Revoke " + n.name, el("p", {}, "Remove this device from every source team and destination grant. Its protected tag and original identity receipt are retained. Delete and re-enroll to restore personal-device ownership."), button("Revoke access", "danger", () => workflowAction("revoke", {id:n.id})))) : null))));
  section.append(card("Pending proposals", ...(w.proposals || []).filter(p => p.status === "pending").map(p => el("div", {class:"card"},
    el("p", {}, p.comment || "Access change"), el("p", {}, "Proposed by " + p.actor + " · revision " + p.revision + " · " + humanDate(p.created_at)),
    el("pre", {class:"code"}, JSON.stringify(p.plan, null, 2)),
    w.writes && !w.blocked ? button("Review and approve", "primary", () => showDialog("Approve complete access plan", el("p", {}, "Approval applies exactly this plan after checking the current device keys, owners, tags and revision. New approvals convert personal devices to protected tagged nodes: personal Taildrop and upstream ownership semantics change. Tailgate preserves their original Google identity."), el("pre", {class:"code"}, JSON.stringify(p.plan, null, 2)), button("Approve and apply", "primary", () => workflowAction("approve", {id:p.id})))) : null,
    w.writes ? button("Reject", "secondary", () => workflowAction("reject", {id:p.id})) : null))));
  section.append(card("Applied plan", el("pre", {class:"code"}, JSON.stringify(w.plan, null, 2)), el("p", {}, "Only enrolled destination devices and concrete ports are supported. Subnet, exit-node and server-key provisioning remain separate administrator operations.")));
  section.append(card("Recent approval journal", ...(w.audit || []).slice(-12).reverse().map(a => el("p", {}, humanDate(a.at) + " · " + a.actor + " · " + a.action + " · revision " + a.revision))));
  return section;
}
function serviceRecipients(service) {
  return data.workflow?.service_access?.find(entry => entry.destination_id === service.destination_id && entry.port === service.port)?.user_ids || [];
}
function serviceDevice(id) {
  const n = data.nodes.find(n => n.id === id);
  const owner = data.workflow?.devices.find(n => n.id === id)?.email;
  return n ? `${deviceName(n)}${owner ? " · " + owner : ""}` : `Unavailable device #${id}`;
}
function editService(existing) {
  const w = data.workflow;
  const name = el("input", {type:"text", maxlength:80, "aria-label":"Service name", value: existing?.name || ""});
  const destination = el("select", {"aria-label":"Service destination"}, ...w.devices.filter(n => n.approved && n.eligible).map(n => el("option", {value:n.id}, n.name)));
  const protocol = el("select", {"aria-label":"Protocol"}, el("option", {value:"tcp"}, "TCP"), el("option", {value:"udp"}, "UDP"));
  const port = el("input", {type:"number", min:1, max:65535, "aria-label":"Port", value:existing?.port.split(":")[1] || "443"});
  if (existing) {destination.value=existing.destination_id; protocol.value=existing.port.split(":")[0]; destination.disabled=true; protocol.disabled=true; port.disabled=true;}
  showDialog(existing ? "Name service" : "Add service", el("p", {}, "Choose an approved destination and one port. Saving a service does not grant access."),
    el("label", {}, "Name", name), el("label", {}, "Destination", destination), el("label", {}, "Protocol", protocol), el("label", {}, "Port", port),
    button("Save service", "primary", () => workflowAction("service-save", {revision:w.revision, inventory:w.inventory, service:{name:name.value, destination_id:destination.value, port:protocol.value+":"+port.value}})));
}
function manageService(service) {
  const w = data.workflow, before = serviceRecipients(service), selected = new Set(before);
  const candidates = permissionUsers();
  const list = el("div", {class:"approval-picker service-picker"});
  const count = el("p", {class:"selection-count", role:"status"});
  const error = el("p", {class:"login-error", role:"alert"});
  const updateCount = () => { count.textContent = `${selected.size} ${selected.size === 1 ? "person" : "people"} selected`; };
  const rows = candidates.map(u => {
    const input = el("input", {type:"checkbox", value:u.id, "aria-label":"Access for " + u.email, onchange:() => {input.checked ? selected.add(u.id) : selected.delete(u.id); updateCount();}});
    input.checked = selected.has(u.id);
    const row = el("label", {}, input, el("span", {}, el("strong", {}, personName(u)), el("small", {}, u.email),
      el("small", {}, `${(u.device_ids || []).length} enrolled ${(u.device_ids || []).length === 1 ? "device" : "devices"}`)));
    list.append(row); return {row, text:(personName(u)+" "+u.email).toLowerCase()};
  });
  const noMatches = el("p", {class:"secondary-text"}, "No matching users.");
  noMatches.hidden = true;
  const search = el("input", {type:"search", placeholder:"Search by name or email…", "aria-label":"Find service recipients", oninput:() => {
    rows.forEach(r => r.row.hidden = !r.text.includes(search.value.toLowerCase()));
    noMatches.hidden = rows.some(r => !r.row.hidden);
  }});
  const review = button("Review changes", "primary", async () => {
    const epoch = authEpoch, desired = [...selected];
    const added = desired.filter(id => !before.includes(id)), removed = before.filter(id => !selected.has(id));
    if (!added.length && !removed.length) {error.textContent = "Select a change to review."; return;}
    review.disabled = true; error.textContent = "";
    const label = id => { const u = candidates.find(u => u.id === id); return u ? `${personName(u)} · ${u.email}` : "Unavailable user"; };
    try {
      const result = await request("/api/workflow/service-propose", {destination_id:service.destination_id, port:service.port, user_ids:desired, revision:w.revision, inventory:w.inventory, comment:`Service access: ${service.name} (${service.port})`});
      if (epoch !== authEpoch) return;
      await refresh();
      if (epoch !== authEpoch || !data) return;
      showDialog("Review service access", el("h3", {}, service.name), el("p", {}, serviceDevice(service.destination_id)+" · "+service.port),
        el("h4", {}, "Grant access"), ...added.map(id => el("p", {}, label(id))), !added.length ? el("p", {}, "No additions") : null,
        el("h4", {}, "Remove access"), ...removed.map(id => el("p", {}, label(id))), !removed.length ? el("p", {}, "No removals") : null,
        el("p", {}, "Changes apply to these users’ approved devices after confirmation."),
        el("div", {class:"dialog-actions"}, button("Cancel proposal", "secondary", () => workflowAction("reject", {id:result.proposal_id})),
          button("Apply access", "primary", () => workflowAction("approve", {id:result.proposal_id}))));
    } catch(e) {if(epoch === authEpoch && !(e instanceof StaleRequest)) {error.textContent=e.message; review.disabled=false;}}
  });
  updateCount();
  review.disabled = !candidates.length;
  showDialog("Access to "+service.name, el("p", {}, serviceDevice(service.destination_id)+" · "+service.port),
    el("p", {}, "Select the people who should have access through their approved devices."), search, count, list, noMatches,
    !candidates.length ? el("p", {}, "Approve a company member before assigning service access.") : null, error,
    el("div", {class:"dialog-actions"}, button("Cancel", "secondary", () => modal.close()), review));
}
function services() {
  const w = data.workflow;
  const section = el("section", {}, heading("Services", "Choose who can reach each service on your network.", w?.writes && !w.blocked ? button("Add service", "primary", () => editService()) : null));
  if (!w) {section.append(el("div", {class:"empty"}, "Service access management is not configured.")); return section;}
  const catalog = w.services || [];
  if (w.blocked) section.append(el("p", {class:"notice"}, "Access changes are paused. Resolve the issue in Access controls before changing permissions."));
  if (!catalog.length) section.append(el("div", {class:"empty"}, el("h2", {}, "No services yet"), el("p", {}, "Add an approved destination and a port, then choose who can access it.")));
  const grid = el("div", {class:"services-grid"});
  for (const service of catalog) {
    const recipients = serviceRecipients(service), destination = w.devices.find(n => n.id === service.destination_id);
    const people = permissionUsers().filter(u => recipients.includes(u.id));
    grid.append(card(service.name, el("p", {class:"service-endpoint"}, serviceDevice(service.destination_id)), el("span", {class:"badge blue"}, service.port.toUpperCase().replace(":", " ")),
      el("h3", {}, `${recipients.length} ${recipients.length === 1 ? "person has" : "people have"} access`),
      el("div", {class:"service-people"}, ...people.map(u => el("div", {class:"service-person"}, personButton(u), el("small", {}, u.email)))),
      !recipients.length ? el("p", {class:"secondary-text"}, "No user permissions assigned.") : null,
      w.writes && !w.blocked && destination?.eligible && destination.approved ? el("div", {class:"dialog-actions"}, button("Rename", "secondary", () => editService(service)), button("Manage access", "primary", () => manageService(service))) : el("p", {class:"secondary-text"}, !destination?.approved ? "Destination is not currently approved." : "Access changes are unavailable.")));
  }
  section.append(grid); return section;
}

function operationalAlerts() {
  const checks = data.operations?.checks || [];
  const issues = checks.filter(c => c.status !== "pass");
  const pending = data.workflow?.proposals?.filter(p => p.status === "pending").length || 0;
  const company = data.workflow?.requests?.filter(r => r.status === "pending").length || 0;
  const devices = data.workflow?.devices?.filter(n => !n.approved && n.eligible).length || 0;
  const blocked = data.workflow?.blocked;
  if (!issues.length && !pending && !devices && !blocked && !company) return null;
  const notices = el("div", {class: "notices", "aria-label": "Administrator notifications"});
  const notice = (title, message, href, label, severe = false) => el("div", {class: "notice" + (severe ? " notice-danger" : ""), role: severe ? "alert" : "status"},
    el("div", {}, el("strong", {}, title), el("p", {}, message)), el("a", {href, class: "notice-link"}, label));
  if (blocked) notices.append(notice("Access approvals paused",
    data.workflow.denial_verified ? "Deny-all verified. Review access before approving devices." : "denial unverified; existing connectivity may remain",
    "#access", "Review access", !data.workflow.denial_verified));
  if (issues.length) notices.append(notice("System needs attention", `${issues.length} ${issues.length === 1 ? "check needs" : "checks need"} review.`, "#settings", "View health", issues.some(c => c.status === "fail")));
  if (pending || devices) notices.append(notice("Awaiting approval", `${pending} pending access proposals · ${devices} devices awaiting approval`, "#access", "Review approvals"));
  if (company) notices.append(notice("Company access requested", `${company} ${company === 1 ? "person is" : "people are"} awaiting your review.`, "#access", "Review requests"));
  return notices;
}
function healthStatus() {
  const checks = data.operations?.checks || [];
  const passed = checks.filter(c => c.status === "pass").length;
  const checksHealthy = checks.length > 0 && passed === checks.length;
  return {checks, passed, checksHealthy, healthy: checksHealthy && !data.workflow?.blocked};
}
function systemHealth() {
  const {checks, passed, checksHealthy} = healthStatus();
  const issueChecks = checks.filter(c => c.status !== "pass");
  const names = {controller_https: "Controller HTTPS", controller_certificate: "Controller certificate", off_host_backup: "Encrypted backup", admin_https: "Console HTTPS", admin_certificate: "Console certificate", operations: "Operational checks", "nginx.service": "Web proxy", "prometheus-node-exporter.service": "Monitoring exporter", "tailgate-admin-certificate.service": "Console certificate renewal", "tailgate-admin-certificate.timer": "Console renewal schedule", "tailgate-admin-key-rotation.service": "API credential rotation", "tailgate-admin-key-rotation.timer": "Credential rotation schedule", "tailgate-admin.service": "Administration service", "tailgate-backup.service": "Encrypted backup job", "tailgate-backup.timer": "Backup schedule", "tailgate-certificate.service": "Controller certificate renewal", "tailgate-certificate.timer": "Controller renewal schedule", "tailgate-health.timer": "Health-check schedule", "tailgate.service": "Controller service", "tailscaled.service": "Management connection"};
  const checkRow = c => el("div", {class: "health-check"},
    el("div", {}, el("strong", {}, names[c.name] || c.name), el("p", {}, c.message)),
    el("span", {class: "pill" + (c.status === "pass" ? "" : " muted")}, {pass: "Passed", warning: "Warning", fail: "Failed", disabled: "Disabled"}[c.status] || "Unknown"));
  const panel = card("System health",
    el("div", {class: "health-overview"}, el("span", {class: "pill" + (checksHealthy ? "" : " muted")}, checksHealthy ? "Operational checks passed" : checks.length ? "Needs attention" : "Status unavailable"),
      el("span", {}, checks.length ? `${passed} of ${checks.length} checks passed` : "No current health checks are available.")),
    data.operations?.generated_at ? el("p", {class: "health-updated"}, "Checked " + humanDate(data.operations.generated_at)) : null,
    ...issueChecks.map(checkRow));
  panel.className = "card full";
  if (checks.length) panel.append(el("details", {class: "health-details"},
    el("summary", {}, `View all ${checks.length} checks`), el("div", {class: "health-checks"}, ...checks.map(checkRow))));
  panel.append(el("p", {class: "health-note"}, "Visible to all administrators. Email alerts are not enabled."));
  return panel;
}
function dns() {
  const s = data.settings;
  const globals = s.globalNameservers || [],
    search = s.searchDomains || [],
    splits = Object.entries(s.splitNameservers || {});
  const effectiveSearch = [...new Set([...(s.magicDNS && s.deviceDomain ? [s.deviceDomain] : []), ...search])];
  const magic = card(
    "MagicDNS",
    el(
      "div",
      { class: "card-header" },
      el("p", {}, "Private device names are resolved by the Tailscale client on each enrolled device."),
      el(
        "span",
        { class: "pill" + (s.magicDNS ? "" : " muted") },
        s.magicDNS ? "Enabled" : "Disabled",
      ),
    ),
    el(
      "dl",
      { class: "definition" },
      el("dt", {}, "Network suffix"),
      el("dd", { class: "mono" }, s.deviceDomain || "Not available"),
    ),
    el(
      "div",
      { class: "rule-line" },
      s.magicDNS && s.deviceDomain ? "machine → machine." + s.deviceDomain : "MagicDNS short names are not enabled.",
    ),
    el("p", {class: "table-note"}, "Devices must enable Use Tailscale DNS settings to use these names automatically."),
  );
  const upstream = card(
    "Internet DNS",
    el("p", {}, "Default resolvers for names outside your private DNS zones. MagicDNS handles private device names separately."),
    el(
      "dl",
      { class: "definition" },
      el("dt", {}, "Default resolvers"),
      el(
        "dd",
        {},
        globals.length ? globals.join(", ") : "Use device’s existing DNS for internet names",
      ),
      el("dt", {}, "Replace device DNS"),
      el("dd", {}, s.overrideDNS ? "Enabled" : "Disabled"),
      el("dt", {}, "Search domains"),
      el("dd", {}, effectiveSearch.join(", ") || "None configured"),
      s.magicDNS && s.deviceDomain ? el("dt", {}, "Automatic suffix") : null,
      s.magicDNS && s.deviceDomain ? el("dd", {}, s.deviceDomain + " (MagicDNS)") : null,
    ),
  );
  const split = card(
    "Split DNS",
    splits.length
      ? el(
          "dl",
          { class: "definition" },
          splits.flatMap(([zone, resolvers]) => [
            el("dt", {}, zone),
            el("dd", {}, resolvers.join(", ")),
          ]),
        )
      : el("p", {}, "No split DNS zones configured."),
  );
  const records = card(
    "Application names",
    el("p", {}, "Private A and AAAA records for your services."),
  );
  records.classList.add("full");
  if (s.records?.length) {
    const table = el(
        "table",
        {},
        el(
          "thead",
          {},
          el(
            "tr",
            {},
            el("th", {}, "Name"),
            el("th", {}, "Type"),
            el("th", {}, "Address"),
          ),
        ),
      ),
      body = el("tbody");
    for (const r of s.records)
      body.append(
        el(
          "tr",
          {},
          el("td", { class: "mono" }, r.name),
          el("td", {}, r.type),
          el("td", { class: "mono" }, r.value),
        ),
      );
    table.append(body);
    records.append(el("div", { class: "table-scroll" }, table));
  } else
    records.append(
      el("p", { class: "secondary-text" }, "No additional service records."),
    );
  return el(
    "section",
    {},
    preview(),
    heading("DNS", "Private names that work on enrolled devices."),
    !data.configAvailable
      ? el("div", { class: "error" }, "DNS configuration is unavailable.")
      : null,
    el(
      "div",
      { class: "cards" },
      magic,
      upstream,
      split,
      card(
        "Configuration",
        el("p", {}, "DNS settings are managed by deployment configuration."),
        el("span", { class: "pill muted" }, "Read-only"),
      ),
      records,
    ),
  );
}
function settings() {
  const s = data.settings;
  return el(
    "section",
    {},
    preview(),
    heading(
      "Settings",
      "Your network’s control service and administration settings.",
    ),
    el(
      "div",
      { class: "cards" },
      card(
        "Network",
        el(
          "dl",
          { class: "definition" },
          el("dt", {}, "Control server"),
          el("dd", { class: "mono" }, s.controlURL || "Not available"),
          el("dt", {}, "Device domain"),
          el("dd", { class: "mono" }, s.deviceDomain || "Not available"),
          el("dt", {}, "Relay map"),
          el(
            "dd",
            {},
            s.ownRelaysOnly ? "Company-operated relays only" : "Not verified",
          ),
        ),
      ),
      card(
        "Administration",
        el(
          "dl",
          { class: "definition" },
          el("dt", {}, "Session"),
          el(
            "dd",
            {},
            data.demo ? "Local preview" : "Private administrator session",
          ),
          el("dt", {}, "Device changes"),
          el("dd", {}, data.writes ? "Enabled" : "Read-only"),
          el("dt", {}, "Access controls"),
          el("dd", {}, data.workflow ? "Reviewed approvals" : "Read-only policy"),
          el("dt", {}, "DNS settings"),
          el("dd", {}, "Read-only"),
        ),
        el(
          "div",
          { class: "rule-line" },
          data.demo
            ? "This preview has no connection to a live network."
            : "Only authorized administrators should use this console.",
        ),
      ),
      systemHealth(),
    ),
  );
}
function bridge() {
  const config = data.bridge;
  const content = el("div", {class:"bridge-page"}, heading("Migration bridge", "Choose which hosted-network accounts may access this network during migration."));
  if (!config || config.error) {
    content.append(el("p", {class:"subtitle"}, config?.error || "Configuration unavailable"));
    return content;
  }
  content.append(el("div", {class:"bridge-notice"},
    el("strong", {}, "Access is limited to listed accounts."),
    el("span", {}, " Destination permissions are managed in ", el("a", {href:"#access"}, "Access controls"), ".")));
  const rules = el("div", {class:"bridge-rules"});
  for (const [id, rule] of Object.entries(config.gateways)) {
    const accounts = el("textarea", {id:`bridge-users-${id}`, rows:"5", placeholder:"alice@example.com", spellcheck:"false", autocapitalize:"none", "aria-describedby":`bridge-users-help-${id}`});
    accounts.disabled = !config.writes;
    accounts.value = (rule.allowed_users || []).join("\n");
    const enabled = el("input", {type:"checkbox", id:`bridge-enabled-${id}`, "aria-labelledby":`bridge-enable-label-${id}`, "aria-describedby":`bridge-enable-help-${id}`});
    enabled.checked = rule.enabled;
    enabled.disabled = !config.writes;
    const feedback = el("p", {class:"bridge-feedback", role:"status", "aria-live":"polite"});
    const save = button("Save bridge rules", "btn primary", async () => {
      const epoch = authEpoch;
      save.disabled = true;
      try {
        await request("/api/bridge-config", {
          id, revision:config.revision, enabled:enabled.checked,
          allowed_users:accounts.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean),
        });
        if (epoch !== authEpoch) return;
        await refresh();
        if (epoch !== authEpoch) return;
        toast("Bridge rules saved. Gateways will fetch the update.");
      } catch (e) {
        if (epoch === authEpoch && !(e instanceof StaleRequest)) feedback.textContent = e.message;
      } finally { save.disabled = !config.writes; }
    });
    save.disabled = !config.writes;
    rules.append(el("section", {class:"bridge-config", "aria-labelledby":`bridge-title-${id}`},
      el("div", {class:"bridge-card-head"},
        el("div", {}, el("h2", {id:`bridge-title-${id}`}, id), el("p", {class:"bridge-meta"}, `Saved revision ${config.revision}`)),
        el("span", {class:`bridge-state${rule.enabled ? " enabled" : ""}`}, rule.enabled ? "Enabled" : "Disabled")),
      el("div", {class:"bridge-card-body"},
        el("label", {class:"bridge-enable", for:`bridge-enabled-${id}`}, enabled,
          el("span", {}, el("strong", {id:`bridge-enable-label-${id}`}, "Enable bridging for listed accounts"),
            el("span", {class:"bridge-control-help", id:`bridge-enable-help-${id}`}, "When disabled, no accounts can cross through this gateway."))),
        el("div", {class:"bridge-field"},
          el("label", {for:`bridge-users-${id}`}, "Allowed account emails"),
          el("p", {class:"bridge-field-hint"}, "Enter one hosted-network account email per line."), accounts,
          el("p", {class:"bridge-field-help", id:`bridge-users-help-${id}`}, "An empty list blocks everyone. Only devices owned by these accounts can bridge; tagged and shared devices remain excluded."))),
      el("div", {class:"bridge-card-footer"},
        el("div", {class:"bridge-save-row"}, save,
          el("p", {}, config.writes ? "Saved rules are fetched automatically by gateways." : "Bridge rules are read-only in this console.")),
        el("p", {class:"bridge-connection-note"}, "Saving rules does not confirm that the gateway is connected."), feedback)));
  }
  const audit = el("section", {class:"bridge-audit", "aria-labelledby":"bridge-audit-title"},
    el("div", {class:"bridge-audit-head"}, el("h2", {id:"bridge-audit-title"}, "Recent changes"),
      el("span", {class:"bridge-meta"}, "Last 10 updates")));
  const entries = el("div", {class:"bridge-audit-list"});
  for (const entry of (config.audit || []).slice(-10).reverse()) {
    entries.append(el("div", {class:"bridge-audit-entry"},
      el("div", {}, el("strong", {}, entry.gateway),
        el("span", {class:"bridge-audit-detail"}, `Revision ${entry.revision} · ${entry.rule.enabled ? "Enabled" : "Disabled"} · ${entry.rule.allowed_users.length} accounts`),
        el("span", {class:"bridge-audit-actor"}, entry.actor)),
      el("time", {datetime:entry.at}, humanDate(entry.at))));
  }
  if (!config.audit?.length) entries.append(el("div", {class:"bridge-audit-empty"},
    el("strong", {}, "No changes yet."), el("p", {}, "Saved rule updates will appear here with who changed them and when.")));
  audit.append(entries);
  content.append(rules, audit);
  return content;
}
function render() {
  if (!data) return;
  drawer.hidden = true;
  const page = ["machines", "users", "services", "access", "bridge", "dns", "settings"].includes(
    location.hash.slice(1),
  )
    ? location.hash.slice(1)
    : "machines";
  document.querySelectorAll("[data-page]").forEach((a) => {
    if (a.dataset.page === page) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  document.title =
    page === "access"
      ? "Access controls · Tailgate"
      : page === "dns"
        ? "DNS · Tailgate"
        : page[0].toUpperCase() + page.slice(1) + " · Tailgate";
  document.querySelector("#network-name").textContent = data.demo
    ? "Example network"
    : data.settings.deviceDomain || "Your network";
  const health = healthStatus(), paused = data.workflow?.blocked;
  const healthLink = document.querySelector("#mode-badge");
  healthLink.textContent = data.demo
    ? "Local preview"
    : paused ? data.workflow.denial_verified ? "Access paused" : "Access unverified" : health.healthy ? "System healthy" : health.checks.length ? "Needs attention" : "Health unknown";
  healthLink.className = "local-badge health-summary" + (!data.demo && health.healthy ? " healthy" : !data.demo && (paused || health.checks.length) ? " attention" : "");
  healthLink.setAttribute("href", paused ? "#access" : "#settings");
  healthLink.setAttribute("aria-label", healthLink.textContent + (paused ? ". Review access approvals" : ". View system health"));
  document.querySelector("#updated").textContent =
    "Updated " +
    new Date(data.updatedAt).toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
    });
  const alerts = operationalAlerts();
  main.replaceChildren(...(alerts ? [alerts] : []), { machines, users, services, access, bridge, dns, settings }[page]());
  setConsoleVisible(true);
}
async function refresh() {
  const epoch = authEpoch;
  try {
    const snapshot = await request("/api/snapshot");
    if (epoch !== authEpoch) return;
    data = snapshot;
    render();
  } catch (e) {
    if (epoch !== authEpoch || e instanceof StaleRequest) return;
    if (!data) {
      await showLogin();
      document.querySelector(".login-error").textContent = e.message;
    } else if (!document.querySelector(".login"))
      main.replaceChildren(
        el("div", { class: "error", role: "alert" }, e.message),
        button("Try again", "secondary", refresh),
      );
  }
}
async function showLogin() {
  clearProtectedState();
  const epoch = authEpoch;
  if (authMode !== "token" && authMode !== "demo") {
    const google = authMode === "google",
      signIn = button(
        google ? "Sign in with Google" : "Reload sign-in",
        "primary",
        () => {
          if (epoch !== authEpoch || signingOut || signIn.disabled) return;
          if (google) location.assign("/auth/google/start");
          else location.reload();
        },
      ),
      error = el("div", { class: "login-error", role: "alert" });
    if (google) {
      signIn.className = "primary google-signin";
      signIn.setAttribute("aria-label", "Sign in with Google");
      signIn.replaceChildren(el("img", {src:"/google-sign-in.png", alt:"", width:"177", height:"40", "aria-hidden":"true"}), el("span", {class:"sr-only"}, "Sign in with Google"));
    }
    signIn.disabled = signingOut;
    main.replaceChildren(
      el(
        "div",
        { class: "login" },
        loginBrand(),
        el("h1", {}, "Sign in to Tailgate"),
        el(
          "p",
          {},
          google
            ? "Use your approved Google administrator account."
            : "The administration service is unavailable. Reload to try again.",
        ),
        signIn,
        error,
        informationLinks(),
      ),
    );
    signIn.focus();
    return;
  }
  const input = el("input", {
      type: "password",
      id: "login-token",
      autocomplete: "current-password",
      required: "",
      maxlength: 8192,
    }),
    error = el("div", { class: "login-error", role: "alert" }),
    submit = el("button", { class: "primary", type: "submit" }, "Sign in");
  const form = el(
    "form",
    { class: "login" },
    loginBrand(),
    el("h1", {}, "Sign in to Tailgate"),
    el("p", {}, "Enter your private administrator token."),
    el("label", { for: "login-token" }, "Administrator token"),
    input,
    error,
    submit,
    informationLinks(),
  );
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (epoch !== authEpoch || signingOut || submit.disabled) return;
    submit.disabled = true;
    error.textContent = "";
    try {
      const result = await request("/api/login", { token: input.value });
      input.value = "";
      if (epoch !== authEpoch) return;
      csrf = result.csrf;
      document.querySelector("#signout").hidden = false;
      await refresh();
    } catch (e) {
      input.value = "";
      if (epoch !== authEpoch || e instanceof StaleRequest) return;
      error.textContent = e.message;
    } finally {
      submit.disabled = false;
    }
  });
  submit.disabled = signingOut;
  main.replaceChildren(form);
  input.focus();
}
document.querySelector("#signout").addEventListener("click", async () => {
  if (signingOut) return;
  signingOut = true;
  // Capture the old CSRF/cookie before clearing; never permit a new login to
  // race the old logout response and have its new cookie removed.
  const revocation = request("/api/logout", {}, { revokeSession: true });
  await showLogin();
  try {
    await revocation;
  } catch {
    const error = document.querySelector(".login-error");
    if (error)
      error.textContent =
        "Server sign-out could not be confirmed. Close this browser session before leaving the console.";
  } finally {
    signingOut = false;
    const submit = document.querySelector(".login .primary");
    if (submit) submit.disabled = false;
  }
});
window.addEventListener("hashchange", render);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    drawer.hidden = true;
    document.querySelectorAll(".row-action").forEach((d) => (d.open = false));
  }
});
modal.addEventListener("click", (e) => {
  if (e.target === modal) {
    const r = modal.getBoundingClientRect();
    if (
      e.clientX < r.left ||
      e.clientX > r.right ||
      e.clientY < r.top ||
      e.clientY > r.bottom
    )
      modal.close();
  }
});
(async () => {
  const epoch = authEpoch;
  try {
    const s = await request("/api/session");
    if (epoch !== authEpoch) return;
    if (!["token", "google", "demo"].includes(s.authMode))
      throw new Error("Authentication mode unavailable");
    authMode = s.authMode;
    setInformationSite(s.publicSiteURL);
    csrf = s.csrf;
    if (s.authenticated && s.role === "member") { location.replace("/start"); return; }
    if (s.authenticated) {
      document.querySelector("#signout").hidden = s.demo;
      await refresh();
    } else await showLogin();
  } catch (e) {
    if (epoch !== authEpoch || e instanceof StaleRequest) return;
    await showLogin();
  }
})();
