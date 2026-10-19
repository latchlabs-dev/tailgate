"use strict";
const main = document.querySelector("#member-main");
let csrf = "", publicSite = "", epoch = 0, refreshID = 0, timer, signedIn = false;
const pending = new Set();
const el = (tag, attrs = {}, ...children) => {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) if (child != null) node.append(child instanceof Node ? child : String(child));
  return node;
};
const button = (label, cls, action) => el("button", {type: "button", class: cls, onclick: action}, label);
const brand = () => el("div", {class: "brand login-brand"}, el("img", {src: "/favicon.svg", alt: "", width: "32", height: "32"}), "tailgate");
const info = () => publicSite ? el("nav", {class: "information-links", "aria-label": "Tailgate information"}, ...[["Home", "/"], ["Privacy", "/privacy"], ["Terms", "/terms"], ["Support", "/support"]].map(([label, path]) => el("a", {href: publicSite + path}, label))) : null;
const shell = (...children) => main.replaceChildren(el("section", {class: "login member-panel"}, brand(), ...children, info()));
class StaleRequest extends Error {}
async function api(path, payload, logout = false) {
  const generation = epoch, controller = new AbortController();
  if (!logout) pending.add(controller);
  try {
    const response = await fetch(path, {method: payload === undefined ? "GET" : "POST", credentials: "same-origin", headers: payload === undefined ? {} : {"Content-Type": "application/json", "X-CSRF-Token": csrf}, body: payload === undefined ? undefined : JSON.stringify(payload), signal: controller.signal});
    const result = await response.json();
    if (!logout && generation !== epoch) throw new StaleRequest();
    if (response.status === 401) {
      signedIn = false; csrf = ""; epoch++; clearTimeout(timer);
      for (const request of pending) request.abort();
      pending.clear(); showLogin(); throw new StaleRequest();
    }
    if (!response.ok) throw new Error(result.error || "Please try again.");
    return result;
  } finally { pending.delete(controller); }
}
function showLogin() {
  document.title = "Get started · Tailgate";
  const signin = el("a", {class: "primary google-signin", href: "/auth/google/member/start", "aria-label": "Sign in with Google"}, el("img", {src: "/google-sign-in.png", alt: "Sign in with Google", width: "177", height: "40"}));
  shell(el("h1", {}, "Get started"), el("p", {}, "Sign in with your company Google account to request access. An administrator will review your request."), signin, el("p", {}, el("a", {href: "/"}, "Admin login")));
}
async function signout() {
  const token = csrf;
  signedIn = false; epoch++; clearTimeout(timer);
  for (const request of pending) request.abort();
  pending.clear(); csrf = token;
  shell(el("h1", {}, "Signing out…"));
  try { await api("/api/logout", {}, true); csrf = ""; showLogin(); }
  catch { shell(el("h1", {}, "Sign-out could not be completed"), el("p", {role: "alert"}, "Try again to end your session."), button("Retry sign out", "secondary", signout)); }
}
async function refresh() {
  const generation = epoch, currentRefresh = ++refreshID;
  clearTimeout(timer);
  try {
    const data = await api("/api/member");
    if (generation !== epoch || currentRefresh !== refreshID || !signedIn) return;
    document.title = "Your company access · Tailgate";
    const requests = data.requests || [], latest = requests.at(-1), error = el("p", {class: "login-error", role: "alert"});
    const content = [el("h1", {}, "Your company access"), el("p", {class: "member-account"}, "Signed in as " + data.email)];
    if (data.approved) {
      content.push(el("h2", {}, "You're approved — connect your device"), el("p", {}, "You're signed in to the Tailgate website. Next, connect your work device using the Tailscale app. Repeat these steps on each device you want to use."));
      if (latest?.note) content.push(el("p", {}, "Administrator note: " + latest.note));
      if (latest?.auto_access?.service) content.push(el("p", {}, "Approved service: " + latest.auto_access.service + "."));
      if (data.controlURL) content.push(
        el("ol", {class: "member-steps"},
          el("li", {}, el("strong", {}, "Install and open Tailscale."), el("p", {}, el("a", {href: "https://tailscale.com/download"}, "Download Tailscale"), " on your work device. If it's already installed, open it and continue.")),
          el("li", {}, el("strong", {}, "Choose the company server."), el("p", {}, "Use the custom control server option in Tailscale and enter this address:"), el("code", {}, data.controlURL),
            el("p", {}, "On macOS with an existing account: open Tailscale → Settings → Accounts, then the down arrow at the bottom left. Enter the address above and choose Add account."),
            el("p", {}, "Setting up a Mac for the first time? Open Tailscale, then paste this command into Terminal and press Return:"),
            el("code", {}, "/Applications/Tailscale.app/Contents/MacOS/Tailscale login --login-server=" + data.controlURL),
            el("p", {}, el("a", {href: "https://tailscale.com/docs/how-to/set-up-custom-control-server", target: "_blank", rel: "noopener noreferrer"}, "Windows, Linux, iPhone and Android setup instructions"), " — choose your device on that page and use the server address above.")),
          el("li", {}, el("strong", {}, "Sign in with your company Google account."), el("p", {}, "Follow the sign-in link opened or shown by Tailscale. In the browser, choose ", el("strong", {}, data.email), ". If Google selects a personal account, choose Use another account. Finish the browser confirmation and any device or VPN permission prompts.")),
          el("li", {}, el("strong", {}, "Check your device, then open your work tools."), el("p", {}, "Return to this page and select Check device status below. Once your device shows Approved, keep Tailscale connected and open the service link provided by your administrator. Each work tool may still ask you to sign in."))),
        el("p", {}, "Device missing? Check that Tailscale is using the company server above and the same Google account shown on this page. If setup stays unfinished or a work tool won't open, contact your administrator with the device name and the message you see."));
      else content.push(el("p", {role: "status"}, "Your setup address is currently unavailable. Contact your administrator for the company server address before signing in through Tailscale."));
      content.push(el("h3", {}, "Your devices"));
      if (!data.devicesAvailable) content.push(el("p", {role: "status"}, "Device status is temporarily unavailable. Try again shortly."));
      else if (!(data.devices || []).length) content.push(el("p", {role: "status"}, "No devices enrolled yet. After you sign in through Tailscale, your device will appear here."));
      else content.push(el("ul", {class: "member-devices"}, ...(data.devices || []).map(device => el("li", {}, device.name + " — " + (device.status === "approved" ? "Approved" : "Finishing setup")))));
      content.push(button("Check device status", "secondary", refresh));
      timer = setTimeout(refresh, 30000);
    } else if (latest?.status === "pending") {
      content.push(el("h2", {}, "Awaiting administrator review"), el("p", {role: "status"}, "Your request has been sent. Your next step is to wait for approval; this page checks automatically. Once approved, you’ll see instructions here to install Tailscale and sign in on your device."), el("p", {}, "Requested access: " + latest.reason), button("Check status", "secondary", refresh));
      timer = setTimeout(refresh, 30000);
    } else {
      if (latest?.status === "rejected" || latest?.status === "revoked") content.push(el("p", {role: "status"}, latest.status === "revoked" ? "Your previous company access was withdrawn." : "Your previous request was declined."), latest.note ? el("p", {}, "Administrator note: " + latest.note) : null);
      const reason = el("textarea", {id: "request-reason", name: "reason", rows: "4", maxlength: "1000", required: "", placeholder: "Which tools do you need, and what will you use them for?"});
      const submit = el("button", {type: "submit", class: "primary"}, "Send request");
      const form = el("form", {onsubmit: async event => {
        event.preventDefault(); if (submit.disabled) return;
        submit.disabled = true; error.textContent = "";
        try { await api("/api/member/request", {reason: reason.value}); if (generation === epoch) await refresh(); }
        catch (e) { if (generation === epoch && !(e instanceof StaleRequest) && e.name !== "AbortError") { error.textContent = e.message; submit.disabled = false; } }
      }}, el("label", {for: "request-reason"}, "What access do you need?"), reason, submit, error);
      content.push(el("p", {}, "First, request access to the work tools you need. After your administrator approves the request, this page will show you how to connect your device and sign in."), form);
    }
    content.push(button("Sign out", "quiet", signout));
    shell(...content);
  } catch (e) {
    if (generation !== epoch || e instanceof StaleRequest || e.name === "AbortError") return;
    shell(el("h1", {}, "Your company access"), el("p", {class: "login-error", role: "alert"}, e.message), button("Try again", "secondary", refresh), button("Sign out", "quiet", signout));
  }
}
(async () => {
  try {
    const session = await api("/api/session");
    publicSite = /^https:\/\/[a-z0-9.-]+$/.test(session.publicSiteURL || "") ? session.publicSiteURL : "";
    csrf = session.csrf;
    if (!session.authenticated) { showLogin(); return; }
    if (session.role !== "member" && session.role !== "admin") { showLogin(); return; }
    signedIn = true; await refresh();
  } catch { shell(el("h1", {}, "Sign-in is temporarily unavailable"), button("Try again", "primary", () => location.reload())); }
})();
