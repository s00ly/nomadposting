"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const composer = $("#composer-content");
const counter = $("#composer-counter");
if (composer && counter) {
  const updateCount = () => {
    const count = Array.from(composer.value).length;
    counter.textContent = `${count} code points`;
    counter.classList.toggle("error", count > 280);
  };
  composer.addEventListener("input", updateCount);
  updateCount();
}

$$('[data-confirm]').forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (!window.confirm(form.dataset.confirm)) event.preventDefault();
  });
});

function base64urlToBytes(value) {
  const padding = "=".repeat((4 - value.length % 4) % 4);
  const base64 = (value + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  return Uint8Array.from(raw, (character) => character.charCodeAt(0));
}

function bytesToBase64url(value) {
  const bytes = new Uint8Array(value);
  let raw = "";
  bytes.forEach((byte) => { raw += String.fromCharCode(byte); });
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeCreationOptions(options) {
  options.challenge = base64urlToBytes(options.challenge);
  options.user.id = base64urlToBytes(options.user.id);
  (options.excludeCredentials || []).forEach((credential) => { credential.id = base64urlToBytes(credential.id); });
  return options;
}

function decodeRequestOptions(options) {
  options.challenge = base64urlToBytes(options.challenge);
  (options.allowCredentials || []).forEach((credential) => { credential.id = base64urlToBytes(credential.id); });
  return options;
}

function serializeCredential(credential) {
  const response = {
    clientDataJSON: bytesToBase64url(credential.response.clientDataJSON),
  };
  if (credential.response.attestationObject) response.attestationObject = bytesToBase64url(credential.response.attestationObject);
  if (credential.response.authenticatorData) response.authenticatorData = bytesToBase64url(credential.response.authenticatorData);
  if (credential.response.signature) response.signature = bytesToBase64url(credential.response.signature);
  if (credential.response.userHandle) response.userHandle = bytesToBase64url(credential.response.userHandle);
  if (credential.response.getTransports) response.transports = credential.response.getTransports();
  return { id: credential.id, rawId: bytesToBase64url(credential.rawId), type: credential.type, response, clientExtensionResults: credential.getClientExtensionResults() };
}

async function ceremony(beginURL, finishURL, mode, bootstrapToken = "") {
  const headers = { "Accept": "application/json" };
  if (bootstrapToken) headers["X-Bootstrap-Token"] = bootstrapToken;
  const begin = await fetch(beginURL, { method: "POST", headers, credentials: "same-origin" });
  if (!begin.ok) throw new Error(await begin.text());
  const payload = await begin.json();
  const publicKey = mode === "register" ? decodeCreationOptions(payload.publicKey) : decodeRequestOptions(payload.publicKey);
  const credential = mode === "register"
    ? await navigator.credentials.create({ publicKey })
    : await navigator.credentials.get({ publicKey });
  const finishHeaders = { "Content-Type": "application/json", "X-CSRF-Token": payload.csrfToken || "" };
  if (bootstrapToken) finishHeaders["X-Bootstrap-Token"] = bootstrapToken;
  const finish = await fetch(finishURL, { method: "POST", headers: finishHeaders, body: JSON.stringify(serializeCredential(credential)), credentials: "same-origin" });
  if (!finish.ok) throw new Error(await finish.text());
  if ((finish.headers.get("content-type") || "").includes("application/json")) {
    const result = await finish.json();
    if (result.recoveryCode) {
      showRecoveryCode(result.recoveryCode);
      return;
    }
  }
  window.location.assign("/");
}

function showRecoveryCode(code) {
  const existing = $("#recovery-code-output");
  if (existing) existing.remove();
  const notice = document.createElement("section");
  notice.id = "recovery-code-output";
  notice.className = "panel recovery-output";
  notice.setAttribute("role", "alert");
  notice.tabIndex = -1;
  const heading = document.createElement("h2");
  heading.textContent = "Store this replacement recovery code offline";
  const warning = document.createElement("p");
  warning.textContent = "It is shown once. The previous recovery code is now invalid.";
  const value = document.createElement("code");
  value.className = "hash mono";
  value.textContent = code;
  const link = document.createElement("a");
  link.href = "/";
  link.className = "button button-purple";
  link.textContent = "Return to control plane";
  notice.append(heading, warning, value, link);
  const main = $("main");
  if (main) main.prepend(notice);
  notice.focus();
}

const authError = $("#auth-error");
const loginButton = $("#passkey-login");
if (loginButton) {
  loginButton.addEventListener("click", async () => {
    authError.textContent = "";
    try { await ceremony("/auth/login/begin", "/auth/login/finish", "login"); }
    catch (error) { authError.textContent = error.message || "Passkey authentication failed."; }
  });
}

const registerButton = $("#passkey-register");
if (registerButton) {
  registerButton.addEventListener("click", async () => {
    authError.textContent = "";
    const bootstrap = $("#bootstrap-token");
    try { await ceremony("/auth/register/begin", "/auth/register/finish", "register", bootstrap ? bootstrap.value : ""); }
    catch (error) { authError.textContent = error.message || "Passkey registration failed."; }
  });
}

const recoveryLogin = $("#recovery-login");
if (recoveryLogin) {
  recoveryLogin.addEventListener("click", async () => {
    authError.textContent = "";
    const input = $("#recovery-code-input");
    try {
      const response = await fetch("/auth/recovery", { method: "POST", headers: { "X-Recovery-Code": input ? input.value : "", "Accept": "application/json" }, credentials: "same-origin" });
      if (!response.ok) throw new Error(await response.text());
      const result = await response.json();
      showRecoveryCode(result.recoveryCode);
    } catch (error) {
      authError.textContent = error.message || "Recovery failed.";
    }
  });
}

const recoveryRotate = $("#recovery-rotate");
if (recoveryRotate) {
  recoveryRotate.addEventListener("click", async () => {
    try {
      const response = await fetch("/auth/recovery/rotate", { method: "POST", headers: { "X-CSRF-Token": recoveryRotate.dataset.csrf || "", "Accept": "application/json" }, credentials: "same-origin" });
      if (!response.ok) throw new Error(await response.text());
      const result = await response.json();
      showRecoveryCode(result.recoveryCode);
    } catch (error) {
      window.alert(error.message || "Recovery rotation failed.");
    }
  });
}
