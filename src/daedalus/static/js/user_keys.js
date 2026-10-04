"use strict";
const feedback = document.getElementById("key-feedback");
async function keyRequest(url, options = {}) {
  const response = await fetch(url, { ...options, headers: {"Content-Type": "application/json"} });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || "Request failed");
  return data;
}
const login = document.getElementById("token-login");
if (login) login.addEventListener("submit", async event => {
  event.preventDefault();
  try {
    await keyRequest("/auth/token", {method: "POST", body: JSON.stringify({token: login.elements.token.value})});
    login.reset(); location.assign("/dashboard");
  } catch (error) { feedback.textContent = error.message; }
});
const create = document.getElementById("create-key");
async function loadKeys() {
  const data = await keyRequest("/api/user-keys");
  const list = document.getElementById("key-list"); list.replaceChildren();
  for (const key of data.keys) {
    const row = document.createElement("p");
    row.textContent = `${key.name} · expires ${key.expires_at} ${key.revoked_at ? "· revoked" : ""} `;
    if (!key.revoked_at) {
      const button = document.createElement("button"); button.textContent = "Revoke";
      button.addEventListener("click", async () => {
        try { await keyRequest(`/api/user-keys/${key.id}`, {method: "DELETE"}); await loadKeys(); }
        catch (error) { feedback.textContent = error.message; }
      }); row.append(button);
    } list.append(row);
  }
}
if (create) {
  loadKeys().catch(error => { feedback.textContent = error.message; });
  create.addEventListener("submit", async event => {
    event.preventDefault();
    try {
      const result = await keyRequest("/api/user-keys", {method: "POST", body: JSON.stringify({name: create.elements.name.value, expires_days: Number(create.elements.expires_days.value)})});
      document.getElementById("new-key").textContent = result.token;
      feedback.textContent = "Copy this key now. It will not be shown again."; await loadKeys();
    } catch (error) { feedback.textContent = error.message; }
  });
}
