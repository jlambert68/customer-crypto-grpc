"use strict";

const state = {
  config: null,
  actor: null,
  records: new Map(),
};

const elements = {
  serviceState: document.querySelector("#service-state"),
  serviceStateLabel: document.querySelector("#service-state-label"),
  identity: document.querySelector("#identity-select"),
  role: document.querySelector("#role-chip"),
  permission: document.querySelector("#permission-summary"),
  readAll: document.querySelector("#read-all"),
  grid: document.querySelector("#record-grid"),
  template: document.querySelector("#record-template"),
  activity: document.querySelector("#activity-log"),
  clearActivity: document.querySelector("#clear-activity"),
};

function logActivity(level, message, details = undefined) {
  const method = level === "error" ? "error" : level === "warn" ? "warn" : "info";
  console[method](`[Customer Crypto] ${message}`, details ?? "");
  const item = document.createElement("li");
  item.className = level;
  const timestamp = document.createElement("time");
  timestamp.dateTime = new Date().toISOString();
  timestamp.textContent = new Date().toLocaleTimeString();
  const label = document.createElement("span");
  label.className = "level";
  label.textContent = level.toUpperCase();
  const text = document.createElement("span");
  text.textContent = details ? `${message} — ${formatDetails(details)}` : message;
  item.append(timestamp, label, text);
  elements.activity.prepend(item);
}

function formatDetails(details) {
  if (typeof details === "string") return details;
  return Object.entries(details).map(([key, value]) => `${key}=${String(value)}`).join(" ");
}

async function api(path, options = {}) {
  const actor = options.actor ?? state.actor?.id;
  const request = {
    method: options.method ?? "GET",
    headers: { Accept: "application/json", ...(options.headers ?? {}) },
  };
  if (actor) request.headers["X-Demo-Identity"] = actor;
  if (options.body !== undefined) {
    request.headers["Content-Type"] = "application/json";
    request.body = JSON.stringify(options.body);
  }
  logActivity("info", `${request.method} ${path}`, actor ? { actor } : undefined);
  const started = performance.now();
  let response;
  try {
    response = await fetch(path, request);
  } catch (error) {
    logActivity("error", `Network failure for ${request.method} ${path}`, error.message);
    throw error;
  }
  const payload = await response.json().catch(() => ({}));
  const details = {
    status: response.status,
    request: response.headers.get("X-Request-ID") ?? "unknown",
    duration_ms: Math.round(performance.now() - started),
  };
  if (!response.ok) {
    const error = new Error(payload.error ?? `HTTP ${response.status}`);
    error.status = response.status;
    logActivity(response.status >= 500 ? "error" : "warn", `${request.method} ${path} rejected`, { ...details, error: error.message });
    throw error;
  }
  logActivity("info", `${request.method} ${path} completed`, details);
  return payload;
}

function selectActor(id) {
  state.actor = state.config.identities.find((identity) => identity.id === id);
  state.records.clear();
  elements.role.textContent = state.actor.role;
  const reads = state.actor.read.join(", ") || "none";
  const updates = state.actor.update.join(", ") || "none";
  elements.permission.textContent = `Expected reads: ${reads}. Owner updates: ${updates}.`;
  logActivity("info", "Demo identity selected", { actor: state.actor.id, role: state.actor.role });
  renderRecords();
}

function renderRecords() {
  elements.grid.replaceChildren();
  for (const objectID of state.config.objects) {
    const fragment = elements.template.content.cloneNode(true);
    const card = fragment.querySelector(".record-card");
    const granted = state.actor.read.includes(objectID);
    const canUpdate = state.actor.update.includes(objectID);
    card.dataset.object = objectID;
    card.classList.toggle("denied", !granted);
    fragment.querySelector(".record-id").textContent = objectID;
    const access = fragment.querySelector(".access-chip");
    access.textContent = granted ? "Read granted" : "Read denied";
    access.classList.toggle("denied", !granted);
    const readButton = fragment.querySelector(".record-read");
    readButton.textContent = granted ? "Read record" : "Try denied read";
    readButton.addEventListener("click", () => readRecord(objectID));
    const form = fragment.querySelector(".record-form");
    form.addEventListener("submit", (event) => updateRecord(event, objectID));
    if (!canUpdate) {
      fragment.querySelector(".form-note").textContent = "Read-only for this identity. Updates are limited to the customer who owns the record.";
      fragment.querySelector(".save-button").hidden = true;
    }
    elements.grid.append(fragment);
  }
}

function cardFor(objectID) {
  return [...elements.grid.querySelectorAll(".record-card")].find((card) => card.dataset.object === objectID);
}

function setCardState(card, kind, title, detail) {
  const box = card.querySelector(".record-state");
  box.className = `record-state ${kind}`;
  box.querySelector(".state-title").textContent = title;
  box.querySelector(".state-detail").textContent = detail;
}

async function readRecord(objectID) {
  const card = cardFor(objectID);
  const button = card.querySelector(".record-read");
  button.disabled = true;
  setCardState(card, "loading", "Requesting encrypted record", `Acting as ${state.actor.id}…`);
  try {
    const record = await api(`/api/v1/records/${encodeURIComponent(objectID)}`);
    state.records.set(objectID, record);
    showRecord(card, record);
  } catch (error) {
    card.querySelector(".record-meta").hidden = true;
    card.querySelector(".record-form").hidden = true;
    setCardState(card, "error", error.status === 403 ? "Access denied" : "Read failed", error.message);
  } finally {
    button.disabled = false;
  }
}

function showRecord(card, record) {
  setCardState(card, "success", "Decrypted locally", `${record.actor} received version ${record.version}.`);
  const meta = card.querySelector(".record-meta");
  meta.hidden = false;
  meta.querySelector(".record-version").textContent = `v${record.version}`;
  meta.querySelector(".record-name").textContent = record.data.name ?? "—";
  const form = card.querySelector(".record-form");
  form.hidden = false;
  for (const input of form.elements) {
    if (!input.name) continue;
    input.value = record.data[input.name] ?? "";
    input.readOnly = !record.can_update;
  }
  const note = form.querySelector(".form-note");
  if (record.can_update) {
    note.textContent = "Saving re-encrypts the full record locally with a fresh DEK and creates the next version.";
  }
}

async function updateRecord(event, objectID) {
  event.preventDefault();
  const card = cardFor(objectID);
  const form = card.querySelector(".record-form");
  const save = card.querySelector(".save-button");
  const changes = {};
  for (const field of ["name", "email", "phone", "city", "notes"]) {
    changes[field] = form.elements[field].value;
  }
  save.disabled = true;
  setCardState(card, "loading", "Encrypting update", "Generating a fresh data-encryption key and recipient envelopes…");
  try {
    const record = await api(`/api/v1/records/${encodeURIComponent(objectID)}`, {
      method: "PATCH",
      body: { changes },
    });
    state.records.set(objectID, record);
    showRecord(card, record);
    logActivity("info", "Encrypted customer update saved", { actor: record.actor, object: objectID, version: record.version });
  } catch (error) {
    setCardState(card, "error", "Update failed", error.message);
  } finally {
    save.disabled = false;
  }
}

async function readAll() {
  elements.readAll.disabled = true;
  logActivity("info", "Reading every record for the selected identity", { actor: state.actor.id });
  for (const objectID of state.config.objects) {
    await readRecord(objectID);
  }
  elements.readAll.disabled = false;
}

async function start() {
  try {
    state.config = await api("/api/v1/config");
    elements.identity.replaceChildren();
    for (const identity of state.config.identities) {
      const option = document.createElement("option");
      option.value = identity.id;
      option.textContent = `${identity.label} (${identity.id})`;
      elements.identity.append(option);
    }
    elements.identity.disabled = false;
    elements.readAll.disabled = false;
    elements.serviceState.classList.add("online");
    elements.serviceStateLabel.textContent = "REST service online";
    selectActor(state.config.identities[0].id);
  } catch (error) {
    elements.serviceState.classList.add("offline");
    elements.serviceStateLabel.textContent = "REST service unavailable";
    elements.permission.textContent = error.message;
  }
}

elements.identity.addEventListener("change", (event) => selectActor(event.target.value));
elements.readAll.addEventListener("click", readAll);
elements.clearActivity.addEventListener("click", () => elements.activity.replaceChildren());
start();
