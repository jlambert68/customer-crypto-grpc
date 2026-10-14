"use strict";

const state = {
  config: null,
  actor: null,
  records: new Map(),
  bypassReadAuthorization: false,
};

const elements = {
  serviceState: document.querySelector("#service-state"),
  serviceStateLabel: document.querySelector("#service-state-label"),
  identity: document.querySelector("#identity-select"),
  role: document.querySelector("#role-chip"),
  permission: document.querySelector("#permission-summary"),
  authorizationToggle: document.querySelector("#authorization-toggle"),
  recordsExplainer: document.querySelector("#records-explainer"),
  readAll: document.querySelector("#read-all"),
  grid: document.querySelector("#record-grid"),
  template: document.querySelector("#record-template"),
  databaseStatus: document.querySelector("#database-status"),
  databaseOutput: document.querySelector("#database-output"),
  decryptionStatus: document.querySelector("#decryption-status"),
  decryptionOutput: document.querySelector("#decryption-output"),
  dekStatus: document.querySelector("#dek-status"),
  dekValue: document.querySelector("#dek-value"),
  dekRows: document.querySelector("#dek-rows"),
  envelopeRecordNode: document.querySelector("#envelope-record-node"),
  envelopeRecordLabel: document.querySelector("#envelope-record-label"),
  envelopeCiphertextLabel: document.querySelector("#envelope-ciphertext-label"),
  envelopeDEKHub: document.querySelector("#envelope-dek-hub"),
  envelopeDEKHint: document.querySelector("#envelope-dek-hint"),
  envelopeRecipients: document.querySelector("#envelope-recipients"),
  envelopeStoreSummary: document.querySelector("#envelope-store-summary"),
  envelopeActorNode: document.querySelector("#envelope-actor-node"),
  envelopeMatchNode: document.querySelector("#envelope-match-node"),
  envelopeKEKNode: document.querySelector("#envelope-kek-node"),
  envelopePlaintextNode: document.querySelector("#envelope-plaintext-node"),
  envelopeOutcome: document.querySelector("#envelope-outcome"),
  envelopeRecipientTemplate: document.querySelector("#envelope-recipient-template"),
  activity: document.querySelector("#activity-log"),
  clearActivity: document.querySelector("#clear-activity"),
};

const processSteps = Object.fromEntries([
  ["request", "process-request"],
  ["gate", "process-gate"],
  ["database", "process-database"],
  ["serverShare", "process-server-share"],
  ["clientCombine", "process-client-combine"],
  ["unwrap", "process-unwrap"],
  ["plaintext", "process-plaintext"],
].map(([name, id]) => {
  const root = document.querySelector(`#${id}`);
  return [name, {
    root,
    status: root.querySelector(".process-status"),
    detail: root.querySelector(".process-detail"),
    value: root.querySelector(".process-value"),
  }];
}));

function setProcessStep(name, stateName, status, detail, value) {
  const step = processSteps[name];
  step.root.className = `process-step ${stateName}`;
  step.status.textContent = status;
  step.detail.textContent = detail;
  step.value.textContent = value;
}

function traceLines(lines) {
  return lines.filter(Boolean).join("\n");
}

function shortHex(value) {
  if (!value) return "not available";
  return value.length > 30 ? `${value.slice(0, 14)}…${value.slice(-10)}` : value;
}

function setEnvelopeUnlockNode(element, stateName, title, detail) {
  element.className = `envelope-unlock-node ${stateName}`;
  element.querySelector("strong").textContent = title;
  element.querySelector("div > span").textContent = detail;
}

function setEnvelopeOutcome(stateName, title, detail) {
  elements.envelopeOutcome.className = `envelope-outcome ${stateName}`;
  elements.envelopeOutcome.querySelector("strong").textContent = title;
  elements.envelopeOutcome.querySelector("span").textContent = detail;
}

function buildEnvelopeRecipient(recipient, value, note, stateNames = []) {
  const root = elements.envelopeRecipientTemplate.content.firstElementChild.cloneNode(true);
  if (stateNames.length > 0) root.classList.add(...stateNames);
  root.querySelector(".envelope-recipient-name").textContent = recipient;
  root.querySelector(".envelope-recipient-value").textContent = value;
  root.querySelector(".envelope-recipient-note").textContent = note;
  return root;
}

function setEnvelopeRecordState(stateName, title, detail) {
  elements.envelopeRecordNode.className = `envelope-graphic-node ciphertext-node ${stateName}`;
  elements.envelopeRecordLabel.textContent = title;
  elements.envelopeCiphertextLabel.textContent = detail;
}

function resetEnvelopeVisual(message = "Read a record to replace this example with its real envelopes.") {
  const actor = state.actor?.id ?? "Choose an identity";
  setEnvelopeRecordState("waiting", "Encrypted record", "No record has been requested yet.");
  elements.envelopeDEKHub.className = "envelope-dek-hub waiting";
  elements.envelopeDEKHint.textContent = "hidden until a valid envelope opens";
  elements.envelopeRecipients.replaceChildren(buildEnvelopeRecipient(
    "Recipient envelopes appear here",
    "wrapped DEK",
    message,
    ["placeholder"],
  ));
  elements.envelopeStoreSummary.textContent = "One ciphertext + a map of named encrypted-DEK envelopes.";
  setEnvelopeUnlockNode(elements.envelopeActorNode, "waiting", actor, "Read a record to look for this identity’s envelope.");
  setEnvelopeUnlockNode(elements.envelopeMatchNode, "waiting", "Matching envelope?", "Waiting for ciphertext.");
  setEnvelopeUnlockNode(elements.envelopeKEKNode, "waiting", "Recover the DEK", "No KEK or DEK yet.");
  setEnvelopeUnlockNode(elements.envelopePlaintextNode, "waiting", "Readable customer data", "Still encrypted.");
  setEnvelopeOutcome("waiting", "Try it with a record", "A valid recipient follows the green path. A wrong identity stops at the envelope lookup.");
}

function beginEnvelopeVisual(objectID, method = "GET") {
  resetEnvelopeVisual(`Waiting for ${objectID} recipient envelopes.`);
  setEnvelopeRecordState("active", `Waiting for ${objectID}`, "The server has not released the encrypted record yet.");
  elements.envelopeDEKHub.className = "envelope-dek-hub active";
  elements.envelopeDEKHint.textContent = "waiting for a matching envelope";
  setEnvelopeUnlockNode(elements.envelopeActorNode, "active", state.actor.id, `${method} ${objectID} is in flight.`);
  setEnvelopeOutcome("active", "Request in progress", `Looking for an envelope named ${state.actor.id}.`);
}

function showEnvelopeVisual(record) {
  const trace = record.process_trace ?? {};
  const material = record.key_material ?? { recipient_envelopes: [] };
  const envelopes = material.recipient_envelopes ?? [];
  const matchingEnvelope = envelopes.find((envelope) => envelope.recipient === record.actor);
  const recovered = Boolean(record.decrypted && material.dek_hex && matchingEnvelope);
  const ciphertextBytes = Number.isFinite(trace.ciphertext_bytes)
    ? `${trace.ciphertext_bytes} encrypted bytes`
    : "encrypted bytes";

  setEnvelopeRecordState("success", `${record.object_id} · version ${record.version}`, `${ciphertextBytes} + record nonce`);
  elements.envelopeDEKHub.className = `envelope-dek-hub ${recovered ? "success" : "locked"}`;
  elements.envelopeDEKHint.textContent = recovered
    ? shortHex(material.dek_hex)
    : "the shared key remains wrapped";

  const recipientCards = [];
  if (!matchingEnvelope) {
    recipientCards.push(buildEnvelopeRecipient(
      record.actor,
      "NO ENVELOPE",
      "Selected identity is not a recipient for this record version.",
      ["missing"],
    ));
  }
  for (const envelope of envelopes) {
    const selected = envelope.recipient === record.actor;
    recipientCards.push(buildEnvelopeRecipient(
      envelope.recipient,
      `wrapped ${shortHex(envelope.wrapped_dek_hex)}`,
      selected ? "This request opens this envelope." : "Same DEK, separately wrapped for this recipient.",
      selected ? ["selected"] : ["dimmed"],
    ));
  }
  if (recipientCards.length === 0) {
    recipientCards.push(buildEnvelopeRecipient(
      "No recipient envelopes",
      "DEK unavailable",
      "This stored version cannot be opened by any listed identity.",
      ["missing"],
    ));
  }
  elements.envelopeRecipients.replaceChildren(...recipientCards);
  const recipientNames = envelopes.map((envelope) => envelope.recipient);
  elements.envelopeStoreSummary.textContent = `1 ciphertext + ${envelopes.length} named envelope${envelopes.length === 1 ? "" : "s"}: ${recipientNames.join(", ") || "none"}.`;

  setEnvelopeUnlockNode(elements.envelopeActorNode, "success", record.actor, `${record.object_id} version ${record.version} was returned to this demo client.`);
  if (!matchingEnvelope) {
    setEnvelopeUnlockNode(elements.envelopeMatchNode, "blocked", `No envelope named ${record.actor}`, "Other recipients’ envelopes cannot be substituted or opened by this identity.");
    setEnvelopeUnlockNode(elements.envelopeKEKNode, "skipped", "No DEK recovered", "Without a matching envelope there is nothing this identity can unwrap.");
    setEnvelopeUnlockNode(elements.envelopePlaintextNode, "skipped", "Ciphertext stays locked", "No readable customer fields were produced.");
    setEnvelopeOutcome("blocked", "The locked box arrived, but its key did not", `${record.actor} can see the ciphertext and ${envelopes.length} other named envelope${envelopes.length === 1 ? "" : "s"}, but none belongs to it.`);
    return;
  }

  setEnvelopeUnlockNode(elements.envelopeMatchNode, "success", `${matchingEnvelope.recipient} envelope found`, `Wrapped DEK ${shortHex(matchingEnvelope.wrapped_dek_hex)}`);
  if (!recovered) {
    setEnvelopeUnlockNode(elements.envelopeKEKNode, "blocked", "Envelope did not open", record.decryption_error || "The client could not recover the DEK.");
    setEnvelopeUnlockNode(elements.envelopePlaintextNode, "skipped", "Ciphertext stays locked", "No readable customer fields were produced.");
    setEnvelopeOutcome("blocked", "A matching envelope exists, but decryption stopped", record.decryption_error || "The cryptographic checks did not produce plaintext.");
    return;
  }

  setEnvelopeUnlockNode(elements.envelopeKEKNode, "success", "Envelope opened → DEK recovered", `KEK ${shortHex(trace.key_encryption_key_hex)} → DEK ${shortHex(material.dek_hex)}`);
  const fields = Object.keys(record.data ?? {}).sort();
  setEnvelopeUnlockNode(elements.envelopePlaintextNode, "success", "Customer JSON is readable", `Decoded fields: ${fields.join(", ") || "none"}.`);
  setEnvelopeOutcome("success", `Only ${record.actor}’s envelope was opened`, "That envelope recovered the common DEK, and the DEK opened the one shared ciphertext.");
}

function showEnvelopeFailure(objectID, error) {
  const denied = error.status === 403;
  const actor = state.actor?.id ?? "selected identity";
  setEnvelopeRecordState("blocked", `${objectID} not released`, denied
    ? "The server ACL stopped the request before ciphertext left the server."
    : "The encrypted record was not returned.");
  elements.envelopeDEKHub.className = "envelope-dek-hub locked";
  elements.envelopeDEKHint.textContent = "no key material returned";
  elements.envelopeRecipients.replaceChildren(buildEnvelopeRecipient(
    "Envelope map not released",
    "nothing to inspect",
    denied ? "Authorization stopped before the envelope layer." : error.message,
    ["placeholder"],
  ));
  elements.envelopeStoreSummary.textContent = "No database payload reached this client.";
  setEnvelopeUnlockNode(elements.envelopeActorNode, "success", actor, `${objectID} was requested.`);
  setEnvelopeUnlockNode(elements.envelopeMatchNode, "skipped", "Envelope lookup not reached", "The client received no envelope map to search.");
  setEnvelopeUnlockNode(elements.envelopeKEKNode, "skipped", "No DEK recovered", "No matching envelope was processed.");
  setEnvelopeUnlockNode(elements.envelopePlaintextNode, "skipped", "No plaintext", "No encrypted payload reached this step.");
  setEnvelopeOutcome("blocked", denied ? "Server authorization stopped first" : "The request failed before decryption", denied
    ? "This is an ACL denial. Disable read authorization to demonstrate the separate envelope boundary."
    : error.message);
}

function resetProcessTrace(message = "Choose a record to begin.") {
  setProcessStep("request", "waiting", "Waiting", message, "No request yet.");
  setProcessStep("gate", "waiting", "Waiting", "No authentication decision yet.", "The flow can stop here before SQLite returns ciphertext.");
  setProcessStep("database", "waiting", "Waiting", "No database row has been returned.", "The full stored JSON will appear in the evidence section below.");
  setProcessStep("serverShare", "waiting", "Waiting", "Waiting for a matching recipient envelope.", "No partial point yet.");
  setProcessStep("clientCombine", "waiting", "Waiting", "No client point has been computed.", "No combined shared point yet.");
  setProcessStep("unwrap", "waiting", "Waiting", "No envelope has been opened.", "No KEK or DEK yet.");
  setProcessStep("plaintext", "waiting", "Waiting", "No plaintext has been produced.", "The server never receives this plaintext.");
}

function beginProcessTrace(objectID, method = "GET") {
  resetProcessTrace();
  const authorization = state.bypassReadAuthorization && method === "GET"
    ? "X-Demo-Read-Authorization: disabled"
    : "read authorization enforced";
  setProcessStep("request", "active", "In flight", `${state.actor.id} is asking the local client gateway for ${objectID}.`, traceLines([
    `method: ${method}`,
    `object: ${objectID}`,
    `demo identity: ${state.actor.id}`,
    `policy header: ${authorization}`,
    "private client share: loaded locally; never displayed or sent",
  ]));
  setProcessStep("gate", "waiting", "Queued", "Waiting for the gRPC server decision.", "Token, revocation state, and read policy will be checked.");
  setProcessStep("database", "waiting", "Not reached", "Waiting for the server gate.", "No ciphertext returned yet.");
  setProcessStep("serverShare", "waiting", "Not reached", "Waiting for encrypted recipient data.", "No partial point yet.");
  setProcessStep("clientCombine", "waiting", "Not reached", "Waiting for the server partial point.", "No combined point yet.");
  setProcessStep("unwrap", "waiting", "Not reached", "Waiting for a combined shared point.", "No KEK or DEK yet.");
  setProcessStep("plaintext", "waiting", "Not reached", "Waiting for a recovered DEK.", "No plaintext yet.");
}

function showProcessTrace(record, method = "GET") {
  const trace = record.process_trace;
  if (!trace) {
    setProcessStep("request", "blocked", "Trace missing", "The request completed without educational trace data.", `method: ${method}\nobject: ${record.object_id}`);
    return;
  }

  const requestDetail = trace.operation === "update"
    ? `The client encrypted and stored ${trace.object_id} v${trace.version}; this trace verifies the fresh version.`
    : `The client gateway requested ${trace.object_id} v${trace.version} as ${trace.actor}.`;
  setProcessStep("request", "success", "Sent", requestDetail, traceLines([
    `method: ${method}`,
    `object: ${trace.object_id}`,
    `version returned: ${trace.version}`,
    `demo identity: ${trace.actor}`,
    "identity token: attached by client gateway; value hidden",
    "private client share: local only; value hidden",
  ]));

  const bypassed = trace.authorization_mode === "bypassed";
  setProcessStep("gate", bypassed ? "bypassed" : "success", bypassed ? "ACL bypassed" : "Allowed", trace.authorization_decision, traceLines([
    `authenticated: ${trace.authenticated}`,
    `read authorization: ${trace.authorization_mode}`,
    `decision: ${trace.authorization_decision}`,
    bypassed ? "write and administrative checks: still enforced" : "ciphertext release: allowed",
  ]));

  setProcessStep("database", "success", "Ciphertext returned", `SQLite returned encrypted ${trace.object_id} v${trace.version}; no customer fields were read as plaintext.`, traceLines([
    `stored JSON: ${trace.stored_json_bytes} bytes`,
    `record nonce: ${trace.record_nonce_hex}`,
    `AES-GCM ciphertext: ${trace.ciphertext_bytes} bytes`,
    `recipient envelopes (${trace.recipients.length}): ${trace.recipients.join(", ") || "none"}`,
    "plaintext customer fields in SQLite: none",
  ]));

  if (trace.status === "blocked") {
    const envelopeSummary = trace.envelope_found
      ? `matching envelope for ${trace.envelope_recipient}: found`
      : `matching envelope for ${trace.actor}: NOT FOUND`;
    setProcessStep("serverShare", "blocked", "Stopped here", trace.stop_reason, traceLines([
      envelopeSummary,
      trace.ephemeral_point_hex ? `R (ephemeral point): ${trace.ephemeral_point_hex}` : "R: unavailable for this identity",
      "server partial S: not returned",
      "private server share: never exposed",
    ]));
    setProcessStep("clientCombine", "skipped", "Not reached", "The client cannot combine points without a server partial result.", "No C or Z value was produced.");
    setProcessStep("unwrap", "skipped", "Not reached", "No combined point means no KEK and no recoverable DEK.", "KEK: unavailable\nDEK: unavailable");
    setProcessStep("plaintext", "skipped", "Still encrypted", "The ciphertext reached the client, but readable customer data did not.", traceLines([
      `actor: ${trace.actor}`,
      `object: ${trace.object_id}`,
      "plaintext: unavailable",
      "result: encryption boundary held",
    ]));
    return;
  }

  setProcessStep("serverShare", "success", "Partial returned", "The server verified this identity’s stored envelope and returned one derived point, not its private scalar share.", traceLines([
    `envelope recipient: ${trace.envelope_recipient}`,
    `R (ephemeral point): ${trace.ephemeral_point_hex}`,
    `S = x_server × R: ${trace.server_partial_point_hex}`,
    "x_server (private scalar): hidden inside server",
  ]));

  setProcessStep("clientCombine", "success", "Combined locally", "The selected client gateway computed its point and added it to the server result.", traceLines([
    `C = x_client × R: ${trace.client_partial_point_hex}`,
    `Z = S + C: ${trace.combined_shared_point_hex}`,
    "x_client (private scalar): hidden inside client gateway",
  ]));

  setProcessStep("unwrap", "success", "DEK recovered", "The combined point produced the KEK that opened this identity’s recipient envelope.", traceLines([
    `envelope AAD: ${trace.envelope_aad_hex}`,
    `wrap nonce: ${trace.wrap_nonce_hex}`,
    `wrapped DEK: ${trace.wrapped_dek_hex}`,
    `KEK: ${trace.key_encryption_key_hex}`,
    `DEK: ${trace.dek_hex}`,
    "KEK and DEK display: educational demo only",
  ]));

  const fields = Object.keys(record.data ?? {}).sort();
  setProcessStep("plaintext", "success", "Plaintext ready", "AES-256-GCM authenticated the object before the gateway decoded and returned its JSON fields.", traceLines([
    `record AAD: ${trace.record_aad_hex}`,
    `record nonce: ${trace.record_nonce_hex}`,
    `plaintext: ${trace.plaintext_bytes} bytes`,
    `decoded fields: ${fields.join(", ")}`,
    "plaintext location: client gateway and browser only",
    "plaintext at gRPC server: never",
  ]));
}

function showProcessFailure(objectID, error, method = "GET") {
  const denied = error.status === 403;
  setProcessStep("request", denied ? "success" : "blocked", denied ? "Sent" : "Failed", `${method} request for ${objectID} as ${state.actor.id}.`, traceLines([
    `method: ${method}`,
    `object: ${objectID}`,
    `demo identity: ${state.actor.id}`,
    `HTTP status: ${error.status ?? "network failure"}`,
  ]));
  setProcessStep("gate", "blocked", denied ? "ACL denied" : "Request failed", error.message, denied
    ? traceLines([
      "authentication: passed for the selected demo identity",
      "read authorization: enforced",
      "ACL decision: access denied",
      "ciphertext release: denied",
    ])
    : "The server process did not return a usable decision.");
  setProcessStep("database", "skipped", "Not reached", denied ? "The ACL stopped the request before the encrypted row was released." : "No encrypted row was returned.", "Database content was not sent to this client.");
  setProcessStep("serverShare", "skipped", "Not reached", "No returned ciphertext or matching envelope was available.", "No server partial point.");
  setProcessStep("clientCombine", "skipped", "Not reached", "There was no server result to combine.", "No client or combined point.");
  setProcessStep("unwrap", "skipped", "Not reached", "No recipient envelope was processed.", "No KEK or DEK.");
  setProcessStep("plaintext", "skipped", "Not reached", "The client received no decryptable payload.", "No plaintext.");
}

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
  if (options.bypassReadAuthorization) request.headers["X-Demo-Read-Authorization"] = "disabled";
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

function updatePermissionSummary() {
  const reads = state.actor.read.join(", ") || "none";
  const updates = state.actor.update.join(", ") || "none";
  if (state.bypassReadAuthorization) {
    elements.permission.textContent = state.actor.role === "rotation"
      ? "Server read ACL bypassed, although rotation already has a recipient envelope for every record. Browser updates remain disabled."
      : `Server read ACL bypassed. Encryption envelopes: ${reads}. Owner updates remain enforced: ${updates}.`;
    elements.recordsExplainer.textContent = state.actor.role === "rotation"
      ? "The rotation service can decrypt every record so it can create fresh encrypted versions after revocation."
      : "Every ciphertext is released. Records without an envelope for the selected identity should remain cryptographically locked.";
  } else if (state.actor.role === "rotation") {
    elements.permission.textContent = "Privileged rotation service: authorized to read C001, C002, and C003 for re-encryption. Interactive customer updates are disabled.";
    elements.recordsExplainer.textContent = "Rotation is intentionally a recipient for every record. Its maintenance writes run through the separate rotation command.";
  } else {
    elements.permission.textContent = `Server-authorized reads: ${reads}. Owner updates: ${updates}.`;
    elements.recordsExplainer.textContent = "Denied reads remain available as test actions so the server-side ACL can be observed.";
  }
}

function selectActor(id) {
  state.actor = state.config.identities.find((identity) => identity.id === id);
  state.records.clear();
  elements.role.textContent = state.actor.role;
  elements.role.classList.toggle("privileged", state.actor.role === "rotation");
  updatePermissionSummary();
  resetInspection(`Selected ${state.actor.id}. Read a record to compare storage and decryption.`);
  resetProcessTrace(`Selected ${state.actor.id}. Read a record to start the live trace.`);
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
    card.classList.toggle("denied", !granted && !state.bypassReadAuthorization);
    card.classList.toggle("bypassed", state.bypassReadAuthorization);
    fragment.querySelector(".record-id").textContent = objectID;
    const access = fragment.querySelector(".access-chip");
    access.textContent = state.bypassReadAuthorization ? "Ciphertext exposed" : granted ? "Read granted" : "Read denied";
    access.classList.toggle("denied", !granted && !state.bypassReadAuthorization);
    access.classList.toggle("bypassed", state.bypassReadAuthorization);
    const readButton = fragment.querySelector(".record-read");
    readButton.textContent = state.bypassReadAuthorization ? "Fetch ciphertext" : granted ? "Read record" : "Try denied read";
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
  beginProcessTrace(objectID, "GET");
  beginEnvelopeVisual(objectID, "GET");
  try {
    const record = await api(`/api/v1/records/${encodeURIComponent(objectID)}`, {
      bypassReadAuthorization: state.bypassReadAuthorization,
    });
    state.records.set(objectID, record);
    showProcessTrace(record, "GET");
    showInspection(record);
    if (record.decrypted) {
      showRecord(card, record);
    } else {
      showLockedRecord(card, record);
    }
  } catch (error) {
    card.querySelector(".record-meta").hidden = true;
    card.querySelector(".record-form").hidden = true;
    setCardState(card, "error", error.status === 403 ? "Access denied" : "Read failed", error.message);
    showProcessFailure(objectID, error, "GET");
    showInspectionFailure(objectID, error);
  } finally {
    button.disabled = false;
  }
}

function showRecord(card, record) {
  setCardState(card, "success", "Decrypted locally", `${record.actor} received version ${record.version}.`);
  const access = card.querySelector(".access-chip");
  access.textContent = "Decrypted";
  access.classList.remove("denied", "bypassed");
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

function showLockedRecord(card, record) {
  card.querySelector(".record-meta").hidden = true;
  card.querySelector(".record-form").hidden = true;
  const access = card.querySelector(".access-chip");
  access.textContent = "Crypto locked";
  access.classList.remove("denied");
  access.classList.add("bypassed");
  setCardState(card, "locked", "Ciphertext received; decryption blocked", record.decryption_error);
  logActivity("warn", "Encryption kept exposed ciphertext locked", {
    actor: record.actor,
    object: record.object_id,
    reason: record.decryption_error,
  });
}

function setInspectionStatus(element, label, kind = "") {
  element.textContent = label;
  element.className = `inspection-chip${kind ? ` ${kind}` : ""}`;
}

function resetInspection(message = "Read a customer record to inspect its stored encrypted representation.") {
  setInspectionStatus(elements.databaseStatus, "Waiting");
  setInspectionStatus(elements.decryptionStatus, "Waiting");
  elements.databaseOutput.textContent = message;
  elements.decryptionOutput.textContent = "No decryption attempt yet.";
  resetKeyMaterial();
  resetEnvelopeVisual(message);
}

function showInspection(record) {
  showEnvelopeVisual(record);
  showKeyMaterial(record);
  setInspectionStatus(elements.databaseStatus, `${record.object_id} v${record.version}`, "success");
  elements.databaseOutput.textContent = typeof record.database_stored === "string"
    ? record.database_stored
    : JSON.stringify(record.database_stored, null, 2);
  if (record.decrypted) {
    setInspectionStatus(elements.decryptionStatus, "Decrypted", "success");
    elements.decryptionOutput.textContent = JSON.stringify(record.data, null, 2);
    return;
  }
  setInspectionStatus(elements.decryptionStatus, "Locked", "locked");
  elements.decryptionOutput.textContent = JSON.stringify({
    status: "decryption blocked",
    actor: record.actor,
    object: record.object_id,
    reason: record.decryption_error,
  }, null, 2);
}

function showInspectionFailure(objectID, error) {
  showEnvelopeFailure(objectID, error);
  const denied = error.status === 403;
  setInspectionStatus(elements.databaseStatus, denied ? "Not released" : "Request failed", "error");
  setInspectionStatus(elements.decryptionStatus, "Not attempted", "error");
  elements.databaseOutput.textContent = denied
    ? `The server authorization check denied ${state.actor.id} access to ${objectID}, so no ciphertext was returned.`
    : error.message;
  elements.decryptionOutput.textContent = "No ciphertext reached the selected client gateway.";
  setInspectionStatus(elements.dekStatus, "Unavailable", "error");
  elements.dekValue.textContent = "No DEK material was returned.";
  setKeyTableMessage("No recipient envelopes were returned.");
}

function setKeyTableMessage(message) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 3;
  cell.textContent = message;
  row.append(cell);
  elements.dekRows.replaceChildren(row);
}

function resetKeyMaterial() {
  setInspectionStatus(elements.dekStatus, "Waiting");
  elements.dekValue.textContent = "Read a decryptable record to reveal the demo key.";
  setKeyTableMessage("No record selected.");
}

function appendKeyText(cell, value, note = "") {
  const code = document.createElement("code");
  code.textContent = value;
  cell.append(code);
  if (note) {
    const small = document.createElement("small");
    small.textContent = note;
    cell.append(small);
  }
}

function showKeyMaterial(record) {
  const material = record.key_material ?? { recipient_envelopes: [] };
  const envelopes = material.recipient_envelopes ?? [];
  const recovered = Boolean(material.dek_hex);
  setInspectionStatus(elements.dekStatus, recovered ? "DEK recovered" : "DEK locked", recovered ? "success" : "locked");
  elements.dekValue.textContent = recovered
    ? material.dek_hex
    : `${record.actor} could not recover the object DEK.`;

  const rows = [];
  if (!envelopes.some((envelope) => envelope.recipient === record.actor)) {
    const row = document.createElement("tr");
    row.className = "selected";
    const party = document.createElement("td");
    appendKeyText(party, record.actor, "Selected identity");
    const wrapped = document.createElement("td");
    appendKeyText(wrapped, "No envelope stored", "This party was not a recipient for this record version.");
    const unwrapped = document.createElement("td");
    appendKeyText(unwrapped, "Unavailable", "Without an envelope, this identity cannot recover the DEK.");
    row.append(party, wrapped, unwrapped);
    rows.push(row);
  }

  for (const envelope of envelopes) {
    const row = document.createElement("tr");
    if (envelope.selected) row.className = "selected";
    const party = document.createElement("td");
    appendKeyText(party, envelope.recipient, envelope.selected ? "Selected identity" : "Encrypted recipient");
    const wrapped = document.createElement("td");
    appendKeyText(wrapped, envelope.wrapped_dek_hex, `Wrap nonce: ${envelope.wrap_nonce_hex}`);
    const unwrapped = document.createElement("td");
    if (recovered) {
      appendKeyText(unwrapped, material.dek_hex, envelope.selected
        ? `Recovered by ${material.recovered_by} in this request.`
        : "Same object DEK; this party's envelope was not opened in this request.");
    } else {
      appendKeyText(unwrapped, "Not recovered", `The request acted only as ${record.actor}.`);
    }
    row.append(party, wrapped, unwrapped);
    rows.push(row);
  }

  if (rows.length === 0) {
    setKeyTableMessage("This encrypted record has no recipient envelopes.");
    return;
  }
  elements.dekRows.replaceChildren(...rows);
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
  beginProcessTrace(objectID, "PATCH");
  beginEnvelopeVisual(objectID, "PATCH");
  try {
    const record = await api(`/api/v1/records/${encodeURIComponent(objectID)}`, {
      method: "PATCH",
      body: { changes },
    });
    state.records.set(objectID, record);
    showProcessTrace(record, "PATCH");
    showInspection(record);
    showRecord(card, record);
    logActivity("info", "Encrypted customer update saved", { actor: record.actor, object: objectID, version: record.version });
  } catch (error) {
    setCardState(card, "error", "Update failed", error.message);
    showProcessFailure(objectID, error, "PATCH");
    showInspectionFailure(objectID, error);
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
    elements.authorizationToggle.disabled = false;
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
elements.authorizationToggle.addEventListener("change", (event) => {
  state.bypassReadAuthorization = event.target.checked;
  state.records.clear();
  updatePermissionSummary();
  resetInspection(state.bypassReadAuthorization
    ? "Server read authorization is bypassed. Fetch any record to expose its ciphertext."
    : "Server read authorization is enforced. Read a record to compare storage and decryption.");
  resetProcessTrace(state.bypassReadAuthorization
    ? "Read any record to see how exposed ciphertext can still stop at the encryption boundary."
    : "Read a record to follow the enforced authorization and decryption path.");
  renderRecords();
  logActivity(state.bypassReadAuthorization ? "warn" : "info", state.bypassReadAuthorization
    ? "Server read authorization disabled for demo requests"
    : "Server read authorization enabled", { actor: state.actor.id });
});
elements.readAll.addEventListener("click", readAll);
elements.clearActivity.addEventListener("click", () => elements.activity.replaceChildren());
start();
