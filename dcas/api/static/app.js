"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const filesBody = $("#files-body");
const nodeGrid = $("#node-grid");
const activityList = $("#activity-list");
const fileDialog = $("#file-dialog");
const toastRegion = $("#toast-region");
let allFiles = [];
let selectedFile = null;
let refreshInProgress = false;

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    throw new Error(payload?.error || payload?.message || `Request failed (${response.status})`);
  }
  return payload;
}

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined && text !== null) element.textContent = text;
  return element;
}

function formatBytes(bytes) {
  const size = Number(bytes) || 0;
  if (size < 1024) return `${size} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = size / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(date);
}

function shorten(value, length = 15) {
  if (!value || value.length <= length * 2 + 3) return value || "—";
  return `${value.slice(0, length)}...${value.slice(-length)}`;
}

function showToast(message, isError = false) {
  const toast = node("div", `toast${isError ? " error" : ""}`, message);
  toastRegion.append(toast);
  window.setTimeout(() => toast.remove(), 4200);
}

function setLoading(button, loading, label) {
  if (loading) {
    button.dataset.originalLabel = button.textContent;
    button.textContent = label;
    button.disabled = true;
  } else {
    button.textContent = button.dataset.originalLabel || label;
    button.disabled = false;
  }
}

function renderFiles(files = allFiles) {
  filesBody.replaceChildren();
  $("#files-count").textContent = String(allFiles.length);
  const query = $("#search-input").value.trim().toLowerCase();
  const visibleFiles = files.filter((file) => (
    !query || [file.filename, file.cid, file.owner].some((value) => String(value || "").toLowerCase().includes(query))
  ));

  if (!visibleFiles.length) {
    const row = node("tr");
    const cell = node("td", "table-message", query ? "No files match your search." : "No files stored yet. Upload a file to get started.");
    cell.colSpan = 5;
    row.append(cell);
    filesBody.append(row);
  } else {
    for (const file of visibleFiles) {
      const row = node("tr");
      const fileCell = node("td");
      const fileIdentity = node("div", "file-cell");
      const fileIcon = node("span", "file-icon", "▤");
      fileIcon.setAttribute("aria-hidden", "true");
      const fileText = node("span");
      const fileButton = node("button", "file-link", file.filename || "Unnamed file");
      fileButton.type = "button";
      fileButton.title = file.filename || "";
      fileButton.addEventListener("click", () => openFile(file));
      const cid = node("span", "file-cid", shorten(file.cid, 10));
      cid.title = file.cid || "";
      fileText.append(fileButton, cid);
      fileIdentity.append(fileIcon, fileText);
      fileCell.append(fileIdentity);

      const sizeCell = node("td", "", formatBytes(file.total_size));
      const ownerCell = node("td");
      ownerCell.append(node("span", "owner-pill", file.owner || "system"));
      const dateCell = node("td", "", formatDate(file.created_at));
      const actionsCell = node("td");
      const action = node("button", "row-action", "↗");
      action.type = "button";
      action.setAttribute("aria-label", `View ${file.filename || "file"} details`);
      action.title = "View details and verify";
      action.addEventListener("click", () => openFile(file));
      const deleteButton = node("button", "row-action row-action-delete", "Delete");
      deleteButton.type = "button";
      deleteButton.setAttribute("aria-label", `Delete ${file.filename || "file"}`);
      deleteButton.title = "Delete file";
      deleteButton.addEventListener("click", () => deleteFile(file));
      const rowActions = node("div", "file-row-actions");
      rowActions.append(action, deleteButton);
      actionsCell.append(rowActions);
      row.append(fileCell, sizeCell, ownerCell, dateCell, actionsCell);
      filesBody.append(row);
    }
  }

  $("#files-summary").textContent = query
    ? `Showing ${visibleFiles.length} of ${allFiles.length} files`
    : `${allFiles.length} ${allFiles.length === 1 ? "file" : "files"} in your library`;
  $("#clear-search").classList.toggle("hidden", !query);
}

function renderNetwork(status) {
  const total = Number(status.total_nodes) || 0;
  const online = Number(status.online_nodes) || 0;
  const offline = Number(status.offline_nodes) || 0;
  const health = total ? Math.round((online / total) * 100) : 0;
  $("#stat-nodes").textContent = `${online} / ${total}`;
  $("#stat-replication").textContent = `Replication factor ${status.replication_factor ?? "—"}`;
  $("#stat-storage").textContent = formatBytes(status.total_used_bytes);
  $("#stat-chunks").textContent = `${Number(status.total_chunks_stored) || 0} chunks across all nodes`;
  $("#sidebar-health").textContent = total && online === total ? "All systems go" : `${health}% available`;
  $("#sidebar-node-count").textContent = `${online} online · ${offline} offline`;
  $("#health-bar").style.width = `${health}%`;
  $("#network-summary").textContent = `${online} of ${total} nodes online · ${health}% available`;
  const dot = $(".sidebar-network-heading .status-dot");
  dot.classList.toggle("warning", online > 0 && online < total);
  dot.classList.toggle("offline", total > 0 && online === 0);
  const summaryDot = $(".network-summary .status-dot");
  summaryDot.classList.toggle("warning", online > 0 && online < total);
  summaryDot.classList.toggle("offline", total > 0 && online === 0);

  nodeGrid.replaceChildren();
  const nodes = Array.isArray(status.nodes) ? status.nodes : [];
  if (!nodes.length) {
    nodeGrid.append(node("div", "empty-state", "No storage nodes are configured."));
    return;
  }
  for (const item of nodes) {
    const onlineNode = Boolean(item.is_online);
    const card = node("article", `node-card${onlineNode ? "" : " offline"}`);
    const symbol = node("span", "node-symbol", "◈");
    symbol.setAttribute("aria-hidden", "true");
    const info = node("div", "node-info");
    info.append(
      node("strong", "", item.node_id),
      node("span", "", `${onlineNode ? "Online" : "Offline"} · ${item.chunk_count} ${item.chunk_count === 1 ? "chunk" : "chunks"} · ${formatBytes(item.used_space_bytes)}`)
    );
    const control = node("button", `node-control${onlineNode ? "" : " recover"}`, onlineNode ? "Take offline" : "Recover");
    control.type = "button";
    control.addEventListener("click", () => changeNodeState(item.node_id, onlineNode, control));
    card.append(symbol, info, control);
    nodeGrid.append(card);
  }
}

function renderActivity(logs) {
  activityList.replaceChildren();
  if (!logs.length) {
    activityList.append(node("div", "empty-state", "No audit events yet. Upload or verify a file to see activity."));
    return;
  }
  const symbols = { UPLOAD: "↑", VERIFY: "✓", VERIFY_CHUNKS: "▦", VERIFY_MERKLE: "◇", AUDIT: "◎", RETRIEVE: "↓", DELETE: "−" };
  for (const event of logs) {
    const row = node("article", "activity-row");
    const status = String(event.status || "success").toLowerCase();
    const icon = node("span", `activity-symbol${status === "failure" ? " failure" : status === "warning" ? " warning" : ""}`, symbols[event.event_type] || "·");
    icon.setAttribute("aria-hidden", "true");
    const type = node("span", "activity-type", String(event.event_type || "EVENT").replaceAll("_", " "));
    const detailText = event.details || event.filename || event.cid || "Network event";
    const detail = node("span", "activity-detail", detailText);
    detail.title = detailText;
    const date = node("time", "activity-date", formatDate(event.timestamp));
    date.dateTime = event.timestamp || "";
    const badge = node("span", `event-status${status === "failure" ? " failure" : status === "warning" ? " warning" : ""}`, status);
    row.append(icon, type, detail, date, badge);
    activityList.append(row);
  }
}

async function loadDashboard() {
  if (refreshInProgress) return;
  refreshInProgress = true;
  try {
    const [fileData, networkData, auditData] = await Promise.all([
      api("/api/files"),
      api("/api/network/status"),
      api("/api/audit-log?limit=8")
    ]);
    allFiles = Array.isArray(fileData.files) ? fileData.files : [];
    renderFiles();
    renderNetwork(networkData);
    $("#stat-files").textContent = String(fileData.count ?? allFiles.length);
    $("#stat-events").textContent = String(auditData.stats?.total_events ?? "—");
    renderActivity(Array.isArray(auditData.logs) ? auditData.logs : []);
  } catch (error) {
    showToast(`Could not load dashboard: ${error.message}`, true);
    $("#files-summary").textContent = "Could not load file library";
    nodeGrid.replaceChildren(node("div", "empty-state", "Could not load storage node status."));
    activityList.replaceChildren(node("div", "empty-state", "Could not load audit history."));
  } finally {
    refreshInProgress = false;
  }
}

function updateSelectedFile(file) {
  selectedFile = file;
  $("#file-prompt").textContent = file.name;
  $("#file-hint").textContent = `${formatBytes(file.size)} · Ready to distribute`;
}

async function openFile(file) {
  selectedFile = file;
  $("#dialog-title").textContent = file.filename || "File details";
  $("#verify-output").replaceChildren();
  $("#file-details").replaceChildren(node("div", "empty-state", "Loading file details…"));
  $("#download-link").href = `/api/download/${encodeURIComponent(file.cid)}`;
  fileDialog.showModal();
  try {
    const info = await api(`/api/file/${encodeURIComponent(file.cid)}`);
    selectedFile = { ...file, ...info };
    const details = $("#file-details");
    details.replaceChildren();
    const fields = [
      ["CONTENT ID", info.cid, true],
      ["SIZE", formatBytes(info.total_size), false],
      ["CHUNKS", String(info.chunk_count ?? "—"), false],
      ["OWNER", info.owner || "system", false],
      ["CREATED", formatDate(info.created_at), false],
      ["SHA-256 FINGERPRINT", info.hash_digest, true],
      ["MERKLE ROOT", info.merkle_root, true]
    ];
    for (const [label, value, wide] of fields) {
      const item = node("div", `detail-item${wide ? " wide" : ""}`);
      item.append(node("span", "", label), node("strong", wide ? "mono" : "", value || "—"));
      details.append(item);
    }
  } catch (error) {
    $("#file-details").replaceChildren(node("div", "empty-state", `Could not load file details: ${error.message}`));
  }
}

async function verifySelectedFile(kind, button) {
  if (!selectedFile?.cid) return;
  const cid = encodeURIComponent(selectedFile.cid);
  const routes = {
    full: `/api/verify/${cid}`,
    chunks: `/api/verify/${cid}/chunks`,
    audit: `/api/verify/${cid}/audit`,
    merkle: `/api/verify/${cid}/merkle/0`
  };
  const labels = { full: "Integrity check", chunks: "Chunk verification", audit: "Network audit", merkle: "Merkle proof" };
  setLoading(button, true, "Verifying…");
  $("#verify-output").replaceChildren();
  try {
    const result = await api(routes[kind], { method: "POST" });
    const passed = result.status === "PASSED";
    const display = node("div", `verify-result${passed ? "" : " fail"}`);
    display.append(
      node("span", "result-mark", passed ? "✓" : "!"),
      node("span", ""),
    );
    const message = display.lastElementChild;
    message.append(
      node("strong", "", `${labels[kind]} ${passed ? "passed" : "failed"}`),
      document.createElement("br"),
      document.createTextNode(result.message || "Verification completed.")
    );
    if (result.elapsed_ms !== undefined) {
      message.append(document.createElement("br"), document.createTextNode(`Completed in ${Number(result.elapsed_ms).toFixed(1)} ms`));
    }
    $("#verify-output").replaceChildren(display);
    showToast(`${labels[kind]} ${passed ? "passed" : "reported an issue"} for ${selectedFile.filename || "file"}.`, !passed);
    await loadDashboard();
  } catch (error) {
    $("#verify-output").textContent = `${labels[kind]} could not complete: ${error.message}`;
    showToast(error.message, true);
  } finally {
    setLoading(button, false, "Verifying…");
  }
}

async function changeNodeState(nodeId, isOnline, button) {
  setLoading(button, true, "Updating…");
  try {
    const action = isOnline ? "fail" : "recover";
    const result = await api(`/api/network/${action}/${encodeURIComponent(nodeId)}`, { method: "POST" });
    showToast(result.message || `${nodeId} updated.`);
    await loadDashboard();
  } catch (error) {
    showToast(`Could not update ${nodeId}: ${error.message}`, true);
  } finally {
    setLoading(button, false, isOnline ? "Take offline" : "Recover");
  }
}

async function deleteFile(file) {
  const filename = file.filename || "this file";
  if (!window.confirm(`Delete "${filename}" from the network? This cannot be undone.`)) return;

  try {
    const result = await api(`/api/file/${encodeURIComponent(file.cid)}`, { method: "DELETE" });
    if (selectedFile?.cid === file.cid && fileDialog.open) fileDialog.close();
    showToast(result.message || `${filename} deleted.`);
    await loadDashboard();
  } catch (error) {
    showToast(`Could not delete ${filename}: ${error.message}`, true);
  }
}

const SPACE_STORAGE_KEY = "dcas.shared-spaces";
const spacesList = $("#spaces-list");
const spaceSelect = $("#space-select");

function readOwnedSpaces() {
  try {
    const spaces = JSON.parse(window.localStorage.getItem(SPACE_STORAGE_KEY) || "[]");
    return Array.isArray(spaces) ? spaces : [];
  } catch (error) {
    showToast(`Could not read spaces stored in this browser: ${error.message}`, true);
    return [];
  }
}

function saveOwnedSpaces(spaces) {
  window.localStorage.setItem(SPACE_STORAGE_KEY, JSON.stringify(spaces));
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function base64UrlToBytes(value) {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function sharedAccessUrl(space) {
  const url = new URL(`/share/${encodeURIComponent(space.space_id)}`, window.location.origin);
  url.hash = new URLSearchParams({ access: space.share_token, key: space.key }).toString();
  return url.toString();
}

function renderSpaceSelector(spaces) {
  spaceSelect.replaceChildren();
  const placeholder = node("option", "", spaces.length ? "Choose a shared space" : "Create a space first");
  placeholder.value = "";
  spaceSelect.append(placeholder);
  for (const space of spaces) {
    const option = node("option", "", space.name);
    option.value = space.space_id;
    spaceSelect.append(option);
  }
  spaceSelect.disabled = spaces.length === 0;
}

function renderOwnedSpaces() {
  const spaces = readOwnedSpaces();
  renderSpaceSelector(spaces);
  spacesList.replaceChildren();
  if (!spaces.length) {
    spacesList.append(node("div", "empty-state", "Your spaces will appear here. Space owner keys are kept in this browser."));
    return;
  }

  for (const space of spaces) {
    const card = node("article", "space-card");
    const info = node("div", "space-card-info");
    const status = node("span", "", "Checking space…");
    info.append(node("strong", "", space.name), status);

    const actions = node("div", "space-card-actions");
    const copyButton = node("button", "button button-secondary", "Copy access link");
    copyButton.type = "button";
    copyButton.disabled = !space.share_token;
    copyButton.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(sharedAccessUrl(space));
        showToast("Read-only access link copied. Anyone with it can read and decrypt this space.");
      } catch (error) {
        showToast(`Could not copy the access link: ${error.message}`, true);
      }
    });

    const rotateButton = node("button", "button button-secondary", space.share_token ? "Replace link" : "Create link");
    rotateButton.type = "button";
    rotateButton.addEventListener("click", () => rotateSpaceLink(space.space_id));
    const revokeButton = node("button", "button button-secondary", "Revoke");
    revokeButton.type = "button";
    revokeButton.disabled = !space.share_token;
    revokeButton.addEventListener("click", () => revokeSpaceLink(space.space_id));
    actions.append(copyButton, rotateButton, revokeButton);
    card.append(info, actions);
    spacesList.append(card);

    api(`/api/spaces/${encodeURIComponent(space.space_id)}/files`, {
      headers: { Authorization: `Bearer ${space.admin_token}` }
    }).then((result) => {
      status.textContent = `${result.count} ${result.count === 1 ? "file" : "files"} · ${space.share_token ? "access link active" : "link revoked"}`;
    }).catch((error) => {
      status.textContent = `Could not load space: ${error.message}`;
    });
  }
}

async function rotateSpaceLink(spaceId) {
  const spaces = readOwnedSpaces();
  const space = spaces.find((item) => item.space_id === spaceId);
  if (!space) return;
  try {
    const result = await api(`/api/spaces/${encodeURIComponent(spaceId)}/link/rotate`, {
      method: "POST",
      headers: { Authorization: `Bearer ${space.admin_token}` }
    });
    space.share_token = result.share_token;
    saveOwnedSpaces(spaces);
    renderOwnedSpaces();
    showToast("New access link created. Any previous link is now invalid.");
  } catch (error) {
    showToast(`Could not create an access link: ${error.message}`, true);
  }
}

async function revokeSpaceLink(spaceId) {
  const spaces = readOwnedSpaces();
  const space = spaces.find((item) => item.space_id === spaceId);
  if (!space || !window.confirm("Revoke this link? People using it will lose future access.")) return;
  try {
    const result = await api(`/api/spaces/${encodeURIComponent(spaceId)}/link`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${space.admin_token}` }
    });
    space.share_token = "";
    saveOwnedSpaces(spaces);
    renderOwnedSpaces();
    showToast(result.message);
  } catch (error) {
    showToast(`Could not revoke the access link: ${error.message}`, true);
  }
}

async function createSharedSpace(event) {
  event.preventDefault();
  const nameInput = $("#space-name");
  if (!window.crypto?.subtle) {
    showToast("Browser encryption requires HTTPS or localhost and Web Crypto support.", true);
    return;
  }
  const button = event.submitter;
  setLoading(button, true, "Creating…");
  try {
    const result = await api("/api/spaces", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: nameInput.value.trim() })
    });
    const key = window.crypto.getRandomValues(new Uint8Array(32));
    const spaces = readOwnedSpaces();
    spaces.push({
      space_id: result.space_id,
      name: result.name,
      admin_token: result.admin_token,
      share_token: result.share_token,
      key: bytesToBase64Url(key)
    });
    saveOwnedSpaces(spaces);
    event.target.reset();
    renderOwnedSpaces();
    showToast("Encrypted space created. Copy its access link to invite readers.");
  } catch (error) {
    showToast(`Could not create the space: ${error.message}`, true);
  } finally {
    setLoading(button, false, "＋ Create encrypted space");
  }
}

async function uploadToSharedSpace(event) {
  event.preventDefault();
  const file = $("#space-file").files[0];
  const space = readOwnedSpaces().find((item) => item.space_id === spaceSelect.value);
  if (!file || !space) {
    showToast("Choose a shared space and a file first.", true);
    return;
  }
  if (!window.crypto?.subtle) {
    showToast("Browser encryption requires HTTPS or localhost and Web Crypto support.", true);
    return;
  }

  const button = event.submitter;
  setLoading(button, true, "Encrypting and uploading…");
  try {
    const keyBytes = base64UrlToBytes(space.key);
    const cryptoKey = await window.crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = new Uint8Array(await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      await file.arrayBuffer()
    ));
    const payload = new Blob([new TextEncoder().encode("DCAS1"), iv, encrypted], { type: "application/octet-stream" });
    const encryptedFile = new File([payload], file.name, { type: "application/octet-stream" });
    const formData = new FormData();
    formData.append("file", encryptedFile, file.name);
    const result = await api(`/api/spaces/${encodeURIComponent(space.space_id)}/files`, {
      method: "POST",
      headers: { Authorization: `Bearer ${space.admin_token}` },
      body: formData
    });
    event.target.reset();
    showToast(`${result.filename} encrypted and added to ${space.name}.`);
    renderOwnedSpaces();
  } catch (error) {
    showToast(`Could not encrypt or upload the file: ${error.message}`, true);
  } finally {
    setLoading(button, false, "Encrypt and upload");
  }
}

async function openSharedSpace() {
  $(".app-shell").classList.add("hidden");
  $("#shared-view").classList.remove("hidden");
  const access = new URLSearchParams(window.location.hash.slice(1));
  const token = access.get("access");
  const key = access.get("key");
  window.history.replaceState(null, "", window.location.pathname);
  const sharedFiles = $("#shared-files");
  if (!token || !key) {
    $("#shared-title").textContent = "Access link is incomplete";
    sharedFiles.replaceChildren(node("div", "empty-state", "Ask the space owner for a new access link."));
    return;
  }

  const spaceId = decodeURIComponent(window.location.pathname.split("/").pop());
  try {
    const result = await api(`/api/spaces/${encodeURIComponent(spaceId)}/files`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    $("#shared-title").textContent = result.name;
    sharedFiles.replaceChildren();
    if (!result.files.length) {
      sharedFiles.append(node("div", "empty-state", "This space does not contain any files yet."));
      return;
    }

    for (const file of result.files) {
      const row = node("article", "shared-file-row");
      const info = node("div");
      info.append(
        node("div", "shared-file-name", file.filename),
        node("div", "shared-file-meta", `${formatBytes(file.total_size)} · Encrypted on the storage network`)
      );
      const download = node("button", "button button-secondary", "Decrypt and download");
      download.type = "button";
      download.addEventListener("click", () => downloadSharedFile(spaceId, file, token, key, download));
      row.append(info, download);
      sharedFiles.append(row);
    }
  } catch (error) {
    $("#shared-title").textContent = "Could not open this space";
    sharedFiles.replaceChildren(node("div", "empty-state", `Access failed: ${error.message}. Ask the owner for a current link.`));
  }
}

async function downloadSharedFile(spaceId, file, token, encodedKey, button) {
  setLoading(button, true, "Decrypting…");
  try {
    const response = await fetch(
      `/api/spaces/${encodeURIComponent(spaceId)}/files/${encodeURIComponent(file.cid)}/download`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      throw new Error(payload?.error || `Request failed (${response.status})`);
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    const header = new TextDecoder().decode(bytes.slice(0, 5));
    if (header !== "DCAS1" || bytes.length < 18) {
      throw new Error("The encrypted file format is invalid.");
    }
    const cryptoKey = await window.crypto.subtle.importKey(
      "raw",
      base64UrlToBytes(encodedKey),
      "AES-GCM",
      false,
      ["decrypt"]
    );
    const plain = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bytes.slice(5, 17) },
      cryptoKey,
      bytes.slice(17)
    );
    const url = URL.createObjectURL(new Blob([plain]));
    const anchor = node("a");
    anchor.href = url;
    anchor.download = file.filename;
    anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    showToast(`Could not decrypt ${file.filename}: ${error.message}`, true);
  } finally {
    setLoading(button, false, "Decrypt and download");
  }
}

$("#file-input").addEventListener("change", (event) => {
  const [file] = event.target.files;
  if (file) updateSelectedFile(file);
});

const dropzone = $("#dropzone");
for (const eventName of ["dragenter", "dragover"]) {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.add("drag-over");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.remove("drag-over");
  });
}
dropzone.addEventListener("drop", (event) => {
  const [file] = event.dataTransfer?.files || [];
  if (file) updateSelectedFile(file);
});

$("#upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = selectedFile || $("#file-input").files[0];
  if (!file) {
    showToast("Choose a file before uploading.", true);
    return;
  }
  const button = $("#upload-submit");
  setLoading(button, true, "Distributing file…");
  try {
    const formData = new FormData();
    formData.append("file", file, file.name);
    formData.append("owner", $("#owner-input").value.trim() || "system");
    formData.append("tags", JSON.stringify($("#tags-input").value.split(",").map((tag) => tag.trim()).filter(Boolean)));
    const result = await api("/api/upload", { method: "POST", body: formData });
    showToast(`${result.filename} stored successfully. CID: ${result.cid}`);
    event.target.reset();
    $("#owner-input").value = "system";
    $("#file-prompt").replaceChildren(
      document.createTextNode("Drop a file here, or "),
      node("span", "", "browse")
    );
    $("#file-hint").textContent = "Any file type · Stored across your network";
    selectedFile = null;
    await loadDashboard();
  } catch (error) {
    showToast(`Upload failed: ${error.message}`, true);
  } finally {
    setLoading(button, false, "＋ Add file to network");
  }
});

$("#text-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const content = $("#text-content").value;
  if (!content.trim()) {
    showToast("Enter some text before saving your note.", true);
    return;
  }
  const button = event.submitter;
  setLoading(button, true, "Saving…");
  try {
    const result = await api("/api/upload/text", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content,
        filename: $("#text-filename").value.trim() || "note.txt",
        owner: $("#owner-input").value.trim() || "system"
      })
    });
    showToast(`${result.filename} stored successfully. CID: ${result.cid}`);
    $("#text-content").value = "";
    await loadDashboard();
  } catch (error) {
    showToast(`Could not save note: ${error.message}`, true);
  } finally {
    setLoading(button, false, "Save note ↗");
  }
});

$("#search-input").addEventListener("input", () => renderFiles());
$("#clear-search").addEventListener("click", (event) => {
  event.preventDefault();
  $("#search-input").value = "";
  renderFiles();
});
$("#refresh-button").addEventListener("click", () => loadDashboard());
$(".close-dialog").addEventListener("click", () => fileDialog.close());
fileDialog.addEventListener("click", (event) => {
  if (event.target === fileDialog) fileDialog.close();
});
$(".dialog-actions").addEventListener("click", (event) => {
  const button = event.target.closest("[data-verify]");
  if (button) verifySelectedFile(button.dataset.verify, button);
});

document.querySelectorAll(".nav-link").forEach((link) => {
  link.addEventListener("click", () => {
    document.querySelectorAll(".nav-link").forEach((item) => item.classList.remove("active"));
    link.classList.add("active");
    $("#current-section").textContent = link.textContent.trim();
  });
});

$("#create-space-form").addEventListener("submit", createSharedSpace);
$("#space-upload-form").addEventListener("submit", uploadToSharedSpace);

if (window.location.pathname.startsWith("/share/")) {
  openSharedSpace();
} else {
  renderOwnedSpaces();
  loadDashboard();
  window.setInterval(loadDashboard, 30000);
}
