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

loadDashboard();
window.setInterval(loadDashboard, 30000);
