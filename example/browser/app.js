/**
 * app.js
 *
 * Handles UI interactions and orchestrates the upload flow.
 * Delegates all memory measurement to memory-profiler.js.
 *
 * DIAGNOSTIC / TRIAGE CODE — sections marked "diagnostic" are not production code.
 * Their purpose is to isolate: GC lag, retained references, large work buffers,
 * and backpressure-induced queue growth.
 */

import { createEncryptor, decryptFetch, getKeyFingerprint, Algorithm } from "/dist/client/index.js";
import {
  isPerformanceMemorySupported,
  startMemoryProfiling,
  stopMemoryProfiling,
  stopSamplingInterval,
  captureMemorySample,
  addMarker,
  resetProfiling,
  buildMemorySummary,
  buildPostUploadSummary,
  buildExportPayload,
  getProfilingMeta,
  getLogs,
  getMemorySamples,
  getRecentChunks,
  getChunkAggregate,
  recordChunkStat,
  saveSession,
  getSessions,
  resetSessions,
  formatBytesToMiB,
  formatTimestamp,
  delay,
} from "./memory-profiler.js";

// ── DOM refs — upload section ─────────────────────────────────────────────────
const fileInput = document.getElementById("file-input");
const algoSel = document.getElementById("algo");
const chunkSizeSel = document.getElementById("chunk-size");
const uploadBtn = document.getElementById("upload-btn");
const progressBar = document.getElementById("progress-bar");
const progressLabel = document.getElementById("progress-label");
const sFilesize = document.getElementById("s-filesize");
const sEncrypted = document.getElementById("s-encrypted");
const sHeap = document.getElementById("s-heap");
const sHeapLimit = document.getElementById("s-heap-limit");
const uploadLogEl = document.getElementById("log");
const cancelBtn = document.getElementById("cancel-btn");
const sFingerprintEl = document.getElementById("s-fingerprint");

// ── DOM refs — download & decrypt section ─────────────────────────────────────
const downloadFileInput = document.getElementById("download-file");
const downloadBtn = document.getElementById("download-btn");
const decryptLogEl = document.getElementById("decrypt-log");

// ── DOM refs — memory profiler section ───────────────────────────────────────
const memorySupportStatus = document.getElementById("memory-support-status");
const memoryProfilerStatus = document.getElementById("memory-profiler-status");
const memorySampleCount = document.getElementById("memory-sample-count");
const latestUsedJsHeap = document.getElementById("latest-used-js-heap");
const latestTotalJsHeap = document.getElementById("latest-total-js-heap");
const latestJsHeapLimit = document.getElementById("latest-js-heap-limit");
const summaryBefore = document.getElementById("summary-before");
const summaryPeak = document.getElementById("summary-peak");
const summaryAfter = document.getElementById("summary-after");
const summaryDeltaPeak = document.getElementById("summary-delta-peak");
const summaryDeltaAfter = document.getElementById("summary-delta-after");
// Post-upload memory refs
const postAfterUpload = document.getElementById("post-after-upload");
const postAfterRelease = document.getElementById("post-after-release");
const postAfter5s = document.getElementById("post-after-5s");
const postAfter15s = document.getElementById("post-after-15s");
const postAfter30s = document.getElementById("post-after-30s");
// Chunk stats refs
const chunkTotalCount = document.getElementById("chunk-total-count");
const chunkTotalInput = document.getElementById("chunk-total-input");
const chunkTotalOutput = document.getElementById("chunk-total-output");
const chunkMinInput = document.getElementById("chunk-min-input");
const chunkAvgInput = document.getElementById("chunk-avg-input");
const chunkMaxInput = document.getElementById("chunk-max-input");
const chunkMinOutput = document.getElementById("chunk-min-output");
const chunkAvgOutput = document.getElementById("chunk-avg-output");
const chunkMaxOutput = document.getElementById("chunk-max-output");
const chunkMinEncrypt = document.getElementById("chunk-min-encrypt");
const chunkAvgEncrypt = document.getElementById("chunk-avg-encrypt");
const chunkMaxEncrypt = document.getElementById("chunk-max-encrypt");
const recentChunksTbody = document.getElementById("recent-chunks-tbody");
// Session history refs
const sessionHistoryTbody = document.getElementById("session-history-tbody");
// Log / export / buttons
const memoryLogOutput = document.getElementById("memory-log-output");
const memoryExportJson = document.getElementById("memory-export-json");
const copyResultsBtn = document.getElementById("copy-memory-results-button");
const resetResultsBtn = document.getElementById("reset-memory-results-button");
const resetSessionsBtn = document.getElementById("reset-sessions-button");

// ── Module-level state for reference release (diagnostic) ─────────────────────
// These are held so releaseUploadReferences() can explicitly null them out,
// allowing us to measure whether reference retention is causing heap growth.
/** @type {File|null} */
let _selectedFile = null;
/** @type {object|null} */
let _currentEncryptor = null;
/** @type {AbortController|null} */
let uploadAbortController = null;

// ── Format helpers ────────────────────────────────────────────────────────────

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1_048_576) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1_073_741_824) return `${(n / 1_048_576).toFixed(1)} MiB`;
  return `${(n / 1_073_741_824).toFixed(2)} GiB`;
}

function fmtMs(n) {
  if (n === null || n === undefined) return "-";
  return n.toFixed(1) + " ms";
}

// ── Upload log ────────────────────────────────────────────────────────────────

function uploadLog(msg, cls = "") {
  const ts = new Date().toISOString().slice(11, 22);
  const span = Object.assign(document.createElement("span"), {
    className: cls,
    textContent: `[${ts}] ${msg}\n`,
  });
  uploadLogEl.appendChild(span);
  uploadLogEl.scrollTop = uploadLogEl.scrollHeight;
}

function decryptLog(msg, cls = "") {
  const ts = new Date().toISOString().slice(11, 22);
  const span = Object.assign(document.createElement("span"), {
    className: cls,
    textContent: `[${ts}] ${msg}\n`,
  });
  decryptLogEl.appendChild(span);
  decryptLogEl.scrollTop = decryptLogEl.scrollHeight;
}

// ── Existing stats-bar memory display ────────────────────────────────────────

function updateMemStats() {
  if (!isPerformanceMemorySupported()) return;
  const mem = performance.memory;
  sHeap.textContent = fmtBytes(mem.usedJSHeapSize);
  sHeapLimit.textContent = fmtBytes(mem.jsHeapSizeLimit);
}

// ── Memory profiler UI renderers ─────────────────────────────────────────────

function renderSupportStatus() {
  const supported = isPerformanceMemorySupported();
  memorySupportStatus.textContent = supported ? "Supported" : "Unsupported";
  memorySupportStatus.dataset.status = supported ? "ok" : "ng";
  if (!supported) {
    sHeap.textContent = "n/a (Chrome only)";
    sHeapLimit.textContent = "n/a (Chrome only)";
  }
}

/** @param {'idle'|'measuring'|'finished'|'failed'} status */
function renderProfilerStatus(status) {
  memoryProfilerStatus.textContent = status;
  memoryProfilerStatus.dataset.status = status;
}

function renderLatestSample() {
  if (!isPerformanceMemorySupported()) return;
  const mem = performance.memory;
  latestUsedJsHeap.textContent = formatBytesToMiB(mem.usedJSHeapSize);
  latestTotalJsHeap.textContent = formatBytesToMiB(mem.totalJSHeapSize);
  latestJsHeapLimit.textContent = formatBytesToMiB(mem.jsHeapSizeLimit);
  memorySampleCount.textContent = String(getMemorySamples().length);
}

function renderSummary() {
  const s = buildMemorySummary();
  summaryBefore.textContent = formatBytesToMiB(s.beforeUsedJSHeapSize);
  summaryPeak.textContent = formatBytesToMiB(s.peakUsedJSHeapSize);
  summaryAfter.textContent = formatBytesToMiB(s.afterUsedJSHeapSize);
  summaryDeltaPeak.textContent = formatBytesToMiB(s.deltaPeakFromBefore);
  summaryDeltaAfter.textContent = formatBytesToMiB(s.deltaAfterFromBefore);
}

function renderPostUploadSummary() {
  const p = buildPostUploadSummary();
  postAfterUpload.textContent = formatBytesToMiB(p.afterUploadUsedJSHeapSize);
  postAfterRelease.textContent = formatBytesToMiB(p.afterReleaseUsedJSHeapSize);
  postAfter5s.textContent = formatBytesToMiB(p.after5sUsedJSHeapSize);
  postAfter15s.textContent = formatBytesToMiB(p.after15sUsedJSHeapSize);
  postAfter30s.textContent = formatBytesToMiB(p.after30sUsedJSHeapSize);
}

function renderChunkStats() {
  const a = getChunkAggregate();
  const fmt = (n) => (n === null ? "-" : fmtBytes(Math.round(n)));
  chunkTotalCount.textContent = String(a.totalChunks);
  chunkTotalInput.textContent = fmtBytes(a.totalInputBytes);
  chunkTotalOutput.textContent = a.totalOutputBytes > 0 ? fmtBytes(a.totalOutputBytes) : "-";
  chunkMinInput.textContent = fmt(a.minInputChunkBytes);
  chunkAvgInput.textContent = fmt(a.avgInputChunkBytes);
  chunkMaxInput.textContent = fmt(a.maxInputChunkBytes);
  chunkMinOutput.textContent = fmt(a.minOutputChunkBytes);
  chunkAvgOutput.textContent = fmt(a.avgOutputChunkBytes);
  chunkMaxOutput.textContent = fmt(a.maxOutputChunkBytes);
  chunkMinEncrypt.textContent = fmtMs(a.minEncryptDurationMs);
  chunkAvgEncrypt.textContent = fmtMs(a.avgEncryptDurationMs);
  chunkMaxEncrypt.textContent = fmtMs(a.maxEncryptDurationMs);
}

function renderRecentChunks() {
  const chunks = getRecentChunks().slice(-10); // Show last 10 for readability
  recentChunksTbody.innerHTML = "";
  for (const c of chunks) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${c.chunkIndex}</td>
      <td>${fmtBytes(c.inputChunkBytes)}</td>
      <td>${c.outputChunkBytes !== null ? fmtBytes(c.outputChunkBytes) : "-"}</td>
      <td>${c.encryptDurationMs !== null ? c.encryptDurationMs.toFixed(1) : "-"}</td>
      <td>${c.enqueueDelayMs !== null ? c.enqueueDelayMs.toFixed(1) : "-"}</td>
      <td>${c.elapsedMs}</td>
    `;
    recentChunksTbody.appendChild(tr);
  }
}

function renderSessionHistory() {
  const sessions = getSessions();
  sessionHistoryTbody.innerHTML = "";
  for (const s of sessions) {
    const p = s.postUploadSummary;
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td title="${s.startedAt}">${s.sessionId.slice(-8)}</td>
      <td>${s.algo} / ${fmtBytes(s.chunkSizeBytes)}</td>
      <td>${fmtBytes(s.fileBytes)}</td>
      <td>${s.durationMs !== null ? (s.durationMs / 1000).toFixed(1) + "s" : "-"}</td>
      <td>${formatBytesToMiB(s.summary.beforeUsedJSHeapSize)}</td>
      <td>${formatBytesToMiB(s.summary.peakUsedJSHeapSize)}</td>
      <td>${formatBytesToMiB(p.afterUploadUsedJSHeapSize)}</td>
      <td>${formatBytesToMiB(p.afterReleaseUsedJSHeapSize)}</td>
      <td>${formatBytesToMiB(p.after5sUsedJSHeapSize)}</td>
      <td>${formatBytesToMiB(p.after15sUsedJSHeapSize)}</td>
      <td>${formatBytesToMiB(p.after30sUsedJSHeapSize)}</td>
    `;
    sessionHistoryTbody.appendChild(tr);
  }
}

function renderLogs() {
  const lines = getLogs()
    .map((e) => `[${formatTimestamp(e.timestamp)}] ${e.message}`)
    .join("\n");
  memoryLogOutput.textContent = lines;
  memoryLogOutput.scrollTop = memoryLogOutput.scrollHeight;
}

function renderExportPayload() {
  memoryExportJson.value = JSON.stringify(buildExportPayload(), null, 2);
}

/** Render all memory result panels. */
function renderMemoryResults() {
  renderLatestSample();
  renderSummary();
  renderPostUploadSummary();
  renderChunkStats();
  renderRecentChunks();
  renderSessionHistory();
  renderLogs();
}

// ── Diagnostic: output stream measurement (backpressure hint) ─────────────────
//
// Wraps a ReadableStream to capture per-chunk output size and inter-chunk delay.
//
// enqueueDelayMs: time from when the previous chunk was handed to the consumer
//   (fetch) to when fetch requested the next chunk via pull().
//   High values indicate the network/fetch side is slower than encryption
//   (backpressure: the consumer cannot keep up with the producer).
//
// readDurationMs: time spent waiting inside reader.read() for the encrypted
//   chunk. Approximates encryption latency if the upstream is not backpressured.
//
/**
 * @param {ReadableStream<Uint8Array>} stream
 * @param {number} uploadStartTime  performance.now() at upload start
 * @param {(stat: {outputChunkIndex:number, outputBytes:number, enqueueDelayMs:number|null, readDurationMs:number, timestamp:number, elapsedMs:number}) => void} onChunk
 * @returns {ReadableStream<Uint8Array>}
 */
function wrapOutputWithMeasurement(stream, uploadStartTime, onChunk) {
  const reader = stream.getReader();
  let outputChunkIndex = 0;
  let lastEnqueueTime = null;

  return new ReadableStream({
    async pull(controller) {
      const pullTime = performance.now();
      // Time since we last gave a chunk to the consumer — a backpressure proxy.
      const enqueueDelayMs = lastEnqueueTime !== null ? pullTime - lastEnqueueTime : null;

      const { done, value } = await reader.read();
      if (done) {
        controller.close();
        return;
      }

      const readDoneTime = performance.now();

      onChunk({
        outputChunkIndex,
        outputBytes: value.byteLength,
        enqueueDelayMs,
        readDurationMs: readDoneTime - pullTime,
        timestamp: Date.now(),
        elapsedMs: Math.round(readDoneTime - uploadStartTime),
      });

      outputChunkIndex++;
      controller.enqueue(value);
      lastEnqueueTime = performance.now();
    },
    cancel(reason) {
      return reader.cancel(reason);
    },
  });
}

// ── Diagnostic: reference release ────────────────────────────────────────────
//
// Explicitly null out any references that might keep the uploaded file or stream
// objects alive in memory. This is NOT production cleanup — it is a deliberate
// triage step. If captureMemorySample('after-release') is noticeably lower than
// captureMemorySample('after-upload'), retained references are a contributing cause.
//
function releaseUploadReferences() {
  // Break references to the File/Blob so GC can collect the underlying ArrayBuffer.
  _selectedFile = null;
  _currentEncryptor = null;

  // Clear the file input's value so the browser releases its internal file handle.
  fileInput.value = "";

  uploadLog("Explicit reference release executed", "dim");
  addMarker("after-release");
}

// ── Post-upload delayed sampling sequence ────────────────────────────────────
//
// Purpose: distinguish GC lag from retained references.
//
//   If heap drops significantly at after-upload-5s / -15s / -30s  → GC lag
//   If heap drops at after-release (before any delay)              → retained references
//   If heap stays high at after-upload-30s                         → persistent leak
//
/**
 * @param {ReturnType<typeof setInterval>|null} memStatsTimer
 * @param {ReturnType<typeof setInterval>|null} memUiTimer
 * @param {{ algo: string, chunkSize: number, fileBytes: number }} uploadMeta
 */
async function runPostUploadSequence(memStatsTimer, memUiTimer, uploadMeta) {
  try {
    // Stop the periodic 'uploading' sampler so post-upload phase log is clean.
    stopSamplingInterval();

    uploadLog("Upload finished");
    captureMemorySample("after-upload");

    // Diagnostic: explicit reference release — measure effect on heap.
    releaseUploadReferences();
    captureMemorySample("after-release");
    renderPostUploadSummary();
    renderMemoryResults();

    uploadLog("Delayed sampling started (5s / 15s / 30s)…", "dim");

    await delay(5000);
    captureMemorySample("after-upload-5s");
    renderPostUploadSummary();
    renderLogs();

    await delay(10000); // +10s = 15s total
    captureMemorySample("after-upload-15s");
    renderPostUploadSummary();
    renderLogs();

    await delay(15000); // +15s = 30s total
    captureMemorySample("after-upload-30s");
    renderPostUploadSummary();
    renderLogs();

    // Finalise profiling and save session record.
    stopMemoryProfiling();
    renderProfilerStatus("finished");

    const meta = getProfilingMeta();
    saveSession({
      sessionId: `session-${Date.now()}`,
      startedAt: meta.startedAt ?? "",
      finishedAt: meta.finishedAt,
      durationMs: meta.durationMs,
      algo: uploadMeta.algo,
      chunkSizeBytes: uploadMeta.chunkSize,
      fileBytes: uploadMeta.fileBytes,
      summary: buildMemorySummary(),
      postUploadSummary: buildPostUploadSummary(),
      chunkStats: getChunkAggregate(),
    });

    uploadLog("Session record saved.", "dim");
    renderSessionHistory();
    renderMemoryResults();
    renderExportPayload();
  } finally {
    clearInterval(memStatsTimer);
    clearInterval(memUiTimer);
    updateMemStats();
  }
}

// ── Cancel upload ────────────────────────────────────────────────────────────

cancelBtn.addEventListener("click", () => {
  uploadAbortController?.abort();
});

// ── File selection ────────────────────────────────────────────────────────────

fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];
  if (!file) return;
  _selectedFile = file;
  sFilesize.textContent = fmtBytes(file.size);
  sEncrypted.textContent = "—";
  progressBar.style.width = "0%";
  progressLabel.textContent = "";
  uploadBtn.disabled = false;
  uploadBtn.textContent = "Encrypt & Upload";
  uploadLogEl.textContent = "";
  uploadLog(`Selected: ${file.name} (${fmtBytes(file.size)})`, "dim");
});

// ── Upload ────────────────────────────────────────────────────────────────────

uploadBtn.addEventListener("click", async () => {
  const file = fileInput.files[0];
  if (!file) return;

  uploadBtn.disabled = true;
  cancelBtn.disabled = false;
  uploadAbortController = new AbortController();
  sEncrypted.textContent = "0 B";
  progressBar.style.width = "0%";
  progressLabel.textContent = "";
  uploadLogEl.textContent = "";

  const algo = algoSel.value;
  const chunkSize = parseInt(chunkSizeSel.value, 10);
  const supported = isPerformanceMemorySupported();

  // Reset previous run data before each upload.
  resetProfiling();
  renderProfilerStatus("idle");
  memorySampleCount.textContent = "0";
  renderMemoryResults();
  renderExportPayload();

  // Start stats-bar polling.
  updateMemStats();
  let memStatsTimer = setInterval(updateMemStats, 400);
  let memUiTimer = null;

  // Flag to track whether the post-upload sequence has been launched.
  // When true, the finally block defers cleanup to runPostUploadSequence().
  let postUploadRunning = false;

  // Per-upload chunk tracking state (diagnostic).
  // onProgress gives cumulative plaintext bytes; we derive per-chunk sizes from deltas.
  // These arrays are local to this upload invocation and will be GC'd after the sequence ends.
  /** @type {Array<{inputBytes:number, encryptMs:number|null, timestamp:number, elapsedMs:number}>} */
  const inputStats = [];
  let prevProgressTotal = 0;
  let prevProgressTime = null;
  let uploadStartTime = 0;

  try {
    if (supported) {
      startMemoryProfiling();
      uploadStartTime = performance.now();
      captureMemorySample("before-upload");
      addMarker("before-upload");
      renderProfilerStatus("measuring");
      memUiTimer = setInterval(() => {
        renderLatestSample();
        renderLogs();
      }, 600);
    }

    // 1. Fetch public key
    uploadLog(`Fetching ${algo.toUpperCase()} public key…`);
    const keyRes = await fetch(`/api/public-key?algo=${algo}`);
    if (!keyRes.ok) throw new Error(`Key fetch failed: ${await keyRes.text()}`);
    const publicKeyPem = await keyRes.text();
    uploadLog("Public key loaded.");
    const fingerprint = await getKeyFingerprint(publicKeyPem);
    sFingerprintEl.textContent = fingerprint;
    uploadLog(`Key fingerprint: ${fingerprint}`, "dim");
    console.log("[app] Upload started");

    // 2. Create encryptor with chunk-level instrumentation via onProgress.
    //    onProgress is called once per encrypted plaintext chunk, giving the
    //    cumulative plaintext total. Delta from previous call = this chunk's size.
    const algorithm = algo === "ecdh" ? Algorithm.ECDH : Algorithm.RSA_OAEP;
    const encryptor = await createEncryptor(publicKeyPem, {
      algorithm,
      chunkSize,
      onProgress(n) {
        const now = performance.now();
        const inputBytes = n - prevProgressTotal;
        const encryptMs = prevProgressTime !== null ? now - prevProgressTime : null;

        inputStats.push({
          inputBytes,
          encryptMs,
          timestamp: Date.now(),
          elapsedMs: Math.round(now - uploadStartTime),
        });

        prevProgressTotal = n;
        prevProgressTime = now;

        // Update progress UI.
        sEncrypted.textContent = fmtBytes(n);
        const pct = Math.min(100, (n / file.size) * 100);
        progressBar.style.width = `${pct.toFixed(2)}%`;
        progressLabel.textContent = `${fmtBytes(n)} / ${fmtBytes(file.size)} (${pct.toFixed(1)}%)`;

        updateMemStats();
      },
    });
    _currentEncryptor = encryptor;

    // 3. Wrap the encrypted output stream to measure output chunk sizes and
    //    inter-chunk timing (backpressure hint).
    //    Output chunk index 0 = wire header (no corresponding onProgress call).
    //    Output chunk index N+1 = corresponds to inputStats[N].
    const rawEncryptedStream = encryptor.encryptFile(file, uploadAbortController.signal);
    const t0 = performance.now();

    const encryptedStream = wrapOutputWithMeasurement(rawEncryptedStream, t0, (outputStat) => {
      const chunkIdx = outputStat.outputChunkIndex - 1; // subtract 1 to skip header
      if (chunkIdx < 0) return; // first output chunk is the wire header; skip
      const input = inputStats[chunkIdx];
      if (!input) return;

      recordChunkStat({
        chunkIndex: chunkIdx,
        inputChunkBytes: input.inputBytes,
        outputChunkBytes: outputStat.outputBytes,
        encryptDurationMs: input.encryptMs,
        enqueueDelayMs: outputStat.enqueueDelayMs,
        timestamp: input.timestamp,
        elapsedMs: input.elapsedMs,
      });

      // Live-update chunk UI periodically (every 5 chunks to reduce DOM churn).
      if (chunkIdx % 5 === 0) {
        renderChunkStats();
        renderRecentChunks();
      }
    });

    // 4. POST the encrypted stream.
    uploadLog(`Encrypting and uploading ${fmtBytes(file.size)}…`);

    const response = await fetch(`/api/upload?algo=${algo}`, {
      method: "POST",
      body: encryptedStream,
      headers: { "Content-Type": "application/octet-stream" },
      // Required for streaming request bodies in Chrome/Safari/Edge.
      duplex: "half",
    });

    const elapsed = ((performance.now() - t0) / 1000).toFixed(1);

    if (!response.ok) {
      const err = await response.json().catch(() => ({ error: response.statusText }));
      throw new Error(err.error ?? response.statusText);
    }

    const result = await response.json();
    progressBar.style.width = "100%";
    progressLabel.textContent = `${fmtBytes(file.size)} / ${fmtBytes(file.size)} (100.0%)`;

    uploadLog(
      `Done in ${elapsed}s | enc: ${result.encFile} (${fmtBytes(result.encBytes)}) | dec: ${result.decFile} (${fmtBytes(result.decBytes)})`,
      "ok",
    );
    console.log("[app] Upload finished");

    // Render final chunk stats.
    renderChunkStats();
    renderRecentChunks();

    uploadBtn.textContent = "Upload again";
    downloadFileInput.value = result.encFile;
    downloadFileInput.dataset.algo = algo;
    downloadBtn.disabled = false;

    if (supported) {
      // Launch post-upload sequence (async — does not block button re-enable).
      // runPostUploadSequence handles its own cleanup of memStatsTimer / memUiTimer.
      postUploadRunning = true;
      runPostUploadSequence(memStatsTimer, memUiTimer, { algo, chunkSize, fileBytes: file.size });
    }
  } catch (err) {
    const wasAborted = err?.name === "AbortError";
    uploadLog(
      wasAborted ? "Upload cancelled." : `Error: ${err.message}`,
      wasAborted ? "dim" : "err",
    );
    progressBar.style.width = "0%";
    uploadBtn.textContent = wasAborted ? "Encrypt & Upload" : "Retry";
    if (!wasAborted) {
      console.error("[app] Upload failed:", err);
      if (supported) renderProfilerStatus("failed");
    }
  } finally {
    uploadBtn.disabled = false;
    cancelBtn.disabled = true;
    uploadAbortController = null;

    if (!postUploadRunning) {
      // Normal path (error or unsupported): clean up immediately.
      clearInterval(memStatsTimer);
      clearInterval(memUiTimer);
      if (supported) stopMemoryProfiling();
      renderMemoryResults();
      renderExportPayload();
    }
    // If postUploadRunning, runPostUploadSequence() handles cleanup in its own finally.
    updateMemStats();
  }
});

// ── Copy results ──────────────────────────────────────────────────────────────

copyResultsBtn.addEventListener("click", async () => {
  const text = memoryExportJson.value;
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    console.log("[app] Copy results: success");
    const orig = copyResultsBtn.textContent;
    copyResultsBtn.textContent = "Copied!";
    setTimeout(() => {
      copyResultsBtn.textContent = orig;
    }, 1500);
  } catch (err) {
    console.error("[app] Copy results: failed", err);
    uploadLog(`Copy failed: ${err.message}`, "err");
  }
});

// ── Reset profiling results ───────────────────────────────────────────────────

resetResultsBtn.addEventListener("click", () => {
  resetProfiling();
  renderProfilerStatus("idle");
  memorySampleCount.textContent = "0";
  latestUsedJsHeap.textContent = "-";
  latestTotalJsHeap.textContent = "-";
  latestJsHeapLimit.textContent = "-";
  summaryBefore.textContent = "-";
  summaryPeak.textContent = "-";
  summaryAfter.textContent = "-";
  summaryDeltaPeak.textContent = "-";
  summaryDeltaAfter.textContent = "-";
  postAfterUpload.textContent = "-";
  postAfterRelease.textContent = "-";
  postAfter5s.textContent = "-";
  postAfter15s.textContent = "-";
  postAfter30s.textContent = "-";
  chunkTotalCount.textContent = "-";
  chunkTotalInput.textContent = "-";
  chunkTotalOutput.textContent = "-";
  recentChunksTbody.innerHTML = "";
  memoryLogOutput.textContent = "";
  memoryExportJson.value = "";
  console.log("[app] Results reset");
});

// ── Reset session history ─────────────────────────────────────────────────────

resetSessionsBtn.addEventListener("click", () => {
  resetSessions();
  renderSessionHistory();
  renderExportPayload();
  console.log("[app] Session history reset");
});

// ── Download & Decrypt ────────────────────────────────────────────────────────

downloadBtn.addEventListener("click", async () => {
  const encFile = downloadFileInput.value.trim();
  if (!encFile) return;

  downloadBtn.disabled = true;
  decryptLogEl.textContent = "";
  decryptLog("Fetching private key…");

  try {
    const algo = downloadFileInput.dataset.algo || algoSel.value;
    const privRes = await fetch(`/api/private-key?algo=${algo}`);
    if (!privRes.ok) throw new Error(`Private key fetch failed: ${await privRes.text()}`);
    const privateKeyPem = await privRes.text();
    decryptLog("Private key loaded. Decrypting stream…", "dim");

    const algorithm = algo === "ecdh" ? Algorithm.ECDH : Algorithm.RSA_OAEP;
    let lastLoggedMiB = 0;
    const plainStream = await decryptFetch(`/api/download/${encFile}`, privateKeyPem, algorithm, {
      onProgress(n) {
        const mib = Math.floor(n / 1_048_576);
        if (mib > lastLoggedMiB) {
          lastLoggedMiB = mib;
          decryptLog(`Decrypted ${fmtBytes(n)}…`, "dim");
        }
      },
    });

    decryptLog("Buffering…", "dim");
    const blob = await new Response(plainStream).blob();
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement("a"), {
      href: url,
      download: encFile.replace(".enc", ".dec"),
    });
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 30_000);

    decryptLog(`Done — ${fmtBytes(blob.size)} decrypted and saved.`, "ok");
  } catch (err) {
    decryptLog(`Error: ${err.message}`, "err");
    console.error("[app] Decrypt failed:", err);
  } finally {
    downloadBtn.disabled = false;
  }
});

// ── Init ──────────────────────────────────────────────────────────────────────

renderSupportStatus();
renderProfilerStatus("idle");

if (!isPerformanceMemorySupported()) {
  renderExportPayload();
}
