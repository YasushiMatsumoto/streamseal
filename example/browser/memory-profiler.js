/**
 * memory-profiler.js
 *
 * Memory sampling, chunk statistics, session history, and JSON export.
 *
 * DIAGNOSTIC / TRIAGE CODE — not production code.
 * Purpose: isolate why JS heap oscillates between ~65 MiB and ~105 MiB during
 * upload, and why the heap is ~25 MiB higher after completion than before.
 *
 * No dependency on DOM or UI logic.
 */

// ── Constants ─────────────────────────────────────────────────────────────────

export const MEMORY_SAMPLING_INTERVAL_MS = 500;

/**
 * Maximum raw chunk stat records retained per upload.
 * Prevents this profiler from consuming unbounded memory during long uploads —
 * which would defeat the purpose of measuring memory.
 */
const RECENT_CHUNKS_MAX = 100;

/** Maximum completed upload sessions retained for trend comparison. */
const SESSIONS_MAX = 5;

// ── Internal state ────────────────────────────────────────────────────────────

/** @type {MemorySample[]} */
let _samples = [];
/** @type {MemoryMarker[]} */
let _markers = [];
/** @type {MemoryLogEntry[]} */
let _logs = [];
/** @type {number|null} */
let _startTime = null;
/** @type {string|null} */
let _startedAt = null;
/** @type {string|null} */
let _finishedAt = null;
/** @type {ReturnType<typeof setInterval>|null} */
let _timer = null;

// Chunk stats — reset at the start of each upload run.
/** @type {ChunkStat[]} Rolling buffer, max RECENT_CHUNKS_MAX */
let _recentChunks = [];
/** @type {ChunkAggregateInternal} Running aggregate updated per recordChunkStat() call */
let _chunkAggregate = _emptyAggregate();

// Session history — persists across uploads; reset only via resetSessions().
/** @type {SessionRecord[]} */
let _sessions = [];

// ── JSDoc type definitions ────────────────────────────────────────────────────

/**
 * @typedef {'before-upload'|'uploading'|'after-upload'|'after-release'|'after-upload-5s'|'after-upload-15s'|'after-upload-30s'|'manual'} SamplePhase
 *
 * @typedef {{
 *   timestamp: number,
 *   elapsedMs: number,
 *   phase: SamplePhase,
 *   usedJSHeapSize: number,
 *   totalJSHeapSize: number,
 *   jsHeapSizeLimit: number,
 * }} MemorySample
 *
 * @typedef {{ timestamp: number, elapsedMs: number, label: string }} MemoryMarker
 * @typedef {{ message: string, timestamp: number }} MemoryLogEntry
 *
 * @typedef {{
 *   beforeUsedJSHeapSize: number|null,
 *   peakUsedJSHeapSize: number|null,
 *   afterUsedJSHeapSize: number|null,
 *   deltaPeakFromBefore: number|null,
 *   deltaAfterFromBefore: number|null,
 * }} MemorySummary
 *
 * @typedef {{
 *   afterUploadUsedJSHeapSize: number|null,
 *   afterReleaseUsedJSHeapSize: number|null,
 *   after5sUsedJSHeapSize: number|null,
 *   after15sUsedJSHeapSize: number|null,
 *   after30sUsedJSHeapSize: number|null,
 * }} PostUploadSummary
 *
 * @typedef {{
 *   chunkIndex: number,
 *   inputChunkBytes: number,
 *   outputChunkBytes: number|null,
 *   encryptDurationMs: number|null,
 *   enqueueDelayMs: number|null,
 *   timestamp: number,
 *   elapsedMs: number,
 * }} ChunkStat
 *
 * @typedef {{
 *   totalInputBytes: number,
 *   totalOutputBytes: number,
 *   totalChunks: number,
 *   minInputChunkBytes: number|null,
 *   maxInputChunkBytes: number|null,
 *   avgInputChunkBytes: number|null,
 *   minOutputChunkBytes: number|null,
 *   maxOutputChunkBytes: number|null,
 *   avgOutputChunkBytes: number|null,
 *   minEncryptDurationMs: number|null,
 *   maxEncryptDurationMs: number|null,
 *   avgEncryptDurationMs: number|null,
 * }} ChunkAggregate
 *
 * @typedef {ChunkAggregate & {
 *   _inputBytesSum: number,
 *   _outputBytesCount: number,
 *   _outputBytesSum: number,
 *   _encryptDurationCount: number,
 *   _encryptDurationSum: number,
 * }} ChunkAggregateInternal
 *
 * @typedef {{
 *   sessionId: string,
 *   startedAt: string,
 *   finishedAt: string|null,
 *   durationMs: number|null,
 *   algo: string,
 *   chunkSizeBytes: number,
 *   fileBytes: number,
 *   summary: MemorySummary,
 *   postUploadSummary: PostUploadSummary,
 *   chunkStats: ChunkAggregate,
 * }} SessionRecord
 */

// ── Utility ───────────────────────────────────────────────────────────────────

/**
 * Returns a Promise that resolves after `ms` milliseconds.
 * Use with await in async upload flows to schedule post-upload samples
 * without blocking the UI thread.
 * @param {number} ms
 * @returns {Promise<void>}
 */
export function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── Profiling lifecycle ───────────────────────────────────────────────────────

export function isPerformanceMemorySupported() {
  return typeof performance !== "undefined" && !!performance.memory;
}

export function startMemoryProfiling() {
  _startTime = performance.now();
  _startedAt = new Date().toISOString();
  _finishedAt = null;
  // Reset per-upload chunk stats. Sessions are intentionally preserved.
  _recentChunks = [];
  _chunkAggregate = _emptyAggregate();
  _timer = setInterval(() => captureMemorySample("uploading"), MEMORY_SAMPLING_INTERVAL_MS);
  _addLog("Memory profiling started");
}

/**
 * Stop the periodic sampler and finalise finishedAt.
 * Safe to call multiple times — second call just updates finishedAt.
 */
export function stopMemoryProfiling() {
  _stopSamplingTimer();
  _finishedAt = new Date().toISOString();
  _addLog(`Memory profiling stopped. Total samples: ${_samples.length}`);
}

/**
 * Stop only the periodic 'uploading' interval without setting finishedAt.
 * Call this when switching from periodic sampling to explicit post-upload samples.
 */
export function stopSamplingInterval() {
  _stopSamplingTimer();
  _addLog("Periodic sampling interval stopped");
}

// ── Sampling ──────────────────────────────────────────────────────────────────

/**
 * Capture a single performance.memory snapshot.
 * @param {SamplePhase} phase
 * @returns {MemorySample|null}
 */
export function captureMemorySample(phase) {
  if (!isPerformanceMemorySupported()) return null;
  const mem = performance.memory;
  /** @type {MemorySample} */
  const sample = {
    timestamp: Date.now(),
    elapsedMs: _startTime !== null ? Math.round(performance.now() - _startTime) : 0,
    phase,
    usedJSHeapSize: mem.usedJSHeapSize,
    totalJSHeapSize: mem.totalJSHeapSize,
    jsHeapSizeLimit: mem.jsHeapSizeLimit,
  };
  _samples.push(sample);
  _addLog(
    `Sample captured: ${phase} used=${formatBytesToMiB(sample.usedJSHeapSize)} at +${sample.elapsedMs}ms`,
  );
  return sample;
}

// ── Markers and accessors ─────────────────────────────────────────────────────

/**
 * @param {string} label
 * @returns {MemoryMarker}
 */
export function addMarker(label) {
  /** @type {MemoryMarker} */
  const marker = {
    timestamp: Date.now(),
    elapsedMs: _startTime !== null ? Math.round(performance.now() - _startTime) : 0,
    label,
  };
  _markers.push(marker);
  _addLog(`Marker: "${label}" at +${marker.elapsedMs}ms`);
  return marker;
}

/** @returns {MemorySample[]} */
export function getMemorySamples() {
  return _samples.slice();
}

/** @returns {MemoryMarker[]} */
export function getMarkers() {
  return _markers.slice();
}

/** @returns {MemoryLogEntry[]} */
export function getLogs() {
  return _logs.slice();
}

// ── Chunk statistics ──────────────────────────────────────────────────────────

/**
 * Record statistics for one encrypted chunk.
 * Maintains a rolling buffer (max RECENT_CHUNKS_MAX) and a running aggregate.
 * The rolling buffer ensures this profiler itself does not consume unbounded memory.
 * @param {ChunkStat} stat
 */
export function recordChunkStat(stat) {
  // Rolling buffer — oldest entries are dropped to cap memory usage.
  _recentChunks.push(stat);
  if (_recentChunks.length > RECENT_CHUNKS_MAX) {
    _recentChunks.shift();
  }

  const a = _chunkAggregate;
  a.totalChunks += 1;
  a.totalInputBytes += stat.inputChunkBytes;
  a._inputBytesSum += stat.inputChunkBytes;

  a.minInputChunkBytes =
    a.minInputChunkBytes === null
      ? stat.inputChunkBytes
      : Math.min(a.minInputChunkBytes, stat.inputChunkBytes);
  a.maxInputChunkBytes =
    a.maxInputChunkBytes === null
      ? stat.inputChunkBytes
      : Math.max(a.maxInputChunkBytes, stat.inputChunkBytes);

  if (stat.outputChunkBytes !== null) {
    a.totalOutputBytes += stat.outputChunkBytes;
    a._outputBytesCount += 1;
    a._outputBytesSum += stat.outputChunkBytes;
    a.minOutputChunkBytes =
      a.minOutputChunkBytes === null
        ? stat.outputChunkBytes
        : Math.min(a.minOutputChunkBytes, stat.outputChunkBytes);
    a.maxOutputChunkBytes =
      a.maxOutputChunkBytes === null
        ? stat.outputChunkBytes
        : Math.max(a.maxOutputChunkBytes, stat.outputChunkBytes);
  }

  if (stat.encryptDurationMs !== null) {
    a._encryptDurationCount += 1;
    a._encryptDurationSum += stat.encryptDurationMs;
    a.minEncryptDurationMs =
      a.minEncryptDurationMs === null
        ? stat.encryptDurationMs
        : Math.min(a.minEncryptDurationMs, stat.encryptDurationMs);
    a.maxEncryptDurationMs =
      a.maxEncryptDurationMs === null
        ? stat.encryptDurationMs
        : Math.max(a.maxEncryptDurationMs, stat.encryptDurationMs);
  }
}

/** @returns {ChunkStat[]} Snapshot of the recent chunk buffer (oldest-first). */
export function getRecentChunks() {
  return _recentChunks.slice();
}

/** @returns {ChunkAggregate} Snapshot of the running aggregate with computed averages. */
export function getChunkAggregate() {
  const a = _chunkAggregate;
  return {
    totalInputBytes: a.totalInputBytes,
    totalOutputBytes: a.totalOutputBytes,
    totalChunks: a.totalChunks,
    minInputChunkBytes: a.minInputChunkBytes,
    maxInputChunkBytes: a.maxInputChunkBytes,
    avgInputChunkBytes: a.totalChunks > 0 ? a._inputBytesSum / a.totalChunks : null,
    minOutputChunkBytes: a.minOutputChunkBytes,
    maxOutputChunkBytes: a.maxOutputChunkBytes,
    avgOutputChunkBytes: a._outputBytesCount > 0 ? a._outputBytesSum / a._outputBytesCount : null,
    minEncryptDurationMs: a.minEncryptDurationMs,
    maxEncryptDurationMs: a.maxEncryptDurationMs,
    avgEncryptDurationMs:
      a._encryptDurationCount > 0 ? a._encryptDurationSum / a._encryptDurationCount : null,
  };
}

// ── Session history ───────────────────────────────────────────────────────────

/**
 * Append a completed session record. Retains at most SESSIONS_MAX entries.
 * Used to detect per-session baseline memory growth across repeated uploads.
 * @param {SessionRecord} record
 */
export function saveSession(record) {
  _sessions.push(record);
  if (_sessions.length > SESSIONS_MAX) {
    _sessions.shift();
  }
  _addLog(`Session ${record.sessionId} saved (total sessions: ${_sessions.length})`);
}

/** @returns {SessionRecord[]} */
export function getSessions() {
  return _sessions.slice();
}

export function resetSessions() {
  _sessions = [];
  _addLog("Session history cleared");
}

// ── Summaries and export ──────────────────────────────────────────────────────

/** @returns {MemorySummary} */
export function buildMemorySummary() {
  const before = _samples.find((s) => s.phase === "before-upload") ?? null;
  const after = _samples.findLast((s) => s.phase === "after-upload") ?? null;
  const peak =
    _samples.length > 0
      ? _samples.reduce((a, b) => (b.usedJSHeapSize > a.usedJSHeapSize ? b : a))
      : null;

  const beforeBytes = before?.usedJSHeapSize ?? null;
  const peakBytes = peak?.usedJSHeapSize ?? null;
  const afterBytes = after?.usedJSHeapSize ?? null;

  return {
    beforeUsedJSHeapSize: beforeBytes,
    peakUsedJSHeapSize: peakBytes,
    afterUsedJSHeapSize: afterBytes,
    deltaPeakFromBefore:
      beforeBytes !== null && peakBytes !== null ? peakBytes - beforeBytes : null,
    deltaAfterFromBefore:
      beforeBytes !== null && afterBytes !== null ? afterBytes - beforeBytes : null,
  };
}

/** @returns {PostUploadSummary} */
export function buildPostUploadSummary() {
  const findLast = (/** @type {SamplePhase} */ phase) =>
    _samples.findLast((s) => s.phase === phase)?.usedJSHeapSize ?? null;
  return {
    afterUploadUsedJSHeapSize: findLast("after-upload"),
    afterReleaseUsedJSHeapSize: findLast("after-release"),
    after5sUsedJSHeapSize: findLast("after-upload-5s"),
    after15sUsedJSHeapSize: findLast("after-upload-15s"),
    after30sUsedJSHeapSize: findLast("after-upload-30s"),
  };
}

/** @returns {{ startedAt: string|null, finishedAt: string|null, durationMs: number|null }} */
export function getProfilingMeta() {
  return {
    startedAt: _startedAt,
    finishedAt: _finishedAt,
    durationMs:
      _startedAt && _finishedAt
        ? new Date(_finishedAt).getTime() - new Date(_startedAt).getTime()
        : null,
  };
}

export function buildExportPayload() {
  if (!isPerformanceMemorySupported()) {
    return {
      userAgent: navigator.userAgent,
      supported: false,
      reason: "performance.memory is not available in this browser",
    };
  }
  return {
    userAgent: navigator.userAgent,
    supported: true,
    samplingIntervalMs: MEMORY_SAMPLING_INTERVAL_MS,
    startedAt: _startedAt,
    finishedAt: _finishedAt,
    durationMs:
      _startedAt && _finishedAt
        ? new Date(_finishedAt).getTime() - new Date(_startedAt).getTime()
        : null,
    summary: buildMemorySummary(),
    postUploadSummary: buildPostUploadSummary(),
    chunkStats: getChunkAggregate(),
    // Rolling buffers — bounded to prevent unbounded export size.
    recentChunks: getRecentChunks(),
    sessions: getSessions(),
    samples: _samples,
    markers: _markers,
    logs: _logs,
  };
}

/**
 * Reset all per-run state (samples, markers, logs, chunk stats).
 * Session history is intentionally NOT reset here — use resetSessions() for that.
 */
export function resetProfiling() {
  if (_timer !== null) {
    clearInterval(_timer);
    _timer = null;
  }
  _samples = [];
  _markers = [];
  _logs = [];
  _startTime = null;
  _startedAt = null;
  _finishedAt = null;
  _recentChunks = [];
  _chunkAggregate = _emptyAggregate();
  // _sessions intentionally preserved.
}

// ── Utility (exported for use in UI layer) ────────────────────────────────────

/**
 * @param {number|null} bytes
 * @returns {string}
 */
export function formatBytesToMiB(bytes) {
  if (bytes === null || typeof bytes !== "number" || Number.isNaN(bytes)) return "-";
  return (bytes / 1024 / 1024).toFixed(2) + " MiB";
}

/**
 * @param {number} timestamp
 * @returns {string}
 */
export function formatTimestamp(timestamp) {
  return new Date(timestamp).toLocaleTimeString("ja-JP", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    fractionalSecondDigits: 3,
  });
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/** @param {string} message */
function _addLog(message) {
  _logs.push({ timestamp: Date.now(), message });
  console.log(`[memory-profiler] ${message}`);
}

function _stopSamplingTimer() {
  if (_timer !== null) {
    clearInterval(_timer);
    _timer = null;
  }
}

/** @returns {ChunkAggregateInternal} */
function _emptyAggregate() {
  return {
    totalInputBytes: 0,
    totalOutputBytes: 0,
    totalChunks: 0,
    minInputChunkBytes: null,
    maxInputChunkBytes: null,
    avgInputChunkBytes: null,
    minOutputChunkBytes: null,
    maxOutputChunkBytes: null,
    avgOutputChunkBytes: null,
    minEncryptDurationMs: null,
    maxEncryptDurationMs: null,
    avgEncryptDurationMs: null,
    // Internal running accumulators (not exposed in ChunkAggregate)
    _inputBytesSum: 0,
    _outputBytesCount: 0,
    _outputBytesSum: 0,
    _encryptDurationCount: 0,
    _encryptDurationSum: 0,
  };
}
