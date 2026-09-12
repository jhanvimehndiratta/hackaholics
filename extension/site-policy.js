(function (root) {
  "use strict";
  const POLICY_VERSION = 1;
  const STORAGE_KEY = "sentinelSitePolicy";

  function normalizeOrigin(value) {
    try {
      const url = new URL(value);
      if (!["http:", "https:"].includes(url.protocol) || url.origin === "null" || url.username || url.password) return null;
      return url.origin;
    } catch { return null; }
  }

  function validatePolicy(value) {
    if (!value || value.policyVersion !== POLICY_VERSION || !Array.isArray(value.pausedOrigins)) throw new Error("Site policy is unavailable or invalid");
    const origins = value.pausedOrigins.map((item) => {
      if (typeof item !== "string") throw new Error("Site policy is unavailable or invalid");
      const normalized = normalizeOrigin(item);
      if (!normalized || normalized !== item) throw new Error("Site policy is unavailable or invalid");
      return normalized;
    });
    return Object.freeze({ policyVersion: POLICY_VERSION, pausedOrigins: Object.freeze([...new Set(origins)].sort()) });
  }

  function createStore(storageArea, changeEvent) {
    if (!storageArea?.get || !storageArea?.set) throw new Error("Site policy storage is unavailable");
    const listeners = new Set();
    async function read() {
      const data = await storageArea.get(STORAGE_KEY);
      // If storage is empty on first run, treat it as protected-by-default
      // by returning a validated empty paused list.
      if (!Object.prototype.hasOwnProperty.call(data || {}, STORAGE_KEY)) return validatePolicy({ policyVersion: POLICY_VERSION, pausedOrigins: [] });
      return validatePolicy(data[STORAGE_KEY]);
    }
    async function isPaused(origin) {
      const normalized = normalizeOrigin(origin);
      if (!normalized) throw new Error("Unsupported page origin");
      return (await read()).pausedOrigins.includes(normalized);
    }
    async function setPaused(origin, paused) {
      const normalized = normalizeOrigin(origin);
      if (!normalized || typeof paused !== "boolean") throw new Error("Unsupported page origin");
      const current = await read();
      const nextSet = new Set(current.pausedOrigins);
      paused ? nextSet.add(normalized) : nextSet.delete(normalized);
      const next = { policyVersion: POLICY_VERSION, pausedOrigins: [...nextSet].sort() };
      if (JSON.stringify(next) !== JSON.stringify(current)) await storageArea.set({ [STORAGE_KEY]: next });
      return validatePolicy(next);
    }
    async function reset() {
      const next = { policyVersion: POLICY_VERSION, pausedOrigins: [] };
      try { if (JSON.stringify(await read()) === JSON.stringify(next)) return validatePolicy(next); } catch {}
      await storageArea.set({ [STORAGE_KEY]: next });
      return validatePolicy(next);
    }
    function subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); }
    changeEvent?.addListener?.((changes, area) => {
      if (area !== "local" || !changes[STORAGE_KEY]) return;
      try { const value = validatePolicy(changes[STORAGE_KEY].newValue); listeners.forEach((fn) => fn(value, null)); }
      catch (error) { listeners.forEach((fn) => fn(null, error)); }
    });
    return Object.freeze({ read, isPaused, setPaused, reset, subscribe });
  }

  root.SentinelSitePolicy = Object.freeze({ POLICY_VERSION, STORAGE_KEY, normalizeOrigin, validatePolicy, createStore });
})(typeof globalThis !== "undefined" ? globalThis : window);
