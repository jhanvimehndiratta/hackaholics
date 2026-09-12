(function (root) {
  "use strict";

  const RULES = [
    { type: "database_url", severity: "critical", rule: "password_bearing_database_url", replacement: "[REDACTED_DATABASE_URL]", pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:/]+:[^\s@/]+@[^\s]+/giu },
    { type: "aws_access_key", severity: "high", rule: "aws_access_key_id", replacement: "[REDACTED_API_KEY]", pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/gu },
    { type: "github_token", severity: "high", rule: "github_token_prefix", replacement: "[REDACTED_API_KEY]", pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b/gu },
    { type: "email", severity: "medium", rule: "email_address", replacement: "[REDACTED_EMAIL]", pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu },
    { type: "internal_ip", severity: "medium", rule: "rfc1918_ipv4", replacement: "[REDACTED_INTERNAL_IP]", pattern: /\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b/gu },
  ];
  const PRIORITY = { database_url: 3, aws_access_key: 2, github_token: 2, api_key: 2, password: 2, email: 2, internal_ip: 1, suspected_secret: 1 };
  const API_KEY = /\bAPI_KEY\s*=\s*(["']?)([A-Z0-9_\-./+=]{12,})\1/giu;
  const CONTEXT_SECRET = /\b(?:token|secret|key)\s*[:=]\s*["']?([A-Za-z0-9_\-./+=]{24,})["']?/giu;
  const PASSWORD_NAME = /^(?:[A-Z0-9_]*_)?(?:password|passwd|pwd|passphrase)$/iu;

  function ensurePolicy(policy) {
    if (policy !== "balanced" && policy !== "strict") throw new Error(`Invalid policy '${policy}'. Must be 'balanced' or 'strict'.`);
  }
  function entropy(value) {
    const counts = new Map();
    for (const c of value) counts.set(c, (counts.get(c) || 0) + 1);
    return -[...counts.values()].reduce((sum, count) => { const p = count / value.length; return sum + p * Math.log2(p); }, 0);
  }
  function preview(value, type) {
    if (type === "password") return `•••••••• (${value.length} characters)`;
    if (["aws_access_key", "github_token", "api_key"].includes(type)) return `${value.slice(0, 3)}…`;
    if (type === "internal_ip") { const [a, b] = value.split("."); return a === "10" ? "10.x.x.x" : a === "172" ? `172.${b}.x.x` : "192.168.x.x"; }
    if (value.includes("@") && !value.includes("://")) { const [local, domain] = value.split("@"); return `${local.slice(0, 1)}…@${domain}`; }
    if (value.includes("://")) return `${value.split("://", 1)[0]}://…`;
    return value.length > 4 ? `${value.slice(0, 4)}…` : "…";
  }
  function validPrivateIp(value) {
    const octets = value.split(".").map(Number);
    if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
    return octets[0] === 10 || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) || (octets[0] === 192 && octets[1] === 168);
  }
  function candidate(meta, value, start, end) {
    return { type: meta.type, severity: meta.severity, rule: meta.rule, safePreview: preview(value, meta.type), replacement: meta.replacement, range: { start, end } };
  }
  function matches(regex, text) { regex.lastIndex = 0; return [...text.matchAll(regex)]; }
  function addPasswords(text, candidates) {
    const assignment = /(["']?)([A-Z0-9_]+)\1\s*[:=]\s*/giu;
    for (const match of matches(assignment, text)) {
      if (!PASSWORD_NAME.test(match[2])) continue;
      const start = match.index + match[0].length;
      const quote = text[start] === '"' || text[start] === "'" ? text[start] : "";
      const valueStart = start + (quote ? 1 : 0);
      let valueEnd;
      if (quote) { valueEnd = text.indexOf(quote, valueStart); if (valueEnd < 0) valueEnd = text.length; }
      else { const rest = text.slice(valueStart); const stop = rest.search(/[\s,;\]}]/u); valueEnd = stop < 0 ? text.length : valueStart + stop; }
      const value = text.slice(valueStart, valueEnd);
      if (!value.trim() || (!quote && (value === '""' || value === "''"))) continue;
      candidates.push(candidate({ type: "password", severity: "critical", rule: "named_password_assignment", replacement: "[REDACTED_PASSWORD]" }, value, valueStart, valueEnd));
    }
  }
  function analyzeText(text, policy = "balanced") {
    ensurePolicy(policy);
    const candidates = [];
    for (const rule of RULES) for (const match of matches(rule.pattern, text)) {
      if (rule.type !== "internal_ip" || validPrivateIp(match[0])) candidates.push(candidate(rule, match[0], match.index, match.index + match[0].length));
    }
    for (const match of matches(API_KEY, text)) {
      let value = match[2]; if (!match[1]) value = value.replace(/\.+$/u, "");
      if (value.length >= 12) { const start = match.index + match[0].indexOf(match[2]); candidates.push(candidate({ type: "api_key", severity: "high", rule: "generic_api_key_assignment", replacement: "[REDACTED_API_KEY]" }, value, start, start + value.length)); }
    }
    addPasswords(text, candidates);
    if (policy === "strict") for (const match of matches(CONTEXT_SECRET, text)) {
      const value = match[1]; if (entropy(value) >= 3.5) { const start = match.index + match[0].indexOf(value); candidates.push(candidate({ type: "suspected_secret", severity: "high", rule: "named_context_high_entropy", replacement: "[REDACTED_SUSPECTED_SECRET]" }, value, start, start + value.length)); }
    }
    candidates.sort((a, b) => a.range.start - b.range.start || (b.range.end - b.range.start) - (a.range.end - a.range.start) || PRIORITY[b.type] - PRIORITY[a.type]);
    const selected = candidates.filter((item, index, all) => !all.slice(0, index).some((existing) => existing.range.start <= item.range.start && existing.range.end >= item.range.end && PRIORITY[existing.type] >= PRIORITY[item.type]));
    selected.sort((a, b) => a.range.start - b.range.start);
    return { decision: selected.length ? "review_required" : "allow", findings: selected.map((item, i) => ({ id: `finding-${i + 1}`, ...item })) };
  }
  function redactText(text, findingIds, policy = "balanced") {
    const analysis = analyzeText(text, policy); const byId = new Map(analysis.findings.map((f) => [f.id, f]));
    const unknown = [...new Set(findingIds)].filter((id) => !byId.has(id)).sort();
    if (unknown.length) throw new Error(`Unknown finding IDs: ${unknown.join(", ")}`);
    const selected = findingIds.map((id) => byId.get(id)).sort((a, b) => a.range.start - b.range.start || (b.range.end - b.range.start) - (a.range.end - a.range.start));
    const outermost = selected.filter((item, index, all) => !all.slice(0, index).some((existing) => existing.range.start <= item.range.start && existing.range.end >= item.range.end));
    let redactedText = text;
    for (const finding of outermost.reverse()) redactedText = redactedText.slice(0, finding.range.start) + finding.replacement + redactedText.slice(finding.range.end);
    return { redactedText, redactedFindingIds: [...findingIds].sort((a, b) => Number(a.split("-")[1]) - Number(b.split("-")[1])) };
  }
  class AuditStore {
    constructor() { this.events = []; }
    record(decision, findings, sent, policy = "balanced") { const event = { id: `event-${this.events.length + 1}`, timestamp: new Date().toISOString(), decision, policy, findingCategories: [...new Set(findings.map((f) => f.type))].sort(), findingCount: findings.length, sent: Boolean(sent) }; this.events.unshift(event); return structuredClone(event); }
    list() { return this.events.map((event) => structuredClone(event)); }
    export(format = "json") { const decisions = {}, findingCategories = {}; for (const event of this.events) { decisions[event.decision] = (decisions[event.decision] || 0) + 1; for (const c of event.findingCategories) findingCategories[c] = (findingCategories[c] || 0) + 1; } const summary = { exportDate: new Date().toISOString(), totalEvents: this.events.length, decisions, findingCategories, events: this.list() }; if (format !== "markdown") return summary; const lines = ["# Sentinel Sanitized Audit Report", "", `- **Export Date:** ${summary.exportDate}`, `- **Total Events:** ${summary.totalEvents}`, "", "## Decision Summary", ""]; const d = Object.keys(decisions).sort(); lines.push(...(d.length ? d.map((k) => `- **${k}:** ${decisions[k]}`) : ["- No decisions recorded."]), "", "## Finding Categories", ""); const c = Object.keys(findingCategories).sort(); lines.push(...(c.length ? c.map((k) => `- **${k}:** ${findingCategories[k]}`) : ["- No findings detected."]), "", "## Event Timeline", ""); if (this.events.length) { lines.push("| Timestamp | Decision | Policy | Categories | Sent |", "| --- | --- | --- | --- | --- |"); for (const e of this.events) lines.push(`| ${e.timestamp} | ${e.decision} | ${e.policy || "balanced"} | ${e.findingCategories.join(", ") || "none"} | ${e.sent ? "True" : "False"} |`); } else lines.push("No events recorded."); return lines.join("\n"); }
    clear() { this.events.length = 0; }
  }
  root.SentinelEngine = Object.freeze({ analyzeText, redactText, AuditStore });
})(typeof globalThis !== "undefined" ? globalThis : window);
