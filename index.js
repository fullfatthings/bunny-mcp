#!/usr/bin/env node
// Minimal MCP server for the bunny.net core and Shield APIs (https://docs.bunny.net/reference).
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { readFileSync } from "node:fs";

const BASE = "https://api.bunny.net";
const KEY = process.env.BUNNY_API_KEY;
if (!KEY) {
  console.error("BUNNY_API_KEY is not set");
  process.exit(1);
}

// Paths are built only from zod-validated numeric IDs, GUIDs and dates, so they cannot leave the given Bunny host.
async function request(method, path, { query, body, base = BASE } = {}) {
  const url = new URL(base + path);
  for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined) url.searchParams.set(k, String(v));
  const headers = { AccessKey: KEY, Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}\n${text}`);
  return text ? JSON.parse(text) : null;
}

const ok = (data) => ({ content: [{ type: "text", text: JSON.stringify(data ?? "Done", null, 2) }] });

// Wraps a handler so API errors reach Claude as tool errors, not protocol errors.
const tool = (fn) => async (args) => {
  try {
    return ok(await fn(args));
  } catch (e) {
    return { content: [{ type: "text", text: e.message }], isError: true };
  }
};

// Full pull zone objects are large; the list only needs enough to pick one.
// Bunny returns a page object when `page` is given and a plain array otherwise.
export function summarisePullZones(page) {
  if (Array.isArray(page)) page = { Items: page };
  return {
    ...page,
    Items: page.Items.map((z) => ({
      Id: z.Id,
      Name: z.Name,
      Enabled: z.Enabled,
      OriginUrl: z.OriginUrl,
      Hostnames: z.Hostnames?.map((h) => h.Value),
    })),
  };
}

// Accepts an ISO 8601 date and returns epoch milliseconds.
export function toMs(date) {
  const ms = Date.parse(date);
  if (Number.isNaN(ms)) throw new Error(`Invalid date: ${date}`);
  return ms;
}

// Shield enums, from https://api.bunny.net/shield/docs/v1/swagger.json.
export const WAF_ACTIONS = { 1: "Block", 2: "Log", 3: "Challenge", 4: "Allow", 5: "Bypass" };
const WAF_OPERATORS = {
  0: "BEGINSWITH", 1: "ENDSWITH", 2: "CONTAINS", 3: "CONTAINSWORD", 4: "STRMATCH", 5: "EQ (integer)",
  6: "GE", 7: "GT", 8: "LE", 9: "LT", 12: "WITHIN", 13: "IPMATCH", 14: "RX (regex)",
  15: "STREQ (exact, case-insensitive)", 17: "DETECTSQLI", 18: "DETECTXSS",
};
const WAF_SEVERITIES = { 0: "NOTICE", 1: "WARNING", 2: "CRITICAL" };
const WAF_TRANSFORMATIONS = [
  "CMDLINE", "COMPRESSWHITESPACE", "CSSDECODE", "HEXENCODE", "HTMLENTITYDECODE", "JSDECODE", "LENGTH",
  "LOWERCASE", "MD5", "NORMALIZEPATH", "NORMALISEPATH", "NORMALIZEPATHWIN", "NORMALISEPATHWIN",
  "REMOVECOMMENTS", "REMOVENULLS", "REMOVEWHITESPACE", "REPLACECOMMENTS", "SHA1", "URLDECODE",
  "URLDECODEUNI", "UTF8TOUNICODE",
]; // numbered from 1
const WAF_VARIABLES = [
  "REQUEST_URI", "REQUEST_URI_RAW", "ARGS", "ARGS_COMBINED_SIZE", "ARGS_GET", "ARGS_GET_NAMES", "ARGS_POST",
  "ARGS_POST_NAMES", "FILES_NAMES", "GEO", "REMOTE_ADDR", "QUERY_STRING", "REQUEST_BASENAME", "REQUEST_BODY",
  "REQUEST_COOKIES_NAMES", "REQUEST_COOKIES", "REQUEST_FILENAME", "REQUEST_HEADERS_NAMES", "REQUEST_HEADERS",
  "REQUEST_LINE", "REQUEST_METHOD", "REQUEST_PROTOCOL", "RESPONSE_BODY", "RESPONSE_HEADERS", "RESPONSE_STATUS",
  "FINGERPRINT", "VERIFIED_BOT_CATEGORY",
];
const WAF_EXECUTION_MODES = { 0: "Log (no rule blocks, including custom Block rules)", 1: "Block" };
const BOT_EXECUTION_MODES = { 0: "LogOnly", 1: "Challenge" };
const BOT_SENSITIVITIES = { 0: "Off", 1: "Low", 2: "Medium", 3: "High" };

// Edge rule enums, from https://core-api-public-docs.b-cdn.net/docs/v3/public.json (EdgeRuleActionType, TriggerTypes).
const EDGE_ACTIONS = Object.fromEntries([
  "Force SSL", "Redirect", "Origin URL", "Override Cache Time", "Block Request", "Set Response Header",
  "Set Request Header", "Force Download", "Disable Token Authentication", "Enable Token Authentication",
  "Override Cache Time Public", "Ignore Query String", "Disable Optimizer", "Force Compression", "Set Status Code",
  "Bypass Perma-Cache", "Override Browser Cache Time", "Origin Storage", "Set Network Rate Limit",
  "Set Connection Limit", "Set Requests Per Second Limit", "Run Edge Script", "Origin Magic Containers",
  "Disable WAF", "Retry Origin", "Override Browser Cache Response Header", "Remove Browser Cache Response Header",
  "Disable Shield Challenge", "Disable Shield", "Disable Shield Bot Detection", "Bypass AWS S3 Authentication",
  "Disable Shield Access Lists", "Disable Shield Rate Limiting", "Enable Request Coalescing",
  "Disable Request Coalescing", "Use Load Balancer", "Force Load Balancer Sticky Session Mode",
  "Strip Cookies (Client to Origin)",
].entries());
const EDGE_TRIGGERS = Object.fromEntries([
  "URL", "Request Header", "Response Header", "URL Extension", "Country Code", "Remote IP", "URL Query String",
  "Random Chance", "Status Code", "Request Method", "Cookie Value", "Country State Code",
  "Origin Retry Attempt Count", "Origin Connection Error",
].entries());

// Settings worth seeing when debugging; everything else in a pull zone (~200 fields) is left to `fields` or `detail`.
const PULL_ZONE_SUMMARY_FIELDS = {
  caching: ["CacheControlMaxAgeOverride", "CacheControlPublicMaxAgeOverride", "EnableSmartCache", "IgnoreQueryStrings",
    "EnableCookieVary", "CookieVaryParameters", "QueryStringVaryParameters", "UseStaleWhileOffline", "UseStaleWhileUpdating",
    "CacheErrorResponses", "DisableCookies"],
  origin: ["OriginResponseTimeout", "OriginConnectTimeout", "OriginRetries", "OriginRetry5XXResponses",
    "EnableOriginShield", "OriginShieldZoneCode", "OriginShieldEnableConcurrencyLimit", "OriginShieldMaxConcurrentRequests",
    "AddHostHeader", "OriginHostHeader", "VerifyOriginSSL"],
  security: ["ShieldDDosProtectionEnabled", "BlockedIps", "BlockedCountries", "BlockNoneReferrer", "BlockPostRequests",
    "ZoneSecurityEnabled", "AllowedReferrers", "BlockedReferrers"],
};

// Trigger values that are credentials: cookie values (e.g. staging gates) and the Authorization header.
// Cookie-header patterns stay visible: they hold cookie names such as SSESS*, which explain caching behaviour.
const isSecretTrigger = (t) => t.Type === 10 || (t.Type === 1 && /^authorization$/i.test(t.Parameter1 ?? ""));
const MATCH = { 0: "matches", 1: "matches all of", 2: "does not match" };
const JOIN = { 0: " OR ", 1: " AND ", 2: " / none of: " };

const describeAction = (a) =>
  [EDGE_ACTIONS[a.ActionType] ?? `action ${a.ActionType}`, a.ActionParameter1, a.ActionParameter2].filter(Boolean).join(" ");

// One readable line per edge rule; the Guid comes first because set_edge_rule_enabled and delete_edge_rule need it.
export function describeEdgeRule(r) {
  const triggers = (r.Triggers ?? []).map((t) => {
    const name = [EDGE_TRIGGERS[t.Type] ?? `trigger ${t.Type}`, t.Parameter1].filter(Boolean).join(" ");
    const values = isSecretTrigger(t) ? "<hidden>" : (t.PatternMatches ?? []).join(", ");
    return `${name} ${MATCH[t.PatternMatchingType] ?? "matches"} ${values}`;
  });
  const actions = [r, ...(r.ExtraActions ?? [])].map(describeAction).join(" + ");
  return `${r.Guid} ${r.Enabled ? "on" : "off"} | ${actions} | ${triggers.join(JOIN[r.TriggerMatchingType] ?? " OR ")} | "${r.Description ?? ""}"`;
}

// Credential fields seen in raw pull zones: Certificate, CertificateKey, ZoneSecurityKey, AWSSigningKey/Secret, LogForwardingToken.
// shortcut: a deny-list, so a new credential field Bunny adds will show; switch to an allow-list if that happens.
const SECRET_FIELD = /(certificate|key|secret|password|token)$/i;

// Hides credential strings and secret edge rule trigger values anywhere in a response.
export function redact(v) {
  if (Array.isArray(v)) return v.map(redact);
  if (!v || typeof v !== "object") return v;
  if (v.PatternMatches && isSecretTrigger(v)) v = { ...v, PatternMatches: ["<hidden>"] };
  return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, typeof x === "string" && x && SECRET_FIELD.test(k) ? "<hidden>" : redact(x)]));
}

// Keeps identity, hostnames, readable edge rules and grouped debugging settings; drops keys such as ZoneSecurityKey and AWSSigning*.
export function summarisePullZone(z) {
  const pick = (keys) => Object.fromEntries(keys.map((k) => [k, z[k]]));
  return {
    Id: z.Id, Name: z.Name, Enabled: z.Enabled, Suspended: z.Suspended, OriginUrl: z.OriginUrl,
    Hostnames: (z.Hostnames ?? []).map((h) => `${h.Value}${h.ForceSSL ? " (force SSL)" : ""}`),
    EdgeRules: (z.EdgeRules ?? []).map(describeEdgeRule),
    ...Object.fromEntries(Object.entries(PULL_ZONE_SUMMARY_FIELDS).map(([group, keys]) => [group, pick(keys)])),
  };
}

// Origin logs live on their own host and take the date as MM-dd-yyyy.
export const originLogDate = (isoDate) => isoDate.replace(/^(\d{4})-(\d{2})-(\d{2})$/, "$2-$3-$1");

// A page of origin logs is about 350 KB, mostly request headers; keep counts and a few header-free samples.
export function summariseOriginErrors(result, samples = 10) {
  const entries = (result?.logs ?? []).map((l) => ({ time: new Date(l.timestamp).toISOString(), ...JSON.parse(l.log) }));
  const count = (k) => entries.reduce((acc, e) => ((acc[e[k]] = (acc[e[k]] ?? 0) + 1), acc), {});
  const times = entries.map((e) => e.time).sort();
  return {
    entries: entries.length,
    hasMoreData: result?.hasMoreData ?? false,
    from: times[0],
    to: times.at(-1),
    byErrorCode: count("ErrorCode"),
    byStatusCode: count("StatusCode"),
    byMessage: count("Message"),
    samples: entries.slice(0, samples).map(({ time, RequestUrl, Method, ErrorCode, StatusCode, Message, OriginAttempts }) =>
      ({ time, Method, RequestUrl, ErrorCode, StatusCode, Message, OriginAttempts })),
  };
}

const legend = (map) => Object.entries(map).map(([k, v]) => `${k} ${v}`).join(", ");
const oneOf = (map) => z.literal(Object.keys(map).map(Number)).describe(legend(map));

export const wafRuleConfiguration = z.strictObject({
  actionType: oneOf(WAF_ACTIONS),
  variableTypes: z
    .strictObject(Object.fromEntries(WAF_VARIABLES.map((v) => [v, z.string().optional()])))
    .describe(
      'Variables to match, e.g. {"REQUEST_HEADERS": "User-Agent"} for one header or {"REQUEST_HEADERS": ""} for all. ' +
        'FINGERPRINT holds the TLS JA4 string (not the Cdn-Ja4 header); use "" for the full string or JA4_A, JA4_B, JA4_C.',
    ),
  operatorType: oneOf(WAF_OPERATORS),
  severityType: oneOf(WAF_SEVERITIES).optional(),
  transformationTypes: z
    .array(z.number().int().min(1).max(WAF_TRANSFORMATIONS.length))
    .optional()
    .describe(WAF_TRANSFORMATIONS.map((t, i) => `${i + 1} ${t}`).join(", ")),
  value: z.string(),
  isNegated: z.boolean().optional(),
  isRegexVariable: z.boolean().optional(),
  chainedRuleConditions: z.array(z.record(z.string(), z.any())).optional(),
});

// The API rejects anything else with a 400; spaces are accepted in practice.
const ruleText = z.string().regex(/^[A-Za-z0-9 ]+$/, "Bunny accepts only letters, numbers and spaces");

// Plain-language warnings for zone settings that silently change what rules do.
export function shieldZoneNotes(zone, customRules = [], botDetection, now = Date.now()) {
  const notes = [`wafExecutionMode ${zone.wafExecutionMode}: ${WAF_EXECUTION_MODES[zone.wafExecutionMode] ?? "unknown"}`];
  if (zone.learningMode) {
    // Bunny returns this without a timezone on reads and with "Z" after updates; both are UTC.
    const until = zone.learningModeUntil && Date.parse(zone.learningModeUntil.replace(/Z?$/, "Z"));
    const expired = until && until < now;
    notes.push(`learningMode is on${expired ? ` although learningModeUntil (${zone.learningModeUntil}) has passed` : ""}`);
  }
  for (const r of customRules) {
    const action = r.ruleConfiguration?.actionType;
    notes.push(`custom rule ${r.id} "${r.ruleName}": ${WAF_ACTIONS[action] ?? `action ${action}`}`);
  }
  if (zone.wafExecutionMode === 0 && customRules.some((r) => [1, 3].includes(r.ruleConfiguration?.actionType)))
    notes.push("WARNING: custom rules set to Block or Challenge only log while wafExecutionMode is 0");
  if (botDetection)
    notes.push(`bot detection executionMode ${botDetection.executionMode}: ${BOT_EXECUTION_MODES[botDetection.executionMode] ?? "unknown"}`);
  return notes;
}

// Returns {field: {before, after}} for scalars and {field: {added, removed, count}} for lists.
export function diffFields(before, after, fields) {
  const diff = {};
  for (const f of fields) {
    const [b, a] = [before?.[f], after?.[f]];
    if (Array.isArray(b) || Array.isArray(a)) {
      const [bs, as] = [new Set(b ?? []), new Set(a ?? [])];
      diff[f] = { added: [...as].filter((x) => !bs.has(x)), removed: [...bs].filter((x) => !as.has(x)), count: as.size };
    } else if (JSON.stringify(b) !== JSON.stringify(a)) diff[f] = { before: b, after: a };
    else diff[f] = "unchanged";
  }
  return diff;
}

// Settings Bunny changed that were not asked for (e.g. UseBackgroundUpdate turning on with UseStaleWhileUpdating).
// Skips usage counters that change on their own and fields that hold credentials.
const UNREPORTED = /^(Monthly|CacheVersion$|ZoneSecurityKey$|AWSSigning)/;
export function sideEffects(before, after, requested) {
  const keys = Object.keys(after ?? {}).filter(
    (k) => !requested.includes(k) && !UNREPORTED.test(k) && typeof after[k] !== "object" && before?.[k] !== after[k],
  );
  return Object.fromEntries(keys.map((k) => [k, { before: before?.[k], after: after[k] }]));
}

// Applies {field: [items]} additions and removals to the current list fields.
export function applyListOps(current, add = {}, remove = {}) {
  const out = {};
  for (const f of new Set([...Object.keys(add), ...Object.keys(remove)])) {
    if (current[f] !== undefined && current[f] !== null && !Array.isArray(current[f])) throw new Error(`${f} is not a list`);
    const drop = new Set(remove[f] ?? []);
    out[f] = [...new Set([...(current[f] ?? []), ...(add[f] ?? [])])].filter((x) => !drop.has(x));
  }
  return out;
}

// Keeps what is needed to read a grouped event log; the context object is large and mostly repeats the key.
export function compactEventGroups(result) {
  if (!result?.groups) return result;
  const iso = (ms) => (ms ? new Date(ms).toISOString() : ms);
  return {
    ...result,
    groups: result.groups.map((g) => ({ ...g.key, count: g.count, firstSeen: iso(g.firstSeen), lastSeen: iso(g.lastSeen) })),
  };
}

async function getShieldZone(pullZoneId) {
  const { data } = await request("GET", `/shield/shield-zone/get-by-pullzone/${pullZoneId}`);
  if (!data) throw new Error(`Pull zone ${pullZoneId} has no Shield zone, so it has no WAF, rate limits or bot detection`);
  return data;
}
const getShieldZoneId = async (pullZoneId) => (await getShieldZone(pullZoneId)).shieldZoneId;

const id = z.number().int().positive();
const pullZoneId = id.describe("Pull zone ID from list_pull_zones");
const read = { readOnlyHint: true };
const write = { readOnlyHint: false, destructiveHint: false };
const destructive = { readOnlyHint: false, destructiveHint: true };

// BUNNY_READONLY=1 registers only tools annotated read-only; a tool without annotations counts as a writer.
export const registers = (annotations, readonly) => !readonly || annotations?.readOnlyHint === true;
const READONLY = /^(1|true|yes|on)$/i.test(process.env.BUNNY_READONLY ?? "");

const { version } = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));
const server = new McpServer({ name: "bunny", version });
const register = (name, def, handler) => registers(def.annotations, READONLY) && server.registerTool(name, def, handler);

register(
  "list_pull_zones",
  {
    description: "List bunny.net pull zones (CDN sites) with their IDs, origins and hostnames.",
    inputSchema: {
      search: z.string().optional().describe("Filter by name or hostname"),
      page: z.number().int().min(1).optional(),
      perPage: z.number().int().min(5).max(1000).optional(),
    },
    annotations: read,
  },
  tool(async (query) => summarisePullZones(await request("GET", "/pullzone", { query }))),
);

register(
  "get_pull_zone",
  {
    description:
      "One pull zone: hostnames, edge rules as readable one-line summaries (Guid first) and the caching, origin and " +
      "security settings that matter when debugging. Credentials (ZoneSecurityKey, AWS signing keys, cookie and " +
      "Authorization trigger values) are left out. For other settings, pass `fields` with the raw names; " +
      "`detail: true` returns the full raw object (about 10,000 tokens) with the same credentials hidden.",
    inputSchema: {
      pull_zone_id: pullZoneId,
      fields: z.array(z.string()).optional().describe("Raw field names to return, e.g. [\"OptimizerEnabled\"]"),
      detail: z.boolean().optional().describe("Return the full raw object. Default false"),
    },
    annotations: read,
  },
  tool(async ({ pull_zone_id, fields, detail }) => {
    const zone = await request("GET", `/pullzone/${pull_zone_id}`);
    if (detail) return redact(zone);
    if (fields?.length) return redact({ Id: zone.Id, ...Object.fromEntries(fields.map((f) => [f, zone[f]])) });
    return summarisePullZone(zone);
  }),
);

register(
  "cdn_statistics",
  {
    description:
      "CDN statistics: bandwidth, requests, cache hit rate and, with load_errors, non-2xx responses. " +
      "Defaults to the last 30 days across all pull zones.",
    inputSchema: {
      pull_zone_id: pullZoneId.optional(),
      date_from: z.string().optional().describe("ISO 8601 date"),
      date_to: z.string().optional().describe("ISO 8601 date"),
      hourly: z.boolean().optional(),
      load_errors: z.boolean().optional(),
    },
    annotations: read,
  },
  tool(({ pull_zone_id, date_from, date_to, hourly, load_errors }) =>
    request("GET", "/statistics", {
      query: { pullZone: pull_zone_id, dateFrom: date_from, dateTo: date_to, hourly, loadErrors: load_errors },
    }),
  ),
);

register(
  "update_pull_zone",
  {
    description:
      "Change pull zone settings and return what changed. Send only the fields to change, using the raw names " +
      "(e.g. CacheControlMaxAgeOverride, UseStaleWhileOffline); read current values with get_pull_zone and `fields`. " +
      "`alsoChanged` lists settings Bunny changed that were not requested. Edit edge rules with save_edge_rule, not here.",
    inputSchema: { pull_zone_id: pullZoneId, fields: z.record(z.string(), z.any()) },
    annotations: write,
  },
  tool(async ({ pull_zone_id, fields }) => {
    const before = await request("GET", `/pullzone/${pull_zone_id}`);
    const after = await request("POST", `/pullzone/${pull_zone_id}`, { body: fields });
    const requested = Object.keys(fields);
    return redact({ changed: diffFields(before, after, requested), alsoChanged: sideEffects(before, after, requested) });
  }),
);

register(
  "purge_cache",
  {
    description: "Purge the CDN cache for one URL (wildcard * allowed at the end), or for a whole pull zone.",
    inputSchema: {
      url: z.string().url().optional(),
      pull_zone_id: pullZoneId.optional(),
      cache_tag: z.string().optional().describe("With pull_zone_id: purge only this cache tag"),
    },
    annotations: write,
  },
  tool(({ url, pull_zone_id, cache_tag }) => {
    if (!url === !pull_zone_id) throw new Error("Give exactly one of url or pull_zone_id");
    return url
      ? request("POST", "/purge", { query: { url } })
      : request("POST", `/pullzone/${pull_zone_id}/purgeCache`, { body: cache_tag ? { CacheTag: cache_tag } : {} });
  }),
);

register(
  "save_edge_rule",
  {
    description:
      "Create an edge rule, or update one by including its Guid (from get_pull_zone). Send the whole rule, " +
      "not only changed fields; to switch a rule on or off use set_edge_rule_enabled. Fields: ActionType, " +
      "ActionParameter1-3, Triggers [{Type, PatternMatches[], PatternMatchingType, Parameter1}], " +
      "TriggerMatchingType, Description, Enabled, OrderIndex, ExtraActions [{ActionType, ActionParameter1-3}]. " +
      `ActionType: ${legend(EDGE_ACTIONS)}. Trigger Type: ${legend(EDGE_TRIGGERS)}. ` +
      "PatternMatchingType and TriggerMatchingType: 0 Match Any, 1 Match All, 2 Match None. " +
      "Edge rules change CDN behaviour and log nothing; to block abusive traffic use a WAF rule (save_waf_rule), " +
      "which can log first and records every match in shield_event_logs.",
    inputSchema: { pull_zone_id: pullZoneId, rule: z.record(z.string(), z.any()) },
    annotations: write,
  },
  tool(({ pull_zone_id, rule }) =>
    request("POST", `/pullzone/${pull_zone_id}/edgerules/addOrUpdate`, { body: rule }),
  ),
);

register(
  "set_edge_rule_enabled",
  {
    description: "Switch an edge rule on or off without resending the whole rule.",
    inputSchema: { pull_zone_id: pullZoneId, guid: z.uuid().describe("Edge rule Guid from get_pull_zone"), enabled: z.boolean() },
    annotations: write,
  },
  tool(({ pull_zone_id, guid, enabled }) =>
    request("POST", `/pullzone/${pull_zone_id}/edgerules/${guid}/setEdgeRuleEnabled`, { body: { Id: pull_zone_id, Value: enabled } }),
  ),
);

register(
  "origin_errors",
  {
    description:
      "Bunny's log of failed requests to a pull zone's origin on one day: why each failed (e.g. http_timeout, " +
      "http_request_failure, dns_lookup, network_socket_exception). Use it to confirm 502 or 504 errors from " +
      "Bunny's side. Origin responses with an error status, such as a PHP-FPM 502, may not appear here. " +
      "Returns counts and samples for one page of up to 200 entries. Which part of the day that page covers " +
      "varies between calls, so check from and to; hasMoreData means other entries exist that this tool does not fetch.",
    inputSchema: {
      pull_zone_id: pullZoneId,
      date: z.iso.date().describe("Day to read, as YYYY-MM-DD (UTC)"),
      detail: z.boolean().optional().describe("Return the raw entries, including request headers (very large). Default false"),
    },
    annotations: read,
  },
  // shortcut: reads only the first page; the continuation token's request format isn't documented in the specs we have.
  tool(async ({ pull_zone_id, date, detail }) => {
    const result = await request("GET", `/${pull_zone_id}/${originLogDate(date)}`, { base: "https://cdn-origin-logging.bunny.net" });
    return detail ? result : summariseOriginErrors(result);
  }),
);

register(
  "delete_edge_rule",
  {
    description: "Permanently delete an edge rule. To switch one off but keep it, save it with Enabled: false instead.",
    inputSchema: { pull_zone_id: pullZoneId, guid: z.uuid().describe("Edge rule Guid from get_pull_zone") },
    annotations: destructive,
  },
  tool(({ pull_zone_id, guid }) => request("DELETE", `/pullzone/${pull_zone_id}/edgerules/${guid}`)),
);

register(
  "get_shield_zone",
  {
    description:
      "WAF (bunny Shield) state for a pull zone: zone settings (wafEnabled, wafExecutionMode, wafDisabledRules, " +
      "wafLogOnlyRules, learningMode), custom WAF rules, rate limits and bot detection. Read `notes` first: it " +
      "explains coded settings and warns when settings stop rules from acting.",
    inputSchema: { pull_zone_id: pullZoneId },
    annotations: read,
  },
  tool(async ({ pull_zone_id }) => {
    const zone = await getShieldZone(pull_zone_id);
    const [customRules, rateLimits, botDetection] = await Promise.all([
      request("GET", `/shield/waf/custom-rules/${zone.shieldZoneId}`, { query: { perPage: 1000 } }),
      request("GET", `/shield/rate-limits/${zone.shieldZoneId}`, { query: { perPage: 1000 } }),
      request("GET", `/shield/shield-zone/${zone.shieldZoneId}/bot-detection`).then((r) => r.data),
    ]);
    const notes = shieldZoneNotes(zone, customRules?.data ?? [], botDetection);
    return redact({ notes, zone, customRules, rateLimits, botDetection });
  }),
);

register(
  "shield_event_logs",
  {
    description:
      "Requests the WAF blocked, challenged or logged for a pull zone. Only the last 72 hours are available. " +
      "Use group_by to summarise, e.g. [\"ruleId\"], [\"ja4\"] or [\"ip\"]. Events can take a minute to appear, " +
      "so wait at least a minute after a change before judging it.",
    inputSchema: {
      pull_zone_id: pullZoneId,
      from: z.string().describe("ISO 8601 date-time, within the last 72 hours"),
      to: z.string().optional().describe("ISO 8601 date-time; defaults to now"),
      query: z.string().optional().describe("Free text across IP, ruleId, URL, User-Agent and rule name"),
      group_by: z
        .array(z.enum(["feature", "ruleId", "ip", "ja4", "ua", "url", "asn", "country", "action"]))
        .optional(),
      page: z.number().int().min(0).optional().describe("Zero-based"),
      page_size: z.number().int().min(1).max(500).optional().describe("Default 50"),
      detail: z.boolean().optional().describe("Include each group's full context object (large). Default false"),
    },
    annotations: read,
  },
  tool(async ({ pull_zone_id, from, to, query, group_by, page, page_size, detail }) => {
    const result = await request("POST", `/shield/event-logs/${await getShieldZoneId(pull_zone_id)}/search`, {
      body: { from: toMs(from), to: to ? toMs(to) : Date.now(), query, groupBy: group_by, page, pageSize: page_size },
    });
    return detail ? result : compactEventGroups(result);
  }),
);

register(
  "update_shield_zone",
  {
    description:
      "Change WAF settings for a pull zone and return what changed. Fields use the names get_shield_zone returns: " +
      `wafEnabled, wafExecutionMode (${legend(WAF_EXECUTION_MODES)}), learningMode, wafDisabledRules, ` +
      "wafLogOnlyRules, dDoSShieldSensitivity and others. A list in `fields` replaces the whole list; to change " +
      "part of a list use `add` or `remove`, e.g. add: {\"wafDisabledRules\": [\"942100\"]}.",
    inputSchema: {
      pull_zone_id: pullZoneId,
      fields: z.record(z.string(), z.any()).optional(),
      add: z.record(z.string(), z.array(z.string())).optional().describe("Items to add to list fields"),
      remove: z.record(z.string(), z.array(z.string())).optional().describe("Items to remove from list fields"),
    },
    annotations: destructive,
  },
  tool(async ({ pull_zone_id, fields = {}, add, remove }) => {
    const before = await getShieldZone(pull_zone_id);
    const changes = { ...fields, ...applyListOps(before, add, remove) };
    if (!Object.keys(changes).length) throw new Error("Nothing to change: give fields, add or remove");
    const res = await request("PATCH", "/shield/shield-zone", {
      body: { shieldZoneId: before.shieldZoneId, shieldZone: { ...changes, shieldZoneId: before.shieldZoneId } },
    });
    return { changed: diffFields(before, res?.data?.shieldZone, Object.keys(changes)) };
  }),
);

register(
  "update_bot_detection",
  {
    description:
      `Change bot detection for a pull zone and return what changed. executionMode: ${legend(BOT_EXECUTION_MODES)}. ` +
      `requestIntegrity, ipAddress and browserFingerprint each take {sensitivity: ${legend(BOT_SENSITIVITIES)}}; ` +
      "browserFingerprint also takes aggression and complexEnabled. Read the current values with get_shield_zone.",
    inputSchema: {
      pull_zone_id: pullZoneId,
      executionMode: oneOf(BOT_EXECUTION_MODES).optional(),
      requestIntegrity: z.object({ sensitivity: oneOf(BOT_SENSITIVITIES) }).optional(),
      ipAddress: z.object({ sensitivity: oneOf(BOT_SENSITIVITIES) }).optional(),
      browserFingerprint: z
        .object({ sensitivity: oneOf(BOT_SENSITIVITIES).optional(), aggression: z.number().int().optional(), complexEnabled: z.boolean().optional() })
        .optional(),
    },
    annotations: write,
  },
  tool(async ({ pull_zone_id, ...changes }) => {
    const shieldZoneId = await getShieldZoneId(pull_zone_id);
    const path = `/shield/shield-zone/${shieldZoneId}/bot-detection`;
    const { data: before } = await request("GET", path);
    const { data: after } = await request("PATCH", path, { body: { ...changes, shieldZoneId } });
    return { changed: diffFields(before, after, Object.keys(changes)) };
  }),
);

register(
  "save_waf_rule",
  {
    description:
      "Create a custom WAF rule (no rule_id) or update one (with rule_id; send the whole rule). To test a rule, " +
      "save it with actionType 2 (Log), check shield_event_logs, then save it again with 1 (Block). Returns " +
      "warnings when zone settings would stop the rule from acting.",
    inputSchema: {
      pull_zone_id: pullZoneId,
      rule_id: id.optional(),
      ruleName: ruleText,
      ruleDescription: ruleText.optional(),
      ruleConfiguration: wafRuleConfiguration,
    },
    annotations: write,
  },
  tool(async ({ pull_zone_id, rule_id, ...rule }) => {
    const zone = await getShieldZone(pull_zone_id);
    const saved = rule_id
      ? await request("PATCH", `/shield/waf/custom-rule/${rule_id}`, { body: rule })
      : await request("POST", "/shield/waf/custom-rule", { body: { ...rule, shieldZoneId: zone.shieldZoneId } });
    const warnings = shieldZoneNotes(zone, [{ ...saved, ruleConfiguration: rule.ruleConfiguration }]).filter(
      (n) => n.startsWith("WARNING") || n.startsWith("learningMode"),
    );
    return { saved, warnings };
  }),
);

register(
  "save_rate_limit",
  {
    description:
      "Create a rate limit (no rule_id) or update one (with rule_id). Fields: ruleName and ruleDescription " +
      "(letters, numbers and spaces only) and ruleConfiguration. Copy the ruleConfiguration shape from an " +
      "existing rate limit in get_shield_zone.",
    inputSchema: {
      pull_zone_id: pullZoneId,
      rule_id: id.optional(),
      ruleName: ruleText,
      ruleDescription: ruleText.optional(),
      ruleConfiguration: z.record(z.string(), z.any()),
    },
    annotations: write,
  },
  tool(async ({ pull_zone_id, rule_id, ...rule }) => {
    if (rule_id) return request("PATCH", `/shield/rate-limit/${rule_id}`, { body: rule });
    return request("POST", "/shield/rate-limit", { body: { ...rule, shieldZoneId: await getShieldZoneId(pull_zone_id) } });
  }),
);

register(
  "delete_shield_rule",
  {
    description:
      "Permanently delete a custom WAF rule or a rate limit by its ID from get_shield_zone. To keep a WAF rule " +
      "but stop it acting, save it with actionType 2 (Log) instead.",
    inputSchema: { kind: z.enum(["waf", "rate_limit"]), rule_id: id },
    annotations: destructive,
  },
  tool(({ kind, rule_id }) =>
    request("DELETE", kind === "waf" ? `/shield/waf/custom-rule/${rule_id}` : `/shield/rate-limit/${rule_id}`),
  ),
);

await server.connect(new StdioServerTransport());
