// Self-check for the pure helpers. Run: npm test
import assert from "node:assert/strict";
process.env.BUNNY_API_KEY ||= "test";
const { summarisePullZones, toMs, shieldZoneNotes, diffFields, applyListOps, compactEventGroups, wafRuleConfiguration, originLogDate, summariseOriginErrors, summarisePullZone, describeEdgeRule, sideEffects, redact, registers } =
  await import("./index.js");

assert.deepEqual(
  summarisePullZones({ HasMoreItems: false, Items: [{ Id: 1, Name: "a", Enabled: true, OriginUrl: "https://o", Hostnames: [{ Value: "a.b-cdn.net" }], EdgeRules: [] }] }),
  { HasMoreItems: false, Items: [{ Id: 1, Name: "a", Enabled: true, OriginUrl: "https://o", Hostnames: ["a.b-cdn.net"] }] },
);
assert.deepEqual(summarisePullZones([{ Id: 2, Name: "b", Hostnames: [] }]).Items[0], { Id: 2, Name: "b", Enabled: undefined, OriginUrl: undefined, Hostnames: [] });
assert.equal(toMs("2026-10-01T00:00:00Z"), 1790812800000);
assert.throws(() => toMs("yesterday"));

// A Block rule in a zone with wafExecutionMode 0 and expired learning mode only logs; the notes must say so.
const now = Date.parse("2026-06-01T00:00:00Z");
const blockRule = { id: 101, ruleName: "Example block rule", ruleConfiguration: { actionType: 1 } };
const notes = shieldZoneNotes({ wafExecutionMode: 0, learningMode: true, learningModeUntil: "2026-01-30T17:05:11" }, [blockRule], { executionMode: 0 }, now);
assert.ok(notes[0].startsWith("wafExecutionMode 0: Log"));
assert.ok(notes.some((n) => n.includes("learningModeUntil (2026-01-30T17:05:11) has passed")));
assert.ok(notes.includes('custom rule 101 "Example block rule": Block'));
assert.ok(notes.some((n) => n.startsWith("WARNING")));
assert.ok(notes.includes("bot detection executionMode 0: LogOnly"));
// Updates return the date with a trailing Z; it must parse the same way.
assert.ok(shieldZoneNotes({ wafExecutionMode: 1, learningMode: true, learningModeUntil: "2026-01-30T17:05:11.7Z" }, [], undefined, now)[1].includes("has passed"));
assert.ok(!shieldZoneNotes({ wafExecutionMode: 1 }, [blockRule]).some((n) => n.startsWith("WARNING")));

assert.deepEqual(
  diffFields({ wafExecutionMode: 0, wafDisabledRules: ["1", "2"], learningMode: false }, { wafExecutionMode: 1, wafDisabledRules: ["2", "3"], learningMode: false }, ["wafExecutionMode", "wafDisabledRules", "learningMode"]),
  { wafExecutionMode: { before: 0, after: 1 }, wafDisabledRules: { added: ["3"], removed: ["1"], count: 2 }, learningMode: "unchanged" },
);

assert.deepEqual(applyListOps({ wafDisabledRules: ["1", "2"] }, { wafDisabledRules: ["2", "3"] }, { wafDisabledRules: ["1"] }), { wafDisabledRules: ["2", "3"] });
assert.deepEqual(applyListOps({ wafDisabledRules: null }, { wafDisabledRules: ["9"] }), { wafDisabledRules: ["9"] });
assert.throws(() => applyListOps({ wafExecutionMode: 0 }, { wafExecutionMode: ["1"] }));

assert.deepEqual(
  compactEventGroups({ total: 1, groups: [{ key: { ruleId: "WAF-1", action: "Blocked" }, count: 5, firstSeen: 1767225600000, lastSeen: 1767225600000, context: { big: true } }] }),
  { total: 1, groups: [{ ruleId: "WAF-1", action: "Blocked", count: 5, firstSeen: "2026-01-01T00:00:00.000Z", lastSeen: "2026-01-01T00:00:00.000Z" }] },
);

assert.equal(originLogDate("2026-02-13"), "02-13-2026");

const originLog = (ms, url) => ({ timestamp: ms, log: JSON.stringify({ RequestUrl: url, Method: "GET", ErrorCode: "http_timeout", StatusCode: 504, Message: "timed out", OriginAttempts: 2, RequestHeaders: [{ Header: "Host", Value: "example.com" }] }) });
const originSummary = summariseOriginErrors({ hasMoreData: true, logs: [originLog(1767225660000, "/b"), originLog(1767225600000, "/a")] }, 1);
assert.deepEqual(
  { ...originSummary, samples: undefined },
  { entries: 2, hasMoreData: true, from: "2026-01-01T00:00:00.000Z", to: "2026-01-01T00:01:00.000Z", byErrorCode: { http_timeout: 2 }, byStatusCode: { 504: 2 }, byMessage: { "timed out": 2 }, samples: undefined },
);
assert.equal(originSummary.samples.length, 1);
assert.equal(originSummary.samples[0].RequestHeaders, undefined);

// A JA4 fingerprint block rule must validate; common mistakes (no action 0, no operator 10, no JA4 variable) must not.
const ja4Rule = { actionType: 1, variableTypes: { FINGERPRINT: "" }, operatorType: 14, severityType: 0, transformationTypes: [], value: "^(a|b)$" };
assert.ok(wafRuleConfiguration.safeParse(ja4Rule).success);
assert.ok(!wafRuleConfiguration.safeParse({ ...ja4Rule, actionType: 0 }).success);
assert.ok(!wafRuleConfiguration.safeParse({ ...ja4Rule, operatorType: 10 }).success);
assert.ok(!wafRuleConfiguration.safeParse({ ...ja4Rule, variableTypes: { JA4: "" } }).success);

// Pull zone summary: readable rules, hidden credentials, no secret keys.
const rawZone = {
  Id: 1, Name: "example", Enabled: true, OriginUrl: "https://192.0.2.1", ZoneSecurityKey: "secret-key", AWSSigningSecret: "aws-secret",
  Hostnames: [{ Value: "www.example.com", ForceSSL: true }],
  EdgeRules: [
    { Guid: "g1", Enabled: true, ActionType: 28, Triggers: [{ Type: 1, Parameter1: "User-Agent", PatternMatches: ["*Ahrefs*"], PatternMatchingType: 0 }], TriggerMatchingType: 0, Description: "Allow crawler" },
    { Guid: "g2", Enabled: false, ActionType: 1, ActionParameter1: "https://example.com/login", ActionParameter2: "302",
      Triggers: [{ Type: 10, Parameter1: "access", PatternMatches: ["cookie-secret"], PatternMatchingType: 2 }, { Type: 0, PatternMatches: ["*/admin*"], PatternMatchingType: 0 }],
      TriggerMatchingType: 1, Description: "Gate", ExtraActions: [{ ActionType: 14, ActionParameter1: "401" }] },
  ],
  OriginResponseTimeout: 60,
};
const zoneSummary = summarisePullZone(rawZone);
assert.deepEqual(zoneSummary.EdgeRules, [
  'g1 on | Disable Shield | Request Header User-Agent matches *Ahrefs* | "Allow crawler"',
  'g2 off | Redirect https://example.com/login 302 + Set Status Code 401 | Cookie Value access does not match <hidden> AND URL matches */admin* | "Gate"',
]);
assert.deepEqual(zoneSummary.Hostnames, ["www.example.com (force SSL)"]);
assert.equal(zoneSummary.origin.OriginResponseTimeout, 60);
const summaryText = JSON.stringify(zoneSummary);
for (const secret of ["secret-key", "aws-secret", "cookie-secret"]) assert.ok(!summaryText.includes(secret), secret);
assert.ok(describeEdgeRule({ Guid: "g3", Enabled: true, ActionType: 5, ActionParameter1: "X", Triggers: [{ Type: 1, Parameter1: "Authorization", PatternMatches: ["Basic abc"] }] }).includes("<hidden>"));
assert.ok(describeEdgeRule({ Guid: "g4", Enabled: true, ActionType: 3, ActionParameter1: "0", Triggers: [{ Type: 1, Parameter1: "Cookie", PatternMatches: ["SSESS*"] }] }).includes("Cookie matches SSESS*"));

// update_pull_zone reports unrequested changes but not usage counters or credentials.
assert.deepEqual(
  sideEffects(
    { UseStaleWhileUpdating: false, UseBackgroundUpdate: false, MonthlyBandwidthUsed: 1, ZoneSecurityKey: "a", EdgeRules: [] },
    { UseStaleWhileUpdating: true, UseBackgroundUpdate: true, MonthlyBandwidthUsed: 2, ZoneSecurityKey: "b", EdgeRules: [{}] },
    ["UseStaleWhileUpdating"],
  ),
  { UseBackgroundUpdate: { before: false, after: true } },
);

console.log("ok");
process.exit(0);

const raw = { ZoneSecurityKey: "s", AWSSigningSecret: "s", LogForwardingToken: "", CacheKeyHeaders: ["X"],
  Hostnames: [{ Value: "a.example.com", HasCertificate: true, Certificate: "pem", CertificateKey: "pem", CertificateKeyType: 0 }],
  EdgeRules: [{ Triggers: [{ Type: 10, PatternMatches: ["letmein"] }, { Type: 0, PatternMatches: ["*/admin*"] }] }] };
assert.deepEqual(redact(raw), { ZoneSecurityKey: "<hidden>", AWSSigningSecret: "<hidden>", LogForwardingToken: "", CacheKeyHeaders: ["X"],
  Hostnames: [{ Value: "a.example.com", HasCertificate: true, Certificate: "<hidden>", CertificateKey: "<hidden>", CertificateKeyType: 0 }],
  EdgeRules: [{ Triggers: [{ Type: 10, PatternMatches: ["<hidden>"] }, { Type: 0, PatternMatches: ["*/admin*"] }] }] });

assert.ok(registers({ readOnlyHint: true }, true));
assert.ok(!registers({ readOnlyHint: false }, true));
assert.ok(!registers(undefined, true));
assert.ok(registers({ readOnlyHint: false }, false));
