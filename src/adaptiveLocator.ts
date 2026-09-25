import type { AdaptiveCandidateScore, AdaptiveElementFingerprint, AdaptiveLocateResult, AdaptiveWebPolicy } from "./adaptiveWebTypes.js";
import { normalizeAdaptiveWebPolicy, normalizeFingerprint } from "./adaptiveWebPolicy.js";

const MAX_CANDIDATES = 2_000;

function normalizedTokens(value: string): ReadonlySet<string> {
  return new Set(value.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim().split(/\s+/).filter(Boolean).slice(0, 256));
}

function jaccardStrings(a: readonly string[], b: readonly string[]): number {
  const left = new Set(a);
  const right = new Set(b);
  if (left.size === 0 && right.size === 0) return 1;
  let intersection = 0;
  for (const value of left) if (right.has(value)) intersection += 1;
  return intersection / (left.size + right.size - intersection);
}

function textSimilarity(a: string, b: string): number {
  return jaccardStrings([...normalizedTokens(a)], [...normalizedTokens(b)]);
}

function attributeTokens(attrs: Readonly<Record<string, string>>): readonly string[] {
  return Object.entries(attrs)
    .filter(([key]) => !["href", "src", "style"].includes(key.toLowerCase()))
    .flatMap(([key, value]) => [`k:${key.toLowerCase()}`, `kv:${key.toLowerCase()}=${value.toLowerCase().slice(0, 256)}`])
    .sort();
}

export function scoreAdaptiveElementCandidate(
  referenceInput: AdaptiveElementFingerprint,
  candidateInput: AdaptiveElementFingerprint,
): number {
  const reference = normalizeFingerprint(referenceInput, "reference");
  const candidate = normalizeFingerprint(candidateInput, "candidate");
  const tag = reference.tag === candidate.tag ? 1 : 0;
  const attributes = jaccardStrings(attributeTokens(reference.attributes), attributeTokens(candidate.attributes));
  const text = textSimilarity(reference.text, candidate.text);
  const parentTag = reference.parent.tag === candidate.parent.tag ? 1 : 0;
  const parentAttrs = jaccardStrings(attributeTokens(reference.parent.attributes), attributeTokens(candidate.parent.attributes));
  const parentText = textSimilarity(reference.parent.text, candidate.parent.text);
  const parent = 0.4 * parentTag + 0.35 * parentAttrs + 0.25 * parentText;
  const siblings = jaccardStrings(reference.siblingTags, candidate.siblingTags);
  const path = jaccardStrings(reference.pathTags, candidate.pathTags);
  const score = 0.2 * tag + 0.25 * attributes + 0.2 * text + 0.2 * parent + 0.075 * siblings + 0.075 * path;
  return Math.max(0, Math.min(1, Number(score.toFixed(6))));
}

export function selectAdaptiveElementCandidate(
  reference: AdaptiveElementFingerprint,
  candidates: readonly AdaptiveElementFingerprint[],
  policyInput: AdaptiveWebPolicy,
): AdaptiveLocateResult {
  const policy = normalizeAdaptiveWebPolicy(policyInput);
  if (candidates.length > MAX_CANDIDATES) throw new RangeError(`candidates exceeds ${MAX_CANDIDATES}`);
  const scored = candidates
    .map((candidate) => ({ candidateId: normalizeFingerprint(candidate, "candidate").id, score: scoreAdaptiveElementCandidate(reference, candidate) }))
    .sort((a, b) => b.score - a.score || a.candidateId.localeCompare(b.candidateId));
  const top = scored[0];
  const second = scored[1];
  if (!top || top.score < policy.adaptiveMinimumConfidence) {
    return Object.freeze({
      schemaVersion: "toadaid.adaptive-locate-result.v1",
      decision: "NO_MATCH",
      selectedCandidateId: null,
      confidence: top?.score ?? 0,
      threshold: policy.adaptiveMinimumConfidence,
      ambiguityMargin: policy.adaptiveAmbiguityMargin,
      candidates: Object.freeze(scored.map((row) => Object.freeze(row))),
    });
  }
  if (second && top.score - second.score < policy.adaptiveAmbiguityMargin) {
    return Object.freeze({
      schemaVersion: "toadaid.adaptive-locate-result.v1",
      decision: "AMBIGUOUS",
      selectedCandidateId: null,
      confidence: top.score,
      threshold: policy.adaptiveMinimumConfidence,
      ambiguityMargin: policy.adaptiveAmbiguityMargin,
      candidates: Object.freeze(scored.map((row) => Object.freeze(row))),
    });
  }
  return Object.freeze({
    schemaVersion: "toadaid.adaptive-locate-result.v1",
    decision: "MATCH",
    selectedCandidateId: top.candidateId,
    confidence: top.score,
    threshold: policy.adaptiveMinimumConfidence,
    ambiguityMargin: policy.adaptiveAmbiguityMargin,
    candidates: Object.freeze(scored.map((row) => Object.freeze(row))),
  });
}
