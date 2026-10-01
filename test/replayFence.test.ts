import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
 createReplayFence, openReplayReconciliation, resolveReplayReconciliation, createReplayRetryAuthorization,
 deterministicIdempotencyKey, createContractBoundIdempotencyGuarantee, validateReplayFenceEnvelope, validateReplayReconciliationEnvelope,
} from "../src/replayFence.js";
import type { CapabilityInvocationEnvelope, CapabilityInvocationStatus } from "../src/invocationTypes.js";
const H='a'.repeat(64), H2='b'.repeat(64), H3='c'.repeat(64);
function canonicalJson(value:unknown):string { if(value===null||typeof value==='boolean'||typeof value==='number'||typeof value==='string') return JSON.stringify(value); if(Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`; const r=value as Record<string,unknown>; return `{${Object.keys(r).sort().map(k=>`${JSON.stringify(k)}:${canonicalJson(r[k])}`).join(',')}}`; }
function digest(value:unknown):string { return createHash('sha256').update(canonicalJson(value)).digest('hex'); }
function inv(status:CapabilityInvocationStatus='AUTHORIZED', id='inv-1', intent=H):CapabilityInvocationEnvelope {
 const authorization=status==='REQUESTED'?null:{checkedAt:'2026-09-25T10:00:00.500Z',decision:'ALLOW' as const,reason:'AUTHORIZED_BY_POLICY' as const,decisionSha256:H};
 const start=['STARTED','CANCEL_REQUESTED','COMPLETED','FAILED'].includes(status)?{startedAt:'2026-09-25T10:00:01.000Z',managerId:'manager-1'}:null;
 const cancellation=status==='CANCEL_REQUESTED'?{requestedAt:'2026-09-25T10:00:02.000Z',managerId:'manager-1',reasonCode:'OPERATOR_CANCEL'}:null;
 const outcome=status==='FAILED'?{kind:'FAILED' as const,failedAt:'2026-09-25T10:00:03.000Z',managerId:'manager-1',errorClass:'KnownFailure',errorFingerprint:H2,evidenceRefs:[]}:status==='COMPLETED'?{kind:'COMPLETED' as const,completedAt:'2026-09-25T10:00:03.000Z',managerId:'manager-1',resultSha256:H2,evidenceRefs:[]}:null;
 const revision=status==='REQUESTED'?0:status==='AUTHORIZED'?1:status==='STARTED'?2:status==='CANCEL_REQUESTED'?3:3;
 const record={schemaVersion:'toadaid.capability-invocation.v1' as const,invocationId:id,revision,status,runId:'run-1',childTaskId:null,capabilityId:'review:fix',toolName:'fix',externalToolCallId:null,createdAt:'2026-09-25T10:00:00.000Z',updatedAt:status==='REQUESTED'?'2026-09-25T10:00:00.000Z':status==='AUTHORIZED'?'2026-09-25T10:00:00.500Z':status==='STARTED'?'2026-09-25T10:00:01.000Z':'2026-09-25T10:00:03.000Z',request:{intentSha256:intent,argumentsSha256:H3},authorization,start,cancellation,outcome,continuity:{previousRecordSha256:status==='REQUESTED'?null:H}};
 return {schemaVersion:'toadaid.capability-invocation-envelope.v1',record,recordSha256:digest(record)};
}
const rt={now:()=>new Date('2026-09-25T10:05:00.000Z'),randomId:()=> 'recon-1'};
const ready={schemaVersion:'toadaid.capability-invocation-contract-ready.v1' as const,invocationId:'inv-1',capabilityId:'review:fix',bindingSha256:H,provider:{providerDescriptorSha256:H,adapterRegistrationSha256:H2,implementationFingerprintSha256:H3},compatibility:{schemaVersion:'toadaid.capability-contract-compatibility.v1' as const,capabilityId:'review:fix',contractId:'toadaid.review.fix',requirementSha256:H3,descriptorSha256:H2,registrySha256:H,version:{major:1,minor:0},features:['idempotency.provider-key'],requestSchemaSha256:H,resultSchemaSha256:H2,receiptSchemaSha256:H3,compatible:true as const,reason:'COMPATIBLE' as const}};
const guarantee=createContractBoundIdempotencyGuarantee(ready,'PROVIDER_KEY');

test('safe read fence is deterministic and sealed',()=>{
 const f=createReplayFence(inv(),{replayClass:'SAFE_READ',createdAt:'2026-09-25T10:01:00.000Z'}); assert.equal(f.record.idempotencyKey,deterministicIdempotencyKey(f.record.binding)); assert.deepEqual(validateReplayFenceEnvelope(f),f);
 const f2=createReplayFence(inv('AUTHORIZED','inv-2'),{replayClass:'SAFE_READ',createdAt:'2026-09-25T10:01:00.000Z'}); assert.notEqual(f.record.idempotencyKey,f2.record.idempotencyKey);
});

test('idempotent write requires explicit adapter guarantee',()=>{assert.throws(()=>createReplayFence(inv(),{replayClass:'IDEMPOTENT_WRITE'}),/requires an explicit/);});

test('non replayable rejects idempotency guarantee',()=>{assert.throws(()=>createReplayFence(inv(),{replayClass:'NON_REPLAYABLE',guarantee}),/only for IDEMPOTENT_WRITE/);});

test('fence must be created before start',()=>{assert.throws(()=>createReplayFence(inv('STARTED'),{replayClass:'SAFE_READ'}),/before invocation start/);});

test('open reconciliation binds exact invocation and blocks replay',()=>{const f=createReplayFence(inv(),{replayClass:'SAFE_READ'}); const r=openReplayReconciliation(f,inv('STARTED'),{reasonCode:'TIMEOUT_UNKNOWN'},rt); assert.equal(r.record.disposition,'BLOCKED_PENDING_RECONCILIATION'); assert.equal(r.record.idempotencyKey,f.record.idempotencyKey);});

test('mismatched invocation cannot use a fence',()=>{const f=createReplayFence(inv(),{replayClass:'SAFE_READ'}); assert.throws(()=>openReplayReconciliation(f,inv('STARTED','inv-other'),{reasonCode:'TIMEOUT_UNKNOWN'},rt),/does not match/);});

test('safe read may retry only after explicit reconciliation resolution',()=>{const f=createReplayFence(inv(),{replayClass:'SAFE_READ'}); const o=openReplayReconciliation(f,inv('STARTED'),{reasonCode:'TIMEOUT_UNKNOWN'},rt); const r=resolveReplayReconciliation(o,{finding:'STILL_UNKNOWN',resolvedAt:'2026-09-25T10:06:00.000Z'},rt); assert.equal(r.record.disposition,'RETRY_ALLOWED'); const a=createReplayRetryAuthorization(f,r,inv('STARTED'),rt); assert.equal(a.idempotencyKey,f.record.idempotencyKey);});

test('confirmed executed always forbids replay',()=>{const f=createReplayFence(inv(),{replayClass:'SAFE_READ'}); const o=openReplayReconciliation(f,inv('STARTED'),{reasonCode:'TIMEOUT_UNKNOWN'},rt); const r=resolveReplayReconciliation(o,{finding:'CONFIRMED_EXECUTED',proofSha256:H3,resolvedAt:'2026-09-25T10:06:00.000Z'},rt); assert.equal(r.record.disposition,'DO_NOT_RETRY'); assert.throws(()=>createReplayRetryAuthorization(f,r,inv('STARTED'),rt));});

test('idempotent write needs confirmed-not-executed proof',()=>{const f=createReplayFence(inv(),{replayClass:'IDEMPOTENT_WRITE',guarantee}); const o=openReplayReconciliation(f,inv('STARTED'),{reasonCode:'TIMEOUT_UNKNOWN'},rt); const unknown=resolveReplayReconciliation(o,{finding:'STILL_UNKNOWN',resolvedAt:'2026-09-25T10:06:00.000Z'},rt); assert.equal(unknown.record.disposition,'BLOCKED_PENDING_RECONCILIATION');});

test('idempotent write confirmed-not-executed permits same-key retry',()=>{const f=createReplayFence(inv(),{replayClass:'IDEMPOTENT_WRITE',guarantee}); const o=openReplayReconciliation(f,inv('STARTED'),{reasonCode:'TIMEOUT_UNKNOWN'},rt); const r=resolveReplayReconciliation(o,{finding:'CONFIRMED_NOT_EXECUTED',proofSha256:H3,proofRefs:[{id:'provider-status',sha256:H2}],resolvedAt:'2026-09-25T10:06:00.000Z'},rt); assert.equal(r.record.disposition,'RETRY_ALLOWED'); const a=createReplayRetryAuthorization(f,r,inv('STARTED'),rt); assert.equal(a.idempotencyKey,f.record.idempotencyKey);});

test('non replayable never authorizes same invocation replay',()=>{const f=createReplayFence(inv(),{replayClass:'NON_REPLAYABLE'}); const o=openReplayReconciliation(f,inv('STARTED'),{reasonCode:'TIMEOUT_UNKNOWN'},rt); const r=resolveReplayReconciliation(o,{finding:'CONFIRMED_NOT_EXECUTED',proofSha256:H3,resolvedAt:'2026-09-25T10:06:00.000Z'},rt); assert.equal(r.record.disposition,'NEW_INVOCATION_REQUIRED'); assert.throws(()=>createReplayRetryAuthorization(f,r,inv('STARTED'),rt));});

test('tampered fence and reconciliation fail integrity',()=>{const f=createReplayFence(inv(),{replayClass:'SAFE_READ'}); const bad={...f,record:{...f.record,replayClass:'NON_REPLAYABLE' as const}}; assert.throws(()=>validateReplayFenceEnvelope(bad),/integrity|guarantee|mismatch/); const o=openReplayReconciliation(f,inv('STARTED'),{reasonCode:'TIMEOUT_UNKNOWN'},rt); const badR={...o,record:{...o.record,reasonCode:'OTHER'}}; assert.throws(()=>validateReplayReconciliationEnvelope(badR),/integrity/);});

test('confirmed findings require proof hash',()=>{const f=createReplayFence(inv(),{replayClass:'SAFE_READ'}); const o=openReplayReconciliation(f,inv('STARTED'),{reasonCode:'TIMEOUT_UNKNOWN'},rt); assert.throws(()=>resolveReplayReconciliation(o,{finding:'CONFIRMED_EXECUTED',resolvedAt:'2026-09-25T10:06:00.000Z'},rt),/requires proofSha256/);});


test('idempotency guarantee is contract-feature bound',()=>{
 assert.equal(guarantee.feature,'idempotency.provider-key');
 assert.throws(()=>createContractBoundIdempotencyGuarantee({...ready,compatibility:{...ready.compatibility,features:[]}},'PROVIDER_KEY'),/does not advertise/);
});

test('idempotency guarantee cannot be reused for another invocation',()=>{
 assert.throws(()=>createReplayFence(inv('AUTHORIZED','inv-2'),{replayClass:'IDEMPOTENT_WRITE',guarantee}),/does not match invocation binding/);
});


test('retry authorization refuses changed invocation record after reconciliation opened',()=>{
 const f=createReplayFence(inv(),{replayClass:'SAFE_READ'});
 const started=inv('STARTED'); const o=openReplayReconciliation(f,started,{reasonCode:'TIMEOUT_UNKNOWN'},rt);
 const r=resolveReplayReconciliation(o,{finding:'STILL_UNKNOWN',resolvedAt:'2026-09-25T10:06:00.000Z'},rt);
 const changedRecord={...started.record,updatedAt:'2026-09-25T10:00:02.000Z'};
 const changed={...started,record:changedRecord,recordSha256:digest(changedRecord)};
 assert.throws(()=>createReplayRetryAuthorization(f,r,changed,rt),/changed since reconciliation/);
});

test('reconciliation resolves once and timestamps are monotonic',()=>{
 const f=createReplayFence(inv(),{replayClass:'SAFE_READ'}); const o=openReplayReconciliation(f,inv('STARTED'),{reasonCode:'TIMEOUT_UNKNOWN',openedAt:'2026-09-25T10:05:00.000Z'},rt);
 assert.throws(()=>resolveReplayReconciliation(o,{finding:'STILL_UNKNOWN',resolvedAt:'2026-09-25T10:04:59.000Z'},rt),/earlier than openedAt/);
 const r=resolveReplayReconciliation(o,{finding:'STILL_UNKNOWN',resolvedAt:'2026-09-25T10:06:00.000Z'},rt);
 assert.throws(()=>resolveReplayReconciliation(r,{finding:'STILL_UNKNOWN',resolvedAt:'2026-09-25T10:07:00.000Z'},rt),/already resolved/);
});

test('tampered contract-bound guarantee is rejected',()=>{
 const bad={...guarantee,implementationFingerprintSha256:H};
 assert.throws(()=>createReplayFence(inv(),{replayClass:'IDEMPOTENT_WRITE',guarantee:bad}),/guarantee integrity mismatch/);
});


test('terminal H1 failure cannot be reopened for replay reconciliation',()=>{
 const f=createReplayFence(inv(),{replayClass:'SAFE_READ'});
 assert.throws(()=>openReplayReconciliation(f,inv('FAILED'),{reasonCode:'TIMEOUT_UNKNOWN'},rt),/active invocation/);
});
