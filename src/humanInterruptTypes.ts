export type HumanInterruptStatus = "OPEN" | "RESOLVED";
export type HumanInterruptReason =
  | "DECISION_REQUIRED"
  | "AMBIGUOUS"
  | "POLICY_REQUIRED"
  | "EXTERNAL_CONFIRMATION"
  | "MANUAL";

export interface HumanInterruptStringSchema {
  type: "string";
  minLength?: number;
  maxLength?: number;
  enum?: readonly string[];
}

export interface HumanInterruptBooleanSchema {
  type: "boolean";
}

export interface HumanInterruptIntegerSchema {
  type: "integer";
  minimum?: number;
  maximum?: number;
}

export type HumanInterruptScalarSchema =
  | HumanInterruptStringSchema
  | HumanInterruptBooleanSchema
  | HumanInterruptIntegerSchema;

export interface HumanInterruptObjectSchema {
  type: "object";
  properties: Readonly<Record<string, HumanInterruptScalarSchema>>;
  required?: readonly string[];
  additionalProperties?: false;
}

export type HumanInterruptResponseSchema =
  | HumanInterruptScalarSchema
  | HumanInterruptObjectSchema;

export type HumanInterruptResponseScalar = string | boolean | number;
export type HumanInterruptResponse =
  | HumanInterruptResponseScalar
  | Readonly<Record<string, HumanInterruptResponseScalar>>;

export interface HumanInterruptRunBinding {
  runId: string;
  runRevision: number;
  runStateSha256: string;
}

export interface HumanInterruptResolution {
  responderId: string;
  resolvedAt: string;
  response: HumanInterruptResponse;
  responseSha256: string;
}

export interface HumanInterruptContinuity {
  previousRecordSha256: string | null;
}

export interface HumanInterruptRecord {
  schemaVersion: "toadaid.human-interrupt.v1";
  interruptId: string;
  revision: number;
  status: HumanInterruptStatus;
  createdAt: string;
  updatedAt: string;
  reason: HumanInterruptReason;
  prompt: string;
  responseSchema: HumanInterruptResponseSchema;
  runBinding: HumanInterruptRunBinding;
  resolution: HumanInterruptResolution | null;
  continuity: HumanInterruptContinuity;
}

export interface HumanInterruptEnvelope {
  schemaVersion: "toadaid.human-interrupt-envelope.v1";
  record: HumanInterruptRecord;
  recordSha256: string;
}

export interface CreateHumanInterruptInput {
  interruptId?: string;
  createdAt: string;
  reason: HumanInterruptReason;
  prompt: string;
  responseSchema: HumanInterruptResponseSchema;
}

export interface ResolveHumanInterruptInput {
  responderId: string;
  resolvedAt: string;
  response: HumanInterruptResponse;
}

export interface HumanInterruptResumeProof {
  schemaVersion: "toadaid.human-interrupt-resume-proof.v1";
  interruptId: string;
  interruptRecordSha256: string;
  runId: string;
  runRevision: number;
  runStateSha256: string;
  responderId: string;
  responseSha256: string;
  verifiedAt: string;
}
