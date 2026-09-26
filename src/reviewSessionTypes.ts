import type {
  OpenCodeReviewMode,
  OpenCodeReviewPlan,
} from "./openCodeReviewAdapter.js";

export interface ReviewSessionBinding {
  readonly repositoryIdentitySha256: string;
  readonly reviewedSourceSha256: string;
  readonly rulesSha256: string;
  readonly reviewMode: OpenCodeReviewMode;
  readonly planSha256: string;
}

export interface ReviewRuntimeIdentity {
  readonly provider: string;
  readonly model: string;
}

export type ReviewSessionTransition =
  | "INITIAL"
  | "RESUME_SAME_RUNTIME"
  | "RESUME_RUNTIME_TRANSITION";

export interface ReviewSessionLineage {
  readonly parentRecordSha256: string | null;
  readonly fromRuntime: ReviewRuntimeIdentity | null;
  readonly toRuntime: ReviewRuntimeIdentity;
  readonly runtimeChanged: boolean;
}

export interface ReviewSessionRecord {
  readonly schemaVersion: "toadaid.review-session.v1";
  readonly sessionId: string;
  readonly revision: number;
  readonly binding: ReviewSessionBinding;
  readonly runtime: ReviewRuntimeIdentity;
  readonly transition: ReviewSessionTransition;
  readonly lineage: ReviewSessionLineage;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly continuity: {
    readonly previousRecordSha256: string | null;
  };
}

export interface ReviewSessionEnvelope {
  readonly schemaVersion: "toadaid.review-session-envelope.v1";
  readonly record: ReviewSessionRecord;
  readonly recordSha256: string;
}

export interface CreateReviewSessionInput {
  readonly sessionId?: string;
  readonly plan: OpenCodeReviewPlan;
  readonly repositoryIdentitySha256: string;
  readonly reviewedSourceSha256: string;
  readonly rulesSha256: string;
  readonly provider: string;
  readonly model: string;
  readonly createdAt?: string;
}

export interface ResumeReviewSessionInput {
  readonly plan: OpenCodeReviewPlan;
  readonly repositoryIdentitySha256: string;
  readonly reviewedSourceSha256: string;
  readonly rulesSha256: string;
  readonly provider: string;
  readonly model: string;
  readonly acceptRuntimeTransition?: boolean;
  readonly resumedAt?: string;
}

export interface ReviewSessionRuntime {
  readonly now?: () => Date;
  readonly randomId?: () => string;
}

export interface CreateReviewPresentationStateInput {
  readonly selectedFindingId?: string | null;
  readonly hiddenFindingIds?: readonly string[];
}

export interface ReviewPresentationState {
  readonly schemaVersion: "toadaid.review-presentation-state.v1";
  readonly sessionRecordSha256: string;
  readonly selectedFindingId: string | null;
  readonly hiddenFindingIds: readonly string[];
}
