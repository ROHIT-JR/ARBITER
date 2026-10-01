// Typed client for the ARBITER FastAPI service (proxied at /api).

export const HYPOTHESES = ["legitimate", "forgery", "impersonation", "replay", "channel_manipulation"] as const;
export type Hypothesis = (typeof HYPOTHESES)[number];

export interface SessionRequest {
  hypothesis: Hypothesis;
  theta: number;
  n_rounds: number;
  backend: "analytic" | "qiskit";
  seed?: number | null;
  trajectory?: boolean;
  periodic_attack_every?: number | null;
}

export interface Verdict {
  session: { id: string; nonce: string; backend: string; rounds: number; rounds_per_cell: number[]; transcript_digest: string };
  decision: "ACCEPT" | "REJECT";
  attribution: Hypothesis;
  reasons: string[];
  layers: {
    nonce_fresh: boolean;
    chsh: { S: number; half_width: number; threshold: number; certified: boolean; flagged: boolean };
    freshness: { rounds: number; mismatches: number; observed_rate: number; expected_rate: number; p_value: number; flagged: boolean };
    unified: {
      rejected: boolean;
      statistic: number;
      threshold: number;
      alpha: number;
      attribution: Hypothesis;
      posterior: Record<Hypothesis, number>;
      theta_hat: Record<string, number>;
    };
    sequential: {
      rejected: boolean;
      stopped_at: number;
      attributed_at: number;
      budget: number;
      log_threshold: number;
      attribution: Hypothesis;
      log_evidence?: number[];
    };
    temporal: {
      rejected: boolean;
      alpha: number;
      per_test_alpha: number;
      multiple_testing: string;
      window: number;
      stride: number;
      streams: Record<"signature" | "freshness" | "chsh", {
        rounds: number;
        flagged: boolean;
        windows: { start: number; stop: number; count: number; mismatch_rate: number; variance: number; skewness: number; excess_kurtosis: number }[];
        burst: {
          longest_run: TemporalTest;
          max_window_count: TemporalTest;
        };
        spectral: { fisher_g: TemporalTest };
      }>;
    };
  };
  simulation_ground_truth: { hypothesis: Hypothesis; theta: number };
  ledger?: { index: number; hash: string };
}

export interface TemporalTest {
  statistic: number;
  threshold: number;
  p_value: number;
  alpha: number;
  flagged: boolean;
}

export interface LedgerSummary {
  genesis_hash: string;
  entries: {
    index: number;
    timestamp: string;
    hash: string;
    type?: string;
    session_id?: string;
    decision?: string;
    attribution?: string;
  }[];
}

export interface LedgerReport {
  ok: boolean;
  entries: number;
  first_bad_index: number | null;
  problems: string[];
}

export type LedgerTamperField = "decision" | "attribution" | "timestamp";

export interface BoundRow {
  attack: string;
  helstrom_error_single_round: number;
  quantum_chernoff: number;
  measured_chernoff: number;
  measurement_efficiency: number;
  rounds_for_epsilon_quantum: number;
  rounds_for_epsilon_measured: number;
}

export interface ProtocolSecurityBound {
  length: number;
  p_err: number;
  p_forge_mismatch: number;
  s_a: number;
  s_v: number;
  p_forge: number;
  p_rep: number;
  p_rob: number;
  epsilon: number;
  assumptions: string[];
}

export interface ProtocolSecurityResponse {
  target_epsilon: number;
  minimum_length: number;
  visibility: number;
  bounds: ProtocolSecurityBound;
  curve: ProtocolSecurityBound[];
}

export type DetectorName = "unified" | "baseline" | "baseline_bonferroni";

export interface AttackAccuracy {
  detection_rate: number;
  correct_attribution_rate: number;
}

export interface DetectorComparison {
  confusion_matrix: Record<Hypothesis, Record<Hypothesis, number>>;
  false_alarm_rate: number;
  attacks: Record<Exclude<Hypothesis, "legitimate">, AttackAccuracy>;
  thresholds?: Record<string, number>;
}

export interface ComparisonResult {
  metadata: {
    theta: number;
    sessions_per_hypothesis: number;
    seed: number;
    n_rounds: number;
    alpha: number;
    cell_counts: number[];
    design: string;
  };
  labels: Hypothesis[];
  detectors: Record<DetectorName, DetectorComparison>;
}

export interface DemoScenario {
  id: string;
  title: string;
  kind: "session" | "resubmit" | "tamper" | "accuracy" | "hardware";
  request?: SessionRequest | { field: LedgerTamperField; value: string; recompute_hashes: boolean };
  source?: string;
  optional?: boolean;
  cached_result?: DemoAccuracyCache | null;
}

export interface DemoAccuracyCache extends ComparisonResult {
  curve: { theta: number; unified: number[]; baseline: number[] }[];
}

export interface DemoCatalog {
  version: number;
  scenarios: DemoScenario[];
}

export const UNREACHABLE = "Cannot reach the ARBITER API. Is uvicorn running on port 8000?";

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`/api${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    });
  } catch {
    throw new Error(UNREACHABLE);
  }
  if (!res.ok) {
    const body = await res.text();
    // The dev/preview proxy answers 5xx with an empty body when the backend is down.
    if (res.status >= 500 && !body.trim()) throw new Error(UNREACHABLE);
    let detail = body.slice(0, 300);
    try {
      const parsed = JSON.parse(body);
      if (parsed.detail) detail = typeof parsed.detail === "string" ? parsed.detail : JSON.stringify(parsed.detail);
    } catch {
      /* not JSON */
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => call<{ status: string; version: string; ledger_entries: number; ledger_capacity: number; demo_mode: boolean }>("/health"),
  runSession: (req: SessionRequest) => call<Verdict>("/sessions", { method: "POST", body: JSON.stringify(req) }),
  resubmit: (id: string) => call<Verdict>(`/sessions/${id}/resubmit?trajectory=true`, { method: "POST" }),
  ledger: (limit = 15) => call<LedgerSummary>(`/ledger?limit=${limit}`),
  verifyLedger: () => call<LedgerReport>("/ledger/verify"),
  tamperLedger: (index: number, field: LedgerTamperField, value: string, recomputeHashes = false) =>
    call<LedgerReport>(`/ledger/${index}/tamper`, {
      method: "POST",
      body: JSON.stringify({ field, value, recompute_hashes: recomputeHashes }),
    }),
  restoreLedger: () => call<LedgerReport>("/ledger/restore", { method: "POST" }),
  bounds: (theta: number) => call<BoundRow[]>(`/bounds?theta=${theta}`),
  security: (epsilon = 1e-10, visibility?: number) =>
    call<ProtocolSecurityResponse>(`/security?epsilon=${epsilon}${visibility === undefined ? "" : `&visibility=${visibility}`}`),
  compare: (theta: number, sessions: number, seed: number) =>
    call<ComparisonResult>(`/compare?theta=${theta}&sessions=${sessions}&seed=${seed}`),
  demoScenarios: () => call<DemoCatalog>("/demo/scenarios"),
};

export const label = (h: string) => h.replaceAll("_", " ");
