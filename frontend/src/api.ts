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
  };
  simulation_ground_truth: { hypothesis: Hypothesis; theta: number };
  ledger?: { index: number; hash: string };
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

export interface BoundRow {
  attack: string;
  helstrom_error_single_round: number;
  quantum_chernoff: number;
  measured_chernoff: number;
  measurement_efficiency: number;
  rounds_for_epsilon_quantum: number;
  rounds_for_epsilon_measured: number;
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
  health: () => call<{ status: string; version: string; ledger_entries: number; ledger_capacity: number }>("/health"),
  runSession: (req: SessionRequest) => call<Verdict>("/sessions", { method: "POST", body: JSON.stringify(req) }),
  resubmit: (id: string) => call<Verdict>(`/sessions/${id}/resubmit?trajectory=true`, { method: "POST" }),
  ledger: (limit = 15) => call<LedgerSummary>(`/ledger?limit=${limit}`),
  verifyLedger: () => call<LedgerReport>("/ledger/verify"),
  bounds: (theta: number) => call<BoundRow[]>(`/bounds?theta=${theta}`),
};

export const label = (h: string) => h.replace("_", " ");
