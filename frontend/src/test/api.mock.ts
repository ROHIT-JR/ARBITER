import type { Verdict, LedgerSummary, ComparisonResult, DetectorComparison } from '../api';

export const mockVerdict: Verdict = {
  session: {
    id: 'test-session-1',
    nonce: 'test-nonce',
    backend: 'analytic',
    rounds: 1200,
    rounds_per_cell: [600, 300, 75, 75, 75, 75],
    transcript_digest: 'abc123',
  },
  decision: 'ACCEPT',
  attribution: 'legitimate',
  reasons: [],
  layers: {
    nonce_fresh: true,
    chsh: { S: 2.55, half_width: 0.1, threshold: 2.0, certified: true, flagged: false },
    freshness: { rounds: 300, mismatches: 12, observed_rate: 0.04, expected_rate: 0.04, p_value: 0.23, flagged: false },
    unified: {
      rejected: false,
      statistic: 5.2,
      threshold: 4.1,
      alpha: 0.01,
      attribution: 'legitimate',
      posterior: { legitimate: 0.9, forgery: 0.05, impersonation: 0.02, replay: 0.02, channel_manipulation: 0.01 },
      theta_hat: { forgery: 0.1, impersonation: 0.0, replay: 0.0, channel_manipulation: 0.0 },
    },
    sequential: {
      rejected: false,
      stopped_at: 800,
      attributed_at: 600,
      budget: 4.6,
      log_threshold: 4.6,
      attribution: 'legitimate',
      log_evidence: [1.2, 2.4, 3.8, 4.1, 5.2],
    },
    temporal: {
      rejected: false,
      alpha: 0.01,
      per_test_alpha: 0.00167,
      multiple_testing: 'bonferroni',
      window: 50,
      stride: 25,
      streams: {
        signature: {
          rounds: 300,
          flagged: false,
          windows: [{ start: 0, stop: 50, count: 50, mismatch_rate: 0.04, variance: 0.001, skewness: 0.1, excess_kurtosis: -0.2 }],
          burst: {
            longest_run: { statistic: 3, threshold: 8, p_value: 0.9, alpha: 0.00167, flagged: false },
            max_window_count: { statistic: 4, threshold: 12, p_value: 0.8, alpha: 0.00167, flagged: false },
          },
          spectral: { fisher_g: { statistic: 1.2, threshold: 6.5, p_value: 0.7, alpha: 0.00167, flagged: false } },
        },
        freshness: {
          rounds: 300,
          flagged: false,
          windows: [{ start: 0, stop: 50, count: 50, mismatch_rate: 0.04, variance: 0.001, skewness: 0.1, excess_kurtosis: -0.2 }],
          burst: {
            longest_run: { statistic: 3, threshold: 8, p_value: 0.9, alpha: 0.00167, flagged: false },
            max_window_count: { statistic: 4, threshold: 12, p_value: 0.8, alpha: 0.00167, flagged: false },
          },
          spectral: { fisher_g: { statistic: 1.2, threshold: 6.5, p_value: 0.7, alpha: 0.00167, flagged: false } },
        },
        chsh: {
          rounds: 300,
          flagged: false,
          windows: [{ start: 0, stop: 50, count: 50, mismatch_rate: 0.04, variance: 0.001, skewness: 0.1, excess_kurtosis: -0.2 }],
          burst: {
            longest_run: { statistic: 3, threshold: 8, p_value: 0.9, alpha: 0.00167, flagged: false },
            max_window_count: { statistic: 4, threshold: 12, p_value: 0.8, alpha: 0.00167, flagged: false },
          },
          spectral: { fisher_g: { statistic: 1.2, threshold: 6.5, p_value: 0.7, alpha: 0.00167, flagged: false } },
        },
      },
    },
  },
  simulation_ground_truth: { hypothesis: 'legitimate', theta: 0.0 },
  ledger: { index: 5, hash: 'a1b2c3d4' },
};

export const mockLedgerSummary: LedgerSummary = {
  genesis_hash: 'genesis_hash',
  entries: [
    {
      index: 0,
      timestamp: '2026-01-01T00:00:00.000000+00:00',
      hash: 'genesis_hash',
      type: 'genesis',
    },
    {
      index: 1,
      timestamp: '2026-01-01T00:01:00.000000+00:00',
      hash: 'hash1',
      type: 'verdict',
      session_id: 'session-1',
      decision: 'ACCEPT',
      attribution: 'legitimate',
    },
  ],
};

const createMockDetectorComparison = (): DetectorComparison => ({
  confusion_matrix: {
    legitimate: { legitimate: 20, forgery: 0, impersonation: 0, replay: 0, channel_manipulation: 0 },
    forgery: { legitimate: 0, forgery: 20, impersonation: 0, replay: 0, channel_manipulation: 0 },
    impersonation: { legitimate: 0, forgery: 0, impersonation: 20, replay: 0, channel_manipulation: 0 },
    replay: { legitimate: 0, forgery: 0, impersonation: 0, replay: 20, channel_manipulation: 0 },
    channel_manipulation: { legitimate: 0, forgery: 0, impersonation: 0, replay: 0, channel_manipulation: 20 },
  },
  false_alarm_rate: 0.01,
  attacks: {
    forgery: { detection_rate: 0.95, correct_attribution_rate: 0.9 },
    impersonation: { detection_rate: 1.0, correct_attribution_rate: 1.0 },
    replay: { detection_rate: 0.9, correct_attribution_rate: 0.85 },
    channel_manipulation: { detection_rate: 0.85, correct_attribution_rate: 0.8 },
  },
  thresholds: { unified: 4.1, sequential: 4.6, baseline: 3.8 },
});

export const mockComparisonResult: ComparisonResult = {
  metadata: {
    theta: 0.5,
    sessions_per_hypothesis: 20,
    seed: 12345,
    n_rounds: 1200,
    alpha: 0.01,
    cell_counts: [600, 300, 75, 75, 75, 75],
    design: 'balanced',
  },
  labels: ['legitimate', 'forgery', 'impersonation', 'replay', 'channel_manipulation'],
  detectors: {
    unified: createMockDetectorComparison(),
    baseline: createMockDetectorComparison(),
    baseline_bonferroni: createMockDetectorComparison(),
  },
};