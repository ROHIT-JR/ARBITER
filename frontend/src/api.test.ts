import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api, UNREACHABLE } from './api';

global.fetch = vi.fn();

describe('api.ts error mapping', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('network error maps to UNREACHABLE', async () => {
    (fetch as any).mockRejectedValue(new TypeError('Failed to fetch'));
    await expect(api.runSession({ hypothesis: 'forgery', n_rounds: 100, theta: 1, backend: 'analytic' }))
      .rejects.toThrow(UNREACHABLE);
  });

  it('timeout maps to UNREACHABLE', async () => {
    (fetch as any).mockRejectedValue(new DOMException('Timeout', 'TimeoutError'));
    await expect(api.runSession({ hypothesis: 'forgery', n_rounds: 100, theta: 1, backend: 'analytic' }))
      .rejects.toThrow(UNREACHABLE);
  });

  it('500 with empty body maps to UNREACHABLE', async () => {
    (fetch as any).mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({}),
      text: async () => '',
    });
    await expect(api.runSession({ hypothesis: 'forgery', n_rounds: 100, theta: 1, backend: 'analytic' }))
      .rejects.toThrow(UNREACHABLE);
  });

  it('500 with FastAPI detail maps to "500: <detail>"', async () => {
    (fetch as any).mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({ detail: 'Internal error: model failed' }),
      text: async () => '{"detail":"Internal error: model failed"}',
    });
    await expect(api.runSession({ hypothesis: 'forgery', n_rounds: 100, theta: 1, backend: 'analytic' }))
      .rejects.toThrow('500: Internal error: model failed');
  });

  it('422 validation error maps to "422: <detail>"', async () => {
    (fetch as any).mockResolvedValue({
      ok: false,
      status: 422,
      json: async () => ({
        detail: [{ loc: ['body', 'n_rounds'], msg: 'ensure this value is greater than or equal to 10' }],
      }),
      text: async () => JSON.stringify({ detail: [{ loc: ['body', 'n_rounds'], msg: 'ensure this value is greater than or equal to 10' }] }),
    });
    await expect(api.runSession({ hypothesis: 'forgery', n_rounds: 5, theta: 1, backend: 'analytic' }))
      .rejects.toThrow('422:');
  });

  it('successful response returns parsed data', async () => {
    const mockResponse = {
      session: { id: 'test-uuid', nonce: 'abc', backend: 'analytic', rounds: 100, rounds_per_cell: [10,10,10,10,10,10], transcript_digest: 'digest' },
      decision: 'ACCEPT' as const,
      attribution: 'legitimate' as const,
      reasons: [],
      layers: {
        nonce_fresh: true,
        chsh: { S: 2.5, half_width: 0.1, threshold: 2.0, certified: true, flagged: false },
        freshness: { rounds: 25, mismatches: 2, observed_rate: 0.08, expected_rate: 0.04, p_value: 0.5, flagged: false },
        unified: { rejected: false, statistic: 1.2, threshold: 5.0, alpha: 0.01, attribution: 'legitimate', posterior: {}, theta_hat: {} },
        sequential: { rejected: false, stopped_at: 100, attributed_at: 100, budget: 100, log_threshold: 4.6, attribution: 'legitimate', log_evidence: [] },
      },
      simulation_ground_truth: { hypothesis: 'legitimate', theta: 0 },
    };
    (fetch as any).mockResolvedValue({
      ok: true,
      json: async () => mockResponse,
    });
    const result = await api.runSession({ hypothesis: 'legitimate', n_rounds: 100, theta: 0, backend: 'analytic' });
    expect(result).toEqual(mockResponse);
  });

  it('fetchVerify handles network error', async () => {
    (fetch as any).mockRejectedValue(new TypeError('Failed to fetch'));
    await expect(api.verifyLedger()).rejects.toThrow(UNREACHABLE);
  });

  it('fetchHealth returns ok', async () => {
    (fetch as any).mockResolvedValue({ ok: true, json: async () => ({ status: 'ok', version: '0.1.0', ledger_entries: 0, ledger_capacity: 1000, demo_mode: true }) });
    const result = await api.health();
    expect(result).toEqual({ status: 'ok', version: '0.1.0', ledger_entries: 0, ledger_capacity: 1000, demo_mode: true });
  });
});