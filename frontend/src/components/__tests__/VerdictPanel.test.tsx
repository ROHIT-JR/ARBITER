import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import VerdictPanel from '../VerdictPanel';
import type { Verdict } from '../../api';

describe('VerdictPanel', () => {
  const mockVerdict: Verdict = {
    decision: 'REJECT',
    attribution: 'forgery',
    simulation_ground_truth: { hypothesis: 'forgery', theta: 1.0 },
    session: { id: 'test-uuid', nonce: 'abc', backend: 'analytic', rounds: 1200, rounds_per_cell: [200, 100, 150, 150, 150, 150], transcript_digest: 'digest' },
    reasons: ['Attack detected with high confidence'],
    layers: {
      nonce_fresh: true,
      chsh: { S: 2.45, half_width: 0.05, threshold: 2.0, certified: true, flagged: false },
      freshness: { rounds: 300, mismatches: 150, observed_rate: 0.5, expected_rate: 0.04, p_value: 1e-50, flagged: true },
      unified: { rejected: true, statistic: 45.2, threshold: 8.9, alpha: 0.01, attribution: 'forgery', posterior: { legitimate: 0.001, forgery: 0.95, impersonation: 0.02, replay: 0.02, channel_manipulation: 0.009 }, theta_hat: { forgery: 1.0 } },
      sequential: { rejected: true, stopped_at: 45, attributed_at: 67, budget: 1200, log_threshold: 4.605, attribution: 'forgery', log_evidence: [0.1, 0.5, 1.2] },
    },
  };

  it('renders REJECT badge for rejected verdict', () => {
    render(<VerdictPanel verdict={mockVerdict} />);
    expect(screen.getByText(/REJECT/i)).toBeInTheDocument();
  });

  it('renders ACCEPT badge for non-rejected verdict', () => {
    render(<VerdictPanel verdict={{ ...mockVerdict, decision: 'ACCEPT' }} />);
    expect(screen.getByText(/ACCEPT/i)).toBeInTheDocument();
  });

  it('shows attribution in attribution div', () => {
    render(<VerdictPanel verdict={mockVerdict} />);
    const attributionElements = screen.getAllByText(/forgery/i);
    const attributionDiv = attributionElements.find(el => el.classList.contains('attribution'));
    expect(attributionDiv).toBeInTheDocument();
  });

  it('shows ground truth with correctness indicator', () => {
    render(<VerdictPanel verdict={mockVerdict} />);
    expect(screen.getByText(/ground truth: forgery/i)).toBeInTheDocument();
    expect(screen.getByText(/✓ correct/i)).toBeInTheDocument();
  });

  it('displays unified GLRT statistic and threshold', () => {
    render(<VerdictPanel verdict={mockVerdict} />);
    expect(screen.getByText(/Λ = 45\.20 vs τ = 8\.90/i)).toBeInTheDocument();
    expect(screen.getByText(/α = 0\.01/i)).toBeInTheDocument();
  });

  it('displays sequential alarm and attribution rounds', () => {
    render(<VerdictPanel verdict={mockVerdict} />);
    expect(screen.getByText(/alarm @ round 45/i)).toBeInTheDocument();
    expect(screen.getByText(/attributed @ 67/i)).toBeInTheDocument();
  });

  it('shows posterior bars for all hypotheses', () => {
    const { container } = render(<VerdictPanel verdict={mockVerdict} />);
    const barLabels = container.querySelectorAll('.bar-label');
    const labels = Array.from(barLabels).map(el => el.textContent || '');
    
    expect(labels).toContain('legitimate');
    expect(labels).toContain('forgery');
    expect(labels).toContain('impersonation');
    expect(labels).toContain('replay');
    expect(labels).toContain('channel manipulation'); // label() replaces _ with space
  });

  it('shows p-value formatting for small values', () => {
    const smallP = { 
      ...mockVerdict, 
      layers: { 
        ...mockVerdict.layers, 
        freshness: { ...mockVerdict.layers.freshness, p_value: 1e-400 } 
      } 
    };
    render(<VerdictPanel verdict={smallP} />);
    expect(screen.getByText(/< 1e-300/i)).toBeInTheDocument();
  });
});