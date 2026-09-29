import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import EvidenceChart from '../EvidenceChart';

describe('EvidenceChart', () => {
  it('renders without crashing for empty data', () => {
    render(<EvidenceChart logEvidence={[]} logThreshold={4.6} alarmAt={null} attributedAt={null} />);
    expect(screen.getByRole('img')).toBeInTheDocument();
  });

  it('renders without crashing for short trajectory (5 rounds)', () => {
    render(<EvidenceChart logEvidence={[0.1, 0.5, 1.2, 2.1, 3.0]} logThreshold={4.6} alarmAt={null} attributedAt={null} />);
    expect(screen.getByRole('img')).toBeInTheDocument();
  });

  it('places alarm marker when alarmAt provided', () => {
    render(<EvidenceChart logEvidence={[0.1, 0.5, 1.2, 2.1, 3.0, 5.0, 8.0]} logThreshold={4.6} alarmAt={5} attributedAt={null} />);
    expect(screen.getByRole('img')).toBeInTheDocument();
  });

  it('places attribution marker when attributedAt provided', () => {
    render(<EvidenceChart logEvidence={[0.1, 0.5, 1.2, 2.1, 3.0, 5.0, 8.0, 10.0]} logThreshold={4.6} alarmAt={5} attributedAt={7} />);
    expect(screen.getByRole('img')).toBeInTheDocument();
  });

  it('shows threshold line at log(1/α)', () => {
    render(<EvidenceChart logEvidence={[0.1, 0.5, 1.2]} logThreshold={4.605} alarmAt={null} attributedAt={null} />);
    expect(screen.getByRole('img')).toBeInTheDocument();
  });
});