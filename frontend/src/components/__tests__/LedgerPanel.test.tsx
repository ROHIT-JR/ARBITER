import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import LedgerPanel from '../LedgerPanel';
import { api } from '../../api';

vi.mock('../../api', async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    api: {
      ledger: vi.fn(),
      verifyLedger: vi.fn(),
      tamperLedger: vi.fn(),
      restoreLedger: vi.fn(),
    },
  };
});

describe('LedgerPanel', () => {
  const mockLedger = {
    genesis_hash: 'a'.repeat(64),
    entries: [
      { index: 0, timestamp: '2026-01-01T00:00:00Z', type: 'genesis', hash: 'a'.repeat(64) },
      { index: 1, timestamp: '2026-01-01T00:00:01Z', decision: 'ACCEPT', attribution: 'legitimate', hash: 'b'.repeat(64) },
    ],
  };

  const mockVerifyOk = { ok: true, entries: 2, first_bad_index: null, problems: [] };
  const mockVerifyFail = { ok: false, entries: 2, first_bad_index: 1, problems: ['chain broken at index 1'] };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.ledger).mockResolvedValue(mockLedger);
    vi.mocked(api.verifyLedger).mockResolvedValue(mockVerifyOk);
  });

  it('renders loading state initially', () => {
    vi.mocked(api.ledger).mockImplementation(() => new Promise(() => {})); // never resolves
    render(<LedgerPanel version={1} demoMode={false} />);
    expect(screen.getByText(/Loading…/i)).toBeInTheDocument();
  });

  it('renders ledger entries after loading', async () => {
    render(<LedgerPanel version={1} demoMode={false} />);
    await waitFor(() => {
      const genesisElements = screen.getAllByText(/genesis/i);
      const genesisSpan = genesisElements.find(el => el.classList.contains('muted') && el.classList.contains('small') && el.classList.contains('mono'));
      expect(genesisSpan).toBeInTheDocument();
    });
    expect(screen.getByText(/ACCEPT/i)).toBeInTheDocument();
    expect(screen.getByText(/legitimate/i)).toBeInTheDocument();
  });

  it('shows verify button', async () => {
    render(<LedgerPanel version={1} demoMode={false} />);
    await waitFor(() => expect(screen.getByRole('button', { name: /verify chain/i })).toBeInTheDocument());
  });

  it('shows OK badge after successful verification', async () => {
    render(<LedgerPanel version={1} demoMode={false} report={mockVerifyOk} />);
    await waitFor(() => expect(screen.getByText(/✓ 2 entries valid/i)).toBeInTheDocument());
  });

  it('shows error badge after failed verification', async () => {
    render(<LedgerPanel version={1} demoMode={false} report={mockVerifyFail} />);
    await waitFor(() => expect(screen.getByText(/✗ chain broken at index 1/i)).toBeInTheDocument());
  });

  it('calls verifyLedger when verify button clicked', async () => {
    const user = userEvent.setup();
    render(<LedgerPanel version={1} demoMode={false} />);
    await waitFor(() => expect(screen.getByRole('button', { name: /verify chain/i })).toBeInTheDocument());
    await act(async () => {
      await user.click(screen.getByRole('button', { name: /verify chain/i }));
    });
    await waitFor(() => expect(api.verifyLedger).toHaveBeenCalledTimes(1));
  });

  it('shows tamper report when verification fails', async () => {
    render(<LedgerPanel version={1} demoMode={false} report={mockVerifyFail} />);
    // The tamper report has a span with the full message, and the badge has a short version
    // Use getByText with a function to match the exact element
    await waitFor(() => {
      const tamperElements = screen.getAllByText(/chain broken at index 1/i);
      const tamperReportSpan = tamperElements.find(el => el.closest('.tamper-report'));
      expect(tamperReportSpan).toBeInTheDocument();
    });
    expect(screen.getByText(/Tamper detected at entry 1/i)).toBeInTheDocument();
  });
});