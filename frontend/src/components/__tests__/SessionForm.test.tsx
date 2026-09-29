import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import SessionForm from '../SessionForm';

describe('SessionForm', () => {
  const mockOnRun = vi.fn();
  const mockOnResubmit = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders all form fields', () => {
    render(<SessionForm busy={false} onRun={mockOnRun} />);

    expect(screen.getByLabelText(/scenario/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/attack strength/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/rounds/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/backend/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/seed/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /run session/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /resubmit last/i })).toBeInTheDocument();
  });

  it('disables theta slider for legitimate hypothesis', () => {
    render(<SessionForm busy={false} onRun={mockOnRun} />);

    const hypothesisSelect = screen.getByLabelText(/scenario/i);
    fireEvent.change(hypothesisSelect, { target: { value: 'legitimate' } });

    const thetaSlider = screen.getByRole('slider');
    expect(thetaSlider).toBeDisabled();
  });

  it('disables theta slider for impersonation hypothesis', () => {
    render(<SessionForm busy={false} onRun={mockOnRun} />);

    const hypothesisSelect = screen.getByLabelText(/scenario/i);
    fireEvent.change(hypothesisSelect, { target: { value: 'impersonation' } });

    const thetaSlider = screen.getByRole('slider');
    expect(thetaSlider).toBeDisabled();
  });

  it('enables theta slider for forgery hypothesis', () => {
    render(<SessionForm busy={false} onRun={mockOnRun} />);

    const hypothesisSelect = screen.getByLabelText(/scenario/i);
    fireEvent.change(hypothesisSelect, { target: { value: 'forgery' } });

    const thetaSlider = screen.getByRole('slider');
    expect(thetaSlider).not.toBeDisabled();
  });

  it('calls onRun with correct data on submit', async () => {
    const user = userEvent.setup();
    render(<SessionForm busy={false} onRun={mockOnRun} />);

    const hypothesisSelect = screen.getByLabelText(/scenario/i);
    await user.selectOptions(hypothesisSelect, 'forgery');

    const roundsInput = screen.getByLabelText(/rounds/i);
    await user.clear(roundsInput);
    await user.type(roundsInput, '800');

    const backendSelect = screen.getByLabelText(/backend/i);
    await user.selectOptions(backendSelect, 'qiskit');

    const seedInput = screen.getByLabelText(/seed/i);
    await user.type(seedInput, '12345');

    const submitButton = screen.getByRole('button', { name: /run session/i });
    await user.click(submitButton);

    expect(mockOnRun).toHaveBeenCalledWith(
      expect.objectContaining({
        hypothesis: 'forgery',
        n_rounds: 800,
        backend: 'qiskit',
        seed: 12345,
      })
    );
  });

  it('disables form when busy', () => {
    render(<SessionForm busy={true} onRun={mockOnRun} />);

    const submitButton = screen.getByRole('button', { name: /running/i });
    expect(submitButton).toBeDisabled();
  });

  it('calls onResubmit when Resubmit last is clicked', async () => {
    const user = userEvent.setup();
    render(<SessionForm busy={false} onRun={mockOnRun} onResubmit={mockOnResubmit} />);

    const resubmitButton = screen.getByRole('button', { name: /resubmit last/i });
    await user.click(resubmitButton);

    expect(mockOnResubmit).toHaveBeenCalledTimes(1);
  });

  it('disables Resubmit when no onResubmit prop', () => {
    render(<SessionForm busy={false} onRun={mockOnRun} />);

    const resubmitButton = screen.getByRole('button', { name: /resubmit last/i });
    expect(resubmitButton).toBeDisabled();
  });
});