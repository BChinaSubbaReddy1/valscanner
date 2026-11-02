import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, vi } from 'vitest';
import App from '../App';
import { authApi } from '../api/client';

function renderAt(route) {
  window.history.pushState({}, 'Password recovery', route);
  return render(<App />);
}

describe('password reset OTP pages', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('submits the email address and advances to OTP verification', async () => {
    const request = vi.spyOn(authApi, 'forgotPassword').mockResolvedValue({
      success: true,
      message: 'If an account matches that email, a verification code will be sent.',
    });

    renderAt('/forgot-password');
    await userEvent.type(screen.getByLabelText(/^email$/i), 'person@example.com');
    await userEvent.click(screen.getByRole('button', { name: /send verification code/i }));

    expect(request).toHaveBeenCalledWith({ email: 'person@example.com' });
    expect(await screen.findByRole('heading', { name: /verify your email/i })).toBeInTheDocument();
    expect(screen.getByText(/if an account matches that email/i)).toBeInTheDocument();
  });

  it('verifies the OTP, resets the password with the returned capability, and reports errors', async () => {
    const verify = vi.spyOn(authApi, 'verifyPasswordResetOtp')
      .mockResolvedValueOnce({ data: { resetToken: 'r'.repeat(43) } })
      .mockRejectedValueOnce(new Error('Invalid or expired verification code'));
    const reset = vi.spyOn(authApi, 'resetPassword').mockResolvedValue({
      success: true,
      message: 'Password reset successfully.',
    });

    renderAt('/verify-otp?email=person%40example.com');
    await userEvent.type(screen.getByLabelText(/verification code/i), '012345');
    await userEvent.click(screen.getByRole('button', { name: /verify code/i }));

    expect(verify).toHaveBeenCalledWith({ email: 'person@example.com', otp: '012345' });
    expect(await screen.findByRole('heading', { name: /reset password/i })).toBeInTheDocument();
    const newPassword = screen.getByLabelText(/new password/i);
    const confirmPassword = screen.getByLabelText(/confirm password/i);
    await userEvent.type(newPassword, 'Pass123');
    await userEvent.type(confirmPassword, 'Pass123');
    expect(screen.getByText('Password must be at least 8 characters long.')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /update password/i }));
    expect(reset).not.toHaveBeenCalled();

    await userEvent.clear(newPassword);
    await userEvent.clear(confirmPassword);
    await userEvent.type(newPassword, 'Pass1234');
    await userEvent.type(confirmPassword, 'Pass1234');
    await userEvent.click(screen.getByRole('button', { name: /update password/i }));

    await waitFor(() => {
      expect(reset).toHaveBeenCalledWith({
        token: 'r'.repeat(43),
        password: 'Pass1234',
      });
    });
    expect(await screen.findByText(/changed successfully/i)).toBeInTheDocument();

    window.history.pushState({}, 'Password recovery', '/verify-otp?email=person%40example.com');
    fireEvent.popState(window);
    await userEvent.type(screen.getByLabelText(/verification code/i), '999999');
    await userEvent.click(screen.getByRole('button', { name: /verify code/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid or expired verification code');
  });

  it('shows a visible resend cooldown and keeps resend disabled during the cooldown', async () => {
    vi.useFakeTimers();
    const request = vi.spyOn(authApi, 'forgotPassword').mockResolvedValue({ success: true });

    renderAt('/verify-otp?email=person%40example.com');
    const resend = screen.getByRole('button', { name: /resend code in 60s/i });
    expect(resend).toBeDisabled();
    expect(request).not.toHaveBeenCalled();

    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(screen.getByRole('button', { name: /resend code in 59s/i })).toBeDisabled();
    expect(request).not.toHaveBeenCalled();
  });
});
