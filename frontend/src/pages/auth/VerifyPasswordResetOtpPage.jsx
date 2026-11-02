import { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { authApi } from '../../api/client';

const RESEND_COOLDOWN_SECONDS = 60;

export default function VerifyPasswordResetOtpPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const email = searchParams.get('email') || '';
  const [otp, setOtp] = useState('');
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);
  const [cooldown, setCooldown] = useState(RESEND_COOLDOWN_SECONDS);
  const [message, setMessage] = useState(
    'If an account matches that email, a verification code will be sent.'
  );
  const [error, setError] = useState('');

  useEffect(() => {
    if (!email) {
      navigate('/forgot-password', { replace: true });
    }
  }, [email, navigate]);

  useEffect(() => {
    if (cooldown <= 0) return undefined;
    const timer = window.setTimeout(() => {
      setCooldown((value) => Math.max(0, value - 1));
    }, 1000);
    return () => window.clearTimeout(timer);
  }, [cooldown]);

  const handleVerify = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError('');
    setMessage('');
    try {
      const response = await authApi.verifyPasswordResetOtp({ email, otp });
      const resetToken = response?.data?.resetToken;
      if (!resetToken) {
        throw new Error('Verification could not be completed. Request a new code and try again.');
      }
      navigate('/reset-password', { state: { resetToken }, replace: true });
    } catch (requestError) {
      setError(requestError.message || 'The verification code is invalid or expired.');
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    setResending(true);
    setError('');
    setMessage('');
    try {
      await authApi.forgotPassword({ email });
      setMessage('If an account matches that email, a new verification code will be sent.');
      setCooldown(RESEND_COOLDOWN_SECONDS);
      setOtp('');
    } catch (requestError) {
      setError(requestError.message || 'A new verification code could not be requested.');
    } finally {
      setResending(false);
    }
  };

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <p className="eyebrow">Account recovery</p>
        <h1>Verify your email</h1>
        <p className="muted">Enter the six-digit verification code sent to {email}.</p>

        <form onSubmit={handleVerify} className="form-grid">
          <label>
            Verification code
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              maxLength={6}
              value={otp}
              onChange={(event) => setOtp(event.target.value.replace(/\D/g, '').slice(0, 6))}
              aria-label="Verification code"
            />
          </label>

          {error ? <div className="message-card error" role="alert">{error}</div> : null}
          {message ? <div className="message-card success" role="status">{message}</div> : null}

          <button type="submit" className="primary-button" disabled={loading || otp.length !== 6}>
            {loading ? 'Verifying…' : 'Verify code'}
          </button>
        </form>

        <div className="auth-links">
          <button
            type="button"
            className="text-button"
            onClick={handleResend}
            disabled={resending || cooldown > 0}
          >
            {resending ? 'Requesting…' : cooldown > 0 ? `Resend code in ${cooldown}s` : 'Resend code'}
          </button>
          <Link to="/forgot-password">Change email</Link>
        </div>
        <div className="auth-links">
          <Link to="/login">Back to login</Link>
        </div>
      </div>
    </div>
  );
}
