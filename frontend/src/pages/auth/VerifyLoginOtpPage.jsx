import { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../../auth/useAuth';
import { authApi } from '../../api/client';

function secondsUntil(timestamp) {
  const remaining = Math.ceil((new Date(timestamp).getTime() - Date.now()) / 1000);
  return Math.max(0, Number.isFinite(remaining) ? remaining : 0);
}

export default function VerifyLoginOtpPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const { verifyLoginOtp } = useAuth();
  const [challenge, setChallenge] = useState(location.state || null);
  const [otp, setOtp] = useState('');
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);
  const [cooldown, setCooldown] = useState(secondsUntil(location.state?.resendAvailableAt));
  const [expiresIn, setExpiresIn] = useState(secondsUntil(location.state?.expiresAt));
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (!location.state?.challengeToken) {
      navigate('/login', { replace: true });
    }
  }, [location.state, navigate]);

  useEffect(() => {
    if (cooldown <= 0 && expiresIn <= 0) return undefined;
    const updateCountdowns = () => {
      setCooldown(Math.max(0, secondsUntil(challenge?.resendAvailableAt)));
      setExpiresIn(Math.max(0, secondsUntil(challenge?.expiresAt)));
    };
    const timer = window.setTimeout(updateCountdowns, 1000);
    return () => window.clearTimeout(timer);
  }, [challenge?.expiresAt, challenge?.resendAvailableAt, cooldown, expiresIn]);

  const handleVerify = async (event) => {
    event.preventDefault();
    if (!challenge?.challengeToken || otp.length !== 6 || expiresIn <= 0) return;
    setLoading(true);
    setError('');
    try {
      await verifyLoginOtp(challenge.challengeToken, otp);
      navigate(challenge.redirectTo || '/', { replace: true });
    } catch (requestError) {
      setError(requestError.message || 'Login verification is invalid or expired.');
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    if (!challenge?.challengeToken) return;
    setResending(true);
    setError('');
    setMessage('');
    try {
      const response = await authApi.resendLoginOtp({ challengeToken: challenge.challengeToken });
      const nextChallenge = { ...challenge, ...response?.data };
      setChallenge(nextChallenge);
      navigate('/verify-login-otp', { replace: true, state: nextChallenge });
      setOtp('');
      setMessage('A new sign-in verification code has been sent.');
    } catch (requestError) {
      setError(requestError.message || 'A new verification code could not be requested.');
    } finally {
      setResending(false);
    }
  };

  if (!challenge?.challengeToken) return null;

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <p className="eyebrow">Two-step verification</p>
        <h1>Verify your sign-in</h1>
        <p className="muted">
          Enter the six-digit code sent to {challenge.maskedEmail || 'your registered email address'}.
        </p>
        <p className="muted" role="status">
          {expiresIn > 0 ? `Code expires in ${expiresIn}s.` : 'This code has expired. Request a new code.'}
        </p>

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
              aria-label="Login verification code"
            />
          </label>

          {error ? <div className="message-card error" role="alert">{error}</div> : null}
          {message ? <div className="message-card success" role="status">{message}</div> : null}

          <button type="submit" className="primary-button" disabled={loading || otp.length !== 6 || expiresIn <= 0}>
            {loading ? 'Verifying…' : 'Verify and sign in'}
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
          <Link to="/login" onClick={() => setChallenge(null)}>Back to login</Link>
        </div>
      </div>
    </div>
  );
}
