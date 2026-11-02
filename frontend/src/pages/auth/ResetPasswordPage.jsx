import { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { authApi } from '../../api/client';

export default function ResetPasswordPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const [form, setForm] = useState({ password: '', confirmPassword: '' });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const token = location.state?.resetToken || '';

  const handleSubmit = async (event) => {
    event.preventDefault();

    if (!token) {
      setError('Verify your email address before resetting your password.');
      return;
    }

    if (form.password.length < 8) {
      setError('');
      return;
    }

    if (form.password !== form.confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    setError('');
    setMessage('');

    try {
      await authApi.resetPassword({ token, password: form.password });
      setMessage('Your password has been changed successfully.');
      setForm({ password: '', confirmPassword: '' });
      navigate('/reset-password', { replace: true, state: null });
    } catch (requestError) {
      setError(requestError.message || 'The password reset failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <p className="eyebrow">Secure reset</p>
        <h1>Reset password</h1>
        <p className="muted">Choose a new password for your account.</p>

        <form onSubmit={handleSubmit} className="form-grid" noValidate>
          <label>
            New password
            <input
              type="password"
              minLength={8}
              maxLength={128}
              autoComplete="new-password"
              value={form.password}
              onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
              aria-invalid={form.password.length > 0 && form.password.length < 8}
              aria-describedby={form.password.length > 0 && form.password.length < 8 ? 'reset-password-error' : undefined}
            />
            {form.password.length > 0 && form.password.length < 8 ? (
              <div id="reset-password-error" className="message-card error" role="alert">
                Password must be at least 8 characters long.
              </div>
            ) : null}
          </label>

          <label>
            Confirm password
            <input
              type="password"
              minLength={8}
              maxLength={128}
              autoComplete="new-password"
              value={form.confirmPassword}
              onChange={(event) => setForm((current) => ({ ...current, confirmPassword: event.target.value }))}
            />
          </label>

          {!token && !message ? (
            <div className="message-card error" role="alert">
              Verify your email address before resetting your password.
            </div>
          ) : null}
          {error ? <div className="message-card error">{error}</div> : null}
          {message ? <div className="message-card success">{message}</div> : null}

          <button type="submit" className="primary-button" disabled={loading || !token}>
            {loading ? 'Updating…' : 'Update password'}
          </button>
        </form>

        <div className="auth-links">
          <Link to="/login">Return to sign in</Link>
        </div>
      </div>
    </div>
  );
}
