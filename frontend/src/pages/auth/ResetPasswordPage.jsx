import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { authApi } from '../../api/client';

export default function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const [form, setForm] = useState({ password: '', confirmPassword: '' });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const token = searchParams.get('token') || '';

  const handleSubmit = async (event) => {
    event.preventDefault();

    if (!token) {
      setError('Password reset token is missing.');
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

        <form onSubmit={handleSubmit} className="form-grid">
          <label>
            New password
            <input
              type="password"
              value={form.password}
              onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
            />
          </label>

          <label>
            Confirm password
            <input
              type="password"
              value={form.confirmPassword}
              onChange={(event) => setForm((current) => ({ ...current, confirmPassword: event.target.value }))}
            />
          </label>

          {error ? <div className="message-card error">{error}</div> : null}
          {message ? <div className="message-card success">{message}</div> : null}

          <button type="submit" className="primary-button" disabled={loading}>
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
