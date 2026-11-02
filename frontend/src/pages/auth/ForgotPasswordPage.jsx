import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { authApi } from '../../api/client';

export default function ForgotPasswordPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError('');

    try {
      await authApi.forgotPassword({ email });
      navigate(`/verify-otp?email=${encodeURIComponent(email.trim())}`);
    } catch (requestError) {
      setError(requestError.message || 'Password reset could not be requested.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <p className="eyebrow">Account recovery</p>
        <h1>Forgot password</h1>

        <form onSubmit={handleSubmit} className="form-grid">
          <label>
            Email
            <input
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="name@company.com"
            />
          </label>

          {error ? <div className="message-card error">{error}</div> : null}

          <button type="submit" className="primary-button" disabled={loading || !email.trim()}>
            {loading ? 'Sending…' : 'Send verification code'}
          </button>
        </form>

        <div className="auth-links">
          <Link to="/login">Back to login</Link>
        </div>
      </div>
    </div>
  );
}
