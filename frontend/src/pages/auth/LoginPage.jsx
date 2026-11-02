import { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../../auth/useAuth';

export default function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [form, setForm] = useState({ identifier: '', password: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleChange = (event) => {
    const { name, value } = event.target;
    setForm((current) => ({ ...current, [name]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();

    if (!form.identifier.trim() || !form.password.trim()) {
      setError('Both email and password are required.');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const response = await login({
        email: form.identifier.trim(),
        password: form.password,
      });
      const challenge = response?.data;
      if (!challenge?.challengeToken || !challenge?.expiresAt) {
        throw new Error('Login verification could not be started. Please try again.');
      }
      navigate('/verify-login-otp', {
        replace: true,
        state: {
          ...challenge,
          redirectTo: location.state?.from || '/',
        },
      });
    } catch (requestError) {
      setError(requestError.message || 'Unable to sign in. Please verify your credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <p className="eyebrow">Security access</p>
        <h1>Sign in</h1>
        <p className="muted">Authenticate to continue to the scanner console.</p>

        <form onSubmit={handleSubmit} className="form-grid" noValidate>
          <label>
            Email
            <input
              type="text"
              name="identifier"
              value={form.identifier}
              onChange={handleChange}
              placeholder="name@company.com"
              aria-label="Email"
            />
          </label>

          <label>
            Password
            <input
              type="password"
              name="password"
              value={form.password}
              onChange={handleChange}
              placeholder="Enter your password"
              aria-label="Password"
            />
          </label>

          {location.state?.logoutError ? (
            <div className="message-card error">{location.state.logoutError} You have been signed out locally.</div>
          ) : null}

          {error ? <div className="message-card error">{error}</div> : null}

          <button type="submit" className="primary-button" disabled={loading}>
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        <div className="auth-links">
          <Link to="/register">Create account</Link>
          <Link to="/forgot-password">Forgot password?</Link>
        </div>
      </div>
    </div>
  );
}
