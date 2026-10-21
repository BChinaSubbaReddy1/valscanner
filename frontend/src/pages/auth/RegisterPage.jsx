import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../auth/useAuth';

export default function RegisterPage() {
  const { register } = useAuth();
  const [form, setForm] = useState({
    firstName: '',
    lastName: '',
    email: '',
    password: '',
    confirmPassword: '',
    role: 'SECURITY_ANALYST',
    organizationName: '',
    organizationContactEmail: '',
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  const handleChange = (event) => {
    setForm((current) => ({ ...current, [event.target.name]: event.target.value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();

    if (!form.firstName.trim() || !form.lastName.trim() || !form.email.trim() || !form.password.trim()) {
      setError('First name, last name, email, and password are required.');
      return;
    }

    if (form.password.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }

    if (form.password.length > 128) {
      setError('Password cannot exceed 128 characters.');
      return;
    }

    if (form.password !== form.confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    if (!['ADMIN', 'SECURITY_ANALYST'].includes(form.role)) {
      setError('Select a supported registration role.');
      return;
    }

    if (!form.organizationName.trim()) {
      setError('Organization name is required.');
      return;
    }

    setLoading(true);
    setError('');
    setSuccess('');

    try {
      const payload = {
        firstName: form.firstName.trim(),
        lastName: form.lastName.trim(),
        email: form.email.trim(),
        password: form.password,
        role: form.role,
      };

      payload.organizationName = form.organizationName.trim();
      if (form.role === 'ADMIN' && form.organizationContactEmail.trim()) {
        payload.organizationContactEmail = form.organizationContactEmail.trim();
      }

      await register(payload);
      setSuccess(form.role === 'ADMIN'
        ? 'Organization Admin request submitted successfully. Your organization registration is pending Super Admin approval.'
        : 'Organization membership request submitted successfully. Your membership is pending Organization Admin approval.');
    } catch (requestError) {
      setError(requestError.message || 'Registration could not be completed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <p className="eyebrow">Create access</p>
        <h1>Register</h1>
        <p className="muted">
          Organization Admin requests create a new organization for Super Admin review. Security Analyst
          requests are associated with an approved organization and remain pending for its Organization Admin.
        </p>

        <form onSubmit={handleSubmit} className="form-grid" noValidate>
          <label>
            First name
            <input
              name="firstName"
              value={form.firstName}
              onChange={handleChange}
              autoComplete="given-name"
              maxLength={150}
            />
          </label>

          <label>
            Last name
            <input
              name="lastName"
              value={form.lastName}
              onChange={handleChange}
              autoComplete="family-name"
              maxLength={150}
            />
          </label>

          <label>
            Email
            <input name="email" type="email" value={form.email} onChange={handleChange} autoComplete="email" />
          </label>

          <label>
            Password
            <input name="password" type="password" value={form.password} onChange={handleChange} autoComplete="new-password" />
          </label>

          <label>
            Confirm password
            <input name="confirmPassword" type="password" value={form.confirmPassword} onChange={handleChange} autoComplete="new-password" />
          </label>

          <label>
            Requested role
            <select name="role" value={form.role} onChange={handleChange}>
              <option value="SECURITY_ANALYST">Security Analyst</option>
              <option value="ADMIN">Organization Admin</option>
            </select>
          </label>

          <label>
            Organization name
            <input
              name="organizationName"
              value={form.organizationName}
              onChange={handleChange}
              autoComplete="organization"
              maxLength={150}
            />
          </label>

          {form.role === 'ADMIN' ? (
            <label>
              Organization contact email
              <input
                name="organizationContactEmail"
                type="email"
                value={form.organizationContactEmail}
                onChange={handleChange}
                autoComplete="email"
                maxLength={255}
              />
            </label>
          ) : null}

          {error ? <div className="message-card error">{error}</div> : null}
          {success ? <div className="message-card success">{success}</div> : null}

          <button type="submit" className="primary-button" disabled={loading || Boolean(success)}>
            {loading ? 'Submitting…' : 'Register'}
          </button>
        </form>

        <div className="auth-links">
          <Link to="/login">Back to sign in</Link>
        </div>
      </div>
    </div>
  );
}
