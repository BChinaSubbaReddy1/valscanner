# Frontend Architecture

The frontend is a Vite + React 18 application using JavaScript and JSX only. The project separates concerns into `api`, `auth`, `components`, `layouts`, `pages`, `routes`, `styles`, and `utils` directories.

## Core flow

- `src/api/client.js` centralizes all REST requests, base URL handling, bearer-token injection, JSON serialization, and standard error parsing.
- `src/auth/AuthContext.jsx` stores the authenticated session, synchronizes it to browser storage, and exposes login/logout helpers to the rest of the app.
- `src/routes/ProtectedRoute.jsx` guards routes using backend-derived roles and user identity rather than hidden UI state alone.
- `src/layouts/AppLayout.jsx` renders a role-aware navigation shell and shared authenticated layout.

## Role model

Supported roles are:

- `SUPER_ADMIN`
- `ADMIN`
- `SECURITY_ANALYST`

The effective role list is derived from API response data. The frontend does not allow users to self-assign a role at registration.

## API configuration

Set the backend URL in a local `.env` file:

```bash
VITE_API_BASE_URL=http://localhost:8080
```

The client uses this value as the API base and injects the bearer token from local storage when a session exists.

## Security patterns

- Protected routes require an authenticated session.
- Role checks happen from the authenticated user object returned by the backend.
- `401 Unauthorized` clears the browser session and emits an authentication-expired event.
- `403 Forbidden` surfaces the backend error message as a user-facing authorization message.
