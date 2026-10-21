# Scanner Frontend

This project is a React + Vite frontend for the Automated Web Application Vulnerability Scanner.

## Prerequisites

- Node.js 18 or later
- npm

## Install dependencies

```powershell
cd C:\Users\bsubb\OneDrive\Documents\VsCode\frontend
npm install
```

## Start the development server

```powershell
cd C:\Users\bsubb\OneDrive\Documents\VsCode\frontend
npm run dev -- --host 0.0.0.0
```

## Run tests

```powershell
cd C:\Users\bsubb\OneDrive\Documents\VsCode\frontend
npm test
```

## Environment configuration

Create a `.env` file based on `.env.example`:

```powershell
Copy-Item .env.example .env
```

Then edit the value to match your backend:

```text
VITE_API_BASE_URL=http://localhost:8080
```
