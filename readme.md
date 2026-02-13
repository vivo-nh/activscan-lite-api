# ACTIVSCAN Lite API (Render) — Tier B (Email OTP)

This is a lightweight scan API intended for deployment to Render using a Dockerfile.

## Endpoints

- `GET /health`
- `POST /otp/request`  (send OTP to email)
- `POST /otp/verify`   (verify OTP; returns `session_token`)
- `POST /scan`         (requires `session_token`; returns scan results)

## Auth

All POST endpoints require:

`Authorization: Bearer <ACTIVSCAN_API_KEY>`

Set `ACTIVSCAN_API_KEY` as a Render Environment Variable.

## Email (SMTP)

To send OTP codes you must set:

- `SMTP_HOST`
- `SMTP_PORT` (e.g. 587)
- `SMTP_USER`
- `SMTP_PASS`
- `SMTP_FROM` (e.g. "ACTIVSCAN <no-reply@yourdomain>")
- `SMTP_TLS` ("true" or "false")

## Storage

SQLite database file `data.db` is created in the container filesystem. For production you should
use a persistent disk or switch to a managed store (e.g., Redis/Postgres).

## Permission model (Tier B)

We require:
- email is OTP-verified
- registrable domain of email matches registrable domain of target (handles .co.uk etc)

Example:
- email `person@example.co.uk` may scan `example.co.uk` or `www.example.co.uk`
- email `person@agency.co.uk` may not scan `example.co.uk` (unless you later add an allowlist)
