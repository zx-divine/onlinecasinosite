# Fortune Apex — Security 2.0

Fortune Apex is a PHP + MySQL community game and record-keeping site. All balances are fictional game units. This repository contains application source and a safe configuration template; it is not a live-verified deployment.

## What is included

- Static public homepage (`index.html`) and shared assets (`assets/`).
- PHP routes for login, logout, player registration, proposals, admin console, contact, password changes and password recovery.
- Protected server-side configuration structure under `database/`; the private `database/config.php` is intentionally excluded.
- One-time installer (`setup.php`) for database/mail configuration and initial Owner setup. Remove it immediately after initial setup succeeds.
- Approved custom HTTP error documents: `400.html`, `401.html`, `403.html`, `404.html`, `500.html`, `503.html`. The root `.htaccess` references them and does not alter their content.
- Privacy policy and community terms.

## Requirements

- Apache with `.htaccess` support (the current target uses Apache-style configuration).
- PHP 8.1+ with PDO MySQL and OpenSSL/TLS support.
- A MySQL database and an SMTP account if email notifications/password recovery are to be used.

## First deployment

1. Create a database and SMTP app password with your providers. Use fresh credentials.
2. Copy `database/config.example.php` to `database/config.php` on the server, or upload a private deployment config. Never commit `database/config.php`.
3. Set `base_url` to your HTTPS deployment URL; enter the exact database host/name/user and fresh DB/SMTP passwords. Replace the example setup key with a long random value before a new installation.
4. Upload the project contents into the document root, preserving folders. Confirm `/database/` is denied by the server before entering live credentials.
5. Open the HTTPS homepage. Use `/setup.php` to test the database and email connection, then create the initial Owner account.
6. Verify sign-in, registration, logout, contact, password recovery, admin authorization, and the six custom error routes.
7. Delete `/setup.php` immediately after initial Owner setup. Do not leave the installer online.

## Configuration notes

The root `.htaccess` contains error-page mapping, defensive headers and sensitive-file blocking. This public copy intentionally omits a host-specific HTTPS redirect. Add a redirect that matches only the actual deployment hostname in your private hosting copy; do not reflect arbitrary `Host` values. If migrating to Nginx, `.htaccess` is ignored and equivalent rules must be placed in the server block.

The provided custom error pages are treated as locked files. Change only their server mapping if needed; do not redesign or rewrite the pages without explicit approval.

## Privacy and limitations

The application audit log records IP addresses. The current code does not automatically expire audit records on a fixed schedule; operators should decide and implement a retention policy. No upload handler or payment integration is included.

Local PHP/JavaScript syntax checks do not prove database connectivity, SMTP deliverability, Apache module support or production security. Test these on the target host before treating the site as production-ready.