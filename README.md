# Fortune Apex

Fortune Apex is a private, friend-run fictional game and community record system. All balances are game units; the site does not offer real-money deposits, cash-outs, or payments.

## What's included
- Static `index.html` homepage.
- PHP handlers for registration, sign-in/out, member dashboard, proposals, admin tools, contact, password changes and reset flows.
- One-time deployment wizard (`setup.php`).
- Bundled SMTP sender (`server/includes/mailer.php`); no PHPMailer folder or Composer install is needed for this edition.
- Custom error pages: `403.html`, `404.html`, `500.html`, `503.html`, mapped in `.htaccess`.
- Privacy Policy and Terms that disclose audit logging, including IP-address logging.

## Important privacy/security rule
This public repository intentionally **does not include `config.php`**. Never commit a real deployment config, database password, SMTP app password, setup key, API token, private email, or hosting-account identifier. `.gitignore` excludes the private config file.

## Deployment
1. Create a database and email account/app password with your host and email provider. Use fresh credentials; do not reuse credentials that have appeared in chat, logs, screenshots, or public commits.
2. Copy `config.example.php` to `config.php` on the server (or create it locally and upload it privately). Set your own HTTPS `base_url`, exact database host/name/user, database password, SMTP details and administrator notification address.
3. Replace the placeholder `setup_key` with a new random value of at least 32 characters. For example, on a machine with PHP installed: `php -r "echo bin2hex(random_bytes(32)), PHP_EOL;"`. Do not leave the example value in place.
4. Upload the repository files into the website document root, preserving `assets/` and `server/`. Keep `config.php` outside public source control. The included `.htaccess` denies direct web access to configuration and deployment notes; confirm your host supports those access-control directives.
5. Open your HTTPS site root to verify that the static homepage loads, then visit `/setup.php`. Enter your private setup key and follow the database/SMTP test wizard. The wizard saves credentials only after its connection checks pass.
6. Complete the first Owner-account setup, sign in and verify the admin panel. Add any further administrator later through the Owner-only Master Admin panel.
7. Test password recovery using an account whose mailbox you control. Check the hosting/PHP error log if database or email delivery fails.
8. After the Owner account is created and verified, delete `setup.php` from the server. Never leave an installer public after installation.

## Configuration and mail
- SMTP defaults shown in the example use `smtp.gmail.com`, port `587`, STARTTLS; replace the example username and sender/notification addresses with accounts you control.
- Use a newly generated app password if using Gmail. Never commit it to this repo.
- This repository was not deployed from the build environment. A local syntax check does not prove database connectivity, provider restrictions, HTTPS setup or live email delivery.

## Privacy and audit logging
The application writes IP addresses into audit events through the server-provided remote address, and displays the latest 100 entries in the admin interface. The current app has no automatic audit-log expiry schedule. Review `privacy.html` and `terms.html` against actual hosting practices before public launch.

## Error pages
The repo includes general themed `403`, `404`, `500`, and `503` HTML pages. These are repository versions; if you have separately customised error pages in your hosting panel, compare and copy those changes into the repo as needed.

## Security verification notes
Static checks cannot replace live testing or a professional security review.
