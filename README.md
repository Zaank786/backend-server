# Secure Admin + Login Backend v3

This package is matched to the updated `admin.html`.

## Railway Variables (required in production)
- `JWT_SECRET` = long random secret
- `ADMIN_USERNAME` = your admin username
- `ADMIN_PASSWORD` = your admin password
- `DATA_SECRET_PIN` = separate security PIN for User Data
- `ALLOWED_ORIGINS` = exact URL(s) hosting admin.html/login page, comma separated
- `NODE_ENV=production`

Optional:
- `USER_USERNAME` / `USER_PASSWORD` creates one configured test user on first login.

Do NOT put these values in GitHub.

## User Data behavior
The Admin Panel has a User Data button. It asks for the Security PIN, then calls `/api/admin/user-data` and shows username/email/status/created time/last login/last activity/profile picture.

Passwords are deliberately NOT stored in readable form and are never returned to the Admin Panel. They are salted scrypt hashes. Admin can reset a password without seeing the old password.

## Persistence
Runtime data is stored under `data/database.json` and media under `uploads/`. Railway's local filesystem can be ephemeral across redeploys, so durable production storage should eventually be moved to a managed database/object storage.
