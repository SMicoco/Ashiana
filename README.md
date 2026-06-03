# Ashiana Sheffield Backend

A single-file Node.js + SQLite backend that:

- Receives Compliments, Comments, and Complaints submissions from the public website.
- Stores every submission in a SQLite database (one file: `ashiana.db`).
- Provides an admin login + dashboard at `/admin.html`.

Self-contained. No Google. No Netlify dependency. Owned by Ashiana.

---

## Run locally (test)

```bash
cd backend
npm install
cp .env.example .env
# edit .env if you want, then:
npm start
```

Visit `http://localhost:3000`. Default sign-in: `admin` / `changeme123`. Change the password from the dashboard immediately.

---

## Deploy to Render.com (recommended, free)

1. Create a free account at https://render.com (sign in with GitHub or email).
2. Push the `backend` folder to a new GitHub repo (private is fine).
3. In Render: New → Web Service → connect that repo. Render reads `render.yaml` and pre-fills everything.
4. Set the two environment variables Render asks you for:
   - `ADMIN_PASSWORD`: pick a strong password (this is your first login).
   - `ALLOWED_ORIGINS`: the URL of your public website, e.g. `https://www.ashianasheffield.org`. You can edit this later.
5. Click Create. Render builds, deploys, gives you a URL like `https://ashiana-backend.onrender.com`.
6. Visit `https://ashiana-backend.onrender.com/admin.html`, sign in with `admin` and your `ADMIN_PASSWORD`, change the password from the dashboard.
7. Send me the Render URL. I plug it into the website forms. Done.

The free tier sleeps after 15 minutes of idle; the first hit after that takes ~30 seconds to wake. For a feedback form this is acceptable. Upgrade to Render's $7/month tier any time to make it always-on.

---

## Deploy elsewhere

This is a standard Node.js + Express app. It runs on:

- **Fly.io** (free tier, always-on globally): `fly launch` reads the Dockerfile.
- **Railway.app** ($5/month after free credit).
- **A VPS** (DigitalOcean / Hetzner / Linode, £4-5/month): clone the repo, `npm install`, `node server.js` behind nginx + pm2.
- **Your own server** (e.g. a Raspberry Pi at the office): same as a VPS.

Anywhere that runs Node 18+ and lets you mount a directory for the SQLite file will work.

---

## Environment variables

| Var | Default | Notes |
|-----|---------|-------|
| `PORT` | 3000 | Most hosts set this for you. |
| `JWT_SECRET` | (required in production) | 32+ random characters. Used to sign admin session cookies. Generate with `openssl rand -hex 32`. |
| `ADMIN_USERNAME` | `admin` | First admin's username (only used on first run). |
| `ADMIN_PASSWORD` | `changeme123` | First admin's password (only used on first run). Change it from the dashboard after first login. |
| `DB_PATH` | `./ashiana.db` | Where SQLite stores data. On hosts with ephemeral filesystems, mount a persistent disk. |
| `ALLOWED_ORIGINS` | (empty) | Comma-separated list of allowed CORS origins. Leave empty to allow all (dev only). |

---

## API

Public (called by website):

- `POST /api/submit` -- form_type, name, email, telephone, position/stage, message, outcome, _honey

Admin (signed cookie required):

- `POST /api/admin/login`           -- username, password
- `POST /api/admin/logout`
- `GET  /api/admin/me`              -- current admin
- `POST /api/admin/change-password` -- currentPassword, newPassword
- `GET  /api/admin/submissions`     -- form_type, q, page, pageSize
- `GET  /api/admin/counts`          -- per-form totals + unread counts
- `POST /api/admin/submissions/:id/read`     -- mark read
- `POST /api/admin/submissions/:id/unread`   -- mark unread
- `POST /api/admin/submissions/:id/archive`  -- hide from list
- `DELETE /api/admin/submissions/:id`        -- permanently delete
- `GET  /api/admin/export.csv?form_type=...` -- download all rows for a form

Health:

- `GET /api/health`

---

## Backups

The whole database is one file: `ashiana.db`. To back up, copy this file. On Render, you can SSH in and `cp /data/ashiana.db /tmp/` then download. Or set up a daily cron that uploads it to S3 / Google Drive / wherever. For a small charity, downloading a CSV from the dashboard once a week is also fine.

---

## Security notes

- Admin passwords are bcrypt-hashed (cost factor 12), never stored as plaintext.
- Sessions are HTTP-only signed JWT cookies, expire after 7 days.
- CORS is allowlist-based via `ALLOWED_ORIGINS` (set this in production).
- Honeypot field silently rejects bot submissions.
- Set `NODE_ENV=production` to enable `Secure` cookies (requires HTTPS).
- The dashboard pages are static HTML with no inline secrets; safe to be public.

---

## Updating

Just `git push`. Render auto-deploys on push. To update on Fly.io: `fly deploy`. On a VPS: `git pull && npm install && pm2 restart ashiana-backend`.
