# Members Portal — OAuth & KV-backed Auth

## Overview

Members-only area on the site, gated by Google OAuth. Members are stored in Cloudflare KV (keyed by email). Authenticated users get an HMAC-SHA256 signed JWT in an HttpOnly cookie (30-day expiry). The worker reverse-proxies `/members/*` pages from GitHub Pages.

## Architecture

```
User → /auth/login → Google OAuth → Worker validates → KV member check → Session cookie
                                                                              ↓
User → /members/* → Worker checks cookie → Proxies to wreck-d.github.io
```

- **Source of truth:** YAML files in `WRECK-d/form-submissions` repo under `members/`
- **Runtime lookup:** Cloudflare KV, keyed by `member:email:<email>`
- **Auth gateway:** Worker intercepts `/auth/*` and `/members/*` via Cloudflare Workers Routes
- **Sessions:** HMAC-SHA256 signed JWT in `__wreckd_session` HttpOnly cookie (30-day expiry)
- **Content serving:** Worker reverse-proxies `/members/*` from GitHub Pages origin

## Files Changed

| File | Change |
|------|--------|
| `worker/worker.js` | Added JWT helpers, Google OAuth flow, login page, members proxy. All existing Stripe functionality preserved. |
| `worker/wrangler.toml` | Added `MEMBERS` KV namespace binding |
| `hugo.toml` | Added "Members" nav link (weight 40) |
| `content/members/_index.md` | Members landing page content |

## Routes Added

| Route | Method | Purpose |
|-------|--------|---------|
| `/auth/login` | GET | Login page with "Sign in with Google" button |
| `/auth/logout` | GET | Clears session cookie, redirects to `/` |
| `/auth/google/start` | GET | Sets CSRF state cookie, redirects to Google OAuth |
| `/auth/google/callback` | GET | Exchanges code for token, fetches profile, checks KV, sets session JWT |
| `/members/*` | GET | Validates session cookie, proxies to `wreck-d.github.io` or redirects to login |

## OAuth Flow (Google)

1. User clicks "Sign in with Google" on `/auth/login`
2. `/auth/google/start` sets `__wreckd_oauth_state` cookie with random state, redirects to Google
3. Google redirects to `/auth/google/callback?code=...&state=...`
4. Worker verifies state matches cookie, exchanges code at `https://oauth2.googleapis.com/token`
5. Fetches profile from `https://www.googleapis.com/oauth2/v2/userinfo`
6. Looks up `member:email:<email>` in KV
7. If found + active: creates JWT, sets `__wreckd_session` cookie, redirects to `/members/`
8. If not found: shows "not a member" message on login page

## Secrets Required

| Secret | Purpose |
|--------|---------|
| `JWT_SECRET` | Signs session JWTs (generate with `openssl rand -hex 32`) |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |

## Deployment Steps

1. **Create KV namespace:**
   ```bash
   cd worker && npx wrangler kv namespace create MEMBERS
   ```
   Replace the placeholder ID in `wrangler.toml` with the actual namespace ID.

2. **Register Google OAuth app** in Google Cloud Console:
   - Redirect URI: `https://wreckd.org.nz/auth/google/callback`

3. **Set worker secrets:**
   ```bash
   npx wrangler secret put JWT_SECRET
   npx wrangler secret put GOOGLE_CLIENT_ID
   npx wrangler secret put GOOGLE_CLIENT_SECRET
   ```

4. **Seed a test member:**
   ```bash
   npx wrangler kv key put --namespace-id=<id> \
     "member:email:your@email.com" \
     '{"name":"Test User","email":"your@email.com","membership":"adult","status":"active"}'
   ```

5. **Add Workers Routes** in Cloudflare dashboard:
   - `wreckd.org.nz/auth/*` → `wreckd-form-worker`
   - `wreckd.org.nz/members/*` → `wreckd-form-worker`

6. **Deploy:**
   ```bash
   npx wrangler deploy
   ```

## Testing

1. Visit `/members/` → should redirect to `/auth/login`
2. Click "Sign in with Google" → complete Google OAuth
3. With test member email → cookie set, redirected to `/members/`
4. With non-member email → "not a member" message
5. Visit `/members/` again → works without re-auth (cookie persists)
6. Visit `/auth/logout` → cookie cleared, redirected to `/`

## Future Phases

- **Phase 2:** Add Facebook, GitHub, Strava OAuth providers. GitHub Action to sync `members/*.yml` → KV on push. Strava uses `member:strava:<athlete_id>` lookup (no email from Strava).
- **Phase 3:** Resend invitation emails via `/api/invite` endpoint.
