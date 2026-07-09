# Game Night Organizer

Game Night Organizer is a web app for running recurring private game nights with organizer accounts, shared invite links, SMS invite waves, RSVP tracking, optional seat assignment, standby management, push notifications, and roster display.

## Current Model
- Web-only app
- Main public domain: `gamenightorganizer.app`
- App-managed SMS through LogicV for neutral invite/reply workflows
- SMS wording must stay neutral: no gambling terms, no game type, no game title, and no branded URL containing restricted wording
- SMS links require `SMS_PUBLIC_BASE_URL` to point at a neutral domain
- Invitee identity is organizer-scoped and primarily based on phone number
- Browser invitee tokens are used to prefill known invitees from SMS links and returning visits
- Web Push is available for organizers and invitees when the browser/platform supports it

## Current Features
- Organizer accounts with dashboard
- Authenticator-app MFA (TOTP)
- Game creation with title, location, date, time, player count, optional multiple-table mode, and optional seat assignment
- Organizer invitee directory at `/invitees`
- Reusable invite lists at `/invitee-lists`
- Neutral SMS invites from game distribution lists, with `IN`, `OUT`, `LATE`, and `STOP` reply handling
- Delayed cancellation SMS notices with a 2-minute grace period
- Seat assignment SMS notices when seat assignment is enabled
- Game page for adding players, editing RSVPs, standby, seat assignment, and co-organizers
- Invitee RSVP page with `IN`, `OUT`, and `LATE`
- Host roster page for signage/display use
- Admin panel for organizer management

## Quick Start
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export SESSION_SECRET="change-me"
uvicorn app:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000`.

## Environment
- `SESSION_SECRET`
- `SESSION_SECURE`
- `APP_BASE_URL`
- `INBOUND_SMS_WEBHOOK_TOKEN`
- `LOGICV_SMS_ENDPOINT` optional override
- `SMS_PUBLIC_BASE_URL` optional neutral SMS link domain; if unset and the app domain contains restricted wording, SMS omits links
- Web Push VAPID variables if push notifications are enabled

## SMS Behavior
- Invite SMS: neutral invite, date/time, `IN/OUT/LATE`, optional neutral link, STOP line
- Cancellation SMS: queued 2 minutes after cancellation; skipped if the game is reopened before the delay expires
- Seat SMS: sent only when seat assignment is enabled and a seat is newly assigned or changed
- STOP replies are recorded in `sms_opt_outs` and block future outbound SMS to that phone

## Security
- Argon2 password hashing
- CSRF protection
- Authenticator-app MFA (TOTP)
- Trusted-device support for organizer login
- Parameterized SQL queries
- Authenticated inbound SMS webhook using `X-Webhook-Token`

## Identity Model
- Organizer invitees are stored per organizer
- Phone number is the main invitee identity key inside the app
- Browser invitee tokens help prefill name/phone on returning visits and SMS invite links
- Old game rows keep their own display name history

## Production Notes
- Recommended behind Caddy or Nginx with TLS
- SQLite database file: the legacy app database in existing deployments
- Keep `SESSION_SECRET` and webhook tokens strong and private
- Set `APP_BASE_URL` to the public domain
- Current deployment layout in this environment:
  - git repo and live runtime are separate directories
  - service uses the legacy app systemd unit name
  - deployment is file-copy based

## Main Paths
- `/register`
- `/login`
- `/dashboard`
- `/games/new`
- `/invitees`
- `/invitee-lists`
- `/admin`

## Repo Layout
- `app.py`: FastAPI application and main logic
- `templates/`: Jinja templates
- `static/`: stylesheets and assets

## License
MIT
