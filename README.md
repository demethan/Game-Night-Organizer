# Poker Invite Manager

Poker Invite Manager is a mobile-first web app for running recurring poker games with organizer accounts, invitee identity, RSVP tracking, standby management, seat assignment, and SMS workflows.

## Current Features
- Organizer accounts with dashboard and admin-managed access
- Game creation with title, location, date, time, total seats, and optional multiple-table mode
- Reusable invitee distribution lists
- Send invite SMS immediately when creating a game from one or more saved lists
- Resend game invites later from additional lists on the organizer game page
- Dedicated organizer announcement page for mobile-friendly broadcast texting
- Invitee RSVP via web link or SMS
- RSVP states: `IN`, `OUT`, `LATE`, `STANDBY`
- Natural-language SMS parsing such as `I'm in`, `can't make it`, or `I'll be late but I'm in`
- Invitee phone verification and browser identity binding
- Organizer/co-organizer management for multiple-table games
- Manual seat assignment trigger, plus automatic single-table assignment when the game fills
- Organizer visibility into the latest inbound SMS reply per invitee
- Standby tracking and promotion
- Admin panel for user management

## Quick Start
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export SESSION_SECRET="change-me"
uvicorn app:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000`

## Environment Notes
Common environment variables used by the app:
- `SESSION_SECRET`
- `SESSION_SECURE`
- `APP_BASE_URL`
- `SMS_SEND_ENABLED`
- `TWILIO_ACCOUNT_SID`
- `TWILIO_AUTH_TOKEN`
- `TWILIO_FROM_NUMBER`
- `TWILIO_MESSAGING_SERVICE_SID`
- `TWILIO_INBOUND_TOKEN`

## SMS Behavior
- Invitees can reply by SMS using strict commands:
  - `IN`
  - `OUT`
  - `LATE 7:30PM`
  - `STANDBY`
  - `STATUS`
  - `VERIFY`
  - `MENU`
- The parser also recognizes conversational replies such as:
  - `I'm in`
  - `can't make it`
  - `running late 7:45pm`
  - `yes`
  - `no`
- Unknown/jibberish SMS replies are rate-limited to reduce cost

## Invitee Identity
- Phone number is the primary invitee identity
- Invitee browser tokens are used to recognize returning users on the same browser
- `VERIFY` by SMS sends an invitee verification link
- Verified phones are treated as globally verified for invitee flows

## Security
- Argon2 password hashing
- CSRF protection for POST routes
- MFA with SMS or TOTP
- Trusted-device flow for MFA bypass on previously verified devices
- Parameterized SQL queries
- SMS rate limiting and duplicate-send controls

## Production Notes
- Recommended behind Caddy or Nginx with TLS
- SQLite database file: `poker.db`
- Keep `SESSION_SECRET` strong and private
- Set `APP_BASE_URL` to the public domain

## Main Paths
- `/register`
- `/login`
- `/dashboard`
- `/games/new`
- `/invitee-lists`
- `/admin`

## Repo Layout
- `app.py`: FastAPI application and main logic
- `templates/`: Jinja templates
- `static/`: stylesheets, JS assets, icons

## License
MIT
