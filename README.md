# Poker Invite Manager

Poker Invite Manager is a web app for running recurring private games with organizer accounts, shared invite links, RSVP tracking, standby management, and roster display.

## Current Model
- Web-only app
- No app-managed SMS or Twilio integration
- Organizers contact players outside the app
- Shared game link for each game
- Invitee identity is based on the phone number entered in the web form
- Invitees are organizer-scoped

## Current Features
- Organizer accounts with dashboard
- Authenticator-app MFA (TOTP)
- Game creation with title, location, date, time, seats, and optional multiple-table mode
- Organizer invitee directory at `/invitees`
- Reusable invite lists at `/invitee-lists`
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

Open `http://localhost:8000`

## Environment
- `SESSION_SECRET`
- `SESSION_SECURE`
- `APP_BASE_URL`

## Security
- Argon2 password hashing
- CSRF protection
- Authenticator-app MFA (TOTP)
- Trusted-device support for organizer login
- Parameterized SQL queries

## Identity Model
- Organizer invitees are stored per organizer
- Phone number is the main invitee identity key inside the app
- Browser token is used only as a convenience on returning visits
- Old game rows keep their own display name history

## Production Notes
- Recommended behind Caddy or Nginx with TLS
- SQLite database file: `poker.db`
- Keep `SESSION_SECRET` strong and private
- Set `APP_BASE_URL` to the public domain
- Current deployment layout in this environment:
  - git repo: `/home/ubuntu/Poker-Game-Organizer`
  - live runtime: `/home/ubuntu/poker-app-next`
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
