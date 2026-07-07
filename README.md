# Game Night Organizer

Game Night Organizer is a web app for running recurring private game nights with organizer accounts, shared invite links, SMS invite waves, RSVP tracking, standby management, and roster display.

## Current Model
- Web-only app
- App-managed SMS through LogicV for neutral invite/reply workflows
- SMS wording must stay neutral: no gambling terms, no game type, and no branded URL containing restricted wording
- Shared game link for each game; SMS links require `SMS_PUBLIC_BASE_URL` to point at a neutral domain
- Invitee identity is based on the phone number entered in the web form
- Invitees are organizer-scoped

## Current Features
- Organizer accounts with dashboard
- Authenticator-app MFA (TOTP)
- Game creation with title, location, date, time, seats, and optional multiple-table mode
- Organizer invitee directory at `/invitees`
- Reusable invite lists at `/invitee-lists`
- Neutral SMS invites from game distribution lists, with `IN`, `OUT`, `LATE`, and `STOP` reply handling
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
- `INBOUND_SMS_WEBHOOK_TOKEN`
- `LOGICV_SMS_ENDPOINT` optional override
- `SMS_PUBLIC_BASE_URL` optional neutral SMS link domain; if unset and the app domain contains restricted wording, SMS omits links

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
- SQLite database file: `poker.db` in existing deployments
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
