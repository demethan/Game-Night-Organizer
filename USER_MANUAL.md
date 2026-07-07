# User Manual - Game Night Organizer

## Organizer Guide

### 1. Account
- Register at `/register`
- Account creation requires accepting the private, non-commercial use policy
- Organizers must invite only people who meet the personal or family relationship criteria
- Commercial or for-profit games are not permitted
- Log in at `/login`
- MFA is authenticator-app only
- Trusted devices can skip repeated MFA prompts

### 2. Invitees
- Open `/invitees`
- Add, edit, search, or delete invitees
- Invitees are scoped to your organizer account
- Phone number is the main identity key used by the app

### 3. Invite Lists
- Open `/invitee-lists`
- Create reusable lists
- Add members from your invitee directory or manually
- Use lists as a planning tool when building games

### 4. Create a Game
- Open `/games/new`
- Enter title, location, date, time, and seat count
- Date defaults to today
- Your organizer row is added as `HOST`
- If multiple-table mode is enabled, co-organizers can be added later

### 5. Share the Invite
- Open the game page
- Use `Copy Invite Text` for manual sharing
- Use `Invites` to send neutral SMS invites to one or more distribution lists
- SMS text does not include game type, game title, gambling wording, or the current branded URL
- SMS links require a neutral `SMS_PUBLIC_BASE_URL`; otherwise invitees reply by SMS with `IN`, `OUT`, or `LATE`
- `STOP` opts the phone number out of future app SMS

### 6. Manage the Game
- Add players manually
- Edit names, phone numbers, and RSVP status
- Promote standby players
- Assign seats manually when you are ready
- Open the roster display page for game-time signage

### 7. Invitee RSVP Flow
- Invitees open the shared game link
- They enter name and optionally phone number
- Phone number helps the app recognize them on later visits
- They can respond `IN`, `OUT`, or `LATE` on the web page or by SMS after receiving an app SMS invite
- They can return later and change their status

### 8. Identity Behavior
- The app does not verify phone numbers by SMS
- The browser remembers the invitee when possible
- If the browser is new or storage was cleared, the invitee may need to re-enter their phone number
- Old games keep their original display names even if the invitee directory changes later

### 9. Roster Display
- Open the roster page from the dashboard or organizer view
- The roster is formatted for full-screen display
- It shows seats and response-time ranking

## Admin Guide

### 1. Admin Access
- Log in with an admin-enabled account
- Open `/admin`

### 2. Organizer Management
- Enable or disable organizer access
- Reset passwords
- Delete organizer accounts when needed

## Tips
- Treat the invitee directory as the organizer source of truth
- Keep phone numbers accurate to avoid duplicate invitees
- Use invite lists to send staged SMS invite waves
- Use the roster page on a tablet or TV during the game

## Troubleshooting
- If the page looks stale, hard refresh
- If an invitee is not recognized, have them re-enter their phone number on the web form
- If the site is unavailable, check `poker-app.service`
