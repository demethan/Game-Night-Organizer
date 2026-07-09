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
- Enter title, location, game type, date, time, and player count
- Date defaults to today
- Your organizer row is added as `HOST`
- Turn on `Multiple Table Mode` only when the game needs table groups and co-organizers
- Turn `Seat Assignment` off for games that do not need seats
- If seat assignment is off, no automatic seats, manual seat button, or seat SMS notices are used

### 5. Share the Invite
- Open the game page
- Use `Copy Invite Text` for manual sharing
- Use `Invites` to send neutral SMS invites to one or more distribution lists
- SMS text does not include game type, game title, gambling wording, or restricted branded wording
- SMS links use the neutral app domain when configured
- Invitees can reply by SMS with `IN`, `OUT`, or `LATE`
- `STOP` opts the phone number out of future app SMS

### 6. Manage the Game
- Add players manually
- Edit names, phone numbers, and RSVP status
- Promote standby players
- Use `Assign Seats Now` only when seat assignment is enabled
- Open the roster display page for game-time signage

### 7. Cancellation
- Cancelling a game updates the app immediately
- Push cancellation notices are immediate
- SMS cancellation notices wait 2 minutes before sending
- Reopening the game during the 2-minute delay cancels the pending SMS
- Cancellation SMS says: `Hi Name, the event is cancelled. Reply STOP to stop messages.`

### 8. Seat Notices
- Seat notices are only sent when `Seat Assignment` is on
- Multi-table SMS wording: `Hi Name, you are assigned to Table A, seat 1.`
- Single-table SMS wording: `Hi Name, you are assigned to seat 1.`
- Seat notices include the STOP line

### 9. Invitee RSVP Flow
- Invitees open the shared game link
- SMS invite links can prefill known name/phone using an invitee token
- Invitees enter name and optionally phone number if not already known
- They can respond `IN`, `OUT`, or `LATE` on the web page or by SMS after receiving an app SMS invite
- They can return later and change their status

### 10. Identity Behavior
- The app does not verify phone numbers by SMS
- The browser remembers the invitee when possible
- If the browser is new or storage was cleared, the invitee may need to re-enter their phone number
- Phone number remains the main identity key for matching invitees
- Old games keep their original display names even if the invitee directory changes later

### 11. Push Notifications
- Organizers and invitees can enable push where supported
- iPhone push requires adding the site to the Home Screen and enabling notifications from the installed web app
- Some iPhone content blockers can block the service worker; disable the blocker for the site if push setup fails

### 12. Roster Display
- Open the roster page from the dashboard or organizer view
- The roster is formatted for full-screen display
- It shows seats and response-time ranking when seat data exists

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
- Turn off seat assignment for casual games that do not need seating
- Use the roster page on a tablet or TV during the game

## Troubleshooting
- If the page looks stale, hard refresh
- If an invitee is not recognized, have them re-enter their phone number on the web form
- If SMS does not send, check opt-out status and `sms_outbound`
- If cancellation SMS does not appear immediately, wait for the 2-minute grace period
- If the site is unavailable, check the app systemd service
