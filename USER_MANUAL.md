# User Manual — Poker Invite Manager

## Organizer Guide

### 1) Create and Access Your Account
- Open `/register` to create an organizer account
- Log in at `/login`
- If MFA is enabled on your account, complete the SMS or authenticator prompt
- If you choose to trust the device, future logins on that device may skip MFA

### 2) Build and Reuse Invite Lists
- Open `/invitee-lists`
- Create one or more reusable lists such as `Core Game`, `Standby`, or `Tournament`
- Open `Manage` on a list to:
  - add people from the invitee directory using checkboxes
  - add a person manually by name and phone number
  - remove people from that list
- These lists can be reused for future games

### 3) Create a Game
- Open `/games/new`
- Enter the title, location, date, time, and seat count
- The date defaults to today
- The form can reuse details from your previous game
- Your organizer record is added automatically as `HOST`
- You can select one or more saved invite lists during creation
- If lists are selected, invite SMS messages are sent as soon as the game is created

### 4) Manage the Game Page
- Open a game from the dashboard
- The organizer page lets you:
  - copy invite text
  - send announcements
  - add players manually
  - invite more people from saved lists
  - edit or remove players
  - manage standby
  - assign seats manually
- For multiple-table games, you can also manage co-organizers and table assignments

### 5) Send Invitations and Announcements
- `Copy Invite Text` gives you a ready-to-send invite message
- The announcement page lets you send a broadcast to filtered groups such as:
  - `IN`
  - `OUT`
  - `LATE`
  - `TABLE`
  - `STANDBY`
- Broadcast messages support variables such as:
  - `{{name}}`
  - `{{status}}`
  - `{{seat}}`
  - `{{table}}`
  - `{{late_eta}}`
  - `{{game}}`
  - `{{game_date}}`
  - `{{game_time}}`
  - `{{location}}`
  - `{{rsvp_link}}`

### 6) Track RSVP Activity
- Invitees can reply from the web page or by SMS
- Supported SMS commands include:
  - `IN`
  - `OUT`
  - `LATE 7:30PM`
  - `STANDBY`
  - `STATUS`
  - `VERIFY`
  - `MENU`
- The app also understands conversational replies such as:
  - `I'm in`
  - `can't make it`
  - `I'll be late but I'm in`
  - `yes`
  - `no`
- On the organizer page, an `SMS` button appears when a player last replied by text
- Clicking that button shows the latest actual inbound SMS message and timestamp

### 7) Seat Assignment
- Seats are not assigned automatically just because enough players responded
- Use `Assign Seats Now` when you want seat assignment to start
- For single-table games, once the game becomes full, seats continue to fill automatically
- Roster pages can be used as at-table signage and display response-time rankings

### 8) Standby and Full Games
- If the game is full, additional players can be added to standby
- Standby order is tracked by response order
- When seats open up, standby players can be promoted into the game

### 9) Dashboard
- The dashboard shows your active and recent games
- Use it to open a game, open the roster page, or create a new one
- The dashboard no longer shows raw internal code or link pills; it focuses on the main actions

---

## Invitee Guide

### 1) Open the Invite
- Tap the invite link you received by text or from the organizer
- The invite page shows the game details and current RSVP counts

### 2) Respond on the Web
- Enter or confirm your name
- Choose `IN`, `OUT`, or `LATE`
- If you choose `LATE`, enter your expected arrival time
- You can return later and change your status

### 3) Respond by SMS
- Reply directly to the invite text
- Simple replies such as `IN`, `OUT`, or `LATE 7:15PM` work
- Natural language such as `I'm in` or `can't make it` is also accepted

### 4) Verify Your Phone
- The app may ask you to verify your phone number
- You can verify from the web flow or by texting `VERIFY`
- `VERIFY` sends a verification link back to that phone
- Opening the link marks the phone as verified for invitee identity
- The browser used to open the link gets an invitee identity token so the app can recognize you later

### 5) Returning to a Game
- If you revisit a game from the same verified browser, the app tries to recognize you automatically
- If you already responded, the page can show your current status and the roster view
- `IN` and `OUT` sections on the invitee page are clickable and can show the player lists

### 6) Full Games and Standby
- If the game is full, you may be offered a standby option
- Standby keeps your place in order and can move you in later if space opens up

---

## Admin Guide

### 1) Access Admin
- Log in with an admin-enabled account
- Open `/admin`

### 2) Manage Organizer Accounts
- Enable or disable organizer access
- Reset organizer passwords
- Delete organizer accounts when necessary

---

## Tips
- Keep organizer phone numbers current if you rely on MFA by SMS
- Invitee phone number is the primary identity key for RSVP matching
- Reusable invite lists work well for phased invites:
  - invite `List A` when the game opens
  - invite `List B` later if more players are needed
- Use the roster page on a TV or tablet during the game for a signage-style display

## Troubleshooting
- If a page looks stale after a design change, hard refresh the browser
- If an invitee says they cannot be recognized, ask them to text `VERIFY` from their phone and open the returned link on the browser they plan to use
- If SMS replies are not updating the game, verify the phone number on the RSVP row matches the sender's number
- If the site is unavailable, check `poker-app.service`
