# Manual acceptance checklist — Desktop executable and Website

> The short, ordered list for the current round, with a result sheet, is `docs/owner_manual_test_checklist.md`. This longer checklist is the full reference.

For a person checking the applications by hand. Tick what works; write what does not. **Nothing here is accepted until you tick
it**; anything not ticked is treated as a defect to fix. Automated results are listed separately in "Automated evidence" so
they are never mistaken for your acceptance.

Verified on this machine on 2026-10-21 (branch `work/desktop-web-completion-2026-10-20`, uncommitted tree): PostgreSQL 17 is
running, `.env` and `certs/dev` exist, ports 5000 / 8765 / 8000 are free, the development database is reachable as the
least-privilege role `qrscs_app`, and the executable (built 04:03) is newer than every client/GUI source file. The primary
screen is 1536 x 864 (logical pixels).

## 0. Start everything

**Use the project's Python 3.12 virtual environment.** On this machine plain `python` is 3.14, which the project does not
support. In PowerShell:

```powershell
cd C:\Project\Quantum-Resistant-Secure-Communication-System
$py = "C:\Users\Vignesh T\venvs\qrscs312\Scripts\python.exe"
```

| Step | Command | Expected |
|---|---|---|
| Server, gateway, Website | `& $py run.py` (leave the window open; **Ctrl+C stops everything**) | "All applications are running."; Website at http://127.0.0.1:8000. It also opens a *source-run* Desktop window — you can close it and use the executable instead |
| Desktop executable | already built: `dist\desktop\QRSCS-Desktop\QRSCS-Desktop.exe` (rebuild only if you change code: `& $py scripts\build_desktop_exe.py`) | Login window with the padlock logo |
| A second Desktop user | `$env:KEY_STORE_DIR="$env:TEMP\qrscs_user2"; & ".\dist\desktop\QRSCS-Desktop\QRSCS-Desktop.exe"` | A second, independent login window. A different key store matters: otherwise two windows on the same machine share one |

The Website needs no gateway setting when you open it at http://127.0.0.1:8000 (the default is `ws://127.0.0.1:8765`; it is under
"Connection settings" if you ever need to change it).

The development database already holds about 4,900 synthetic accounts from earlier test runs. Use fresh, recognisable usernames.
(To test against an empty database instead, tell me; I will not change `.env` without your approval.)

## 0b. The 20 corrections of the UI-parity cycle (2026-10-21) — check these first

Each line is one of your reported items. Mark it only after looking at the real screen. The Website is the reference; the Desktop
should look and behave the same where the platforms allow.

- [ ] **1 Existing account.** Register with a phone number that already has an account: *one* sentence, "An account with this phone
  number already exists. Please log in." (Desktop and Website). Logging in with a wrong password still shows the generic message.
- [ ] **2 Same name twice.** Register two accounts that choose the same username: both succeed. Each is shown by that name; where
  the two meet (a chat list, a group, a message sender) the `@handle` tells them apart. A message to one never reaches the other.
  The phone number is still unique.
- [ ] **3 Own safety number.** Settings no longer has a "Your safety number" card (either client). In a contact's verification
  window (Desktop: **Verify Identity / Re-verify**; Website: **Re-verify**) use **Show my safety number**.
- [ ] **4 Blocked Users (Desktop).** Settings → Blocked Users: the title, explanation, list/empty state and Close are aligned.
- [ ] **5 Edit forms (Desktop).** Display name, Password and Bio forms open on the card's own white background, no grey band.
- [ ] **6 Profile row.** Settings starts with your picture, display name and handle. Select the picture: an enlarged viewer opens
  with **Change picture** (only there). With no picture you see a placeholder and "You haven't added a profile picture yet".
- [ ] **7 Voice recorder (Website).** Attach → Voice Message: record, watch the timer and level bars, listen to the preview,
  Record again, Cancel, Send. Block the microphone in the browser: a clear message, no broken dialog.
- [ ] **8 Desktop voice playback.** Send a voice message Website → Desktop and Desktop → Website: the play button works, the time
  and progress move, you **hear it**. A damaged file shows "can't be played" and Save still works.
- [ ] **9 Reactions.** React to a text, a photo, a voice message on one client: the same pills (emoji + count) appear on the other,
  also after you reopen the chat. One person never counts twice.
- [ ] **10 Replies.** Reply to a text, a photo and a voice message on both clients: the quote names the right person and shows an
  excerpt or "Photo / Voice message / Video message / the file name". Click it: it jumps to the original. Delete the original:
  the quote says "Message deleted".
- [ ] **11 Voice/video cards (Desktop).** Same layout as the Website: play/pause, progress, time, **Save**, timestamp and ticks.
- [ ] **12 Status bar (Desktop).** The bottom bar shows only Connected/Disconnected. Encryption is in **Chat settings**; your own
  phone number is in Settings. The contact's phone number appears nowhere.
- [ ] **13 Header avatar.** There is no separate profile icon. Click (or Tab to and press Enter on) the avatar: the contact's picture
  opens, with a placeholder when they have none.
- [ ] **14 Chat settings.** One gear in each chat header opens Chat settings: contact info, search, pinned, media, wallpaper,
  mark read, history, mute/archive/block. In a group the Members button stays visible and only the admin sees Add members;
  Leave group is in Chat settings. Verification status is never hidden.
- [ ] **15 Verification line.** A verified contact shows just "Verified" and **Re-verify**. A contact who is not verified shows the
  comparison. After the contact's key changes the status becomes "Key changed" at once and sending is refused until you verify again.
- [ ] **16 Search.** Type half a phone number in the Website search box: no chat appears. Enter on a real phone number opens that
  person only; Enter on a number nobody uses says so and creates nothing. Reload: no phantom chats.
- [ ] **17 Website picture.** Settings → profile picture → Change picture: choose an image, drag/zoom in the crop dialog, Save. A
  contact sees it (Website header avatar and Desktop). Try a PDF, a tiny image and a huge image: each is refused with a reason.
- [ ] **18 Gateway address.** The Website login shows no URL box; "Connection settings" opens it. Sign-in works with and without
  opening it.
- [ ] **19 Group events.** In a group, add, remove and leave: each shows one line ("Alice added Bob", "Bob left the group",
  "Alice removed Carol") on both clients, once, in order, also after reopening. A removed person sees nothing afterwards.
- [ ] **20 Group attachments.** Send a file, a voice message and a video message in a group from each client: every member
  receives and can play/save them; someone removed from the group does not receive later ones.

## 0c. Retest after the owner's first round (2026-10-22)

Rebuild the Desktop first if you use the executable (`& $py scripts\build_desktop_exe.py`); reload the Website (Ctrl+F5).

- [ ] **T14 Website, create group by phone.** Groups → Create group → type a member's phone number, Enter: their *name* and @handle
  appear with **Add** and are not yet a member. Add → a chip with the name. An unknown number says so. Create: the group has them.
  Also Group info → Add members with a phone number: the same name preview first.
- [ ] **T12 Desktop dropdown.** The gear in a chat header opens a menu (Contact info, Search, Pinned, Media gallery, Wallpaper, Mute or
  archive…). Contact info opens the detailed window. In a group the first entry is Group details and the last is Leave group.
- [ ] **T12 Desktop gallery.** Media gallery looks like the Website's (title, close, "Voice messages & files" rows); clicking a row
  jumps to that message.
- [ ] **T12 Desktop cards.** A file shows a type tile, name over size and a round download button; a voice message shows the title
  "Voice message", a rounded player (play, time, progress, volume/mute) and Save.
- [ ] **T17 Desktop picture editor.** Settings → your picture → Change picture: the editor shows the circle, zoom, drag, arrow keys;
  Save picture. A PDF, a tiny image and a huge image are refused with the Website's wording.
- [ ] **T11 / T20 audio (needs your hardware).** Run `& $py scripts\audio_selftest.py` and read what it says for each microphone
  and for playback. Tell me the summary lines. Until that is known, T11 and T20 stay FAIL.

## 0d. Adding someone you have never spoken to, requests and key follow-through (2026-10-22)

Use the executable in `dist\desktop-r3\QRSCS-Desktop\` (see `PROJECT_STATE.md`), and reload the Website (Ctrl+F5).
Three people: **A** (creates the group), **B** and **C** (never spoken to A).

- [ ] **Add by phone number.** A: Groups → Create group → type B's phone number, Enter: B's *name*, @handle and "Not verified yet — …"
  appear. Add. Create. The group exists with B in it.
- [ ] **Ask without a conversation.** In that preview press **Ask to verify**: B gets a request in their Inbox naming A. Nothing is
  verified yet and A's search/preview created no chat.
- [ ] **Approve.** B approves in the Inbox. Both now show *Verified* for each other; on the Website the Establish key button
  disappears by itself and a message A→B and B→A is readable. B can read and send in the group.
- [ ] **Group info.** Open Group info on each client: members show Verified / Not verified / Not seen yet; while someone cannot read
  the group a notice says so and **Verify** opens that person's comparison.
- [ ] **Deny.** C is asked and denies: nobody is verified, C never receives the group key, and A is told (a "declined" message on the Website, "Denied" in the Inbox on the Desktop).
- [ ] **Verify by hand.** Skip the request: A and B each press Confirm match in their own chat. Whichever order, B can read the group
  afterwards (it may take a few seconds).
- [ ] **Key change.** If a contact's safety number changes ("Key changed"), approving their request is refused and an approval of
  your own request does not re-trust them; you must verify again by hand.
- [ ] **Removed member.** Remove B before verifying B: B never gets the key.

## 0e. Joining a group by invitation, and the Desktop's new look (2026-10-22)

Restart the server and gateway (`& $py run.py`), reload the Website with Ctrl+F5 (the page now loads `main.js?v=1.10.0`), and use the
executable you were told to use. Four people: **A** (admin), **B**, **C**, **D**.

- [ ] **A creates `#LAB` with B, C and D** (Website or Desktop). The group exists with only A in it; A is told invitations were sent;
  Group info shows "Waiting for approval: B, C, D".
- [ ] **B, C and D each get a notice** (Website toast / Desktop banner), a number on the Inbox tab or rail, and a card "A wants to add
  you to the group “#LAB”. You join only if you approve." with Approve and Deny. Nobody else gets anything.
- [ ] **B approves, C denies, D does nothing.** Only B joins; A sees "B approved and joined", "C declined", and D still waiting.
- [ ] **B and A chat in the group at once**, both directions, with nobody pressing Establish key; Group info shows B as Verified.
- [ ] **C and D never see the group** and never get its key.
- [ ] **B (a member, not admin) asks to add E**: A approves; only then E receives an invitation, and E joins only by approving it.
- [ ] **Desktop look.** Settings → Appearance: choose Dark, restart, and the whole app is dark like the Website (rail with names and Log out,
  a green "Connected" pill beside Chats, All/Unread/Direct/Groups chips). Type a phone number in the search box and press Enter: that person
  is looked up. Typing only filters the list.

## 1. Accounts and sessions

- [ ] Website: register a new account; the form returns to Login with a success message; log in.
- [ ] Desktop: register; the form returns to Login with the number filled in; log in.
- [ ] Wrong password is refused on both with the same wording ("Invalid phone number or password"); the right password then works.
  An unregistered phone number must give the *same* message.
- [ ] Log out and back in (both): conversations and history are still there, nothing duplicated.
- [ ] Close and reopen the Desktop executable: same identity (a contact's verification window → **Show my safety number** unchanged).

## 2. Identity verification (between two accounts, ideally one Website + one Desktop)

- [ ] **Show my safety number** (in a contact's verification window) works on both clients.
- [ ] In a chat, the other person's number is shown (Desktop: **Verify Identity**; Website: the verification details).
- [ ] What one app shows for the other person equals what *that person's* app shows as their own (**Show my safety number**).
- [ ] Confirming the match marks the contact Verified; messaging is blocked until both sides have verified.
- [ ] Safety-number banner is readable at phone width (Website, section 7).

## 3. Direct messages

- [ ] Send both ways: Website ↔ Desktop, Website ↔ Website, Desktop ↔ Desktop.
- [ ] Multi-line (Shift+Enter) works; Enter sends; the composer grows then scrolls.
- [ ] Ticks change as messages are delivered and read; the typing indicator appears.
- [ ] Reply, edit, delete for everyone, react, forward, copy (Website: right-click a bubble; Desktop: the ⋯ button that appears on hover).
- [ ] Search in a conversation, pin a message, a draft survives switching chats, mute, archive.
- [ ] Offline: log one person out, send three messages, log them in: all three arrive once.
- [ ] **Retry / repeated-send protection** (exploratory — this exact manual path is **not verified**): the automated tests prove the
  server stores and delivers a repeated send once (protocol level), and that a *simulated* failed send shows a Retry bubble that
  delivers once. They do not stop the server. Try it: open a Website chat, stop the server, send a message, start the server again,
  press Retry if a Retry bubble is offered. Expected: the message arrives **once**. Report exactly what you see, including if no
  Retry bubble appears while disconnected.

## 4. Groups

- [ ] Create a group with several members (mixed clients). Messages reach exactly the members.
- [ ] Add a member (they receive the group); remove a member (they lose it and later messages); leave a group.
- [ ] A non-admin's add-member request goes to the admin's Inbox and is approved there.
- [ ] A non-member never sees the group.
- [ ] Each add / leave / remove appears as a line in the group on **both** clients, names the right people (the actor and the member), appears once, and
  is still there after logging out and in. A member added later does not see events from before they joined.
- [ ] Send a file, a voice message and a video to the group from the Website **and** from the Desktop: every member can open/play it, a removed member
  cannot, and a retry after a disconnect does not duplicate it.

## 5. Files and media

- [ ] Send an image and a file; the recipient sees them and can save them; the gallery lists them.
- [ ] A file over 25 MiB is refused with a clear message.
- [ ] Voice / video recording (microphone/camera needed): record, send, play back. Do this **Desktop → Website and Website → Desktop** and listen: the
  automated tests prove the audio decodes to a real signal, only a person can confirm it is audible.

## 6. Devices, inbox, blocking, profiles

- [ ] Website Settings → enroll a second browser, authorize it, revoke it; the revoked one is refused.
- [ ] Desktop **Devices** (rail button): list, authorize, revoke.
- [ ] Request verification from a contact; they approve it from **Inbox** (both clients).
- [ ] Block and unblock a contact; the blocked person is not told.
- [ ] Profile picture (choose, crop, upload), bio, username and password changes; other users see them.

## 7. Look and feel

- [ ] Desktop: default size, then minimum size (1000 x 650), then maximised; nothing overlaps or is clipped (check the header of an
  *unverified* contact and of a *group*, and the Settings dialog, which should scroll with Logout/Close always visible).
- [ ] Website: light, dark and system themes; wide, tablet and phone widths (browser DevTools: F12, then Ctrl+Shift+M, width 390);
  Tab order and a visible focus ring; text is readable in both themes.
- [ ] Error states are understandable (wrong password, server unreachable, expired session).

## 8. Server restart, connection loss and sign-in again

Expected behaviour is *different* for the two clients:

- [ ] **Website:** stop the server (Ctrl+C), watch the header status say **Reconnecting**; start the server again within about two
  minutes (`& $py run.py`): it **reconnects by itself** and messaging resumes. If you wait longer than about two minutes it gives up
  and you must log in again.
- [ ] **Desktop:** after the server stops, a red banner appears — "Connection to the server was lost…" — and the status bar says
  Disconnected. It does **not** reconnect by itself. After the server is back, press **Sign in again**, log in, and your
  conversations and verified contacts are still there.

## 9. Not covered by GUI automation (only you can check these)

The automated suites cannot reach these, so they have **only** widget-level tests behind them:

- Desktop **Devices**, **Inbox** and group **member list** dialogs (buttons inside list rows are invisible to UI Automation).
- Desktop **attaching** a file (the operating system's file dialog) and Desktop message **context actions** (⋯ menu).
- Voice/video recording with a real microphone/camera (automated tests use synthetic and fake devices), profile-picture cropping, wallpaper, and the look of anything at real screen sizes.
- Real network conditions (everything automated ran over loopback on this machine).

## 10. Automated evidence (not your acceptance)

| Area | Evidence | Where |
|---|---|---|
| Whole regression | 2,118 passed, 0 failed, 0 skipped (15 batches) | `PROJECT_STATE.md`; security matrix, 2026-10-21 |
| Multi-user | 32/32 scenarios at 10, 20 and 30 standing accounts, through the real EXE and Chrome | `docs/architecture/acceptance_testing.md` |
| Website registration | 100/100 repeated (3 of 60 failed before the TLS fix) | same |
| Confidentiality | pattern scan: 0 matches in logs, database rows and blobs. **A clean pattern scan does not prove no leak is possible** | `tests/acceptance/test_zz_confidentiality.py` |
| Screenshots | 35 real captures of the new UI (Website 21, Desktop 14) plus the Desktop in the dark theme (14) | `screenshots/preliminary/` |

## 11. Report back

For each item: **PASS** or **FAIL**. For a FAIL: what you did, what you expected, what happened, which client (Website / Desktop
EXE / both), and a screenshot if you can. Items you did not get to are **NOT TESTED** (not pass).
