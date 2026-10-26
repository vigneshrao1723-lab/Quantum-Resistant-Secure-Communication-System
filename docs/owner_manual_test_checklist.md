# Owner manual test checklist (2026-10-22)

What to check by hand, in order, with what you should see. Mark each line **PASS**, **FAIL** or **NOT TESTED** in the result sheet at
the end and send me the sheet. Automated tests cannot do the things marked **(you)**: looking at the screen, listening, and real
hardware. Anything not ticked is treated as a defect to fix.

## 0. Start everything (5 minutes)

1. Stop the old server: in the `run.py` window press **Ctrl+C** (it was started before the latest changes).
2. In PowerShell:

```powershell
cd <your clone of the repository>
$py = ".\venv\Scripts\python.exe"   # the python.exe of your repository venv (README, step 2)
& $py run.py                      # leave open. Website: http://127.0.0.1:8000. Close the extra Desktop window it opens.
```

3. Desktop user 1: `& ".\dist\desktop\QRSCS-Desktop\QRSCS-Desktop.exe"`
4. Desktop user 2 (separate key store): `$env:KEY_STORE_DIR="$env:TEMP\qrscs_user2"; & ".\dist\desktop\QRSCS-Desktop\QRSCS-Desktop.exe"`
5. Website: open http://127.0.0.1:8000 in Chrome and press **Ctrl+F5**. For a second Website user use a **separate Chrome profile or an Incognito window**.

**Four test people** (register each with a fresh username and phone number; the development database already holds thousands of test accounts):

| Person | Where | Role in the tests |
|---|---|---|
| **A** | Desktop window 1 | group admin / inviter |
| **B** | Website, Chrome window 1 | invited, approves |
| **C** | Website, Incognito window | invited, denies |
| **D** | Desktop window 2 | invited, ignores |

Do not use Android; it is paused.

## 1. The new feature — joining a group by invitation (most important)

- [ ] **1.1 Create.** A: **New group** (Desktop: the group icon beside Chats) → name `#LAB` → add B, C and D (type each phone number and press **Add**, or tick them) → OK.
  *Expect:* a message that invitations were sent; `#LAB` exists with **only A in it**; Group info shows "Waiting for approval: B, C, D".
- [ ] **1.2 Notices.** B, C and D each see: a notice ("A invited you to “#LAB”"), a **number on the Inbox** (Website tab / Desktop rail), and in **Inbox** a card
  "A wants to add you to the group “#LAB”. You join only if you approve." with **Approve / Deny**. *Expect:* nobody else gets one.
- [ ] **1.3 Decide.** B presses **Approve**; C presses **Deny**; D does nothing.
  *Expect:* only B joins `#LAB`. A is told "B approved and joined" and "C declined"; D's invitation is still pending. C and D never see the group.
- [ ] **1.4 Secure chat, automatically.** A and B send each other messages in `#LAB`, both directions, **without pressing Establish key or Verify**.
  *Expect:* both are readable at once. In Group info B shows **✓ Verified**.
- [ ] **1.5 Late approval.** D now approves (Inbox → Approve). *Expect:* D joins and can read new messages and send; A, B see "D added" once.
- [ ] **1.6 Non-admin request.** B (a member, not admin) adds a new person E (**Group info → Add members / Request**). *Expect:* the request goes to **A's Inbox** (not E's);
  only after A approves does **E** get an invitation; E joins only by approving it.
- [ ] **1.7 Removed member.** A removes B. *Expect:* B loses the group and receives nothing sent afterwards.

## 2. Adding someone you have never chatted with, by phone number

- [ ] **2.1 Website.** Groups → Create group → type a phone number → **Enter**. *Expect:* the person's **name and @handle** appear with "Not verified yet…", an **Add** button and **Ask to verify**; nothing is added until you press Add. An unused number says "No account uses that phone number."
- [ ] **2.2 Ask to verify.** Press **Ask to verify**. *Expect:* the person gets a request in their Inbox naming you; nothing is verified or created until they approve.
- [ ] **2.3 Group info → Add members** (phone number): the same preview first, then an invitation (not an instant add).
- [ ] **2.4 Approve / deny a plain request.** Approve one request and deny another. *Expect:* approved → both show **Verified**, the secure session is established by itself and messages flow both ways; denied → nothing is verified and no key moves.
- [ ] **2.5 Key change.** If a contact ever shows "Key changed", approving their request is refused; you must verify again by hand.

## 3. The five items you marked FAIL last time

- [ ] **T11 / T20 — hear a voice message (you, real microphone).** Run `& $py scripts\audio_selftest.py` and send me the **Summary** lines. Then: record a voice message on the Desktop and on the Website, play each on **both** clients.
  *Expect:* you hear it. If a microphone says **SILENT**, switch Windows' default input to the one that says OK and try again. Also try a **video** message with the real camera.
- [ ] **T12 — Desktop looks like the Website.** Gear in a chat header = dropdown (Contact info, Search, Pinned, Media gallery, Chat wallpaper, Mute or archive…); media gallery = the Website's card; file cards have a type tile and a round download button; voice cards have a rounded player with volume.
  *Write down anything that still differs (screen + what).*
- [ ] **T14 — group creation by phone with the name shown first** (2.1 above) and **"members chatting"**: tell me exactly what you tried when two group members could not chat directly (the Website shows "Not verified / Establish key" in a **direct** chat until both verify; that is the design).
- [ ] **T17 — Desktop picture editor like the Website's.** Settings → your picture → Change picture: a circle over the picture, zoom slider, drag, arrow keys; **Save picture**. A PDF, a tiny image and a huge image are refused with a reason.
- [ ] **Website search.** Search for an existing contact and for an unused phone number (type, then Enter). *Expect:* typing only filters; an unused number shows a message and **creates no conversation**; reload shows no phantom chats. **If it still fails, send a screenshot and the exact steps.**

## 4. Desktop look and navigation (you, by eye)

- [ ] **4.1 Rail** shows a name under each icon (Chats, Archived, Inbox, Devices, Settings, Log out); **Log out** works.
- [ ] **4.2 Beside "Chats"** a green **Connected** pill; stop the server briefly and it turns red "Disconnected" (the red banner and Sign in again still appear).
- [ ] **4.3 Chips** All / Unread / Direct / Groups filter the chat list.
- [ ] **4.4 Search** box: typing a name only filters; **Enter** on a phone number (or `@handle`) looks that person up and opens a chat; typing alone creates nothing.
- [ ] **4.5 Dark theme.** Settings → **Appearance → Dark**, restart the app. Everything is dark like the Website (rail, list, bubbles, dialogs, menus), text readable everywhere. Try **Light** and **Follow Windows** too.
- [ ] **4.6 Inbox** is a list of cards (scrolls); Approve / Deny work with the mouse **and** the keyboard (Tab, Space).

## 5. Quick re-check of what passed before (5 minutes)

- [ ] Same display name for two accounts: both register; `@handle` tells them apart in groups; a message goes only to the person you chose.
- [ ] Duplicate phone number: "An account with this phone number already exists. Please log in." (one sentence). Wrong password: the generic message.
- [ ] Reactions and replies on text, photo, voice: right person/excerpt, jump to original, "Message deleted" when the original is deleted, reactions survive a reload.
- [ ] Profile picture: Website upload with crop; the contact sees it on both clients; bad files refused.
- [ ] Group events (added / left / removed) appear once, with the right names, and persist after reopening.
- [ ] Group file, photo, voice, video: every member can open or play; a removed member receives nothing new.
- [ ] Blocked Users and the edit forms look right; safety number only behind **Show my safety number**; **Verified / Re-verify** labels.

## 6. Result sheet (copy this and send it back)

| # | Item | PASS / FAIL / NOT TESTED | What you saw (if FAIL) |
|---|---|---|---|
| 1.1 | Create group with invitations | | |
| 1.2 | Notices, badge, Inbox cards | | |
| 1.3 | Only approvers join | | |
| 1.4 | Secure chat, nothing pressed | | |
| 1.5 | Late approval | | |
| 1.6 | Non-admin request needs admin then person | | |
| 1.7 | Removed member gets nothing | | |
| 2.1 | Phone number shows name first | | |
| 2.2 | Ask to verify | | |
| 2.3 | Add members by phone (invitation) | | |
| 2.4 | Approve / deny a plain request | | |
| 2.5 | Key change refused | | |
| T11 / T20 | Voice and video audible (real hardware) | | |
| T12 | Desktop matches the Website | | |
| T14 | Group creation by phone / members chatting | | |
| T17 | Desktop picture editor | | |
| — | Website search | | |
| 4.1 | Rail with names, Log out | | |
| 4.2 | Connected pill | | |
| 4.3 | Filter chips | | |
| 4.4 | Search Enter looks up a number | | |
| 4.5 | Dark / Light / Follow Windows | | |
| 4.6 | Inbox cards, keyboard | | |
| 5 | Quick re-check of earlier passes | | |

For every **FAIL** send: which client (Website / Desktop EXE), what you did step by step, what you expected, what happened, and a screenshot.
The automated evidence behind all of this (2,188 regression tests, 33 acceptance scenarios) is in `docs/report/test_results_summary.md`; it is **not** your acceptance.
