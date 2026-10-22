// Phase 15 -- Web Interoperability, Stage 1 (DOM wiring only -- all
// protocol/crypto logic lives in app.js/protocol.js/crypto.js).
// Phase 17 -- persistence/reconnect UI wiring added.
// Phase 18 -- groups, file/image attachments, history recovery, read
// receipts wired in below; still DOM wiring only, no new protocol/
// crypto logic in this file.
// Phase 19.17A -- UI/UX parity pass: every session.*() call site below
// is unchanged from before this pass (same method, same arguments,
// same order) -- only how results are rendered into the DOM changed,
// to match mobile/app.py's design language. window.__session is also
// unchanged, so tests/test_web_*_e2e.py's Playwright drivers, which
// call straight into the real session object, are unaffected.

import { WebClientSession } from "./app.js";

// Developer diagnostics (the #devLog panel) are opt-in only -- an
// ordinary user visiting the plain URL never sees them; appendLog()
// below still always writes to #log regardless, so nothing here
// changes what gets logged, only whether the panel is shown.
if (new URLSearchParams(location.search).get("debug") === "1") {
  document.getElementById("devLog").hidden = false;
}

const logEl = document.getElementById("log");
const warningEl = document.getElementById("securityWarning");
const messagesEl = document.getElementById("messages");
const readStatusEl = document.getElementById("readStatus");
const fingerprintEl = document.getElementById("fingerprintDisplay");
const peerPresenceEl = document.getElementById("peerPresence");
const connectionStatusEl = document.getElementById("connectionStatus");
const groupListEl = document.getElementById("groupList");
const groupMessagesEl = document.getElementById("groupMessages");
const activeGroupIdEl = document.getElementById("activeGroupId");
const myDeviceIdEl = document.getElementById("myDeviceId");
const deviceListEl = document.getElementById("deviceList");
const deviceFingerprintDisplayEl = document.getElementById("deviceFingerprintDisplay");

const screenLogin = document.getElementById("screen-login");
const screenApp = document.getElementById("screen-app");
const authStatusEl = document.getElementById("authStatus");
const sidebarEl = document.getElementById("sidebar");
const mainPaneEl = document.getElementById("mainPane");
const mainEmptyEl = document.getElementById("mainEmpty");
const chatViewEl = document.getElementById("chatView");
const groupChatViewEl = document.getElementById("groupChatView");
const settingsViewEl = document.getElementById("settingsView");
const chatListEl = document.getElementById("chatList");
const chatTitleEl = document.getElementById("chatTitle");
const chatAvatarEl = document.getElementById("chatAvatar");
const peerVerifiedBadgeEl = document.getElementById("peerVerifiedBadge");
const groupTitleEl = document.getElementById("groupTitle");
const groupSubEl = document.getElementById("groupSub");
const groupAvatarEl = document.getElementById("groupAvatar");
const groupInfoViewEl = document.getElementById("groupInfoView");
const groupInfoNameEl = document.getElementById("groupInfoName");
const groupInfoSubEl = document.getElementById("groupInfoSub");
const groupInfoMembersEl = document.getElementById("groupInfoMembers");
const inboxListEl = document.getElementById("inboxList");

let session = null;
let observedDeviceFingerprint = null;
let activeDirectPeer = null;

// Direct-chat targets opened this session -- UI-only bookkeeping so
// the sidebar has something to list (no persisted conversation list
// exists at the protocol layer yet; this never substitutes for one,
// it only remembers who was opened in THIS tab so re-clicking works).
const knownDirectPeers = new Set();

function appendLog(text) {
  logEl.textContent += text + "\n";
  logEl.scrollTop = logEl.scrollHeight;
}

// Deliberately non-blocking (no alert()/confirm()), auto-clearing --
// mirrors gui/status_bar.py::set_security_notice()'s own reasoning:
// a malicious/forged packet must not be able to repeatedly interrupt
// the user just by resending itself.
function showSecurityWarning(text) {
  warningEl.textContent = text;
  warningEl.style.display = "block";
  clearTimeout(showSecurityWarning._timer);
  showSecurityWarning._timer = setTimeout(() => {
    warningEl.style.display = "none";
  }, 6000);
}

function initialOf(name) {
  return (name || "?").trim().charAt(0).toUpperCase() || "?";
}

// The open direct chat's account handle. The search box is ONLY a search box: what is typed
// there never decides who a message, verification or key is for.
function currentPeer() {
  return activeDirectPeer || "";
}

// The name to SHOW for an account handle. Display names are not unique (two people may both be
// "Vignesh"); everything that addresses, verifies or authorizes keeps using the handle.
function nameOf(handle) {
  return (session && session.displayNameFor(handle)) || handle || "";
}

// Display name plus, when it differs, the muted @handle: two people may share a display name,
// and the handle is what tells them apart on screen.
function nameWithHandleHtml(handle) {
  const name = nameOf(handle);
  return name === handle
    ? escapeHtml(name)
    : `${escapeHtml(name)} <span class="row-handle">@${escapeHtml(handle)}</span>`;
}

// Handles seen on screen whose display names are not known yet are fetched in one batch.
const pendingNameLookups = new Set();
const requestedNameLookups = new Set();
let nameLookupTimer = null;
function requestDisplayNames(handles) {
  if (!session) return;
  for (const handle of handles || []) {
    if (handle && !session.displayNames.has(handle) && !requestedNameLookups.has(handle)) {
      pendingNameLookups.add(handle);
    }
  }
  if (pendingNameLookups.size === 0 || nameLookupTimer) return;
  nameLookupTimer = setTimeout(async () => {
    nameLookupTimer = null;
    const batch = Array.from(pendingNameLookups);
    pendingNameLookups.clear();
    batch.forEach((handle) => requestedNameLookups.add(handle));
    try { await session.fetchDisplayNames(batch); } catch { /* names fall back to handles */ }
  }, 60);
}

// Re-label everything that shows a person after display names arrived.
function refreshShownNames() {
  renderChatList();
  if (session) renderGroupList();
  if (activeDirectPeer) {
    chatTitleEl.querySelector(".chat-header-name").textContent = nameOf(activeDirectPeer);
  }
  for (const label of document.querySelectorAll(".bubble-sender[data-handle]")) {
    label.textContent = nameOf(label.dataset.handle);
  }
  for (const row of document.querySelectorAll(".group-event")) {
    if (row._event) row.querySelector(".bubble").textContent = groupEventText(row._event);
  }
  if (typeof groupInfoViewEl !== "undefined" && !groupInfoViewEl.hidden) renderGroupInfo();
  const ownName = document.getElementById("ownDisplayName");
  if (ownName && session) ownName.textContent = nameOf(session.username);
}

function looksLikePhoneNumber(text) {
  return /^\+?[\d\s().-]{6,}$/.test(text || "");
}

// ------------------------------------------------------------------
// Phase 1 UI polish -- small presentation helpers. None of these read
// or write session state; they only build DOM / format values that
// the existing callbacks already hand to this file.
// ------------------------------------------------------------------

const SVG_NS = "http://www.w3.org/2000/svg";

// One icon from index.html's inline <symbol> set.
function icon(name, className = "icon") {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", className);
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(SVG_NS, "use");
  use.setAttribute("href", `#i-${name}`);
  svg.appendChild(use);
  return svg;
}

// Several row templates below are built with innerHTML; usernames and
// group names are user-chosen, so they're escaped on the way in.
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]
  ));
}

// History timestamps are naive-UTC ISO strings -- the same convention
// WebClientSession.fetchLastSeen() already handles by appending "Z".
function parseServerTimestamp(value) {
  if (!value) return null;
  const text = String(value);
  const hasZone = /[zZ]$|[+-]\d\d:?\d\d$/.test(text);
  const date = new Date(hasZone ? text : `${text}Z`);
  return Number.isNaN(date.getTime()) ? null : date;
}

function messageDate(options) {
  if (options && options.historical) return parseServerTimestamp(options.timestamp);
  return new Date();
}

function formatMessageTime(date) {
  return date ? date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }) : "";
}

function formatDayLabel(date) {
  const now = new Date();
  const sameDay = (a, b) => a.getFullYear() === b.getFullYear()
    && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  if (sameDay(date, now)) return "Today";
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  if (sameDay(date, yesterday)) return "Yesterday";
  return date.toLocaleDateString([], {
    weekday: "short", day: "numeric", month: "short",
    year: date.getFullYear() === now.getFullYear() ? undefined : "numeric",
  });
}

function formatBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

// Brief, non-blocking feedback for user-initiated actions (Copy,
// Establish key, Request Approval, ...). Their outcome previously
// reached only the hidden developer log, so a click looked like it did
// nothing. Announced politely to screen readers; at most three stack.
function toast(message, kind = "info") {
  let region = document.getElementById("toastRegion");
  if (!region) {
    region = document.createElement("div");
    region.id = "toastRegion";
    region.className = "toast-region";
    region.setAttribute("role", "status");
    region.setAttribute("aria-live", "polite");
    document.body.appendChild(region);
  }
  const el = document.createElement("div");
  el.className = `toast is-${kind}`;
  el.appendChild(icon(kind === "error" ? "alert" : kind === "success" ? "check" : "info"));
  const text = document.createElement("span");
  text.textContent = message;
  el.appendChild(text);
  region.appendChild(el);
  while (region.children.length > 3) region.firstElementChild.remove();
  const dismiss = () => {
    el.classList.add("is-leaving");
    setTimeout(() => el.remove(), 200);
  };
  setTimeout(dismiss, kind === "error" ? 5000 : 2800);
  el.addEventListener("click", dismiss);
}

// ------------------------------------------------------------------
// Phase 1.5 -- Appearance (Light / Dark / System). A per-browser
// display preference only (localStorage, like the wallpaper choice's
// local-only spirit) -- never sent to the server. index.html's inline
// head script applies it before first paint; this keeps it in sync.
// ------------------------------------------------------------------

const THEME_STORAGE_KEY = "qrscs.theme";
const darkSchemeQuery = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
const reducedMotionQuery = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
let themeTransitionTimer = null;

function readThemePreference() {
  try { return localStorage.getItem(THEME_STORAGE_KEY) || "system"; } catch { return "system"; }
}

function applyTheme(preference, { animate = false } = {}) {
  const root = document.documentElement;
  const dark = preference === "dark" || (preference === "system" && !!darkSchemeQuery?.matches);
  if (animate && !reducedMotionQuery?.matches) {
    // A short, shared colour cross-fade -- removed again right after.
    root.classList.add("theme-switching");
    clearTimeout(themeTransitionTimer);
    themeTransitionTimer = setTimeout(() => root.classList.remove("theme-switching"), 320);
  }
  root.dataset.theme = preference;
  root.dataset.colorScheme = dark ? "dark" : "light";
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", dark ? "#16171F" : "#FFFFFF");
  document.querySelectorAll('input[name="themePref"]').forEach((radio) => {
    radio.checked = radio.value === preference;
  });
  const loginThemeUse = document.querySelector("#loginThemeBtn use");
  if (loginThemeUse) loginThemeUse.setAttribute("href", dark ? "#i-sun" : "#i-moon");
}

function setThemePreference(preference) {
  try { localStorage.setItem(THEME_STORAGE_KEY, preference); } catch { /* display-only preference */ }
  applyTheme(preference, { animate: true });
}

darkSchemeQuery?.addEventListener?.("change", () => {
  if (readThemePreference() === "system") applyTheme("system", { animate: true });
});
document.querySelectorAll('input[name="themePref"]').forEach((radio) => {
  radio.addEventListener("change", () => { if (radio.checked) setThemePreference(radio.value); });
});
document.getElementById("loginThemeBtn")?.addEventListener("click", () => {
  setThemePreference(document.documentElement.dataset.colorScheme === "dark" ? "light" : "dark");
});
applyTheme(readThemePreference());

// Initials avatars get one of a few muted tones, chosen from the name
// (stable for the same person everywhere), instead of one flat colour.
const AVATAR_TONES = 6;
function avatarTone(name) {
  let hash = 0;
  for (const ch of String(name || "")) hash = (hash * 31 + ch.codePointAt(0)) >>> 0;
  return String(hash % AVATAR_TONES);
}

// ------------------------------------------------------------------
// Phase 1.5 -- sidebar row metadata (last message, time, unread).
// Purely a view over messages THIS tab has rendered or received --
// nothing is fetched or persisted for it: a conversation not opened
// yet this session simply shows its default subtitle.
// ------------------------------------------------------------------

const conversationActivity = new Map(); // "d:<peer>" | "g:<conversationId>" -> { preview, date, unread }

function activityKey(isGroup, key) { return `${isGroup ? "g" : "d"}:${key}`; }

function attachmentPreview(payloadType, contentMetadata) {
  if (payloadType === "image") return "Photo";
  if (payloadType === "voice") return "Voice message";
  if (payloadType === "video") return "Video message";
  return contentMetadata?.filename ? `File: ${contentMetadata.filename}` : "File";
}

function isConversationOnScreen(isGroup, key) {
  return isGroup
    ? key === activeGroupIdEl.value && !groupChatViewEl.hidden
    : key === activeDirectPeer && !chatViewEl.hidden;
}

function noteConversationActivity(isGroup, key, sender, previewText, options = {}) {
  if (!key) return;
  const id = activityKey(isGroup, key);
  const entry = conversationActivity.get(id) || { preview: "", date: null, unread: 0 };
  const mine = sender === "me" || sender === session?.username;
  const who = mine ? "You: " : (isGroup ? `${sender}: ` : "");
  entry.preview = options.isDeleted ? "Message deleted" : `${who}${previewText || ""}`;
  entry.date = messageDate(options) || entry.date;
  if (!mine && !options.historical && !isConversationOnScreen(isGroup, key)) entry.unread += 1;
  conversationActivity.set(id, entry);
  if (isGroup) renderGroupList(); else renderChatList();
}

function clearConversationUnread(isGroup, key) {
  const entry = conversationActivity.get(activityKey(isGroup, key));
  if (entry) entry.unread = 0;
}

function formatRowTime(date) {
  if (!date) return "";
  const now = new Date();
  if (date.toDateString() === now.toDateString()) return formatMessageTime(date);
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  if (date.toDateString() === yesterday.toDateString()) return "Yesterday";
  return date.toLocaleDateString([], { day: "numeric", month: "short" });
}

function updateTabBadges() {
  let chats = 0;
  let groups = 0;
  for (const [id, entry] of conversationActivity) {
    if (id.startsWith("g:")) groups += entry.unread; else chats += entry.unread;
  }
  for (const [badgeId, count] of [["chatsBadge", chats], ["groupsBadge", groups]]) {
    const badge = document.getElementById(badgeId);
    if (!badge) continue;
    badge.textContent = count > 99 ? "99+" : String(count);
    badge.hidden = count === 0;
  }
}

// Shared right-hand metadata column for a conversation row: time on
// top; muted marker, unread count and the options button underneath.
function rowMetaHtml(entry, muted, label) {
  const time = entry?.date ? `<span class="row-time">${escapeHtml(formatRowTime(entry.date))}</span>` : '<span class="row-time"></span>';
  const unread = entry?.unread ? `<span class="row-unread" aria-label="${entry.unread} unread">${entry.unread > 99 ? "99+" : entry.unread}</span>` : "";
  const mutedIcon = muted ? '<svg class="icon row-muted-icon" aria-label="Muted" role="img"><use href="#i-bell-off"/></svg>' : "";
  return `
      <div class="row-meta">
        ${time}
        <div class="row-meta-bottom">
          ${mutedIcon}${unread}
          <button type="button" class="row-mute-btn${muted ? " is-muted" : ""}" aria-label="Options for ${escapeHtml(label)}${muted ? " (muted)" : ""}" title="Conversation options"><svg class="icon" aria-hidden="true"><use href="#i-chevron-down"/></svg></button>
        </div>
      </div>`;
}

// Error path for a user-initiated action: still logged exactly as
// before, and now also shown.
function reportActionError(error) {
  appendLog(`ERROR: ${error.message}`);
  toast(error.message, "error");
}

// The timestamp element every bubble footer starts with -- the visible
// short time, with the full date/time as its hover title.
function buildFooter(options) {
  const footer = document.createElement("div");
  footer.className = "bubble-footer";
  const date = messageDate(options);
  const time = document.createElement("span");
  time.className = "bubble-time";
  time.textContent = formatMessageTime(date);
  if (date) time.title = date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  footer.appendChild(time);
  return footer;
}

// ------------------------------------------------------------------
// Screen / panel navigation (pure presentation state)
// ------------------------------------------------------------------

function showAppShell() {
  screenLogin.hidden = true;
  screenApp.hidden = false;
}

function setMainView(view) {
  // view: "empty" | "chat" | "groupChat" | "groupInfo" | "settings"
  mainEmptyEl.hidden = view !== "empty";
  chatViewEl.hidden = view !== "chat";
  groupChatViewEl.hidden = view !== "groupChat";
  groupInfoViewEl.hidden = view !== "groupInfo";
  settingsViewEl.hidden = view !== "settings";
  mainPaneEl.classList.toggle("is-empty", view === "empty");
  sidebarEl.classList.toggle("is-chat-open", view !== "empty");
}

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => {
      b.classList.remove("is-active");
      b.setAttribute("aria-selected", "false");
    });
    document.querySelectorAll(".sidebar-panel").forEach((p) => p.classList.remove("is-active"));
    btn.classList.add("is-active");
    btn.setAttribute("aria-selected", "true");
    document.querySelector(`.sidebar-panel[data-panel="${btn.dataset.tab}"]`).classList.add("is-active");
    const sidebarTitleEl = document.getElementById("sidebarTitle");
    if (sidebarTitleEl) sidebarTitleEl.textContent = btn.querySelector(".tab-label")?.textContent || "Chats";
    if (btn.dataset.tab === "inbox") renderInboxList();
  });
});

// The number of requests waiting for THIS account's decision, on the Inbox tab.
function updateInboxBadge(count) {
  const badge = document.getElementById("inboxBadge");
  if (!badge) return;
  badge.textContent = String(count);
  badge.hidden = !count;
}

async function refreshInboxBadge() {
  if (!session) return;
  try {
    const notifications = await session.loadInbox();
    updateInboxBadge(notifications.filter((n) => n.status === "pending" && n.requester_username !== session.username).length);
  } catch {
    // The badge is a convenience; the Inbox itself reports a failed load.
  }
}

function isInboxTabActive() {
  const btn = document.querySelector('.tab-btn[data-tab="inbox"]');
  return !!btn && btn.classList.contains("is-active");
}

document.getElementById("chatBackBtn").addEventListener("click", () => setMainView("empty"));
document.getElementById("groupBackBtn").addEventListener("click", () => setMainView("empty"));
// Settings had no way back on a phone-width screen (the sidebar is
// hidden while any main view is open there) -- same "back to list"
// as the chat views above.
document.getElementById("settingsBackBtn").addEventListener("click", () => setMainView("empty"));

document.getElementById("settingsToggleBtn").addEventListener("click", () => {
  setMainView("settings");
  loadMyBio();
  renderOwnProfile();
});

// The Settings profile row: your picture (a button -- it opens the enlarged viewer, the one place
// the picture can be changed), your display name and your handle.
function renderOwnProfile() {
  if (!session) return;
  requestDisplayNames([session.username]);
  document.getElementById("ownDisplayName").textContent = nameOf(session.username);
  document.getElementById("ownHandle").textContent = `@${session.username}`;
  loadPeerAvatar(document.getElementById("myProfilePicAvatar"), session.username, initialOf(nameOf(session.username)));
}

// Bio: view/edit this account's own bio (the same bio_request/
// change_bio_request round trips Desktop and Android use; the server caps it
// at 256 characters and returns an error for more).
async function loadOwnSafetyNumber() {
  const el = document.getElementById("ownSafetyNumber");
  if (!session || !el) return;
  try {
    const value = await session.ownFingerprint();
    if (value) el.textContent = value;
  } catch { /* leave the placeholder */ }
}
const NO_BIO_HINT = "No bio set. It is shown on your profile.";
async function loadMyBio() {
  if (!session) return;
  try {
    const bio = await session.fetchBio(session.username);
    document.getElementById("bioInput").value = bio;
    document.getElementById("bioHint").textContent = bio || NO_BIO_HINT;
  } catch { /* keep whatever is showing */ }
}
document.getElementById("bioToggleBtn").addEventListener("click", () => {
  const form = document.getElementById("bioForm");
  form.hidden = !form.hidden;
  if (!form.hidden) document.getElementById("bioInput").focus();
});
document.getElementById("bioSaveBtn").addEventListener("click", async () => {
  if (!session) return;
  const hintEl = document.getElementById("bioHint");
  const bio = document.getElementById("bioInput").value.trim();
  try {
    const result = await session.changeBio(bio);
    if (!result.success) throw new Error(result.error || "Could not save your bio.");
    hintEl.textContent = bio || NO_BIO_HINT;
    document.getElementById("bioForm").hidden = true;
    toast("Bio saved", "success");
  } catch (error) {
    hintEl.textContent = error.message;
  }
});

// Phase 19.18 -- L-5/Web-parity closure: Change Username / Change
// Password, previously disabled placeholders. Each toggle button
// reveals its own inline form; the actual request is the same
// session method Desktop/Mobile already call.
document.getElementById("changeUsernameToggleBtn").addEventListener("click", () => {
  const form = document.getElementById("changeUsernameForm");
  form.hidden = !form.hidden;
});
document.getElementById("changeUsernameSubmitBtn").addEventListener("click", async () => {
  const hintEl = document.getElementById("changeUsernameHint");
  const newName = document.getElementById("newUsernameInput").value.trim();
  if (!newName || !session) return;
  try {
    const result = await session.changeDisplayName(newName);
    if (!result.success) throw new Error(result.error || "Could not change your name.");
    hintEl.textContent = "Name updated.";
    document.getElementById("newUsernameInput").value = "";
  } catch (error) {
    hintEl.textContent = error.message;
  }
});

document.getElementById("changePasswordToggleBtn").addEventListener("click", () => {
  const form = document.getElementById("changePasswordForm");
  form.hidden = !form.hidden;
});
document.getElementById("changePasswordSubmitBtn").addEventListener("click", async () => {
  const hintEl = document.getElementById("changePasswordHint");
  const currentPassword = document.getElementById("currentPasswordInput").value;
  const newPassword = document.getElementById("newPasswordInput").value;
  const confirmPassword = document.getElementById("confirmNewPasswordInput").value;
  if (!currentPassword || !newPassword || !session) return;
  try {
    const result = await session.changePassword(currentPassword, newPassword, confirmPassword);
    if (!result.success) throw new Error(result.error || "Could not change password.");
    hintEl.textContent = "Password changed.";
    document.getElementById("currentPasswordInput").value = "";
    document.getElementById("newPasswordInput").value = "";
    document.getElementById("confirmNewPasswordInput").value = "";
  } catch (error) {
    hintEl.textContent = error.message;
  }
});

// Choosing a picture does not upload it: the file is checked, then shown in a crop dialog where the
// person positions and zooms it, and only the square they leave visible is uploaded (as a PNG).
const PROFILE_PICTURE_TYPES = ["image/png", "image/jpeg", "image/webp", "image/gif"];
const PROFILE_PICTURE_MAX_INPUT_BYTES = 10 * 1024 * 1024;
const PROFILE_PICTURE_MIN_SIDE = 64;
const PROFILE_PICTURE_MAX_SIDE = 8192;
const PROFILE_PICTURE_OUTPUT_SIDE = 256;

// Returns {bitmap} or {error} -- never throws.
async function checkProfilePictureFile(file) {
  if (!PROFILE_PICTURE_TYPES.includes(file.type)) {
    return { error: "Choose a PNG, JPEG, WebP or GIF image." };
  }
  if (file.size > PROFILE_PICTURE_MAX_INPUT_BYTES) {
    return { error: `That image is too large (${formatBytes(file.size)}). Choose one under ${formatBytes(PROFILE_PICTURE_MAX_INPUT_BYTES)}.` };
  }
  let bitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    return { error: "That file couldn't be read as an image." };
  }
  if (bitmap.width < PROFILE_PICTURE_MIN_SIDE || bitmap.height < PROFILE_PICTURE_MIN_SIDE) {
    bitmap.close?.();
    return { error: `That image is too small. Use one at least ${PROFILE_PICTURE_MIN_SIDE} \u00D7 ${PROFILE_PICTURE_MIN_SIDE} pixels.` };
  }
  if (bitmap.width > PROFILE_PICTURE_MAX_SIDE || bitmap.height > PROFILE_PICTURE_MAX_SIDE) {
    bitmap.close?.();
    return { error: `That image is too large. Use one no bigger than ${PROFILE_PICTURE_MAX_SIDE} \u00D7 ${PROFILE_PICTURE_MAX_SIDE} pixels.` };
  }
  return { bitmap };
}

function openProfilePictureCropper(bitmap, onUploaded) {
  const VIEW = 280;
  const overlay = document.createElement("div");
  overlay.className = "confirm-modal crop-modal";
  const card = document.createElement("div");
  card.className = "confirm-modal-card crop-card";
  card.setAttribute("role", "dialog");
  card.setAttribute("aria-modal", "true");
  card.setAttribute("aria-labelledby", "cropTitle");
  overlay.appendChild(card);

  const title = document.createElement("div");
  title.className = "confirm-modal-title";
  title.id = "cropTitle";
  title.textContent = "Adjust your picture";
  card.appendChild(title);

  const hint = document.createElement("div");
  hint.className = "confirm-modal-message";
  hint.textContent = "Drag to position it, and use the slider to zoom. The circle is what people will see.";
  card.appendChild(hint);

  const canvas = document.createElement("canvas");
  canvas.className = "crop-canvas";
  canvas.width = VIEW;
  canvas.height = VIEW;
  canvas.tabIndex = 0;
  canvas.setAttribute("aria-label", "Picture position. Use the arrow keys to move it, plus and minus to zoom.");
  card.appendChild(canvas);

  const zoomRow = document.createElement("label");
  zoomRow.className = "crop-zoom";
  const zoomLabel = document.createElement("span");
  zoomLabel.textContent = "Zoom";
  const zoom = document.createElement("input");
  zoom.type = "range";
  zoom.min = "1";
  zoom.max = "4";
  zoom.step = "0.01";
  zoom.value = "1";
  zoom.id = "cropZoom";
  zoom.setAttribute("aria-label", "Zoom");
  zoomRow.append(zoomLabel, zoom);
  card.appendChild(zoomRow);

  const errorEl = document.createElement("div");
  errorEl.className = "crop-error";
  errorEl.setAttribute("role", "alert");
  errorEl.hidden = true;
  card.appendChild(errorEl);

  const actions = document.createElement("div");
  actions.className = "confirm-modal-actions";
  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.className = "btn btn-ghost btn-sm";
  cancelBtn.textContent = "Cancel";
  const saveBtn = document.createElement("button");
  saveBtn.type = "button";
  saveBtn.className = "btn btn-primary btn-sm";
  saveBtn.id = "cropSaveBtn";
  saveBtn.textContent = "Save picture";
  actions.append(cancelBtn, saveBtn);
  card.appendChild(actions);

  // The image is scaled so it always COVERS the square (never leaves an empty edge), then zoomed
  // and shifted; the shift is clamped so the square stays inside the image.
  const base = Math.max(VIEW / bitmap.width, VIEW / bitmap.height);
  let zoomLevel = 1;
  let offsetX = (VIEW - bitmap.width * base) / 2;
  let offsetY = (VIEW - bitmap.height * base) / 2;
  const scale = () => base * zoomLevel;
  function clamp() {
    const w = bitmap.width * scale();
    const h = bitmap.height * scale();
    offsetX = Math.min(0, Math.max(VIEW - w, offsetX));
    offsetY = Math.min(0, Math.max(VIEW - h, offsetY));
  }
  function setZoom(next, anchorX = VIEW / 2, anchorY = VIEW / 2) {
    const clamped = Math.min(4, Math.max(1, next));
    const ratio = clamped / zoomLevel;
    offsetX = anchorX - (anchorX - offsetX) * ratio;
    offsetY = anchorY - (anchorY - offsetY) * ratio;
    zoomLevel = clamped;
    zoom.value = String(zoomLevel);
    clamp();
    draw();
  }
  const ctx = canvas.getContext("2d");
  function draw() {
    ctx.clearRect(0, 0, VIEW, VIEW);
    ctx.drawImage(bitmap, offsetX, offsetY, bitmap.width * scale(), bitmap.height * scale());
    // Dim everything outside the circle.
    ctx.save();
    ctx.fillStyle = "rgba(15, 16, 22, 0.55)";
    ctx.beginPath();
    ctx.rect(0, 0, VIEW, VIEW);
    ctx.arc(VIEW / 2, VIEW / 2, VIEW / 2 - 2, 0, Math.PI * 2, true);
    ctx.fill("evenodd");
    ctx.restore();
    ctx.strokeStyle = "rgba(255, 255, 255, 0.9)";
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(VIEW / 2, VIEW / 2, VIEW / 2 - 2, 0, Math.PI * 2);
    ctx.stroke();
  }
  draw();

  let drag = null;
  canvas.addEventListener("pointerdown", (event) => {
    canvas.setPointerCapture(event.pointerId);
    drag = { x: event.clientX, y: event.clientY, ox: offsetX, oy: offsetY };
  });
  canvas.addEventListener("pointermove", (event) => {
    if (!drag) return;
    offsetX = drag.ox + (event.clientX - drag.x);
    offsetY = drag.oy + (event.clientY - drag.y);
    clamp();
    draw();
  });
  const endDrag = () => { drag = null; };
  canvas.addEventListener("pointerup", endDrag);
  canvas.addEventListener("pointercancel", endDrag);
  canvas.addEventListener("wheel", (event) => {
    event.preventDefault();
    setZoom(zoomLevel * (event.deltaY < 0 ? 1.08 : 1 / 1.08));
  }, { passive: false });
  canvas.addEventListener("keydown", (event) => {
    const step = 12;
    const moves = { ArrowLeft: [step, 0], ArrowRight: [-step, 0], ArrowUp: [0, step], ArrowDown: [0, -step] };
    if (moves[event.key]) {
      event.preventDefault();
      offsetX += moves[event.key][0];
      offsetY += moves[event.key][1];
      clamp();
      draw();
    } else if (event.key === "+" || event.key === "=") {
      event.preventDefault();
      setZoom(zoomLevel + 0.1);
    } else if (event.key === "-" || event.key === "_") {
      event.preventDefault();
      setZoom(zoomLevel - 0.1);
    }
  });
  zoom.addEventListener("input", () => setZoom(Number(zoom.value)));

  function close() {
    bitmap.close?.();
    dismissOverlay(overlay);
  }
  cancelBtn.addEventListener("click", close);
  overlay.addEventListener("keydown", (event) => {
    if (event.key === "Escape") { event.stopPropagation(); close(); }
  });

  saveBtn.addEventListener("click", async () => {
    saveBtn.disabled = true;
    cancelBtn.disabled = true;
    errorEl.hidden = true;
    try {
      // The visible square, in source pixels -> a fixed-size square PNG.
      const out = document.createElement("canvas");
      out.width = PROFILE_PICTURE_OUTPUT_SIDE;
      out.height = PROFILE_PICTURE_OUTPUT_SIDE;
      const sourceSide = VIEW / scale();
      out.getContext("2d").drawImage(
        bitmap, -offsetX / scale(), -offsetY / scale(), sourceSide, sourceSide,
        0, 0, PROFILE_PICTURE_OUTPUT_SIDE, PROFILE_PICTURE_OUTPUT_SIDE
      );
      const blob = await new Promise((resolve, reject) => {
        out.toBlob((b) => (b ? resolve(b) : reject(new Error("Could not prepare the picture."))), "image/png");
      });
      const bytes = new Uint8Array(await blob.arrayBuffer());
      const result = await session.uploadProfilePicture(bytes, "image/png");
      if (result && result.success === false) throw new Error(result.error || "The server refused the picture.");
      close();
      toast("Profile picture updated", "success");
      onUploaded(bytes);
    } catch (error) {
      errorEl.textContent = `Upload failed: ${error.message}`;
      errorEl.hidden = false;
      saveBtn.disabled = false;
      cancelBtn.disabled = false;
    }
  });

  mountOverlay(overlay, canvas);
}

document.getElementById("profilePicInput").addEventListener("change", async () => {
  const input = document.getElementById("profilePicInput");
  const file = input.files && input.files[0];
  input.value = "";
  if (!file || !session) return;
  const hintEl = document.getElementById("myProfilePicHint");
  const checked = await checkProfilePictureFile(file);
  if (checked.error) {
    hintEl.textContent = checked.error;
    toast(checked.error, "error");
    return;
  }
  hintEl.textContent = "Select your picture to view or change it. It is visible to anyone who looks your account up.";
  openProfilePictureCropper(checked.bitmap, (bytes) => {
    setAvatarImage(document.getElementById("myProfilePicAvatar"), bytes, "image/png");
    document.getElementById("myProfilePicAvatar").onclick = () => showProfilePictureViewer(session.username);
    document.dispatchEvent(new CustomEvent("own-picture-updated", { detail: { bytes } }));
  });
});

document.getElementById("settingsLogoutBtn").addEventListener("click", () => {
  document.getElementById("logoutBtn").click();
});

// Phase 19.24 -- Attachment Menu: one small, consistent menu exposing
// every attachment kind (Photo/File, Voice Message, Video Message) --
// mirrors gui/input_bar.py's/mobile/app.py's own identical three
// choices, so the feature looks and behaves like the same app across
// all three clients.
// Where an attachment goes: the OPEN chat -- a direct peer or a group. Captured when the picker or
// recorder is opened, so switching views mid-way can never redirect it.
function activeAttachmentTarget() {
  if (!groupChatViewEl.hidden) {
    const conversationId = activeGroupIdEl.value;
    return { kind: "group", conversationId, container: groupMessagesEl, target: { conversationId } };
  }
  const peerUsername = currentPeer();
  return { kind: "direct", peerUsername, container: messagesEl, target: { peerUsername } };
}

// Sends bytes to ``where`` through the one encrypted attachment pipeline and shows them in that
// chat's transcript. A group message is one stored copy delivered to every member.
async function sendAttachmentTo(where, bytes, filename, mimeType, renderType) {
  await session.sendAttachment(where.target, bytes, filename, mimeType);
  if (where.kind === "direct") {
    knownDirectPeers.add(where.peerUsername);
    renderChatList();
  }
  // Only into the transcript that is still open: the person may have moved on while it uploaded.
  const stillOpen = where.kind === "group"
    ? !groupChatViewEl.hidden && activeGroupIdEl.value === where.conversationId
    : !chatViewEl.hidden && currentPeer() === where.peerUsername;
  if (stillOpen) {
    renderAttachment(where.container, "me", renderType, bytes, {
      filename, mime_type: mimeType, size_bytes: bytes.length,
    });
  }
}

for (const [buttonId, isGroup] of [["attachBtn", false], ["groupAttachBtn", true]]) {
document.getElementById(buttonId).addEventListener("click", (event) => {
  event.preventDefault();
  event.stopPropagation();
  closeAnyOpenPopup();
  const menu = createMenu("Attach");
  const options = [
    ["file", "Photo / File", "image"],
    ["voice", "Voice Message", "mic"],
    ["video", "Video Message", "video"],
  ];
  for (const [choice, label, iconName] of options) {
    const btn = createMenuItem(label, iconName);
    btn.addEventListener("click", (clickEvent) => {
      clickEvent.stopPropagation();
      closeAnyOpenPopup();
      if (choice === "file") {
        document.getElementById(isGroup ? "groupAttachmentInput" : "attachmentInput").click();
      } else {
        openMediaRecorderModal(choice);
      }
    });
    menu.appendChild(btn);
  }
  openPopup(menu, event, event.currentTarget);
});
}
for (const [inputId, sendId] of [["attachmentInput", "sendAttachmentBtn"], ["groupAttachmentInput", "sendGroupAttachmentBtn"]]) {
  document.getElementById(inputId).addEventListener("change", () => {
    const input = document.getElementById(inputId);
    const hasFile = input.files.length > 0;
    const btn = document.getElementById(sendId);
    btn.hidden = !hasFile;
    // Name the picked file on the button itself, so it's clear what
    // "Send" will send.
    const file = hasFile ? input.files[0] : null;
    btn.querySelector(".composer-file-label").textContent = file ? `Send ${file.name}` : "Send file";
    btn.title = file ? `Send ${file.name} (${formatBytes(file.size)})` : "";
  });
}

// ------------------------------------------------------------------
// Phase 19.24 -- Voice/Video Messages: a REAL recording, via the
// browser's own native getUserMedia()/MediaRecorder APIs -- no new
// dependency, no server-side change. The recorded Blob is pushed
// through session.sendAttachment() completely unmodified (the SAME
// AES-256-GCM/ML-DSA/blob-storage pipeline FILE/IMAGE already use --
// see domain/payload_type.py's own module docstring for the shared
// trust-model rationale); classifyAttachment() (app.js) labels it
// PayloadType.VOICE/VIDEO from the recorder's own reported mimeType.
// ------------------------------------------------------------------

const MAX_VOICE_SECONDS = 120;
const MAX_VIDEO_SECONDS = 60;

function formatClock(totalSeconds) {
  const s = Math.max(0, Math.round(totalSeconds || 0));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

// A human reason for a failed getUserMedia(), so the person knows what to do.
function recorderAccessMessage(error, mode) {
  const device = mode === "video" ? "camera and microphone" : "microphone";
  switch (error && error.name) {
    case "NotAllowedError":
    case "SecurityError":
      return `Access to the ${device} was blocked. Allow it in your browser's site settings, then try again.`;
    case "NotFoundError":
    case "OverconstrainedError":
      return `No ${device} was found. Connect one and try again.`;
    case "NotReadableError":
    case "AbortError":
      return `The ${device} is being used by another app. Close it and try again.`;
    default:
      return `Couldn't use the ${device}${error && error.message ? `: ${error.message}` : "."}`;
  }
}

function openMediaRecorderModal(mode) {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    toast("Recording isn't available here. Open this page over HTTPS or on localhost.", "error");
    return;
  }
  const constraints = mode === "video" ? { audio: true, video: true } : { audio: true };
  const where = activeAttachmentTarget();
  navigator.mediaDevices.getUserMedia(constraints).then((stream) => {
    _buildMediaRecorderModal(mode, stream, where);
  }).catch((error) => {
    appendLog(
      `ERROR: could not access the ${mode === "video" ? "camera/microphone" : "microphone"}: ${error.message}`
    );
    toast(recorderAccessMessage(error, mode), "error");
  });
}

function _buildMediaRecorderModal(mode, stream, where) {
  const maxSeconds = mode === "video" ? MAX_VIDEO_SECONDS : MAX_VOICE_SECONDS;
  const overlay = document.createElement("div");
  overlay.className = "media-recorder-modal";
  const card = document.createElement("div");
  card.className = "media-recorder-card";
  card.dataset.state = "idle";
  card.setAttribute("role", "dialog");
  card.setAttribute("aria-modal", "true");
  card.setAttribute("aria-labelledby", "recorderTitle");
  overlay.appendChild(card);

  const header = document.createElement("div");
  header.className = "media-recorder-header";
  const badge = document.createElement("span");
  badge.className = "media-recorder-badge";
  badge.setAttribute("aria-hidden", "true");
  badge.appendChild(icon(mode === "video" ? "video" : "mic"));
  const headerText = document.createElement("div");
  const titleEl = document.createElement("div");
  titleEl.className = "confirm-modal-title";
  titleEl.id = "recorderTitle";
  titleEl.textContent = mode === "video" ? "Video message" : "Voice message";
  const subtitleEl = document.createElement("div");
  subtitleEl.className = "media-recorder-subtitle";
  subtitleEl.textContent = `Up to ${formatClock(maxSeconds)}. Sent end-to-end encrypted.`;
  headerText.append(titleEl, subtitleEl);
  header.append(badge, headerText);
  card.appendChild(header);

  let previewEl = null;
  if (mode === "video") {
    previewEl = document.createElement("video");
    previewEl.className = "media-recorder-preview";
    previewEl.autoplay = true;
    previewEl.muted = true;
    previewEl.playsInline = true;
    previewEl.srcObject = stream;
    previewEl.setAttribute("aria-label", "Camera preview");
    card.appendChild(previewEl);
  }

  // Live input level while recording (voice and video alike): proof the microphone is working.
  const meter = document.createElement("div");
  meter.className = "media-recorder-meter";
  meter.setAttribute("aria-hidden", "true");
  const bars = Array.from({ length: 24 }, () => {
    const bar = document.createElement("span");
    meter.appendChild(bar);
    return bar;
  });
  card.appendChild(meter);

  const timerEl = document.createElement("div");
  timerEl.className = "media-recorder-timer";
  timerEl.setAttribute("role", "timer");
  timerEl.setAttribute("aria-label", "Recording time");
  timerEl.textContent = "0:00";
  card.appendChild(timerEl);

  const statusEl = document.createElement("div");
  statusEl.className = "media-recorder-status";
  statusEl.setAttribute("aria-live", "polite");
  statusEl.textContent = "Press Record when you are ready.";
  card.appendChild(statusEl);

  const recordBtn = document.createElement("button");
  recordBtn.type = "button";
  recordBtn.dataset.role = "record";
  recordBtn.className = "btn btn-primary btn-sm";
  // Icon + word instead of the old glyphs (which render at a different size and colour on
  // every platform).
  const setRecordLabel = (label, iconName) => {
    recordBtn.replaceChildren(icon(iconName), document.createTextNode(label));
  };
  setRecordLabel("Record", "mic");
  card.appendChild(recordBtn);

  const actionsRow = document.createElement("div");
  actionsRow.className = "media-recorder-actions";
  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.className = "btn btn-ghost btn-sm";
  cancelBtn.textContent = "Cancel";
  const sendBtn = document.createElement("button");
  sendBtn.type = "button";
  sendBtn.className = "btn btn-primary btn-sm";
  sendBtn.textContent = "Send";
  sendBtn.disabled = true;
  actionsRow.appendChild(cancelBtn);
  actionsRow.appendChild(sendBtn);
  card.appendChild(actionsRow);

  overlay._returnFocus = document.activeElement;
  document.body.appendChild(overlay);
  recordBtn.focus({ preventScroll: true });

  let recorder = null;
  let chunks = [];
  let recordedBlob = null;
  let recordedUrl = null;
  let elapsedSeconds = 0;
  let tickInterval = null;
  let audioContext = null;
  let levelFrame = null;

  function setState(state) {
    card.dataset.state = state;
    card.classList.toggle("is-recording", state === "recording");
  }

  function stopMeter() {
    if (levelFrame) cancelAnimationFrame(levelFrame);
    levelFrame = null;
    bars.forEach((bar) => { bar.style.transform = "scaleY(0.12)"; });
  }

  function startMeter() {
    try {
      audioContext = audioContext || new (window.AudioContext || window.webkitAudioContext)();
      const analyser = audioContext.createAnalyser();
      analyser.fftSize = 64;
      audioContext.createMediaStreamSource(stream).connect(analyser);
      const data = new Uint8Array(analyser.frequencyBinCount);
      const paint = () => {
        analyser.getByteFrequencyData(data);
        bars.forEach((bar, i) => {
          const level = (data[i % data.length] || 0) / 255;
          bar.style.transform = `scaleY(${Math.max(0.12, Math.min(1, level * 1.4))})`;
        });
        levelFrame = requestAnimationFrame(paint);
      };
      paint();
    } catch { /* the meter is cosmetic */ }
  }

  function stopAllTracks() {
    stream.getTracks().forEach((track) => track.stop());
  }

  function cleanupAndClose() {
    if (tickInterval) clearInterval(tickInterval);
    stopMeter();
    if (recorder && recorder.state !== "inactive") {
      recorder.onstop = null;
      try { recorder.stop(); } catch { /* already stopped */ }
    }
    stopAllTracks();
    if (audioContext) audioContext.close().catch(() => {});
    if (recordedUrl) URL.revokeObjectURL(recordedUrl);
    dismissOverlay(overlay);
  }

  function startRecording() {
    // Record again: the previous take is discarded.
    if (recordedUrl) { URL.revokeObjectURL(recordedUrl); recordedUrl = null; }
    recordedBlob = null;
    chunks = [];
    elapsedSeconds = 0;
    timerEl.textContent = "0:00";
    if (mode === "voice" && previewEl) { previewEl.remove(); previewEl = null; }
    if (mode === "video" && previewEl) {
      previewEl.controls = false;
      previewEl.removeAttribute("src");
      previewEl.muted = true;
      previewEl.srcObject = stream;
      previewEl.play().catch(() => {});
    }
    try {
      recorder = new MediaRecorder(stream);
    } catch (error) {
      statusEl.textContent = `Recording isn't supported here: ${error.message}`;
      return;
    }
    recorder.ondataavailable = (event) => {
      if (event.data && event.data.size > 0) chunks.push(event.data);
    };
    recorder.onerror = (event) => {
      statusEl.textContent = `Recording failed: ${event.error?.message || "the recorder reported an error."}`;
      setState("idle");
      stopMeter();
    };
    recorder.onstop = () => {
      stopMeter();
      recordedBlob = new Blob(
        chunks, { type: recorder.mimeType || (mode === "video" ? "video/webm" : "audio/webm") }
      );
      if (recordedBlob.size === 0) {
        statusEl.textContent = "Nothing was recorded. Check your microphone and try again.";
        setState("idle");
        setRecordLabel("Record", "mic");
        return;
      }
      setState("recorded");
      statusEl.textContent = mode === "video" ? "Watch your recording, then send it." : "Listen to your recording, then send it.";
      sendBtn.disabled = false;
      recordBtn.className = "btn btn-ghost btn-sm";
      setRecordLabel("Record again", "mic");
      recordedUrl = URL.createObjectURL(recordedBlob);
      if (mode === "video" && previewEl) {
        previewEl.srcObject = null;
        previewEl.muted = false;
        previewEl.controls = true;
        previewEl.src = recordedUrl;
        previewEl.setAttribute("aria-label", "Your recording");
      } else if (mode === "voice") {
        previewEl = document.createElement("audio");
        previewEl.className = "media-recorder-preview";
        previewEl.controls = true;
        previewEl.src = recordedUrl;
        previewEl.setAttribute("aria-label", "Your recording");
        card.insertBefore(previewEl, statusEl);
      }
    };
    recorder.start();
    setState("recording");
    statusEl.textContent = "Recording…";
    recordBtn.className = "btn btn-primary btn-sm";
    setRecordLabel("Stop", "stop");
    sendBtn.disabled = true;
    startMeter();
    tickInterval = setInterval(() => {
      elapsedSeconds += 1;
      timerEl.textContent = formatClock(elapsedSeconds);
      if (elapsedSeconds >= maxSeconds) stopRecording();
    }, 1000);
  }

  function stopRecording() {
    if (tickInterval) { clearInterval(tickInterval); tickInterval = null; }
    if (recorder && recorder.state !== "inactive") recorder.stop();
  }

  recordBtn.addEventListener("click", () => {
    if (recorder && recorder.state === "recording") {
      stopRecording();
    } else {
      startRecording();
    }
  });

  cancelBtn.addEventListener("click", cleanupAndClose);
  overlay.addEventListener("keydown", (event) => {
    if (event.key === "Escape") { event.stopPropagation(); cleanupAndClose(); }
  });

  sendBtn.addEventListener("click", async () => {
    if (!recordedBlob) return;
    sendBtn.disabled = true;
    statusEl.textContent = "Sending…";
    const filename = mode === "video" ? "video-message.webm" : "voice-message.webm";
    try {
      const bytes = new Uint8Array(await recordedBlob.arrayBuffer());
      await sendAttachmentTo(where, bytes, filename, recordedBlob.type, mode);
      cleanupAndClose();
    } catch (error) {
      reportActionError(error);
      statusEl.textContent = `Couldn't send: ${error.message}`;
      sendBtn.disabled = false;
    }
  });
}

// ------------------------------------------------------------------
// Message / attachment rendering -- same decrypted plaintext bytes/
// text app.js's callbacks already authenticated and decrypted; this
// file never touches ciphertext or key material.
// ------------------------------------------------------------------

// Phase 19.23 -- Issue 3: real SENT/DELIVERED/READ ticks on Web,
// keyed by peer username (a live-sent bubble has no server message_id
// yet to key by -- see resolveOldestUnackedSentTick()'s own comment)
// instead of the plain "X has read up to here" line this used to be
// the only user-visible signal of. peer username -> [tick <span>],
// oldest-sent-first; only ever populated for the direct panel
// (messagesEl) -- ticks are a direct-message-only concept, mirroring
// server/client_handler.py's own direct-only message_delivered/
// message_queued relay branch.
const pendingSentTicksByPeer = {};

// Phase 1 UI polish: ticks are drawn as SVG (see setTickStatus()) --
// one check for sent/queued, two for delivered/read, read additionally
// coloured (.tick-read). The checks are separate paths 8 units apart
// on an 11-unit-high grid, which leaves a constant ~1.5px gap between
// them instead of two text glyphs colliding or drifting apart.
const TICK_SHAPE = { sent: 1, queued: 1, delivered: 2, read: 2 };
const TICK_LABEL = { sent: "Sent", queued: "Sent", delivered: "Delivered", read: "Read" };
const TICK_PATH = "M1 5.8 L3.6 8.4 L8 2.2";

// ------------------------------------------------------------------
// Phase 19.24 (continued) -- Message Lifecycle Events UI (Reply/Edit/
// Delete/Forward/Copy/React), mirroring gui/message_widget.py +
// gui/chat_window.py (Desktop) and mobile/app.py (Android) exactly,
// adapted to plain DOM + a native right-click context menu (the
// browser-appropriate equivalent of Desktop's right-click menu /
// Android's long-press menu).
// ------------------------------------------------------------------

// EVERY currently-rendered bubble that has a real message_id --
// addressable by Reply/Edit/Delete/React/Forward. Reset whenever a
// conversation panel is cleared (openDirectChat()/openGroupChat()).
const bubblesByMessageId = new Map();

// A live-sent bubble has no server-assigned message_id at render time
// (sendMessage()/sendGroupMessage() return only the client-generated
// clientMessageId) -- mirrors gui/message_widget.py's "live-N"
// placeholder / mobile/app.py's "_bubbles_awaiting_message_id" FIFO.
// peer/group key -> [bubble, ...], oldest-first; resolved by
// onMessageDelivered/onMessageQueued (direct only -- group sends get
// no per-recipient ack, matching every other client) or, for a
// received/historical row, by messageId already arriving directly in
// onMessage/onAttachment's own options (no separate resolution step
// needed there -- see loadHistory()/_handleChat()'s own additions).
const pendingSentBubblesByKey = {};

function registerBubbleMessageId(bubble, messageId) {
  if (!bubble || !messageId) return;
  bubble.dataset.messageId = messageId;
  bubblesByMessageId.set(messageId, bubble);
  // A reply rendered before its original (e.g. the original's id only arrived now) resolves now.
  refreshRepliesTo(messageId);
}

function resolveOldestPendingSentBubble(key, messageId) {
  const pending = pendingSentBubblesByKey[key];
  if (!pending || !pending.length) return;
  const bubble = pending.shift();
  registerBubbleMessageId(bubble, messageId);
}

function clearMessageLifecycleState() {
  bubblesByMessageId.clear();
  for (const key of Object.keys(pendingSentBubblesByKey)) delete pendingSentBubblesByKey[key];
  clearComposerContext();
}

// Composer Reply/Edit state -- only one of the two panels (direct XOR
// group) is ever visible at a time (setMainView()), so one shared
// state object is safe; cleared on every panel switch.
let pendingReplyMessageId = null;
let editingMessageId = null;
let editingExpectedVersion = 0;

function activeComposerElements() {
  if (!chatViewEl.hidden) {
    return {
      contextBar: document.getElementById("composerContext"),
      contextText: document.getElementById("composerContextText"),
      input: document.getElementById("messageText"),
    };
  }
  if (!groupChatViewEl.hidden) {
    return {
      contextBar: document.getElementById("groupComposerContext"),
      contextText: document.getElementById("groupComposerContextText"),
      input: document.getElementById("groupMessageText"),
    };
  }
  return null;
}

// Phase 1.5 -- the bar above the composer states plainly what the next
// Send will do: reply to a message, or save an edit (in which case the
// Send button itself becomes "Save").
function setComposerContext({ mode, title, text }) {
  const els = activeComposerElements();
  if (!els) return;
  const bar = els.contextBar;
  bar.dataset.mode = mode;
  // The leading glyph tells you which one you are in before you read the
  // label: pencil while editing, arrow while replying. Presentation only.
  bar.querySelector(".composer-context-icon use")
    ?.setAttribute("href", mode === "edit" ? "#i-edit" : "#i-reply");
  bar.querySelector(".composer-context-title").textContent = title;
  els.contextText.textContent = text || "";
  bar.querySelector(".composer-context-icon use").setAttribute("href", mode === "edit" ? "#i-edit" : "#i-reply");
  bar.querySelector("button").setAttribute("aria-label", mode === "edit" ? "Cancel editing" : "Cancel reply");
  bar.hidden = false;
  const view = bar.closest(".chat-view");
  const composer = view?.querySelector(".composer");
  composer?.classList.toggle("is-editing", mode === "edit");
  const sendBtn = composer?.querySelector(".composer-send");
  if (sendBtn) {
    sendBtn.querySelector(".composer-send-label").textContent = mode === "edit" ? "Save" : "Send";
    sendBtn.querySelector("use").setAttribute("href", mode === "edit" ? "#i-check" : "#i-send");
    sendBtn.setAttribute("aria-label", mode === "edit" ? "Save edit" : "Send");
  }
}

function clearComposerContext() {
  pendingReplyMessageId = null;
  editingMessageId = null;
  editingExpectedVersion = 0;
  for (const barId of ["composerContext", "groupComposerContext"]) {
    const bar = document.getElementById(barId);
    if (bar) bar.hidden = true;
  }
  document.querySelectorAll(".composer.is-editing").forEach((composer) => {
    composer.classList.remove("is-editing");
    const sendBtn = composer.querySelector(".composer-send");
    if (sendBtn) {
      sendBtn.querySelector(".composer-send-label").textContent = "Send";
      sendBtn.querySelector("use").setAttribute("href", "#i-send");
      sendBtn.removeAttribute("aria-label");
    }
  });
}

document.getElementById("composerContextCancel").addEventListener("click", clearComposerContext);
document.getElementById("groupComposerContextCancel").addEventListener("click", clearComposerContext);

// ------------------------------------------------------------------
// Phase 19.24 -- Typing Indicator. Mirrors gui/chat_window.py's/
// mobile/app.py's identical debounce contract exactly (QTimer/Kivy
// Clock become plain setTimeout here): arm is_typing=True once on the
// first keystroke after idle, never resend on subsequent keystrokes;
// re-arm a 3s idle-stop timer on every keystroke; stop immediately on
// composer-cleared-to-empty OR an actual send. Receiver side tracks
// per-sender state (Map<conversationId, Map<username, timeoutId>>)
// with an independent 5s auto-expiry timer, same reasoning as the
// other two clients' own comments: protects against a sender's
// connection dropping mid-type, since no matching is_typing=False
// would ever arrive. A live hint only -- never persisted, never
// replayed by loadHistory().
// ------------------------------------------------------------------

let typingActive = false;
let typingStopTimer = null;
const typingSenders = new Map(); // conversationId -> Map<username, timeoutId>

function typingStatusElements() {
  if (!chatViewEl.hidden) {
    return { conversationId: currentConversationId(messagesEl), label: document.getElementById("typingStatus") };
  }
  if (!groupChatViewEl.hidden) {
    return { conversationId: currentConversationId(groupMessagesEl), label: document.getElementById("groupTypingStatus") };
  }
  return null;
}

function stopTypingImmediately() {
  clearTimeout(typingStopTimer);
  typingStopTimer = null;
  if (!typingActive) return;
  typingActive = false;
  const els = typingStatusElements();
  if (els?.conversationId && session) session.sendTypingIndicator(els.conversationId, false);
}

function onComposerTextChanged(text) {
  const els = typingStatusElements();
  if (!els?.conversationId || !session) return;
  if (!text) {
    stopTypingImmediately();
    return;
  }
  if (!typingActive) {
    typingActive = true;
    session.sendTypingIndicator(els.conversationId, true);
  }
  clearTimeout(typingStopTimer);
  typingStopTimer = setTimeout(stopTypingImmediately, 3000);
}

function renderTypingStatus(conversationId) {
  const els = typingStatusElements();
  if (!els || els.conversationId !== conversationId) return;
  const senders = typingSenders.get(conversationId);
  const names = senders ? Array.from(senders.keys()) : [];
  if (names.length === 0) {
    els.label.textContent = "";
    els.label.hidden = true;
    return;
  }
  let text;
  if (names.length === 1) text = `${names[0]} is typing…`;
  else if (names.length === 2) text = `${names[0]} and ${names[1]} are typing…`;
  else text = `${names.length} people are typing…`;
  els.label.textContent = text;
  els.label.hidden = false;
}

function expireTypingSender(conversationId, username) {
  const senders = typingSenders.get(conversationId);
  if (senders) {
    senders.delete(username);
    if (senders.size === 0) typingSenders.delete(conversationId);
  }
  renderTypingStatus(conversationId);
}

function onTypingIndicatorReceived(conversationId, username, isTyping) {
  let senders = typingSenders.get(conversationId);
  if (isTyping) {
    if (!senders) {
      senders = new Map();
      typingSenders.set(conversationId, senders);
    }
    clearTimeout(senders.get(username));
    senders.set(username, setTimeout(() => expireTypingSender(conversationId, username), 5000));
  } else if (senders) {
    clearTimeout(senders.get(username));
    senders.delete(username);
    if (senders.size === 0) typingSenders.delete(conversationId);
  }
  renderTypingStatus(conversationId);
}

function resetTypingStatusDisplay() {
  for (const id of ["typingStatus", "groupTypingStatus"]) {
    const el = document.getElementById(id);
    if (el) {
      el.textContent = "";
      el.hidden = true;
    }
  }
}

document.getElementById("messageText").addEventListener("input", (event) => onComposerTextChanged(event.target.value));
document.getElementById("groupMessageText").addEventListener("input", (event) => onComposerTextChanged(event.target.value));

// ------------------------------------------------------------------
// Phase 19.24 -- Drafts: per-conversation, unsent composer text that
// survives switching to a different conversation and back. In-memory
// only, this page's lifetime -- never sent over the wire, never
// persisted to disk. Mirrors gui/chat_window.py's/mobile/app.py's
// identical save-on-leave/restore-on-enter contract exactly, including
// the same "not while a reply/edit is in progress" exclusion (that
// text belongs to the pending action, not a draft of a fresh message).
// ------------------------------------------------------------------

const drafts = new Map(); // conversationId -> unsent composer text

function saveCurrentDraftIfAny() {
  const els = activeComposerElements();
  if (!els) return;
  const container = !chatViewEl.hidden ? messagesEl : groupMessagesEl;
  const conversationId = currentConversationId(container);
  if (!conversationId) return;
  if (editingMessageId !== null || pendingReplyMessageId !== null) return;
  const text = els.input.value;
  if (text) drafts.set(conversationId, text);
  else drafts.delete(conversationId);
}

// ---- Right-click context menu -------------------------------------

function buildBubbleContextActions(bubble) {
  // Mirrors gui/message_widget.py::_build_message_context_menu()'s
  // exact action set and conditions.
  if (!bubble.dataset.messageId) return [];
  if (bubble.dataset.deleted === "1") {
    return [["delete_me", "Delete for me", false]];
  }
  const actions = [
    ["reply", "Reply", false],
    ["copy", "Copy", false],
    ["forward", "Forward", false],
    ["react", "React …", false],
  ];
  // Phase 19.24 -- Pinned Messages: any member may pin/unpin any
  // message, sent or received alike -- see gui/message_widget.py::
  // _build_message_context_menu()'s identical note.
  actions.push(
    bubble.dataset.pinned === "1" ? ["unpin", "Unpin", false] : ["pin", "Pin", false]
  );
  if (bubble.dataset.mine === "1") {
    if (bubble.dataset.supportsEdit === "1") actions.push(["edit", "Edit", false]);
    actions.push(["delete_me", "Delete for me", false]);
    actions.push(["delete_everyone", "Delete for everyone", true]);
  } else {
    actions.push(["delete_me", "Delete for me", false]);
  }
  return actions;
}

// Element that had focus when the current popup opened -- focus goes
// back there when the popup is dismissed with Escape.
let popupOpener = null;

function closeAnyOpenPopup() {
  document.querySelectorAll(".bubble-context-menu, .bubble-popup").forEach((el) => el.remove());
  document.querySelectorAll(".bubble.is-menu-open").forEach((el) => el.classList.remove("is-menu-open"));
}

document.addEventListener("click", closeAnyOpenPopup);

function createMenu(label) {
  const menu = document.createElement("div");
  menu.className = "bubble-context-menu";
  menu.setAttribute("role", "menu");
  if (label) menu.setAttribute("aria-label", label);
  return menu;
}

function createMenuItem(label, iconName) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.setAttribute("role", "menuitem");
  btn.textContent = label;
  if (iconName) btn.prepend(icon(iconName));
  return btn;
}

// Places a popup at the pointer, or -- for a keyboard-triggered event,
// which carries no coordinates -- under ``anchor``. Measured after
// insertion and clamped to the viewport (flipping above the pointer
// when there's no room below), so a menu opened near an edge never
// spills off-screen or causes page overflow.
function positionPopup(el, event, anchor) {
  const margin = 8;
  let x = event?.clientX || 0;
  let y = event?.clientY || 0;
  let flipFrom = y;
  const anchorEl = (anchor && anchor.isConnected) ? anchor
    : (event?.target instanceof Element && event.target.isConnected ? event.target : null);
  if (!x && !y && anchorEl) {
    const rect = anchorEl.getBoundingClientRect();
    x = rect.left;
    y = rect.bottom + 4;
    flipFrom = rect.top - 4;
  }
  const { width, height } = el.getBoundingClientRect();
  let left = Math.min(x, window.innerWidth - width - margin);
  let top = y;
  if (top + height > window.innerHeight - margin) {
    top = flipFrom - height;
    el.style.transformOrigin = "bottom left";
  }
  left = Math.max(margin, left);
  top = Math.max(margin, Math.min(top, window.innerHeight - height - margin));
  el.style.left = `${Math.round(left)}px`;
  el.style.top = `${Math.round(top)}px`;
}

function openPopup(el, event, anchor) {
  popupOpener = document.activeElement;
  document.body.appendChild(el);
  positionPopup(el, event, anchor);
  // Keyboard-opened (no pointer coordinates): move focus into the
  // popup so arrow keys / Enter work immediately.
  if (!event || (!event.clientX && !event.clientY)) {
    el.querySelector("button:not(:disabled)")?.focus();
  }
}

// Keyboard support for every popup/menu: arrows move between items,
// Escape closes and returns focus to whatever opened it. Escape also
// closes the lightbox / gallery / confirm modal (topmost first).
document.addEventListener("keydown", (event) => {
  const popup = document.querySelector(".bubble-context-menu, .bubble-popup");
  if (popup && ["ArrowDown", "ArrowUp", "ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
    const items = Array.from(popup.querySelectorAll("button:not(:disabled)"));
    if (!items.length) return;
    const horizontal = popup.classList.contains("bubble-popup") && popup.querySelector(".bubble-popup-emoji-row");
    const forward = horizontal ? "ArrowRight" : "ArrowDown";
    const backward = horizontal ? "ArrowLeft" : "ArrowUp";
    const index = items.indexOf(document.activeElement);
    let nextIndex = null;
    if (event.key === forward) nextIndex = index < 0 ? 0 : (index + 1) % items.length;
    else if (event.key === backward) nextIndex = index < 0 ? items.length - 1 : (index - 1 + items.length) % items.length;
    else if (event.key === "Home") nextIndex = 0;
    else if (event.key === "End") nextIndex = items.length - 1;
    if (nextIndex !== null) {
      event.preventDefault();
      items[nextIndex].focus();
    }
    return;
  }
  if (event.key !== "Escape") return;
  if (popup) {
    event.preventDefault();
    closeAnyOpenPopup();
    if (popupOpener && popupOpener.isConnected) popupOpener.focus();
    popupOpener = null;
    return;
  }
  const overlays = document.querySelectorAll(".lightbox, .confirm-modal");
  const top = overlays[overlays.length - 1];
  if (top) {
    event.preventDefault();
    dismissOverlay(top);
    return;
  }
  if (!groupCreateModalEl.hidden) {
    event.preventDefault();
    closeGroupCreateModal();
    return;
  }
  // Escape inside the composer cancels a pending reply/edit.
  const els = activeComposerElements();
  if (els && !els.contextBar.hidden && document.activeElement === els.input) {
    event.preventDefault();
    const wasEditing = editingMessageId !== null;
    clearComposerContext();
    if (wasEditing) els.input.value = "";
  }
});

// Removes a lightbox/modal overlay and restores focus to the control
// that opened it.
function dismissOverlay(overlay) {
  const returnFocus = overlay._returnFocus;
  overlay.remove();
  if (returnFocus && returnFocus.isConnected) returnFocus.focus({ preventScroll: true });
}

function mountOverlay(overlay, initialFocus) {
  overlay._returnFocus = document.activeElement;
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) dismissOverlay(overlay);
  });
  document.body.appendChild(overlay);
  if (initialFocus) initialFocus.focus({ preventScroll: true });
}

const BUBBLE_ACTION_ICONS = {
  reply: "reply", copy: "copy", forward: "forward", react: "smile",
  pin: "pin", unpin: "pin", edit: "edit", delete_me: "trash", delete_everyone: "trash",
};

function showBubbleContextMenu(bubble, event, anchor) {
  event.preventDefault();
  event.stopPropagation();
  closeAnyOpenPopup();
  const actions = buildBubbleContextActions(bubble);
  if (!actions.length) return;
  const menu = createMenu("Message actions");
  let separated = false;
  for (const [action, label, danger] of actions) {
    if (!separated && action.startsWith("delete")) {
      const separator = document.createElement("div");
      separator.className = "menu-separator";
      separator.setAttribute("role", "separator");
      menu.appendChild(separator);
      separated = true;
    }
    const btn = createMenuItem(label, BUBBLE_ACTION_ICONS[action]);
    if (danger) btn.classList.add("is-danger");
    btn.addEventListener("click", (clickEvent) => {
      clickEvent.stopPropagation();
      closeAnyOpenPopup();
      handleBubbleContextAction(action, bubble, clickEvent);
    });
    menu.appendChild(btn);
  }
  openPopup(menu, event, anchor || bubble);
  // Marks which message the open menu belongs to (cleared by
  // closeAnyOpenPopup()).
  bubble.classList.add("is-menu-open");
}

const REACTION_CHOICES = ["\u{1F44D}", "❤️", "\u{1F602}", "\u{1F62E}", "\u{1F622}", "\u{1F64F}"];
const REACTION_NAMES = {
  "\u{1F44D}": "Thumbs up", "❤️": "Heart", "\u{1F602}": "Laughing",
  "\u{1F62E}": "Surprised", "\u{1F622}": "Sad", "\u{1F64F}": "Thank you",
};

function myReactionOn(bubble) {
  const mine = (bubble._reactions || []).find((entry) => entry.user === session?.username);
  return mine ? mine.reaction : null;
}

function showReactionPicker(bubble, event, anchor) {
  closeAnyOpenPopup();
  const popup = document.createElement("div");
  popup.className = "bubble-popup";
  popup.setAttribute("role", "menu");
  popup.setAttribute("aria-label", "Choose a reaction");
  const row = document.createElement("div");
  row.className = "bubble-popup-emoji-row";
  const current = myReactionOn(bubble);
  for (const emoji of REACTION_CHOICES) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.setAttribute("role", "menuitem");
    btn.textContent = emoji;
    btn.setAttribute("aria-label", REACTION_NAMES[emoji] || emoji);
    btn.title = REACTION_NAMES[emoji] || "";
    if (emoji === current) btn.classList.add("is-current");
    btn.addEventListener("click", (clickEvent) => {
      clickEvent.stopPropagation();
      closeAnyOpenPopup();
      sendReaction(bubble, emoji);
    });
    row.appendChild(btn);
  }
  popup.appendChild(row);
  openPopup(popup, event, anchor || bubble);
}

// ------------------------------------------------------------------
// Phase 19.24 -- Mute: local-only, per-conversation preference,
// mirroring gui/conversation_list_widget.py's ConversationRow.
// contextMenuEvent()/mobile/app.py's _open_mute_popup() exact action
// set and the same underlying session.muteConversation()/
// unmuteConversation() call every platform shares. Unlike Desktop/
// Mobile, this web client has no unread-badge or notification surface
// of its own AT ALL to suppress (#chatList/#groupList render a static
// "Direct message"/"N members" subtitle, never a live unread count or
// preview) -- so here mute is honestly just a stored, toggleable
// preference with no additional suppression behaviour to wire, rather
// than an overclaimed one. Reuses the SAME .bubble-context-menu popup
// shell showBubbleContextMenu() already uses (Web has no native
// right-click menu or long-press gesture of its own to piggyback on,
// same reasoning as mobile's touch-button choice).
// ------------------------------------------------------------------

function buildMuteActions(key, isGroup) {
  const actions = session?.isConversationMuted(key)
    ? [["unmute", "Unmute", false]]
    : [
        ["mute_1h", "Mute for 1 hour", false],
        ["mute_8h", "Mute for 8 hours", false],
        ["mute_1w", "Mute for 1 week", false],
        ["mute_forever", "Mute until I turn it back on", false],
      ];
  // Phase 19.24 -- Archive: retains history, purely a "don't show in
  // my main list" local preference, offered in the same menu as Mute
  // (mirrors mobile/app.py's _open_mute_popup() adding it to the same
  // popup).
  actions.push(
    session?.isConversationArchived(key)
      ? ["unarchive", "Unarchive", false]
      : ["archive", "Archive", false]
  );
  // Phase 19.24 -- Block User: only meaningful for a direct
  // conversation -- `key` there is a username (what session.
  // blockUser() needs); for a group it is a conversation_id, and
  // blocking a "conversation" rather than a person has no meaning
  // (mirrors gui/conversation_list_widget.py's identical is_group
  // guard).
  if (!isGroup) {
    actions.push(
      session?.isUserBlocked(key)
        ? ["unblock", "Unblock", false]
        : ["block", "Block", true]
    );
  }
  return actions;
}

// Real Yes/No confirmation before a destructive, irreversible action
// (Delete for Everyone, Block User) actually runs -- mirrors gui/
// chat_window.py::_confirm_delete_for_everyone()/_confirm_block_user()
// on Desktop and mobile/app.py's equivalent Popups. A custom modal
// rather than window.confirm(), for visual consistency with the rest
// of this app (the recorder modal already established this same
// overlay/card pattern) and so it can be dismissed the same way every
// other popup in this file is. doAction() is the actual action,
// called only on confirm -- tests bypass only this modal by calling
// that function directly, same convention as everywhere else in this
// project.
function showConfirmModal(title, message, confirmLabel, doAction) {
  const overlay = document.createElement("div");
  overlay.className = "confirm-modal";
  const card = document.createElement("div");
  card.className = "confirm-modal-card";
  card.setAttribute("role", "alertdialog");
  card.setAttribute("aria-modal", "true");
  overlay.appendChild(card);

  const titleEl = document.createElement("div");
  titleEl.className = "confirm-modal-title";
  titleEl.id = `confirm-title-${Date.now()}`;
  titleEl.textContent = title;
  card.setAttribute("aria-labelledby", titleEl.id);
  card.appendChild(titleEl);

  const messageEl = document.createElement("div");
  messageEl.className = "confirm-modal-message";
  messageEl.textContent = message;
  card.appendChild(messageEl);

  const actionsRow = document.createElement("div");
  actionsRow.className = "confirm-modal-actions";
  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.className = "btn btn-ghost btn-sm";
  cancelBtn.textContent = "Cancel";
  const confirmBtn = document.createElement("button");
  confirmBtn.type = "button";
  // Every caller of this modal confirms an irreversible action
  // (Delete for Everyone, Block) -- styled as such.
  confirmBtn.className = "btn btn-danger-solid btn-sm";
  confirmBtn.textContent = confirmLabel;
  actionsRow.appendChild(cancelBtn);
  actionsRow.appendChild(confirmBtn);
  card.appendChild(actionsRow);

  // Escape / backdrop click behave exactly like Cancel (mountOverlay()).
  cancelBtn.addEventListener("click", () => dismissOverlay(overlay));
  confirmBtn.addEventListener("click", () => {
    dismissOverlay(overlay);
    doAction();
  });

  mountOverlay(overlay, cancelBtn);
}

// Peer profile: picture, name, bio and presence for the open direct chat (the
// same details Desktop's "View Profile" and Android's avatar tap show).
async function showPeerProfile(username) {
  if (!session || !username) return;
  const overlay = document.createElement("div");
  overlay.className = "confirm-modal";
  const card = document.createElement("div");
  card.className = "confirm-modal-card profile-card";
  card.setAttribute("role", "dialog");
  card.setAttribute("aria-modal", "true");
  overlay.appendChild(card);

  const avatar = document.createElement("div");
  avatar.className = "avatar lg";
  avatar.dataset.tone = avatarTone(username);
  avatar.textContent = initialOf(nameOf(username));
  card.appendChild(avatar);

  const nameEl = document.createElement("div");
  nameEl.className = "confirm-modal-title";
  nameEl.id = `profile-title-${Date.now()}`;
  nameEl.textContent = nameOf(username);
  card.setAttribute("aria-labelledby", nameEl.id);
  card.appendChild(nameEl);

  // The handle tells apart two people who chose the same display name.
  const handleEl = document.createElement("div");
  handleEl.className = "profile-handle";
  handleEl.textContent = `@${username}`;
  card.appendChild(handleEl);

  const presenceEl = document.createElement("div");
  presenceEl.className = "profile-presence";
  presenceEl.textContent = document.getElementById("peerPresence")?.textContent || "";
  card.appendChild(presenceEl);

  const bioEl = document.createElement("div");
  bioEl.className = "confirm-modal-message profile-bio";
  bioEl.textContent = "Loading...";
  card.appendChild(bioEl);

  const actionsRow = document.createElement("div");
  actionsRow.className = "confirm-modal-actions";
  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "btn btn-ghost btn-sm";
  closeBtn.textContent = "Close";
  closeBtn.addEventListener("click", () => dismissOverlay(overlay));
  actionsRow.appendChild(closeBtn);
  card.appendChild(actionsRow);

  mountOverlay(overlay, closeBtn);

  loadPeerAvatar(avatar, username, initialOf(username));
  try {
    const bio = await session.fetchBio(username);
    bioEl.textContent = bio || "No bio set.";
  } catch {
    bioEl.textContent = "Profile details are unavailable right now.";
  }
}
document.getElementById("peerProfileBtn").addEventListener("click", () => showPeerProfile(activeDirectPeer));

// Group Info: add members / leave. Both only send the request -- the server
// decides (admin adds directly, others go to the admin's Inbox) and the
// result comes back as the group_members_added / group_member_left events.
let groupAddLookup = null;  // a phone number shown by name, waiting for "Add"
const groupAddLookupEl = document.getElementById("groupAddLookup");
function clearGroupAddLookup() {
  groupAddLookup = null;
  groupAddLookupEl.hidden = true;
  groupAddLookupEl.replaceChildren();
}
document.getElementById("groupAddMemberInput").addEventListener("input", () => {
  const value = document.getElementById("groupAddMemberInput").value.trim();
  if (!groupAddLookup || groupAddLookup.phone !== value) clearGroupAddLookup();
});
document.getElementById("groupAddMemberBtn").addEventListener("click", async () => {
  const conversationId = activeGroupIdEl.value;
  const group = session?.groups.get(conversationId);
  if (!group) return;
  const input = document.getElementById("groupAddMemberInput");
  const hint = document.getElementById("groupAddHint");
  const typed = input.value.trim();
  let names;
  if (looksLikePhoneNumber(typed)) {
    if (!(groupAddLookup && groupAddLookup.phone === typed)) {
      // First look the person up and show them by name; the second press (or the Add beside the
      // name) adds them.
      groupAddLookup = null;
      const found = await previewMemberByPhone(typed, groupAddLookupEl, () => document.getElementById("groupAddMemberBtn").click());
      if (found && input.value.trim() === typed) groupAddLookup = { phone: typed, found };
      return;
    }
    names = [groupAddLookup.found.username];
    clearGroupAddLookup();
  } else {
    names = input.value.split(/[\s,;]+/).map((n) => n.trim()).filter(Boolean);
  }
  if (names.length === 0) {
    hint.textContent = "Enter a username to add.";
    return;
  }
  const fresh = [...new Set(names)].filter((n) => n !== session.username && !group.members.includes(n));
  if (fresh.length === 0) {
    hint.textContent = "Everyone you entered is already in this group.";
    return;
  }
  session.addGroupMembers(conversationId, fresh, true);
  input.value = "";
  hint.textContent = !group.admin || group.admin === session.username
    ? "Invitation sent. They join when they approve it in their Inbox."
    : "Request sent. The group admin will see it in their Inbox; the person is then invited and joins only if they approve.";
  setTimeout(() => renderGroupInfo(), 600);
});
document.getElementById("groupAddMemberInput").addEventListener("keydown", (event) => {
  if (event.key === "Enter") { event.preventDefault(); document.getElementById("groupAddMemberBtn").click(); }
});
function doLeaveGroup(conversationId) {
  if (session) session.leaveGroup(conversationId);
}
document.getElementById("leaveGroupBtn").addEventListener("click", () => {
  const conversationId = activeGroupIdEl.value;
  const group = session?.groups.get(conversationId);
  if (!group) return;
  showConfirmModal(
    "Leave this group?",
    `You will stop receiving messages from "${group.name}". Someone in the group can add you again later.`,
    "Leave group",
    () => doLeaveGroup(conversationId),
  );
});

function doBlockUser(key) {
  if (!session) return;
  session.blockUser(key);
}

function applyMuteAction(key, action) {
  if (!session) return;
  if (action === "unmute") session.unmuteConversation(key);
  else if (action === "archive") session.archiveConversation(key);
  else if (action === "unarchive") session.unarchiveConversation(key);
  else if (action === "block") {
    showConfirmModal(
      "Block User?",
      `Block ${key}? They will no longer be able to message you, see ` +
        `your presence, or verify your identity. You can unblock them later.`,
      "Block",
      () => doBlockUser(key)
    );
  }
  else if (action === "unblock") session.unblockUser(key);
  else session.muteConversation(key, action.slice("mute_".length));
}

function showMuteMenu(key, event, refresh, isGroup = false) {
  event.preventDefault();
  event.stopPropagation();
  closeAnyOpenPopup();
  const menu = createMenu("Conversation options");
  const muteIcons = { unmute: "bell", archive: "archive", unarchive: "archive", block: "x", unblock: "user-check" };
  for (const [action, label, danger] of buildMuteActions(key, isGroup)) {
    const btn = createMenuItem(label, muteIcons[action] || "bell-off");
    if (danger) btn.classList.add("is-danger");
    btn.addEventListener("click", (clickEvent) => {
      clickEvent.stopPropagation();
      closeAnyOpenPopup();
      applyMuteAction(key, action);
      refresh();
    });
    menu.appendChild(btn);
  }
  openPopup(menu, event, event.currentTarget);
}

// ------------------------------------------------------------------
// Chat settings: the tools for the OPEN chat in one menu. The tools themselves (search, pinned
// messages, media, wallpaper, mark as read, load history, contact info) are the existing controls
// -- same ids, same handlers -- kept in the header's hidden .tool-registry; a menu item runs
// the one it stands for, positioned at the Chat settings button. Verification status and a group's
// members stay visible in the header.
// ------------------------------------------------------------------

const DIRECT_CHAT_TOOLS = [
  ["peerProfileBtn", "Contact info", "info"],
  ["searchBtn", "Search in conversation", "search"],
  ["pinnedBtn", "Pinned messages", "pin"],
  ["galleryBtn", "Media gallery", "image"],
  ["wallpaperBtn", "Chat wallpaper", "palette"],
  ["markReadBtn", "Mark as read", "check-check"],
  ["loadHistoryBtn", "Load history", "history"],
];
const GROUP_CHAT_TOOLS = [
  ["groupSearchBtn", "Search in conversation", "search"],
  ["groupPinnedBtn", "Pinned messages", "pin"],
  ["groupGalleryBtn", "Media gallery", "image"],
  ["groupWallpaperBtn", "Chat wallpaper", "palette"],
  ["loadGroupHistoryBtn", "Load history", "history"],
];

function showChatSettingsMenu(event, isGroup) {
  event.preventDefault();
  event.stopPropagation();
  closeAnyOpenPopup();
  const anchor = event.currentTarget;
  const rect = anchor.getBoundingClientRect();
  // Where a tool's own popup/panel should open from: just under the Chat settings button.
  const origin = { clientX: Math.round(rect.right - 8), clientY: Math.round(rect.bottom + 6) };
  const menu = createMenu("Chat settings");
  for (const [toolId, label, iconName] of (isGroup ? GROUP_CHAT_TOOLS : DIRECT_CHAT_TOOLS)) {
    const item = createMenuItem(label, iconName);
    item.dataset.tool = toolId;
    item.addEventListener("click", (clickEvent) => {
      clickEvent.stopPropagation();
      closeAnyOpenPopup();
      document.getElementById(toolId).dispatchEvent(new MouseEvent("click", { ...origin, bubbles: false, cancelable: true }));
    });
    menu.appendChild(item);
  }
  const key = isGroup ? activeGroupIdEl.value : activeDirectPeer;
  if (key) {
    const separator = document.createElement("div");
    separator.className = "menu-separator";
    separator.setAttribute("role", "separator");
    menu.appendChild(separator);
    const options = createMenuItem(isGroup ? "Mute or archive…" : "Mute, archive or block…", "bell-off");
    options.dataset.tool = "conversationOptions";
    options.addEventListener("click", (clickEvent) => {
      clickEvent.stopPropagation();
      closeAnyOpenPopup();
      const fakeEvent = {
        preventDefault() {}, stopPropagation() {}, ...origin, currentTarget: anchor, target: anchor,
      };
      showMuteMenu(key, fakeEvent, isGroup ? renderGroupList : renderChatList, isGroup);
    });
    menu.appendChild(options);
  }
  openPopup(menu, event, anchor);
}
document.getElementById("chatSettingsBtn").addEventListener("click", (event) => showChatSettingsMenu(event, false));
document.getElementById("groupSettingsBtn").addEventListener("click", (event) => showChatSettingsMenu(event, true));

// ------------------------------------------------------------------
// Phase 19.24 -- Chat Wallpaper: local-only, per-conversation --
// never sent to or stored by the server. Same preset ids/colors as
// gui/styles.py::WALLPAPER_PRESETS/mobile/app.py's own WALLPAPER_
// PRESETS -- see style.css's .wallpaper-* classes for the actual
// gradients applied to #messages/#groupMessages.
// ------------------------------------------------------------------

const WALLPAPER_PRESETS = {
  lavender: "Lavender",
  ocean: "Ocean",
  sunset: "Sunset",
  mint: "Mint",
  midnight: "Midnight",
};

function applyWallpaper(container, conversationId) {
  for (const id of Object.keys(WALLPAPER_PRESETS)) {
    container.classList.remove(`wallpaper-${id}`);
  }
  const wallpaperId = session?.getConversationWallpaper(conversationId);
  if (wallpaperId) container.classList.add(`wallpaper-${wallpaperId}`);
}

function showWallpaperPicker(container, conversationId, event) {
  event.preventDefault();
  event.stopPropagation();
  closeAnyOpenPopup();
  const current = session?.getConversationWallpaper(conversationId);
  const menu = createMenu("Chat wallpaper");
  const options = [[null, "Default"], ...Object.entries(WALLPAPER_PRESETS)];
  for (const [wallpaperId, label] of options) {
    const isCurrent = (wallpaperId || null) === (current || null);
    const btn = createMenuItem(label);
    btn.prepend(isCurrent ? icon("check") : swatch(wallpaperId));
    if (isCurrent) {
      btn.classList.add("is-current");
      btn.setAttribute("aria-current", "true");
    }
    btn.addEventListener("click", (clickEvent) => {
      clickEvent.stopPropagation();
      closeAnyOpenPopup();
      if (!session || !conversationId) return;
      session.setConversationWallpaper(conversationId, wallpaperId);
      applyWallpaper(container, conversationId);
    });
    menu.appendChild(btn);
  }
  openPopup(menu, event, event.currentTarget);
}

// A small colour sample for each wallpaper menu entry.
function swatch(wallpaperId) {
  const el = document.createElement("span");
  el.className = `menu-swatch${wallpaperId ? ` wallpaper-${wallpaperId}` : ""}`;
  el.setAttribute("aria-hidden", "true");
  return el;
}

// ------------------------------------------------------------------
// Phase 19.24 -- Message Search: operates ONLY on bubbles already
// decrypted and rendered inside the given container (#messages or
// #groupMessages) -- the query text itself is never sent to the
// server, and there is no second history fetch. Mirrors gui/
// message_widget.py::MessageWidget.find_matches()'s exact contract.
// ------------------------------------------------------------------

function searchMatchingBubbles(container, query) {
  query = (query || "").trim().toLowerCase();
  if (!query) return [];
  return Array.from(container.querySelectorAll(".bubble")).filter((bubble) => {
    const text = bubble.dataset.text;
    return !!text && bubble.dataset.deleted !== "1" && text.toLowerCase().includes(query);
  });
}

function highlightSearchMatch(container, bubble) {
  clearSearchHighlight(container);
  if (!bubble) return;
  bubble.classList.add("is-search-match");
  container._searchHighlighted = bubble;
  bubble.scrollIntoView({ block: "center", behavior: "smooth" });
}

function clearSearchHighlight(container) {
  const bubble = container._searchHighlighted;
  container._searchHighlighted = null;
  if (bubble) bubble.classList.remove("is-search-match");
}

function setupSearchBar(container, els) {
  container._searchMatches = [];
  container._searchIndex = -1;

  function showCurrentMatch() {
    const bubble = container._searchMatches[container._searchIndex];
    highlightSearchMatch(container, bubble);
    els.resultLabel.textContent = `${container._searchIndex + 1} of ${container._searchMatches.length}`;
  }

  function closeBar() {
    els.bar.hidden = true;
    els.input.value = "";
    container._searchMatches = [];
    container._searchIndex = -1;
    els.resultLabel.textContent = "";
    clearSearchHighlight(container);
  }
  container._closeSearchBar = closeBar;

  function next() {
    if (!container._searchMatches.length) return;
    container._searchIndex = (container._searchIndex + 1) % container._searchMatches.length;
    showCurrentMatch();
  }

  function prev() {
    if (!container._searchMatches.length) return;
    container._searchIndex =
      (container._searchIndex - 1 + container._searchMatches.length) % container._searchMatches.length;
    showCurrentMatch();
  }

  els.toggleBtn.addEventListener("click", () => {
    if (!els.bar.hidden) {
      closeBar();
      return;
    }
    els.bar.hidden = false;
    els.input.focus();
  });

  els.input.addEventListener("input", () => {
    container._searchMatches = searchMatchingBubbles(container, els.input.value);
    if (!container._searchMatches.length) {
      container._searchIndex = -1;
      clearSearchHighlight(container);
      els.resultLabel.textContent = els.input.value.trim() ? "No matches" : "";
      return;
    }
    container._searchIndex = 0;
    showCurrentMatch();
  });

  els.input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      next();
    }
  });
  els.nextBtn.addEventListener("click", next);
  els.prevBtn.addEventListener("click", prev);
  els.closeBtn.addEventListener("click", closeBar);
}

// ------------------------------------------------------------------
// Phase 19.24 -- Pinned Messages: a real, server-synchronized panel
// (NOT a fake local-only button -- pin/unpin is a real message_pin/
// message_unpin protocol round trip with a server-side row that
// synchronizes to every conversation member and every one of this
// account's own other authorized devices via ordinary history reload,
// mirrors gui/chat_window.py::handle_open_pinned_messages_panel()'s
// identical contract) listing every currently-pinned message, with
// click-to-navigate.
// ------------------------------------------------------------------

function getPinnedBubbles(container) {
  return Array.from(container.querySelectorAll(".bubble")).filter(
    (bubble) => bubble.dataset.pinned === "1"
  );
}

function showPinnedMessagesPanel(container, event) {
  event.preventDefault();
  event.stopPropagation();
  closeAnyOpenPopup();
  const pinned = getPinnedBubbles(container);
  const menu = createMenu("Pinned messages");
  menu.classList.add("is-pinned-panel");
  const heading = document.createElement("div");
  heading.className = "menu-heading";
  heading.textContent = "Pinned messages";
  menu.appendChild(heading);
  if (!pinned.length) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = "No pinned messages";
    btn.disabled = true;
    menu.appendChild(btn);
  } else {
    for (const bubble of pinned) {
      const preview = bubble.dataset.text || "[Attachment]";
      const shown = preview.length > 60 ? preview.slice(0, 57) + "…" : preview;
      const pinnedEl = bubble.querySelector(".bubble-pinned");
      const by = pinnedEl && pinnedEl.textContent.includes(" by ")
        ? pinnedEl.textContent.replace("\u{1F4CC} ", "") : "";
      const btn = document.createElement("button");
      btn.type = "button";
      btn.setAttribute("role", "menuitem");
      // Message first (its text is what the item is read/matched by),
      // "Pinned by" underneath as a quieter second line.
      const body = document.createElement("span");
      body.className = "menu-item-body";
      const main = document.createElement("span");
      main.className = "menu-item-text";
      main.textContent = shown;
      body.appendChild(main);
      if (by) {
        const sub = document.createElement("span");
        sub.className = "menu-item-sub";
        sub.textContent = by;
        body.appendChild(sub);
      }
      btn.appendChild(body);
      btn.addEventListener("click", (clickEvent) => {
        clickEvent.stopPropagation();
        closeAnyOpenPopup();
        flashBubble(container, bubble);
      });
      menu.appendChild(btn);
    }
  }
  openPopup(menu, event, event.currentTarget);
}

// ------------------------------------------------------------------
// Media Gallery (this closure pass -- closes the previous Desktop-only
// gap). Mirrors gui/chat_window.py::handle_open_media_gallery()'s
// exact grouping (Photos & Videos grid, Voice Messages & Files list)
// and its core contract: operates ENTIRELY over already-decrypted,
// already-rendered bubbles currently in the DOM -- no second history
// fetch, no server-side plaintext indexing. A tile/row never rebuilds
// a second player -- it points at (image: opens the same already-
// decrypted objectUrl; voice/video/file: scrolls to) the real,
// already-tested inline bubble element renderAttachment() built,
// exactly the same "operate on already-rendered content" principle
// this file's search/pinned-messages features already established.
// ------------------------------------------------------------------

function getMediaBubbles(container) {
  return Array.from(container.querySelectorAll(".bubble[data-payload-type]")).filter(
    (bubble) => bubble.dataset.payloadType
      && bubble.dataset.payloadType !== "text"
      && bubble.dataset.deleted !== "1"
  );
}

function _buildGalleryTile(bubble, overlay) {
  // A real <button>, so every tile is reachable and activatable from
  // the keyboard, not just by mouse.
  const tile = document.createElement("button");
  tile.type = "button";
  tile.className = "gallery-tile";
  if (bubble.dataset.payloadType === "image") {
    const img = bubble.querySelector("img");
    if (img && img.src) {
      const thumb = document.createElement("img");
      thumb.src = img.src;
      thumb.alt = "";
      thumb.className = "gallery-thumb";
      tile.setAttribute("aria-label", `View image${img.alt ? `: ${img.alt}` : ""}`);
      // Opens the same in-app lightbox the bubble itself uses (was a
      // new browser tab showing a bare blob: URL).
      tile.addEventListener("click", () => openLightbox(img.src));
      tile.appendChild(thumb);
      return tile;
    }
  }
  const label = document.createElement("div");
  label.className = "gallery-tile-label";
  label.textContent = bubble.dataset.payloadType === "video" ? "\u{1F3AC} Video" : "[Media]";
  tile.appendChild(label);
  tile.addEventListener("click", () => {
    dismissOverlay(overlay);
    bubble.scrollIntoView({ behavior: "smooth", block: "center" });
  });
  return tile;
}

function _buildGalleryFileRow(bubble, overlay) {
  const row = document.createElement("button");
  row.type = "button";
  row.className = "gallery-file-row";
  const metaEl = bubble.querySelector(".msg-meta");
  row.textContent = metaEl ? metaEl.textContent : (bubble.dataset.payloadType || "file");
  row.prepend(icon(bubble.dataset.payloadType === "voice" ? "mic" : "file"));
  row.addEventListener("click", () => {
    dismissOverlay(overlay);
    bubble.scrollIntoView({ behavior: "smooth", block: "center" });
  });
  return row;
}

function showMediaGallery(container, event) {
  event.preventDefault();
  closeAnyOpenPopup();

  const overlay = document.createElement("div");
  overlay.className = "confirm-modal";
  const card = document.createElement("div");
  card.className = "confirm-modal-card gallery-card";
  card.setAttribute("role", "dialog");
  card.setAttribute("aria-modal", "true");
  card.setAttribute("aria-label", "Media gallery");
  overlay.appendChild(card);

  const header = document.createElement("div");
  header.className = "gallery-header";
  const titleEl = document.createElement("div");
  titleEl.className = "confirm-modal-title";
  titleEl.textContent = "Media Gallery";
  header.appendChild(titleEl);
  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "btn-icon";
  closeBtn.setAttribute("aria-label", "Close media gallery");
  closeBtn.appendChild(icon("x"));
  closeBtn.addEventListener("click", () => dismissOverlay(overlay));
  header.appendChild(closeBtn);
  card.appendChild(header);

  const media = getMediaBubbles(container);

  if (!media.length) {
    const empty = document.createElement("div");
    empty.className = "confirm-modal-message gallery-empty";
    empty.textContent = "No media in this conversation yet.";
    card.appendChild(empty);
    mountOverlay(overlay, closeBtn);
    return;
  }

  const imagesAndVideos = media.filter(
    (b) => b.dataset.payloadType === "image" || b.dataset.payloadType === "video"
  );
  const otherFiles = media.filter((b) => !imagesAndVideos.includes(b));

  if (imagesAndVideos.length) {
    const heading = document.createElement("div");
    heading.className = "gallery-section-heading";
    heading.textContent = "Photos & Videos";
    card.appendChild(heading);
    const grid = document.createElement("div");
    grid.className = "gallery-grid";
    for (const bubble of imagesAndVideos) grid.appendChild(_buildGalleryTile(bubble, overlay));
    card.appendChild(grid);
  }

  if (otherFiles.length) {
    const heading = document.createElement("div");
    heading.className = "gallery-section-heading";
    heading.textContent = "Voice Messages & Files";
    card.appendChild(heading);
    const list = document.createElement("div");
    list.className = "gallery-list";
    for (const bubble of otherFiles) list.appendChild(_buildGalleryFileRow(bubble, overlay));
    card.appendChild(list);
  }

  mountOverlay(overlay, closeBtn);
}

function showForwardPicker(bubble, event) {
  closeAnyOpenPopup();
  const targets = [];
  for (const peer of knownDirectPeers) targets.push({ peerUsername: peer, label: peer });
  if (session) {
    for (const [conversationId, group] of session.groups) {
      targets.push({ conversationId, label: `\u{1F465} ${group.name}` });
    }
  }
  if (!targets.length) return;
  const popup = document.createElement("div");
  popup.className = "bubble-popup";
  popup.setAttribute("role", "menu");
  popup.setAttribute("aria-label", "Forward to");
  const heading = document.createElement("div");
  heading.className = "bubble-popup-heading";
  heading.textContent = "Forward to";
  popup.appendChild(heading);
  const list = document.createElement("div");
  list.className = "bubble-popup-list";
  for (const target of targets) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.setAttribute("role", "menuitem");
    btn.textContent = target.label;
    btn.addEventListener("click", (clickEvent) => {
      clickEvent.stopPropagation();
      closeAnyOpenPopup();
      forwardBubbleTo(bubble, target);
    });
    list.appendChild(btn);
  }
  popup.appendChild(list);
  openPopup(popup, event, bubble);
}

async function handleBubbleContextAction(action, bubble, event) {
  const messageId = bubble.dataset.messageId;

  if (action === "reply") {
    pendingReplyMessageId = messageId;
    editingMessageId = null;
    const preview = bubble.dataset.text || "[Attachment]";
    setComposerContext({
      mode: "reply",
      title: `Replying to ${bubbleAuthor(bubble)}`,
      text: preview.length > 120 ? preview.slice(0, 117) + "…" : preview,
    });
    activeComposerElements()?.input.focus();
    return;
  }

  if (action === "copy") {
    if (bubble.dataset.text) {
      try {
        await navigator.clipboard.writeText(bubble.dataset.text);
        toast("Copied to clipboard", "success");
      } catch (error) {
        appendLog(`ERROR: could not copy to clipboard: ${error.message}`);
        toast("Couldn't copy to the clipboard.", "error");
      }
    }
    return;
  }

  if (action === "forward") {
    if (event) showForwardPicker(bubble, event);
    return;
  }

  if (action === "react") {
    if (event) showReactionPicker(bubble, event, bubble);
    return;
  }

  if (action === "edit") {
    if (bubble.dataset.supportsEdit !== "1" || bubble.dataset.mine !== "1") return;
    pendingReplyMessageId = null;
    editingMessageId = messageId;
    editingExpectedVersion = Number(bubble.dataset.editVersion || 0);
    const original = bubble.dataset.text || "";
    setComposerContext({
      mode: "edit",
      title: "Editing message",
      text: original.length > 120 ? original.slice(0, 117) + "…" : original,
    });
    const els = activeComposerElements();
    if (els) {
      els.input.value = bubble.dataset.text || "";
      els.input.focus();
    }
    return;
  }

  if (action === "pin") {
    try {
      session.pinMessage(messageId);
    } catch (error) {
      reportActionError(error);
      return;
    }
    // Optimistic local update, mirrors gui/chat_window.py's identical
    // immediate-feedback comment -- the eventual message_pinned
    // notification simply re-applies the same state, a harmless no-op
    // repeat.
    setBubblePinned(bubble, true, null);
    toast("Message pinned", "success");
    return;
  }

  if (action === "unpin") {
    try {
      session.unpinMessage(messageId);
    } catch (error) {
      reportActionError(error);
      return;
    }
    setBubblePinned(bubble, false);
    toast("Message unpinned");
    return;
  }

  if (action === "delete_me") {
    try {
      session.deleteMessageForMe(messageId);
    } catch (error) {
      reportActionError(error);
      return;
    }
    // No server broadcast for delete-for-me (server/client_handler.py::
    // handle_message_delete_for_me()'s docstring, unchanged from
    // Desktop/Android) -- applied to the bubble directly here.
    markBubbleDeleted(bubble);
    return;
  }

  if (action === "delete_everyone") {
    if (bubble.dataset.mine !== "1") return;
    showConfirmModal(
      "Delete for Everyone?",
      "This message will be permanently deleted for everyone in this " +
        "conversation. This cannot be undone.",
      "Delete",
      () => doDeleteForEveryone(messageId)
    );
    return;
  }
}

function doDeleteForEveryone(messageId) {
  try {
    session.deleteMessageForEveryone(messageId);
  } catch (error) {
    reportActionError(error);
  }
}

function sendReaction(bubble, emoji) {
  const conversationId = bubble.dataset.conversationId;
  if (!conversationId) return;
  try {
    session.addReaction(conversationId, bubble.dataset.messageId, emoji);
  } catch (error) {
    reportActionError(error);
  }
}

async function forwardBubbleTo(bubble, target) {
  // Attachment bubbles (image/file/voice/video) retain their
  // decrypted bytes/mime_type on the element itself (renderAttachment()
  // above) precisely so this branch can forward them for real, through
  // session.forwardAttachment() -- the same normal sendAttachment()
  // pipeline an ordinary send already uses, re-encrypted for the
  // target, never a reuse of the original ciphertext.
  try {
    if (bubble._attachmentBytes) {
      await session.forwardAttachment(
        target, bubble._attachmentBytes, bubble._attachmentFilename || "attachment",
        bubble._attachmentMimeType || "application/octet-stream",
      );
    } else if (bubble.dataset.text) {
      await session.forwardTextMessage(target, bubble.dataset.text);
    }
    toast(`Forwarded to ${target.label}`, "success");
  } catch (error) {
    reportActionError(error);
  }
}

function markBubbleDeleted(bubble) {
  bubble.dataset.deleted = "1";
  bubble.dataset.text = "";
  bubble.classList.add("is-deleted");
  // Remove any content already rendered for this bubble (attachment
  // preview/link, or a pre-existing text node) -- exactly one tombstone
  // node replaces it, regardless of the original payload type.
  // An attachment's timestamp lives inside its action row -- lift it
  // back onto the bubble before that row goes, so the tombstone keeps
  // its time.
  const footer = bubble.querySelector(".bubble-footer");
  if (footer && footer.parentElement !== bubble) bubble.appendChild(footer);
  bubble.querySelectorAll(".bubble-text, .msg-meta, .bubble-image, .msg-image-actions, .bubble-file, .bubble-media, .bubble-reply-preview").forEach((el) => el.remove());
  bubble.classList.remove("is-attachment");
  const textEl = document.createElement("div");
  textEl.className = "bubble-text";
  textEl.textContent = "Message deleted";
  bubble.insertBefore(textEl, bubble.querySelector(".bubble-footer"));
  updateBubbleReactions(bubble, []);
  setBubblePinned(bubble, false);
  refreshRepliesTo(bubble.dataset.messageId);
}

function applyBubbleEdit(bubble, newText, editVersion) {
  if (bubble.dataset.supportsEdit !== "1") return;
  bubble.dataset.text = newText;
  bubble.dataset.editVersion = String(editVersion);
  const textEl = bubble.querySelector(".bubble-text");
  if (textEl) textEl.textContent = newText;
  refreshRepliesTo(bubble.dataset.messageId);
  // Phase 1.5: the edited state lives in the footer, ahead of the time
  // ("edited · 6:53 PM ✓ ✓") -- visible, but quieter than the text.
  const footer = bubble.querySelector(".bubble-footer");
  if (footer && !footer.querySelector(".bubble-edited")) {
    const edited = document.createElement("span");
    edited.className = "bubble-edited";
    edited.textContent = "edited";
    const dot = document.createElement("span");
    dot.className = "bubble-footer-dot";
    dot.setAttribute("aria-hidden", "true");
    dot.textContent = "·";
    footer.prepend(edited, dot);
  }
}

// Reaction chips -- one equal-height chip per distinct emoji, rendered
// as a sibling directly under the bubble (inside its .msg-row) so a
// reaction arriving never reflows the bubble's own text/footer.
// Chips are diffed by emoji rather than rebuilt, so only a genuinely
// new chip plays the entry animation. Tapping a chip reuses the exact
// sendReaction() path the picker uses: someone else's emoji -> react
// with it too; your own -> reopen the picker to change it.
function updateBubbleReactions(bubble, reactions) {
  bubble._reactions = reactions || [];
  let reactionsEl = bubble._reactionsEl;
  if (!reactionsEl) {
    reactionsEl = document.createElement("div");
    reactionsEl.className = "bubble-reactions";
    reactionsEl.setAttribute("role", "group");
    reactionsEl.setAttribute("aria-label", "Reactions");
    bubble._reactionsEl = reactionsEl;
    const row = bubble.parentElement;
    if (row) bubble.after(reactionsEl);
  }
  if (!reactionsEl.isConnected && bubble.parentElement) bubble.after(reactionsEl);

  const groups = new Map(); // emoji -> [usernames], first-reaction order
  for (const entry of bubble._reactions) {
    if (!entry.reaction) continue;
    if (!groups.has(entry.reaction)) groups.set(entry.reaction, []);
    // One person counts once per emoji, however many times the same reaction is replayed.
    if (!groups.get(entry.reaction).includes(entry.user)) groups.get(entry.reaction).push(entry.user);
  }
  if (!groups.size) {
    reactionsEl.replaceChildren();
    reactionsEl.hidden = true;
    return;
  }
  reactionsEl.hidden = false;

  const existing = new Map(
    Array.from(reactionsEl.children).map((chip) => [chip.dataset.emoji, chip])
  );
  for (const [emoji, chip] of existing) {
    if (!groups.has(emoji)) chip.remove();
  }
  let previous = null;
  for (const [emoji, users] of groups) {
    let chip = existing.get(emoji);
    if (!chip) {
      chip = document.createElement("button");
      chip.type = "button";
      chip.className = "reaction-chip is-new";
      chip.dataset.emoji = emoji;
      const emojiEl = document.createElement("span");
      emojiEl.className = "reaction-emoji";
      emojiEl.setAttribute("aria-hidden", "true");
      emojiEl.textContent = emoji;
      const countEl = document.createElement("span");
      countEl.className = "reaction-count";
      chip.append(emojiEl, countEl);
      chip.addEventListener("animationend", () => chip.classList.remove("is-new"), { once: true });
      chip.addEventListener("click", (event) => {
        event.stopPropagation();
        if (chip.classList.contains("is-mine")) {
          showReactionPicker(bubble, event, chip);
        } else {
          sendReaction(bubble, emoji);
        }
      });
    }
    const mine = users.includes(session?.username);
    const count = users.length;
    chip.querySelector(".reaction-count").textContent = String(count);
    chip.classList.toggle("is-mine", mine);
    chip.setAttribute("aria-pressed", mine ? "true" : "false");
    const name = REACTION_NAMES[emoji] || emoji;
    chip.setAttribute(
      "aria-label",
      `${name}: ${count} ${count === 1 ? "reaction" : "reactions"}${mine ? ", including yours" : ""}`
    );
    chip.title = users.map((user) => (user === session?.username ? "You" : nameOf(user))).join(", ");
    if (previous) previous.after(chip);
    else reactionsEl.prepend(chip);
    previous = chip;
  }
}

function setBubblePinned(bubble, pinned, pinnedBy) {
  // Phase 19.24 -- Pinned Messages: shows/hides a small "📌 Pinned by
  // X" marker -- mirrors gui/message_widget.py::MessageBubble.set_
  // pinned() exactly. bubble.dataset.pinned drives buildBubbleContext
  // Actions()'s Pin/Unpin toggle above, and searchMatchingBubbles()/
  // a future "pinned messages" query both read bubble.dataset.text
  // unaffected by this.
  bubble.dataset.pinned = pinned ? "1" : "0";
  if (pinned && bubble.dataset.pinSeq === undefined) bubble.dataset.pinSeq = String(++pinSequence);
  if (!pinned) delete bubble.dataset.pinSeq;
  let pinnedEl = bubble.querySelector(".bubble-pinned");
  queueMicrotask(() => refreshPinnedBar(bubble.closest(".message-scroll")));
  if (!pinned) {
    if (pinnedEl) pinnedEl.remove();
    return;
  }
  if (!pinnedEl) {
    pinnedEl = document.createElement("div");
    pinnedEl.className = "bubble-pinned";
    bubble.insertBefore(pinnedEl, bubble.firstChild);
  }
  pinnedEl.textContent = pinnedBy ? `\u{1F4CC} Pinned by ${pinnedBy === session?.username ? "you" : nameOf(pinnedBy)}` : "\u{1F4CC} Pinned";
}

// Display name for a rendered bubble's author ("You" for your own).
function bubbleAuthor(bubble) {
  if (!bubble) return "";
  if (bubble.dataset.mine === "1") return "You";
  const label = bubble.querySelector(".bubble-sender");
  if (label && label.textContent) return label.textContent;
  return activeDirectPeer || "";
}

// What a reply quotes, for the message it points at: its text, or a label for media (never the
// media itself), or "Message deleted".
const MEDIA_REPLY_LABELS = {
  image: "\u{1F4F7} Photo", voice: "\u{1F3A4} Voice message", video: "\u{1F3AC} Video message",
};
function replyExcerptFor(referenced) {
  if (referenced.dataset.deleted === "1") return "Message deleted";
  const type = referenced.dataset.payloadType;
  if (type && type !== "text") {
    return MEDIA_REPLY_LABELS[type] || `\u{1F4C4} ${referenced._attachmentFilename || "File"}`;
  }
  return referenced.dataset.text || "Message";
}

// Resolve a reply by the original's stable message id -- never by matching text -- and only
// within the same conversation. An original that is not loaded (or not visible to this account)
// is shown as unavailable rather than guessed at.
function applyReplyReference(bubble, replyToMessageId) {
  if (!bubble || !replyToMessageId || bubble.dataset.deleted === "1") return;
  bubble.dataset.replyTo = replyToMessageId;
  let referenced = bubblesByMessageId.get(replyToMessageId) || null;
  if (referenced && (referenced.dataset.conversationId || "") !== (bubble.dataset.conversationId || "")) {
    referenced = null;
  }
  if (referenced) setBubbleReplyPreview(bubble, replyExcerptFor(referenced), referenced);
  else setBubbleReplyPreview(bubble, "Original message unavailable", null, { unavailable: true });
}

function refreshRepliesTo(messageId) {
  if (!messageId) return;
  for (const reply of document.querySelectorAll(`.bubble[data-reply-to="${CSS.escape(messageId)}"]`)) {
    applyReplyReference(reply, messageId);
  }
}

// Phase 1.5: the quoted block names who is being replied to, and
// clicking it jumps to (and briefly highlights) that original message.
function setBubbleReplyPreview(bubble, previewText, referenced = null, { unavailable = false } = {}) {
  if (!previewText) return;
  let replyEl = bubble.querySelector(".bubble-reply-preview");
  if (!replyEl) {
    replyEl = document.createElement("div");
    replyEl.className = "bubble-reply-preview";
    // After the sender name / pin marker, before the content.
    const anchor = bubble.querySelector(".bubble-text, .msg-meta, .bubble-image, .bubble-media, .bubble-file");
    bubble.insertBefore(replyEl, anchor || bubble.firstChild);
  }
  replyEl.classList.toggle("is-unavailable", unavailable);
  const author = document.createElement("span");
  author.className = "reply-author";
  author.textContent = unavailable ? "Reply" : (bubbleAuthor(referenced) || "Reply");
  const text = document.createElement("span");
  text.className = "reply-text";
  text.textContent = previewText.length > 120 ? previewText.slice(0, 117) + "…" : previewText;
  replyEl.replaceChildren(author, text);
  replyEl.classList.remove("is-link");
  replyEl.removeAttribute("title");
  replyEl.removeAttribute("role");
  replyEl.removeAttribute("tabindex");
  replyEl.onclick = null;
  replyEl.onkeydown = null;
  if (referenced) {
    replyEl.classList.add("is-link");
    replyEl.title = "Show the original message";
    replyEl.setAttribute("role", "button");
    replyEl.tabIndex = 0;
    replyEl.onclick = (event) => {
      event.stopPropagation();
      if (!referenced.isConnected) return;
      const container = referenced.closest(".message-scroll");
      if (container) flashBubble(container, referenced);
    };
    replyEl.onkeydown = (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        replyEl.onclick(event);
      }
    };
  }
}

// Navigate to a message and highlight it TEMPORARILY: a soft glow that
// fades back to normal (search results keep their highlight; a pinned/
// reply jump does not).
function flashBubble(container, bubble) {
  highlightSearchMatch(container, bubble);
  bubble.classList.remove("is-flash");
  void bubble.offsetWidth; // restart the animation on repeat jumps
  bubble.classList.add("is-flash");
  clearTimeout(bubble._flashTimer);
  bubble._flashTimer = setTimeout(() => {
    bubble.classList.remove("is-flash");
    if (container._searchHighlighted === bubble) clearSearchHighlight(container);
  }, 2200);
}

// ------------------------------------------------------------------
// Phase 1.5 -- Pinned-message bar (WhatsApp-style): one compact bar
// under the header presenting a single pinned message -- the most
// recently pinned one. The protocol still allows several pins per
// conversation (one-pin enforcement is a Phase 2 backend/state
// change); when there are several, the bar shows "1 of N" and each
// click jumps to the shown one, then advances to the next.
// ------------------------------------------------------------------

let pinSequence = 0;

function pinnedBarFor(container) {
  return document.getElementById(container === groupMessagesEl ? "groupPinnedBar" : "pinnedBar");
}

function orderedPinnedBubbles(container) {
  return getPinnedBubbles(container).sort(
    (a, b) => Number(b.dataset.pinSeq || 0) - Number(a.dataset.pinSeq || 0)
  );
}

function refreshPinnedBar(container) {
  const bar = container && pinnedBarFor(container);
  if (!bar) return;
  const pinned = orderedPinnedBubbles(container);
  // The unpin affordance lives in the same wrapper as the bar button, so
  // both show/hide together -- the bar button keeps its own hidden flag
  // for anything that still reads it directly.
  const wrap = bar.closest(".pinned-bar-wrap") || bar;
  if (!pinned.length) {
    bar.hidden = true;
    wrap.hidden = true;
    bar._activeBubble = null;
    container._pinCursor = 0;
    return;
  }
  const index = (container._pinCursor || 0) % pinned.length;
  container._pinCursor = index;
  const bubble = pinned[index];
  const text = bubble.dataset.text || attachmentPreview(bubble.dataset.payloadType, { filename: bubble._attachmentFilename });
  bar.querySelector(".pinned-bar-label").textContent =
    pinned.length > 1 ? `Pinned message · ${index + 1} of ${pinned.length}` : "Pinned message";
  // Sender + timestamp on the banner, exactly like a WhatsApp/Signal
  // pin: "You: text · 8:30 PM" (the time only when the bubble has one).
  const when = bubble.querySelector(".bubble-time")?.textContent || "";
  bar.querySelector(".pinned-bar-text").textContent =
    `${bubbleAuthor(bubble)}: ${text}${when ? ` · ${when}` : ""}`;
  bar.setAttribute("aria-label", `Pinned message from ${bubbleAuthor(bubble)}: ${text}. Show in conversation.`);
  bar._activeBubble = bubble;
  bar.hidden = false;
  wrap.hidden = false;
}

for (const [barId, getContainer] of [["pinnedBar", () => messagesEl], ["groupPinnedBar", () => groupMessagesEl]]) {
  document.getElementById(barId)?.addEventListener("click", () => {
    const container = getContainer();
    const pinned = orderedPinnedBubbles(container);
    if (!pinned.length) return;
    const index = (container._pinCursor || 0) % pinned.length;
    flashBubble(container, pinned[index]);
    container._pinCursor = (index + 1) % pinned.length;
    refreshPinnedBar(container);
  });
}

// Unpin from the banner itself -- the SAME real message_unpin round trip
// the context menu's Unpin runs (handleBubbleContextAction), never a
// local-only clear, so every member's banner clears with it. Sits in the
// wrapper, not inside the bar button, so it is a separate focusable
// control rather than an interactive element nested in one.
for (const [btnId, getContainer] of [["pinnedUnpinBtn", () => messagesEl], ["groupPinnedUnpinBtn", () => groupMessagesEl]]) {
  document.getElementById(btnId)?.addEventListener("click", (event) => {
    event.stopPropagation();
    const bar = pinnedBarFor(getContainer());
    const bubble = bar && bar._activeBubble;
    if (!bubble || !bubble.isConnected || bubble.dataset.pinned !== "1") return;
    handleBubbleContextAction("unpin", bubble, event);
  });
}

function setTickStatus(span, status) {
  span.dataset.status = status;
  span.replaceChildren();
  // Phase 1.5: each check is its OWN element in a flex row with a fixed
  // 2px gap (style.css .msg-tick) -- never one glyph/path pair that can
  // read as a single merged mark.
  const checks = TICK_SHAPE[status] || 0;
  for (let i = 0; i < checks; i += 1) {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("class", "tick-svg");
    svg.setAttribute("viewBox", "0 0 9 11");
    svg.setAttribute("width", "9");
    svg.setAttribute("height", "11");
    svg.setAttribute("aria-hidden", "true");
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", TICK_PATH);
    svg.appendChild(path);
    span.appendChild(svg);
  }
  // Shape carries the state; the label makes it explicit for screen
  // readers and on hover, so it never relies on colour alone.
  const label = TICK_LABEL[status] || "";
  span.setAttribute("role", "img");
  span.setAttribute("aria-label", label);
  span.title = label;
  // .tick-read: style.css's --read-tick, a lighter tint of Desktop's
  // COLOR_READ_RECEIPT blue so it stays legible on the sent bubble.
  span.classList.toggle("tick-read", status === "read");
}

function resolveOldestUnackedSentTick(peerUsername, status) {
  const spans = pendingSentTicksByPeer[peerUsername];
  if (!spans || !spans.length) return;
  if (status === "read") {
    // A read receipt is a conversation-wide "read up to now" watermark
    // (server/client_handler.py's own C2 Read Receipts design), not a
    // per-message id -- mirrors mobile/app.py's _on_read_receipt()
    // sweeping every tracked bubble at once, for the identical reason.
    for (const span of spans) setTickStatus(span, "read");
    return;
  }
  const target = spans.find((span) => span.dataset.status === "sent");
  if (target) setTickStatus(target, status);
}

// Appends a tick <span> to ``footer`` for a "mine" bubble in the
// direct panel only, and registers it for later live resolution.
// ``initialStatus`` is "sent" for a live send (nothing has been
// acknowledged yet) or the real historical status (sent/delivered/
// read) restored from history's own additive delivery_status field --
// see app.js::loadHistory()'s own status computation.
function appendSentTick(footer, container, initialStatus) {
  if (container !== messagesEl || !activeDirectPeer) return;
  const span = document.createElement("span");
  span.className = "msg-tick";
  setTickStatus(span, initialStatus || "sent");
  footer.appendChild(span);
  if (!pendingSentTicksByPeer[activeDirectPeer]) pendingSentTicksByPeer[activeDirectPeer] = [];
  pendingSentTicksByPeer[activeDirectPeer].push(span);
}

// Phase 19.24 (continued): key used for pendingSentBubblesByKey /
// onMessageDelivered's own resolution -- the peer username for a
// direct send (group sends get no per-recipient ack at all, mirroring
// every other client, so this is never consulted for one).
function currentSentBubbleKey(container) {
  return container === messagesEl ? activeDirectPeer : null;
}

function currentConversationId(container) {
  if (container === groupMessagesEl) return activeGroupIdEl.value || null;
  if (container === messagesEl && activeDirectPeer) {
    return session?.directConversationIds.get(activeDirectPeer) || null;
  }
  return null;
}

// Phase 1 UI polish -- a "Today"/"Yesterday"/date divider whenever the
// calendar day changes between consecutive rows in a panel. Purely
// derived from each row's own timestamp; never a .bubble, so search/
// pinned/gallery (which only query .bubble) are unaffected.
function insertDateSeparatorIfNeeded(container, date) {
  if (!date) return;
  const dayKey = date.toDateString();
  const separators = container.querySelectorAll(".date-sep");
  const last = separators[separators.length - 1];
  if (last && last.dataset.day === dayKey) return;
  const separator = document.createElement("div");
  separator.className = "date-sep";
  separator.setAttribute("role", "separator");
  separator.dataset.day = dayKey;
  separator.textContent = formatDayLabel(date);
  container.appendChild(separator);
}

// Consecutive rows from the same sender visually group (tighter
// spacing, sender name shown once, joined corners).
function isContinuationOf(container, senderKey) {
  const previous = container.lastElementChild;
  return !!previous && previous.classList.contains("msg-row")
    && !previous.classList.contains("is-failed-row")
    && previous.dataset.sender === senderKey;
}

// Desktop hover toolbar: React / Reply / More -- shortcuts into the
// exact same handlers the right-click menu runs. Hidden entirely on
// touch devices (style.css), where long-press -> contextmenu remains
// the entry point; never needed for any action to be reachable.
function buildHoverActions(bubble) {
  const bar = document.createElement("div");
  bar.className = "msg-actions";
  bar.setAttribute("role", "toolbar");
  bar.setAttribute("aria-label", "Message actions");
  const buttons = [
    ["react", "smile", "React"],
    ["reply", "reply", "Reply"],
    ["more", "more", "More actions"],
  ];
  for (const [action, iconName, label] of buttons) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "msg-action-btn";
    btn.setAttribute("aria-label", label);
    btn.title = label;
    btn.appendChild(icon(iconName));
    btn.addEventListener("click", (event) => {
      event.stopPropagation();
      if (action === "more") showBubbleContextMenu(bubble, event, btn);
      else if (action === "react") showReactionPicker(bubble, event, btn);
      else handleBubbleContextAction(action, bubble, event);
    });
    bar.appendChild(btn);
  }
  return bar;
}

function bubbleShell(container, sender, options, extraClass) {
  const mine = sender === "me" || sender === session?.username;
  const senderKey = mine ? "\u0000me" : sender;
  insertDateSeparatorIfNeeded(container, messageDate(options));
  const continued = isContinuationOf(container, senderKey);
  const row = document.createElement("div");
  row.className = `msg-row ${mine ? "is-mine" : "is-theirs"}${options.historical ? " is-historical" : ""}${continued ? " is-continued" : ""}${extraClass ? " " + extraClass : ""}`;
  row.dataset.sender = senderKey;
  const bubble = document.createElement("div");
  bubble.className = "bubble";
  // Focusable so the message actions are keyboard-reachable: the
  // context-menu key, Shift+F10 or Enter opens the same menu a
  // right-click does.
  bubble.tabIndex = 0;
  if (!mine) {
    const senderLabel = document.createElement("div");
    senderLabel.className = "bubble-sender";
    senderLabel.dataset.handle = sender;
    senderLabel.textContent = nameOf(sender);
    requestDisplayNames([sender]);
    bubble.appendChild(senderLabel);
  }
  row.appendChild(bubble);
  row.appendChild(buildHoverActions(bubble));
  container.appendChild(row);
  container.scrollTop = container.scrollHeight;

  // Phase 19.24 (continued) -- Message Lifecycle Events UI.
  bubble.dataset.mine = mine ? "1" : "0";
  bubble.dataset.conversationId = currentConversationId(container) || "";
  bubble.addEventListener("contextmenu", (event) => showBubbleContextMenu(bubble, event));
  bubble.addEventListener("keydown", (event) => {
    if (event.target !== bubble) return;
    if (event.key === "ContextMenu" || (event.key === "F10" && event.shiftKey) || event.key === "Enter") {
      showBubbleContextMenu(bubble, event, bubble);
    }
  });

  const messageId = options.messageId;
  if (messageId) {
    registerBubbleMessageId(bubble, messageId);
  } else if (mine && !options.historical) {
    const key = currentSentBubbleKey(container);
    if (key) {
      if (!pendingSentBubblesByKey[key]) pendingSentBubblesByKey[key] = [];
      pendingSentBubblesByKey[key].push(bubble);
    }
  }

  return bubble;
}

function renderTextMessage(container, sender, text, options = {}) {
  const bubble = bubbleShell(container, sender, options);
  bubble.dataset.text = text;
  bubble.dataset.supportsEdit = "1";
  const textEl = document.createElement("div");
  textEl.className = "bubble-text";
  textEl.textContent = text;
  bubble.appendChild(textEl);
  // A historical row now shows its real send time (history entries
  // carry it) instead of the literal word "history".
  const footer = buildFooter(options);
  bubble.appendChild(footer);

  const mine = sender === "me" || sender === session?.username;
  if (mine) appendSentTick(footer, container, options.status);

  // Phase 19.24 (continued): a HISTORICAL row already carries its
  // full lifecycle state (reply target/deleted/edited/reactions)
  // directly -- unlike a live one, which only ever carries
  // messageId/replyToMessageId at render time (see loadHistory()'s
  // own comment for why history alone can supply all of this in one
  // pass, with no separate live-only round trip needed).
  if (options.isDeleted) {
    markBubbleDeleted(bubble);
    return;
  }
  if (options.editVersion) applyBubbleEdit(bubble, text, options.editVersion);
  if (options.replyToMessageId) applyReplyReference(bubble, options.replyToMessageId);
  if (options.reactions && options.reactions.length) updateBubbleReactions(bubble, options.reactions);
  if (options.isPinned) setBubblePinned(bubble, true, options.pinnedBy);
}

// ------------------------------------------------------------------
// Phase 19.24 -- Message Retry. Desktop/Mobile already benefit from
// this via ClientSession.send_chat_message()'s/MobileClientSession.
// send_message()'s client_message_id idempotency (Task 2/Phase
// 19.24) -- this closes the same gap on Web, which previously just
// logged the error to #log and left the typed text sitting in the
// composer, with no persistent, visible record in the transcript that
// a message failed, and no dedicated way to resend it.
//
// Deliberately NOT built on bubbleShell(): a failed bubble has no
// server-assigned message_id and NEVER will (the send never reached
// the server) -- bubbleShell()'s own "no messageId -> push onto
// pendingSentBubblesByKey, awaiting a delivered/queued tick" branch
// would leave it occupying a slot a later, genuinely-sent message's
// real ack needs, exactly the FIFO-leak class of bug this mirrors
// fixing on mobile/app.py's identical _bubbles_awaiting_message_id.
// ------------------------------------------------------------------

function renderFailedBubble(container, text, { replyToMessageId, clientMessageId, peerUsername, conversationId, isGroup }) {
  insertDateSeparatorIfNeeded(container, new Date());
  const row = document.createElement("div");
  row.className = "msg-row is-mine is-failed-row";
  if (isContinuationOf(container, "\u0000me")) row.classList.add("is-continued");
  const bubble = document.createElement("div");
  bubble.className = "bubble is-failed";
  bubble.dataset.mine = "1";
  bubble.dataset.text = text;

  const textEl = document.createElement("div");
  textEl.className = "bubble-text";
  textEl.textContent = text;
  bubble.appendChild(textEl);

  bubble.appendChild(buildFooter({}));

  // The failure + Retry sit under the bubble on the chat background
  // (red on purple was unreadable), as an icon + words, not colour
  // alone.
  const status = document.createElement("div");
  status.className = "msg-failed-status";
  status.setAttribute("role", "status");
  const statusText = document.createElement("span");
  statusText.textContent = "Failed to send";
  status.append(icon("alert"), statusText);

  const retryBtn = document.createElement("button");
  retryBtn.type = "button";
  retryBtn.className = "bubble-retry-btn";
  const retryLabel = document.createElement("span");
  retryLabel.textContent = "Retry";
  retryBtn.append(icon("retry"), retryLabel);
  retryBtn.addEventListener("click", () => {
    retryBtn.disabled = true;
    retryLabel.textContent = "Retrying…";
    const sendPromise = isGroup
      ? session.sendGroupMessage(conversationId, text, replyToMessageId, clientMessageId)
      : session.sendMessage(peerUsername, text, replyToMessageId, clientMessageId);
    sendPromise
      .then(() => {
        row.remove();
        renderTextMessage(container, "me", text, { replyToMessageId });
      })
      .catch((error) => {
        reportActionError(error);
        retryBtn.disabled = false;
        retryLabel.textContent = "Retry";
      });
  });
  status.appendChild(retryBtn);

  row.appendChild(bubble);
  row.appendChild(status);
  container.appendChild(row);
  container.scrollTop = container.scrollHeight;
  return bubble;
}

function _buildMediaSaveLink(objectUrl, filename) {
  const saveLink = document.createElement("a");
  saveLink.className = "media-action";
  saveLink.href = objectUrl;
  saveLink.download = filename;
  saveLink.setAttribute("aria-label", `Save ${filename}`);
  const label = document.createElement("span");
  label.textContent = "Save";
  saveLink.append(icon("download"), label);
  return saveLink;
}

// The row under an image/voice/video: its actions on the left, the
// timestamp (+ ticks) on the right, on one line.
function _buildMediaActionRow(...actions) {
  const row = document.createElement("div");
  row.className = "msg-image-actions";
  row.append(...actions);
  return row;
}

const FILE_EXTENSION_PATTERN = /\.([a-z0-9]{1,5})$/i;

// Phase 18 -- a decrypted FILE renders as a downloadable object URL
// link; an IMAGE renders directly as an <img> -- both built from the
// SAME decrypted bytes app.js's onAttachment callback already
// authenticated and decrypted; this file never touches ciphertext or
// key material, only the plaintext bytes handed to it. Phase 19.24 --
// VOICE/VIDEO render the browser's own native <audio>/<video controls>
// element, same reasoning.
function renderAttachment(container, sender, payloadType, bytes, contentMetadata, options = {}) {
  const bubble = bubbleShell(container, sender, options);
  // Edit is TEXT-only (mirrors ClientSession.edit_message()'s own
  // scope) -- an attachment bubble never offers it. Forward, unlike
  // Edit, DOES support attachments -- see forwardBubbleTo()'s own
  // comment for why the bytes/metadata below are what makes that
  // possible (previously discarded after building the playable/
  // viewable element, the same gap Desktop/Mobile had).
  bubble.dataset.supportsEdit = "0";
  bubble._attachmentBytes = bytes;
  bubble._attachmentFilename = contentMetadata.filename || null;
  bubble._attachmentMimeType = contentMetadata.mime_type || null;
  bubble.dataset.payloadType = payloadType;
  bubble.classList.add("is-attachment");

  if (options.isDeleted) {
    bubble.appendChild(buildFooter(options));
    markBubbleDeleted(bubble);
    return;
  }
  if (options.reactions && options.reactions.length) updateBubbleReactions(bubble, options.reactions);
  if (options.isPinned) setBubblePinned(bubble, true, options.pinnedBy);

  const meta = document.createElement("div");
  meta.className = "msg-meta";
  // Voice/video are labeled by payloadType, not filename, to match
  // Desktop/Mobile's fixed "Voice message"/"Video message" bubble
  // label (the recorder always sets a real filename like
  // "voice-message.webm", which would otherwise leak the raw filename
  // into the label instead of the canonical, cross-platform text).
  meta.textContent = { voice: "Voice message", video: "Video message" }[payloadType]
    || contentMetadata.filename
    || (payloadType === "image" ? "image" : "file");
  bubble.appendChild(meta);

  const blob = new Blob([bytes], { type: contentMetadata.mime_type || "application/octet-stream" });
  const objectUrl = URL.createObjectURL(blob);
  const footer = buildFooter(options);

  if (payloadType === "voice") {
    // Phase 19.24 -- Voice Messages: the browser's own native <audio>
    // element IS the real playback control -- no custom player code
    // needed, and it never touches disk (objectUrl is an in-memory
    // Blob URL, released the moment this bubble is gone).
    const audio = document.createElement("audio");
    audio.className = "bubble-media";
    audio.controls = true;
    audio.src = objectUrl;
    bubble.appendChild(audio);
    bubble.appendChild(_buildMediaActionRow(
      _buildMediaSaveLink(objectUrl, contentMetadata.filename || "voice-message"), footer
    ));
  } else if (payloadType === "video") {
    const video = document.createElement("video");
    video.className = "bubble-media";
    video.controls = true;
    video.src = objectUrl;
    bubble.appendChild(video);
    bubble.appendChild(_buildMediaActionRow(
      _buildMediaSaveLink(objectUrl, contentMetadata.filename || "video-message"), footer
    ));
  } else if (payloadType === "image") {
    const img = document.createElement("img");
    img.className = "bubble-image msg-image";
    img.src = objectUrl;
    img.alt = contentMetadata.filename || "received image";
    img.decoding = "async";
    img.addEventListener("click", () => openLightbox(objectUrl));
    bubble.appendChild(img);

    // Phase 19.23 -- Issue 4: explicit, always-visible View/Save
    // controls -- previously an image bubble offered no button at
    // all, only a click-to-zoom on the image itself with no save
    // affordance whatsoever (a file attachment already had its own
    // always-visible download link a few lines below; an image had
    // no equivalent). Nothing here is hidden behind :hover; they share
    // one row with the timestamp.
    const viewBtn = document.createElement("button");
    viewBtn.type = "button";
    viewBtn.className = "media-action";
    viewBtn.setAttribute("aria-label", `View ${img.alt}`);
    const viewLabel = document.createElement("span");
    viewLabel.textContent = "View";
    viewBtn.append(icon("expand"), viewLabel);
    viewBtn.addEventListener("click", () => openLightbox(objectUrl));
    bubble.appendChild(_buildMediaActionRow(
      viewBtn, _buildMediaSaveLink(objectUrl, contentMetadata.filename || "image"), footer
    ));
  } else {
    // A file renders as an attachment card: type icon + extension,
    // filename, human-readable size, download affordance. The whole
    // card is the (unchanged) download link.
    const filename = contentMetadata.filename || "download";
    const sizeBytes = contentMetadata.size_bytes || bytes.length;
    const extension = (filename.match(FILE_EXTENSION_PATTERN) || [])[1] || "";
    const link = document.createElement("a");
    link.className = "bubble-file msg-file";
    link.href = objectUrl;
    link.download = filename;
    link.title = `Download ${filename}`;
    const iconBox = document.createElement("span");
    iconBox.className = "file-icon";
    iconBox.appendChild(icon("file"));
    if (extension) {
      const ext = document.createElement("span");
      ext.className = "file-ext";
      ext.textContent = extension;
      iconBox.appendChild(ext);
    }
    const info = document.createElement("span");
    info.className = "file-info";
    const nameEl = document.createElement("span");
    nameEl.className = "file-name";
    nameEl.textContent = filename;
    const sizeEl = document.createElement("span");
    sizeEl.className = "file-size";
    sizeEl.textContent = formatBytes(sizeBytes);
    info.append(nameEl, sizeEl);
    const download = document.createElement("span");
    download.className = "file-download";
    download.appendChild(icon("download"));
    const downloadLabel = document.createElement("span");
    downloadLabel.className = "sr-only";
    downloadLabel.textContent = "Download";
    download.appendChild(downloadLabel);
    link.append(iconBox, info, download);
    bubble.appendChild(link);
    bubble.appendChild(footer);
  }

  const mine = sender === "me" || sender === session?.username;
  if (mine) appendSentTick(footer, container, options.status);
  if (options.replyToMessageId) applyReplyReference(bubble, options.replyToMessageId);
}

// Full-screen image viewer: visible close button (focused on open),
// Escape (global keydown handler) and a click anywhere close it.
function openLightbox(objectUrl) {
  const box = document.createElement("div");
  box.className = "lightbox";
  box.setAttribute("role", "dialog");
  box.setAttribute("aria-modal", "true");
  box.setAttribute("aria-label", "Image preview");
  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "lightbox-close";
  closeBtn.setAttribute("aria-label", "Close image preview");
  closeBtn.appendChild(icon("x"));
  closeBtn.addEventListener("click", (event) => {
    event.stopPropagation();
    dismissOverlay(box);
  });
  const img = document.createElement("img");
  img.src = objectUrl;
  img.alt = "";
  box.append(closeBtn, img);
  box._returnFocus = document.activeElement;
  box.addEventListener("click", (event) => {
    if (event.target === box) dismissOverlay(box);
  });
  document.body.appendChild(box);
  closeBtn.focus({ preventScroll: true });
}

// Phase 19.17C -- profile pictures. Fills an .avatar element with a
// real photo (crop-to-fill via .avatar img's own CSS, never
// stretched) instead of its initial-letter fallback, and makes it
// open the same read-only openLightbox() an attachment image already
// uses -- no raw blob id or file path is ever shown, just the decoded
// bytes as an object URL like every other image in this app.
function setAvatarImage(el, bytes, contentType) {
  const blob = new Blob([bytes], { type: contentType || "image/png" });
  const objectUrl = URL.createObjectURL(blob);
  el.innerHTML = "";
  const img = document.createElement("img");
  img.src = objectUrl;
  img.alt = "Profile picture";
  el.appendChild(img);
  el.style.cursor = "pointer";
  el.onclick = () => openLightbox(objectUrl);
}

function resetAvatarInitial(el, initial) {
  el.innerHTML = "";
  el.textContent = initial;
  el.style.cursor = "";
  el.onclick = null;
}

// The enlarged picture viewer: the real picture, or a polished placeholder when there is none.
// For this account's own picture it is also the one place "Change picture" lives.
async function showProfilePictureViewer(username) {
  if (!session || !username) return;
  const isOwn = username === session.username;
  const overlay = document.createElement("div");
  overlay.className = "confirm-modal picture-viewer";
  const card = document.createElement("div");
  card.className = "confirm-modal-card picture-viewer-card";
  card.setAttribute("role", "dialog");
  card.setAttribute("aria-modal", "true");
  overlay.appendChild(card);

  const big = document.createElement("div");
  big.className = "avatar xl";
  big.dataset.tone = avatarTone(username);
  big.textContent = initialOf(nameOf(username));
  big.setAttribute("aria-hidden", "true");
  card.appendChild(big);

  const nameEl = document.createElement("div");
  nameEl.className = "confirm-modal-title";
  nameEl.id = `picture-title-${Date.now()}`;
  nameEl.textContent = isOwn ? "Your profile picture" : nameOf(username);
  card.setAttribute("aria-labelledby", nameEl.id);
  card.appendChild(nameEl);

  const handleEl = document.createElement("div");
  handleEl.className = "profile-handle";
  handleEl.textContent = `@${username}`;
  card.appendChild(handleEl);

  const captionEl = document.createElement("div");
  captionEl.className = "confirm-modal-message picture-caption";
  captionEl.textContent = "Loading...";
  card.appendChild(captionEl);

  const actionsRow = document.createElement("div");
  actionsRow.className = "confirm-modal-actions";
  let changeBtn = null;
  if (isOwn) {
    changeBtn = document.createElement("button");
    changeBtn.type = "button";
    changeBtn.id = "pictureChangeBtn";
    changeBtn.className = "btn btn-primary btn-sm";
    changeBtn.textContent = "Change picture";
    changeBtn.addEventListener("click", () => {
      dismissOverlay(overlay);
      document.getElementById("profilePicInput").click();
    });
    actionsRow.appendChild(changeBtn);
  }
  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "btn btn-ghost btn-sm";
  closeBtn.textContent = "Close";
  closeBtn.addEventListener("click", () => dismissOverlay(overlay));
  actionsRow.appendChild(closeBtn);
  card.appendChild(actionsRow);

  mountOverlay(overlay, closeBtn);

  const refresh = async () => {
    let picture = null;
    try { picture = await session.fetchProfilePicture(username); } catch { picture = null; }
    if (!overlay.isConnected) return;
    if (picture) {
      const url = URL.createObjectURL(new Blob([picture.bytes], { type: picture.contentType || "image/png" }));
      big.replaceChildren();
      const img = document.createElement("img");
      img.src = url;
      img.alt = "";
      big.appendChild(img);
      captionEl.textContent = "";
      captionEl.hidden = true;
      if (changeBtn) changeBtn.textContent = "Change picture";
    } else {
      captionEl.hidden = false;
      captionEl.textContent = isOwn
        ? "You haven't added a profile picture yet."
        : `${nameOf(username)} hasn't added a profile picture.`;
      if (changeBtn) changeBtn.textContent = "Add a picture";
    }
  };
  await refresh();
}

// Best-effort: a peer with no uploaded picture, or a fetch failure
// (offline peer, transient error), silently keeps the initial-letter
// fallback that's already showing -- never blocks or errors the chat
// screen itself over a missing/failed avatar.
async function loadPeerAvatar(el, username, initial) {
  resetAvatarInitial(el, initial);
  // Whether or not there is a picture, selecting the avatar opens the viewer (a placeholder says
  // so plainly) -- there is no separate "profile picture" control.
  el.style.cursor = "pointer";
  el.onclick = () => showProfilePictureViewer(username);
  if (!session) return;
  try {
    const picture = await session.fetchProfilePicture(username);
    if (picture && el.isConnected) {
      setAvatarImage(el, picture.bytes, picture.contentType);
      el.onclick = () => showProfilePictureViewer(username);
    }
  } catch { /* keep the initial-letter fallback */ }
}

// ------------------------------------------------------------------
// Sidebar: direct-chat list (UI-only bookkeeping, see knownDirectPeers)
// ------------------------------------------------------------------

// Phase 19.24 -- Archive: local-only filter, mirrors gui/chat_
// window.py's self._show_archived/mobile/app.py's identical flag --
// flipped only by #archivedChatsToggle/#archivedGroupsToggle below.
let showArchivedChats = false;
let showArchivedGroups = false;

// Local narrowing of the lists already on screen: the search box's text (a
// case-insensitive name match) and the "unread only" toggle. Nothing is sent
// anywhere.
//
// The search box has a second job -- it holds the open chat's username, and
// typing a username there opens that chat -- so its text only counts as a
// SEARCH while (a) it differs from the open chat's name and (b) it matches at
// least one existing conversation. Typing a brand-new username therefore never
// empties the list, and an open chat never filters the Groups tab away.
let sidebarUnreadOnly = false;
function searchText() {
  return (document.getElementById("peerUsername")?.value || "").trim().toLowerCase();
}
// Groups: a search that matches no group (e.g. a phone number being looked up) leaves the
// Groups tab as it is rather than emptying it.
function effectiveFilterText(labels) {
  const value = searchText();
  if (!value) return "";
  return labels.some((label) => String(label).toLowerCase().includes(value)) ? value : "";
}
function passesSidebarFilter(label, activity, filterText) {
  if (sidebarUnreadOnly && !activity?.unread) return false;
  return !filterText || String(label).toLowerCase().includes(filterText);
}

function renderChatList() {
  chatListEl.innerHTML = "";
  const allPeers = Array.from(knownDirectPeers).filter(
    (peer) => Boolean(session?.isConversationArchived(peer)) === showArchivedChats
  );
  requestDisplayNames(allPeers);
  const filterText = searchText();
  const peers = allPeers.filter((peer) => passesSidebarFilter(
    `${nameOf(peer)} ${peer}`, conversationActivity.get(activityKey(false, peer)), filterText
  ));
  if (peers.length === 0) {
    chatListEl.innerHTML = sidebarUnreadOnly && allPeers.length > 0
      ? '<div class="empty-hint">No unread chats.</div>'
      : showArchivedChats
        ? '<div class="empty-hint">No archived chats.</div>'
        : filterText
          ? '<div class="empty-hint">No chats match. Press Enter to look this person up and start a chat.</div>'
          : '<div class="empty-hint">Search a phone number or username, then press Enter to start a chat.</div>';
    renderStartChatSuggestion(filterText);
    return;
  }
  const onlineUsers = session?.onlineUsers || new Set();
  for (const peer of peers) {
    const row = document.createElement("div");
    const selected = peer === activeDirectPeer;
    row.className = `row-card${selected ? " is-selected" : ""}`;
    const muted = session?.isConversationMuted(peer);
    const online = onlineUsers.has(peer);
    const activity = conversationActivity.get(activityKey(false, peer));
    const subtitle = activity?.preview || (online ? "Online" : "Direct message");
    if (activity?.unread) row.classList.add("has-unread");
    row.innerHTML = `
      <div class="avatar" data-tone="${avatarTone(peer)}">${escapeHtml(initialOf(nameOf(peer)))}<span class="presence-dot${online ? " is-online" : ""}"></span></div>
      <div class="row-main">
        <div class="row-title">${nameWithHandleHtml(peer)}</div>
        <div class="row-sub${!activity?.preview && online ? " is-online" : ""}">${escapeHtml(subtitle)}</div>
      </div>${rowMetaHtml(activity, muted, peer)}`;
    // Keyboard-operable row: focusable, Enter/Space opens it.
    row.tabIndex = 0;
    if (selected) row.setAttribute("aria-current", "true");
    row.addEventListener("click", () => openDirectChat(peer));
    row.addEventListener("keydown", (event) => {
      if (event.target === row && (event.key === "Enter" || event.key === " ")) {
        event.preventDefault();
        openDirectChat(peer);
      }
    });
    row.querySelector(".row-mute-btn").addEventListener("click", (event) => {
      showMuteMenu(peer, event, renderChatList);
    });
    chatListEl.appendChild(row);
  }
  renderStartChatSuggestion(filterText);
  updateTabBadges();
}

// Search results are separate from the conversation list: a "Start chat" action, never a new row.
function renderStartChatSuggestion(filterText) {
  const query = (document.getElementById("peerUsername")?.value || "").trim();
  if (!filterText || !query || showArchivedChats) return;
  const known = Array.from(knownDirectPeers).some(
    (peer) => peer.toLowerCase() === query.toLowerCase() || nameOf(peer).toLowerCase() === query.toLowerCase()
  );
  if (known) return;
  const suggestion = document.createElement("div");
  suggestion.className = "search-result";
  suggestion.innerHTML = `
    <div class="search-result-text">
      <div class="search-result-title">${escapeHtml(query)}</div>
      <div class="search-result-sub">${looksLikePhoneNumber(query) ? "Look up this phone number" : "Look up this username"}</div>
    </div>`;
  const startBtn = document.createElement("button");
  startBtn.type = "button";
  startBtn.className = "btn btn-primary btn-xs";
  startBtn.id = "startChatBtn";
  startBtn.textContent = "Start chat";
  startBtn.addEventListener("click", () => startChatFromSearch(query));
  suggestion.appendChild(startBtn);
  chatListEl.appendChild(suggestion);
}

// The ONLY way a search turns into a chat: an explicit Enter or "Start chat".
async function startChatFromSearch(query) {
  const text = (query || "").trim();
  if (!text || !session) return;
  let handle = text;
  if (looksLikePhoneNumber(text)) {
    try {
      const found = await session.lookupUserByPhone(text);
      if (!found) { toast("No account uses that phone number.", "error"); return; }
      handle = found.username;
    } catch (error) {
      toast(error.message, "error");
      return;
    }
  }
  document.getElementById("peerUsername").value = "";
  openDirectChat(handle);
}

document.getElementById("peerUsername").addEventListener("input", () => {
  renderChatList();
  if (session) renderGroupList();
});
// A verified contact shows one concise line ("Verified" + Re-verify). The safety-number comparison
// lives in the details below it: always open while the contact is NOT verified (that is when the
// comparison is needed), and opened on demand -- by Re-verify or the chevron -- once they are.
let safetyDetailsRequested = false;
function setSafetyDetailsRequested(open) {
  safetyDetailsRequested = open;
  renderPeerIdentity(activeDirectPeer);
  if (open) document.getElementById("confirmVerifiedBtn").focus({ preventScroll: true });
}
document.getElementById("securityBarToggle").addEventListener("click", () => setSafetyDetailsRequested(!safetyDetailsRequested));
document.getElementById("reverifyBtn").addEventListener("click", () => setSafetyDetailsRequested(true));

// Your own number is not on display all the time: it appears, next to the number you are comparing,
// only when asked for.
document.getElementById("showOwnNumberBtn").addEventListener("click", (event) => {
  const panel = document.getElementById("ownNumberPanel");
  const open = panel.hidden;
  panel.hidden = !open;
  event.currentTarget.setAttribute("aria-expanded", String(open));
  event.currentTarget.textContent = open ? "Hide my safety number" : "Show my safety number";
  document.getElementById("ownNumberPeer").textContent = nameOf(activeDirectPeer);
  if (open) loadOwnSafetyNumber();
});

document.getElementById("unreadFilterToggle").addEventListener("click", (event) => {
  sidebarUnreadOnly = !sidebarUnreadOnly;
  event.currentTarget.setAttribute("aria-pressed", String(sidebarUnreadOnly));
  event.currentTarget.classList.toggle("is-active", sidebarUnreadOnly);
  renderChatList();
  if (session) renderGroupList();
});
// Header shortcuts: both do exactly what the existing controls already do.
document.getElementById("newChatHeaderBtn").addEventListener("click", () => {
  document.querySelector('.tab-btn[data-tab="chats"]').click();
  document.getElementById("peerUsername").focus();
});
document.getElementById("newGroupHeaderBtn").addEventListener("click", () => {
  document.querySelector('.tab-btn[data-tab="groups"]').click();
  openGroupCreateModal();
});

document.getElementById("archivedChatsToggle").addEventListener("click", () => {
  showArchivedChats = !showArchivedChats;
  document.getElementById("archivedChatsToggle").textContent = showArchivedChats ? "Back to Chats" : "Archived";
  renderChatList();
});

// Phase 19.17C -- a LIVE direct message's identityKey is the peer's
// username (WebClientSession._handleChat(): "conversationId || sender",
// and conversationId is unset for a direct packet); a HISTORICAL one
// (loadHistory()) is the real conversation_id (UUID) instead -- mirrors
// mobile/app.py::_resolve_identity_key()'s own docstring on this exact
// same split. Translated back to one consistent per-peer key so the
// sidebar never shows a raw UUID row and "is this the open chat?"
// comparisons work for both live and historical messages alike.
function resolveDirectPeerKey(identityKey) {
  if (session?.groups.has(identityKey)) return identityKey;
  for (const [peer, conversationId] of session?.directConversationIds || []) {
    if (conversationId === identityKey) return peer;
  }
  return identityKey;
}

// ------------------------------------------------------------------
// Phase 19.24 -- Presence/Last Seen: mirrors gui/chat_window.py::
// _refresh_presence_label()'s today/yesterday/date phrasing and
// "Online" the exact same way session.onlineUsers already tells every
// other presence indicator in this file. fetchLastSeen() is a real
// server round trip (WebClientSession.fetchLastSeen()) -- server/
// client_handler.py::handle_last_seen_request() itself hides it in
// either direction a block exists, so no separate check is needed
// here.
// ------------------------------------------------------------------

function _formatLastSeen(date) {
  const now = new Date();
  const sameDay = (a, b) => a.getFullYear() === b.getFullYear()
    && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  const hhmm = date.toTimeString().slice(0, 5);
  if (sameDay(date, now)) return `Last seen today at ${hhmm}`;
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  if (sameDay(date, yesterday)) return `Last seen yesterday at ${hhmm}`;
  // Fixed "DD Mon YYYY" format, matching Desktop/Mobile's
  // strftime("%d %b %Y, %H:%M") exactly -- not toLocaleDateString(),
  // which is locale/browser-dependent and would render the same
  // last_seen timestamp differently per platform.
  const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const dd = String(date.getDate()).padStart(2, "0");
  return `Last seen ${dd} ${MONTHS[date.getMonth()]} ${date.getFullYear()}, ${hhmm}`;
}

async function refreshPeerPresence(peerUsername) {
  if (!session || !peerUsername) {
    peerPresenceEl.textContent = "";
    return;
  }
  if ((session.onlineUsers || new Set()).has(peerUsername)) {
    peerPresenceEl.textContent = "Online";
    peerPresenceEl.dataset.online = "1";
    return;
  }
  peerPresenceEl.textContent = "";
  peerPresenceEl.dataset.online = "0";
  try {
    const lastSeen = await session.fetchLastSeen(peerUsername);
    // The round trip is async -- the open chat may already be a
    // DIFFERENT peer by the time it resolves; never apply a stale
    // result to it.
    if (currentPeer() !== peerUsername) return;
    if (lastSeen) peerPresenceEl.textContent = _formatLastSeen(lastSeen);
  } catch (error) {
    appendLog(`ERROR: could not fetch last seen: ${error.message}`);
  }
}

// Phase 1 UI polish -- ONE renderer for everything the header shows
// about a peer's identity (badge, safety-number strip, its state), all
// read from the same session.peers entry. Previously the badge and the
// fingerprint line were written independently from three call sites,
// so after "Confirm match" the badge said "verified" while the line
// beside it still said "[UNVERIFIED]". Reads state only -- never
// changes it.
const PEER_STATE_UI = {
  VERIFIED: { label: "Verified", icon: "shield-check" },
  UNVERIFIED: { label: "Unverified", icon: "shield" },
  KEY_CHANGED: { label: "Key changed", icon: "shield-alert" },
};

const SECURITY_STATUS_TEXT = {
  VERIFIED: "Verified",
  UNVERIFIED: "Not verified",
  KEY_CHANGED: "Key changed \u2014 verify again",
};

// What is actually happening while a direct connection is being secured after an approved request:
// "establishing" or "failed" only (once it is ready the Establish key button is simply gone and a
// toast said so). Never invented: it is set only by the session's own onSecureConnection reports.
const secureConnectionStatus = new Map(); // peer handle -> { state, detail }

function renderPeerIdentity(peerUsername) {
  const known = peerUsername ? session?.peers.get(peerUsername) : null;
  const state = known ? known.state : "UNVERIFIED";
  const ui = PEER_STATE_UI[state]
    || { label: state.charAt(0) + state.slice(1).toLowerCase().replace(/_/g, " "), icon: "shield-alert" };

  peerVerifiedBadgeEl.replaceChildren(icon(ui.icon), document.createTextNode(ui.label));
  peerVerifiedBadgeEl.dataset.state = state;
  peerVerifiedBadgeEl.classList.toggle("is-unverified", state !== "VERIFIED");

  const bar = document.getElementById("securityBar");
  bar.dataset.state = state;
  bar.querySelector(".security-bar-icon use").setAttribute("href", `#i-${ui.icon}`);
  let statusText = SECURITY_STATUS_TEXT[state] || ui.label;
  const secure = state === "VERIFIED" ? secureConnectionStatus.get(peerUsername) : null;
  if (secure && secure.state === "establishing") statusText += " \u00B7 Establishing secure session\u2026";
  if (secure && secure.state === "failed") statusText += " \u00B7 Secure session failed \u2014 press Establish key to retry";
  document.getElementById("securityStatusText").textContent = statusText;

  const verified = state === "VERIFIED";
  const detailsOpen = !verified || safetyDetailsRequested;
  const details = document.getElementById("safetyDetails");
  details.hidden = !detailsOpen;
  const toggle = document.getElementById("securityBarToggle");
  toggle.setAttribute("aria-expanded", String(detailsOpen));
  toggle.setAttribute("aria-label", detailsOpen ? "Hide safety numbers" : "Show safety numbers");
  bar.classList.toggle("is-expanded", detailsOpen && verified);
  document.getElementById("reverifyBtn").hidden = !verified || detailsOpen;
  if (!detailsOpen) document.getElementById("ownNumberPanel").hidden = true;

  // "Establish key" is only an action while there is no secure session with this person yet.
  const conversationId = peerUsername ? session?.directConversationIds?.get(peerUsername) : null;
  document.getElementById("establishKeyBtn").hidden = Boolean(conversationId && session.sessionKeys.has(conversationId));

  if (!known) {
    // Left empty until the identity is actually observed -- the
    // placeholder text comes from CSS (:empty), so nothing here can be
    // mistaken for a real, observed fingerprint.
    fingerprintEl.replaceChildren();
    return;
  }
  const label = document.createElement("span");
  label.className = "fp-label";
  const peerName = document.createElement("b");
  peerName.textContent = nameOf(peerUsername);
  const stateText = document.createElement("span");
  stateText.className = "sr-only";
  stateText.textContent = ` [${state}]`;
  label.append("Safety number with ", peerName, stateText);
  const value = document.createElement("span");
  value.className = "fp-value";
  value.setAttribute("aria-label", `Safety number ${known.fingerprint}`);
  const fingerprintText = String(known.fingerprint || "");
  const groups = fingerprintText.includes(" ")
    ? fingerprintText.split(/\s+/).filter(Boolean)
    : fingerprintText.match(/.{1,4}/g) || [];
  for (const group of groups) {
    const groupEl = document.createElement("span");
    groupEl.className = "fp-group";
    groupEl.textContent = group;
    value.appendChild(groupEl);
  }
  fingerprintEl.replaceChildren(label, value);
}

let directOpenGeneration = 0;
function openDirectChat(peerUsername) {
  if (!peerUsername) return;
  const openGeneration = ++directOpenGeneration;
  if (peerUsername !== activeDirectPeer) safetyDetailsRequested = false;
  saveCurrentDraftIfAny();
  stopTypingImmediately();
  resetTypingStatusDisplay();
  activeDirectPeer = peerUsername;
  requestDisplayNames([peerUsername]);
  chatTitleEl.querySelector(".chat-header-name").textContent = nameOf(peerUsername);
  chatTitleEl.querySelector(".chat-header-name").title = `@${peerUsername}`;
  chatAvatarEl.dataset.tone = avatarTone(peerUsername);
  clearConversationUnread(false, peerUsername);
  loadPeerAvatar(chatAvatarEl, peerUsername, initialOf(nameOf(peerUsername)));

  // This peer's identity may already have been observed (e.g. the
  // network announcement arrived before the user searched for them) --
  // session.peers already has it in that case, and clearing the display
  // here would erase real data with nothing left to repopulate it, since
  // onPeerObserved only fires again on a NEW announcement. Reflect
  // whatever is already known instead of assuming "nothing yet".
  renderPeerIdentity(peerUsername);

  refreshPeerPresence(peerUsername);

  setMainView("chat");
  renderChatList();

  // Phase 19.17C -- messages-disappear-on-reopen fix: opening a chat
  // never actually loaded its history before now -- #messages is a
  // single shared DOM node across every peer, cleared by nothing and
  // populated only by live traffic in THIS tab, so a peer's own
  // history became genuinely irretrievable the moment their earlier
  // messages scrolled out or the page reloaded, until the user
  // happened to notice and click the separate "Load history" icon.
  // forgetRenderedHistory() first, same reason as mobile/app.py's
  // open_chat(): without it, a conversation already viewed once this
  // tab session would have its history silently skipped as "already
  // rendered" into DOM content this clear just wiped. Errors are
  // non-fatal (e.g. no session key yet for a brand-new contact) --
  // appendLog() already reports them.
  messagesEl.innerHTML = "";
  // Forget what was rendered at the same moment the DOM is cleared (not after the next network
  // round trip), so a history load already in flight cannot be undone and rendered twice.
  const knownConversationId = session?.directConversationIds?.get(peerUsername);
  if (knownConversationId) session.forgetRenderedHistory(knownConversationId);
  refreshPinnedBar(messagesEl);
  // Phase 19.23 -- Issue 3: this peer's tick registry points at <span>
  // elements the innerHTML clear above just detached -- without this,
  // re-opening an already-viewed peer (forgetRenderedHistory() below
  // makes their history render again) would keep stacking duplicate,
  // now-orphaned entries here on every reopen.
  delete pendingSentTicksByPeer[peerUsername];
  // Phase 19.24 (continued) -- a bubble from whichever conversation
  // was open before belongs to DOM content the clear above just
  // detached -- reset so nothing here can resolve into or address a
  // bubble that no longer exists on screen.
  clearMessageLifecycleState();

  // Phase 19.24 -- Drafts: restore whatever unsent text this
  // conversation had, or leave the composer empty if it never had one.
  document.getElementById("messageText").value =
    drafts.get(currentConversationId(messagesEl)) || "";

  // Phase 19.24 -- Chat Wallpaper: keyed by the peer's own username,
  // same convention as Mute/Archive/Block above for a direct
  // conversation -- never the resolved conversation_id.
  applyWallpaper(messagesEl, peerUsername);

  // Phase 19.24 -- Message Search: match indices are only valid for
  // the conversation they were computed against -- always close/reset
  // the bar when switching conversations (mirrors gui/chat_window.py
  // ::open_conversation()'s own handle_close_search_bar() call).
  if (messagesEl._closeSearchBar) messagesEl._closeSearchBar();

  if (session) {
    session.openDirectConversation(peerUsername)
      .then((conversationId) => {
        if (openGeneration !== directOpenGeneration) return 0; // another chat was opened since
        if (!knownConversationId) session.forgetRenderedHistory(conversationId);
        return session.loadHistory(conversationId, false);
      })
      .catch((error) => {
        appendLog(`ERROR: ${error.message}`);
        // No such account: close the view rather than leave a phantom chat behind.
        if (activeDirectPeer === peerUsername && !knownDirectPeers.has(peerUsername) && /not found|no such|unknown|does not exist/i.test(error.message)) {
          activeDirectPeer = null;
          setMainView("empty");
          renderChatList();
          toast(`No account named "${peerUsername}".`, "error");
        }
      });
  }
}

document.getElementById("peerUsername").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    startChatFromSearch(event.target.value.trim());
  }
});
// A completed entry opens the chat too -- not just Enter. "input" fires
// on every keystroke AND on a single programmatic fill() (unlike
// "change", which native text inputs only raise on blur -- fill() does
// not blur the field, so relying on "change" here left a fill()-driven
// entry with no trigger at all). Debounced so real typing settles
// before acting instead of reopening the view on every character;
// fill()'s one-shot "input" clears the debounce window well inside any
// reasonable wait.
//
// Guarded against re-firing on the ALREADY-active peer: any earlier
// fill() of this same field (e.g. the peer-verification flow re-uses
// it to look up a fingerprint) leaves this timer pending, and under
// real thread contention (WASM ML-KEM/ML-DSA operations block the JS
// main thread) it can fire seconds late -- landing in the middle of an
// unrelated later interaction such as an open message search.
// openDirectChat() unconditionally wipes #messages and closes the
// search bar (_closeSearchBar()) even when re-opening the peer that
// is already open, so a late-firing no-op debounce was silently
// destroying in-progress UI state (search results, a highlighted
// match) with no code change and no visible user action responsible.
// (Typing used to open a chat 300 ms after every keystroke, so a half-typed phone number such
// as "+91" became a conversation in the list. Typing now only filters; see startChatFromSearch().)

// ------------------------------------------------------------------
// Sidebar: groups
// ------------------------------------------------------------------

function renderGroupList() {
  if (!session) return;
  groupListEl.innerHTML = "";
  const allGroups = Array.from(session.groups.entries()).filter(
    ([conversationId]) => session.isConversationArchived(conversationId) === showArchivedGroups
  );
  const groupFilterText = effectiveFilterText(allGroups.map(([, group]) => group.name));
  const groups = allGroups.filter(([conversationId, group]) =>
    passesSidebarFilter(group.name, conversationActivity.get(activityKey(true, conversationId)), groupFilterText));
  if (groups.length === 0 && sidebarUnreadOnly && allGroups.length > 0) {
    groupListEl.innerHTML = '<div class="empty-hint">No unread groups.</div>';
    updateTabBadges();
    return;
  }
  if (groups.length === 0) {
    if (showArchivedGroups) {
      groupListEl.innerHTML = '<div class="empty-hint">No archived groups.</div>';
    } else {
      groupListEl.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon" aria-hidden="true"><svg class="icon"><use href="#i-users"/></svg></div>
          <div class="empty-state-title">No groups yet</div>
          <div class="empty-state-text">Create a group to start a conversation.</div>
          <button type="button" class="btn btn-primary btn-sm empty-state-action"><svg class="icon" aria-hidden="true"><use href="#i-plus"/></svg>Create group</button>
        </div>`;
      groupListEl.querySelector(".empty-state-action").addEventListener("click", openGroupCreateModal);
    }
    updateTabBadges();
    return;
  }
  for (const [conversationId, group] of groups) {
    const row = document.createElement("div");
    row.className = `row-card${conversationId === activeGroupIdEl.value ? " is-selected" : ""}`;
    const muted = session.isConversationMuted(conversationId);
    const activity = conversationActivity.get(activityKey(true, conversationId));
    const memberCount = `${group.members.length} ${group.members.length === 1 ? "member" : "members"}`;
    if (activity?.unread) row.classList.add("has-unread");
    row.innerHTML = `
      <div class="avatar is-group" data-tone="${avatarTone(group.name)}">${escapeHtml(initialOf(group.name))}</div>
      <div class="row-main">
        <div class="row-title">${escapeHtml(group.name)}</div>
        <div class="row-sub">${escapeHtml(activity?.preview || memberCount)}</div>
      </div>${rowMetaHtml(activity, muted, group.name)}`;
    row.tabIndex = 0;
    if (conversationId === activeGroupIdEl.value) row.setAttribute("aria-current", "true");
    row.addEventListener("click", () => openGroupChat(conversationId, group));
    row.addEventListener("keydown", (event) => {
      if (event.target === row && (event.key === "Enter" || event.key === " ")) {
        event.preventDefault();
        openGroupChat(conversationId, group);
      }
    });
    row.querySelector(".row-mute-btn").addEventListener("click", (event) => {
      showMuteMenu(conversationId, event, renderGroupList, true);
    });
    groupListEl.appendChild(row);
  }
  updateTabBadges();
}

document.getElementById("archivedGroupsToggle").addEventListener("click", () => {
  showArchivedGroups = !showArchivedGroups;
  document.getElementById("archivedGroupsToggle").textContent = showArchivedGroups ? "Back to Groups" : "Archived";
  renderGroupList();
});

// Group membership events (see WebClientSession.onGroupEvent): one fixed sentence per event, built
// from the server-recorded fields and the display names -- never from text a peer sent. An event
// is shown once, whether it arrived live or in history.
const renderedGroupEventIds = new Set();

function groupEventText(event) {
  const me = session?.username;
  // Display names are not unique: when two people in this group share a name, the handle tells
  // them apart ("Sam (@sam_7f3a) added Sam (@sam)").
  const members = session?.groups.get(event.conversationId)?.members || [];
  const who = (handle) => {
    if (!handle) return "Someone";
    const name = nameOf(handle);
    const namesake = [...new Set([event.actor, event.subject, ...members])]
      .some((other) => other && other !== handle && nameOf(other) === name);
    return namesake ? `${name} (@${handle})` : name;
  };
  if (event.type === "member_added") {
    if (!event.actor) return `${who(event.subject)} was added to the group`;
    if (event.actor === me) return `You added ${who(event.subject)}`;
    if (event.subject === me) return `${who(event.actor)} added you`;
    return `${who(event.actor)} added ${who(event.subject)}`;
  }
  if (event.type === "member_removed") {
    if (event.actor === me) return `You removed ${who(event.subject)}`;
    if (event.subject === me) return `${who(event.actor)} removed you`;
    return `${who(event.actor)} removed ${who(event.subject)}`;
  }
  return event.subject === me ? "You left the group" : `${who(event.subject)} left the group`;
}

function renderGroupEvent(container, event) {
  if (renderedGroupEventIds.has(event.id)) return;
  renderedGroupEventIds.add(event.id);
  requestDisplayNames([event.actor, event.subject].filter(Boolean));
  insertDateSeparatorIfNeeded(container, event.timestamp);
  const row = document.createElement("div");
  row.className = "msg-row is-system group-event";
  row.dataset.eventId = event.id;
  row.dataset.eventType = event.type;
  row._event = event;
  const bubble = document.createElement("div");
  bubble.className = "bubble";
  bubble.setAttribute("role", "status");
  bubble.textContent = groupEventText(event);
  row.appendChild(bubble);
  container.appendChild(row);
  container.scrollTop = container.scrollHeight;
}

function openGroupChat(conversationId, group) {
  saveCurrentDraftIfAny();
  stopTypingImmediately();
  resetTypingStatusDisplay();
  activeGroupIdEl.value = conversationId;
  groupTitleEl.textContent = group.name;
  requestDisplayNames(group.members);
  groupSubEl.textContent = `${group.members.length} members • ${group.members.map(nameOf).join(", ")}`;
  groupAvatarEl.textContent = initialOf(group.name);
  groupAvatarEl.dataset.tone = avatarTone(group.name);
  clearConversationUnread(true, conversationId);
  setMainView("groupChat");
  renderGroupList();

  // See openDirectChat()'s own comment -- identical fix, group side.
  groupMessagesEl.innerHTML = "";
  renderedGroupEventIds.clear();
  refreshPinnedBar(groupMessagesEl);
  clearMessageLifecycleState();

  // Phase 19.24 -- Drafts: restore whatever unsent text this group had,
  // or leave the composer empty if it never had one.
  document.getElementById("groupMessageText").value = drafts.get(conversationId) || "";

  // Phase 19.24 -- Chat Wallpaper.
  applyWallpaper(groupMessagesEl, conversationId);

  // Phase 19.24 -- Message Search: see openDirectChat()'s own
  // identical comment.
  if (groupMessagesEl._closeSearchBar) groupMessagesEl._closeSearchBar();

  if (session) {
    session.forgetRenderedHistory(conversationId);
    session.loadHistory(conversationId, true).catch((error) => appendLog(`ERROR: ${error.message}`));
  }
}

// Section 8 -- Group Information panel: name, "N members • M online", and
// a per-member role row (Admin / Online / Offline), matching Android's own
// Members dialog (mobile/app.py::_open_group_members_dialog()). Reads only
// session.groups (already populated by _handleGroupCreateResult()) and
// session.onlineUsers (already populated by the user_list handler) -- no
// new network calls, no new protocol logic.
async function renderPendingInvitations(conversationId) {
  let holder = document.getElementById("groupPendingInvitations");
  if (!holder) {
    holder = document.createElement("div");
    holder.id = "groupPendingInvitations";
    holder.className = "group-key-notice";
    holder.hidden = true;
    groupInfoMembersEl.before(holder);
  }
  let waiting = [];
  try {
    const notifications = await session.loadInbox();
    waiting = notifications.filter(
      (n) => n.type === "group_invitation" && n.status === "pending" && n.conversation_id === conversationId
        && n.requester_username === session.username
    );
  } catch {
    // Shown only when it loads; the member list itself does not depend on it.
  }
  if (activeGroupIdEl.value !== conversationId) return;
  holder.hidden = waiting.length === 0;
  holder.textContent = waiting.length
    ? `Waiting for approval: ${waiting.map((n) => nameOf(n.recipient_username || n.candidate_username)).join(", ")}. They join the group only if they approve the invitation in their Inbox.`
    : "";
}

function renderGroupInfo() {
  const conversationId = activeGroupIdEl.value;
  const group = session?.groups.get(conversationId);
  if (!group) return;

  const onlineUsers = session.onlineUsers || new Set();
  // The server's online list never includes the viewer themself --
  // but the viewer is, by definition, online right now.
  const isMemberOnline = (m) => m === session.username || onlineUsers.has(m);
  const onlineCount = group.members.filter(isMemberOnline).length;

  groupInfoNameEl.textContent = group.name;
  groupInfoSubEl.textContent = `${group.members.length} members • ${onlineCount} online`;

  // Phase 19.18 -- Group Info remove-member closure: admin-only, same
  // gating mobile/app.py::_open_group_members_dialog() already uses
  // (hiding Remove for a non-admin here is a convenience only --
  // server/client_handler.py::handle_group_remove_member() re-derives
  // the admin from the database on every call and rejects anyone
  // else, so this can never grant anything the server would refuse).
  const isSelfAdmin = group.admin && group.admin === session.username;

  // Invitations this account sent for this group that are still waiting for the person's decision.
  renderPendingInvitations(conversationId);

  // This account cannot read the group yet: say why and what finishes it, never a bare silence.
  const keyNotice = document.getElementById("groupKeyNotice");
  const holdsKey = session.sessionKeys.has(conversationId);
  keyNotice.hidden = holdsKey;
  keyNotice.textContent = holdsKey ? "" : (
    "You do not have this group's key yet, so you cannot read or send messages in it. It arrives once "
    + "you and the member who holds it (usually the admin) have verified each other \u2014 use Verify next to their name."
  );

  groupInfoMembersEl.innerHTML = "";
  for (const username of group.members) {
    const isAdmin = group.admin && username === group.admin;
    const isOnline = isMemberOnline(username);
    const roleText = isAdmin ? "Admin" : (isOnline ? "Online" : "Offline");
    const roleClass = isAdmin ? "" : (isOnline ? "is-online" : "is-offline");

    const row = document.createElement("div");
    row.className = "member-row";
    row.innerHTML = `
      <div class="avatar sm" data-tone="${avatarTone(username)}">${escapeHtml(initialOf(nameOf(username)))}<span class="presence-dot${isOnline ? " is-online" : ""}"></span></div>
      <div class="row-title">${nameWithHandleHtml(username)}${username === session.username ? ' <span class="member-you">(you)</span>' : ""}</div>
      <div class="member-role ${roleClass}">${roleText}</div>`;

    // Whether this account and that member have verified each other decides whether a group key can
    // move between them (it is only ever wrapped for, and accepted from, a verified identity).
    if (username !== session.username) {
      const known = session.peers.get(username);
      const state = known ? known.state : "UNSEEN";
      const label = { VERIFIED: "\u2713 Verified", UNVERIFIED: "Not verified", KEY_CHANGED: "Key changed", UNSEEN: "Not seen yet" }[state];
      const trust = document.createElement("span");
      trust.className = `member-trust ${state === "VERIFIED" ? "is-verified" : state === "KEY_CHANGED" ? "is-attention" : ""}`;
      trust.textContent = label;
      row.appendChild(trust);
      if (state !== "VERIFIED") {
        const verifyBtn = document.createElement("button");
        verifyBtn.className = "btn btn-ghost btn-xs";
        verifyBtn.type = "button";
        verifyBtn.textContent = "Verify";
        verifyBtn.setAttribute("aria-label", `Verify ${nameOf(username)} to share group keys`);
        verifyBtn.addEventListener("click", () => {
          document.querySelector('.tab-btn[data-tab="chats"]').click();
          openDirectChat(username);
        });
        row.appendChild(verifyBtn);
      }
    }

    if (isSelfAdmin && username !== session.username && !isAdmin) {
      const removeBtn = document.createElement("button");
      removeBtn.className = "btn btn-danger btn-xs";
      removeBtn.setAttribute("aria-label", `Remove ${username} from the group`);
      removeBtn.textContent = "Remove";
      removeBtn.addEventListener("click", async () => {
        removeBtn.disabled = true;
        try {
          const result = await session.removeGroupMember(conversationId, username);
          if (!result.success) throw new Error(result.error || "Could not remove member.");
          // Server-confirmed outcome, reflected locally -- other
          // members' own clients learn of this via the existing
          // group_member_left broadcast (unchanged, server-side);
          // this session's own group state is updated directly since
          // it will never receive its own broadcast back.
          group.members = group.members.filter((m) => m !== username);
          renderGroupInfo();
          renderGroupList();
        } catch (error) {
          reportActionError(error);
          removeBtn.disabled = false;
        }
      });
      row.appendChild(removeBtn);
    }

    groupInfoMembersEl.appendChild(row);
  }
}

// "input" + debounce, not "change": a completed conversation_id opens that
// group's chat view if it's already known, same as clicking its row-card.
// (Unlike the person search, this only ever opens a group the user is
// already a member of; it never creates anything.)
let activeGroupIdDebounce = null;
document.getElementById("activeGroupId").addEventListener("input", (event) => {
  clearTimeout(activeGroupIdDebounce);
  const conversationId = event.target.value.trim();
  activeGroupIdDebounce = setTimeout(() => {
    const group = session?.groups.get(conversationId);
    if (group) openGroupChat(conversationId, group);
  }, 300);
});

document.getElementById("groupInfoBtn").addEventListener("click", () => {
  renderGroupInfo();
  setMainView("groupInfo");
});
document.getElementById("groupInfoBackBtn").addEventListener("click", () => setMainView("groupChat"));

// ------------------------------------------------------------------
// Inbox (Phase 19.18 -- L-5 closure: session.loadInbox()/
// respondToInbox() now wire into the real, already-existing,
// already-tested server-side Inbox protocol -- the same one Desktop/
// Mobile already used. Card layout/split mirrors gui/inbox_dialog.py
// exactly: pending, actionable requests first, then a resolved-status
// history line for requests this account sent itself.
// ------------------------------------------------------------------

function renderInboxCard(notification) {
  const isGroupRequest = notification.type === "group_add_request";
  const isInvitation = notification.type === "group_invitation";
  const requester = notification.requester_username || "Someone";
  const isMine = requester === session.username;
  const groupName = notification.group_name || "the group";
  let title = "VERIFICATION REQUEST";
  let bodyText = `${requester} wants to verify their identity`;
  if (isGroupRequest) {
    title = "GROUP MEMBER REQUEST";
    bodyText = `${nameOf(requester)} wants to add ${nameOf(notification.candidate_username) || "a member"} to ${groupName}`;
  } else if (isInvitation && isMine) {
    title = "GROUP INVITATION SENT";
    bodyText = `You invited ${nameOf(notification.recipient_username || notification.candidate_username)} to ${groupName}`;
  } else if (isInvitation) {
    title = "GROUP INVITATION";
    bodyText = `${nameOf(requester)} wants to add you to the group \u201C${groupName}\u201D. You join only if you approve.`;
  }

  const card = document.createElement("div");
  card.className = "card notif-card";
  card.innerHTML = `
    <div class="notif-title"></div>
    <div class="notif-body"></div>`;
  card.querySelector(".notif-title").textContent = title;
  card.querySelector(".notif-body").textContent = bodyText;

  if (notification.status === "pending" && !isMine) {
    const actions = document.createElement("div");
    actions.className = "notif-actions";
    const approveBtn = document.createElement("button");
    approveBtn.className = "btn btn-primary btn-sm";
    approveBtn.textContent = "Approve";
    const denyBtn = document.createElement("button");
    denyBtn.className = "btn btn-ghost btn-sm";
    denyBtn.textContent = "Deny";
    const statusEl = document.createElement("div");
    statusEl.className = "notif-body";

    const respond = (approve) => async () => {
      approveBtn.disabled = true;
      denyBtn.disabled = true;
      try {
        // An admin approving someone's request to add a person INVITES that person (who must then
        // approve too); an approved invitation adds the invitee.
        await session.respondToInbox(notification, approve, isGroupRequest);
        // Phase 19.23 -- Issue 1: approving a verification_request
        // marks the requester VERIFIED on this browser -- add them to
        // the sidebar immediately, mirroring the direct Verify button's
        // identical addition above.
        if (approve && notification.type === "verification_request" && requester) {
          knownDirectPeers.add(requester);
          renderChatList();
        }
        renderInboxList();
      } catch (error) {
        statusEl.textContent = error.message;
        approveBtn.disabled = false;
        denyBtn.disabled = false;
      }
    };
    approveBtn.addEventListener("click", respond(true));
    denyBtn.addEventListener("click", respond(false));

    actions.appendChild(approveBtn);
    actions.appendChild(denyBtn);
    card.appendChild(actions);
    card.appendChild(statusEl);
  } else {
    const resolvedEl = document.createElement("div");
    resolvedEl.className = "notif-resolved";
    const who = nameOf(notification.recipient_username || notification.candidate_username);
    resolvedEl.textContent = (isInvitation && isMine ? {
      approved: `${who} approved and joined`,
      denied: `${who} declined`,
      pending: `Waiting for ${who} to approve`,
      expired: "Expired \u2014 no longer valid",
    } : {
      approved: "Approved", denied: "Denied", pending: "Waiting for a response...", expired: "Expired",
    })[notification.status] || notification.status || "";
    card.appendChild(resolvedEl);
  }

  return card;
}

async function renderInboxList() {
  if (!session) return;
  inboxListEl.innerHTML = '<div class="empty-hint">Loading...</div>';
  let notifications;
  try {
    notifications = await session.loadInbox();
  } catch (error) {
    inboxListEl.innerHTML = "";
    const errEl = document.createElement("div");
    errEl.className = "empty-hint";
    errEl.textContent = error.message;
    inboxListEl.appendChild(errEl);
    return;
  }

  const myUsername = session.username;
  // A notification never names its own recipient explicitly (see
  // server/client_handler.py's _serialize_*_notification() docstrings)
  // -- if this account is not the requester, it can only be the
  // recipient, since loadInbox() is already scoped to "one of the two
  // parties".
  const actionable = notifications.filter((n) => n.status === "pending" && n.requester_username !== myUsername);
  const sent = notifications.filter(
    (n) => n.requester_username === myUsername && (n.status !== "pending" || n.type === "group_invitation")
  );
  updateInboxBadge(actionable.length);

  inboxListEl.innerHTML = "";
  if (!actionable.length && !sent.length) {
    inboxListEl.innerHTML = '<div class="empty-hint">Nothing here yet.</div>';
    return;
  }
  for (const n of actionable) inboxListEl.appendChild(renderInboxCard(n));
  for (const n of sent) inboxListEl.appendChild(renderInboxCard(n));
}

// ------------------------------------------------------------------
// Login / Register -- mirrors gui/login_window.py + mobile/app.py::
// LoginScreen's single-toggle mode switch exactly (see index.html's
// own comment on this screen).
// ------------------------------------------------------------------

let authMode = "login";

function setAuthMode(mode) {
  authMode = mode;
  const isRegister = mode === "register";
  document.getElementById("regUsernameField").hidden = !isRegister;
  document.getElementById("regConfirmPasswordField").hidden = !isRegister;
  document.getElementById("connectBtn").textContent = isRegister ? "Register" : "Login";
  document.getElementById("toggleModeBtn").textContent = isRegister ? "Already have an account? Login" : "Create an account";
}

document.getElementById("toggleModeBtn").addEventListener("click", () => {
  setAuthMode(authMode === "login" ? "register" : "login");
  authStatusEl.textContent = "";
  authStatusEl.classList.remove("is-error");
});

// The gateway address: this page's own host by default (the common case), overridable with
// ?gateway=ws://host:port or, in "Connection settings", by hand.
(function initGatewayAddress() {
  const input = document.getElementById("gatewayUrl");
  const fromQuery = new URLSearchParams(location.search).get("gateway");
  if (fromQuery && /^wss?:\/\//.test(fromQuery)) {
    input.value = fromQuery;
  } else if (location.hostname && !["127.0.0.1", "localhost"].includes(location.hostname)
             && input.value === "ws://127.0.0.1:8765") {
    input.value = `${location.protocol === "https:" ? "wss" : "ws"}://${location.hostname}:8765`;
  }
})();

document.getElementById("connectBtn").addEventListener("click", async () => {
  const gatewayUrl = document.getElementById("gatewayUrl").value.trim();
  const phoneNumber = document.getElementById("phoneNumber").value;
  const password = document.getElementById("password").value;
  const connectBtn = document.getElementById("connectBtn");

  authStatusEl.classList.remove("is-error");
  connectBtn.disabled = true;

  // Registration: a one-shot request on its own throwaway session,
  // exactly like ClientSession.register()/MobileClientSession.register()
  // -- never touches `session`/window.__session, no persistent
  // connection, no auto-login afterward (matches both other clients:
  // success just switches back to the login form).
  if (authMode === "register") {
    authStatusEl.textContent = "Creating your account...";
    try {
      const regUsername = document.getElementById("regUsername").value.trim();
      const confirmPassword = document.getElementById("regConfirmPassword").value;
      const regSession = new WebClientSession({ gatewayUrl });
      await regSession.register(
        regUsername, regUsername, `${regUsername}@users.invalid`,
        phoneNumber, password, confirmPassword
      );
      setAuthMode("login");
      authStatusEl.textContent = "Account created. Please log in.";
    } catch (error) {
      authStatusEl.textContent = error.message;
      authStatusEl.classList.add("is-error");
    } finally {
      connectBtn.disabled = false;
    }
    return;
  }

  authStatusEl.textContent = "Connecting...";

  session = new WebClientSession({
    gatewayUrl,
    onLog: appendLog,
    onSecurityWarning: showSecurityWarning,
    // identityKey distinguishes a group (its conversation_id) from a
    // direct peer (their username) -- mirrors client/session.py::
    // handle_chat()'s own identity_key. Routed to the group panel if
    // it names a known group, otherwise to the direct-messaging panel.
    onMessage: (identityKey, sender, text, options) => {
      if (session.groups.has(identityKey)) {
        // Phase 1.5: only into the group that's actually open -- the
        // single shared #groupMessages node used to receive every
        // group's live messages, mixing conversations (the same fix
        // 19.17C made for direct chats). Other groups count as unread
        // and load normally when opened.
        noteConversationActivity(true, identityKey, sender, text, options || {});
        if (identityKey === activeGroupIdEl.value) {
          renderTextMessage(groupMessagesEl, sender, text, options || {});
        }
        return;
      }
      // Phase 19.17C -- #messages is one shared DOM node for every
      // direct peer; without this check, a live message from peer B
      // rendered directly into whatever peer A's chat you currently
      // have open (message-mixing between unrelated conversations).
      const peerKey = resolveDirectPeerKey(identityKey);
      knownDirectPeers.add(peerKey);
      noteConversationActivity(false, peerKey, sender, text, options || {});
      if (peerKey === activeDirectPeer) {
        renderTextMessage(messagesEl, sender, text, options || {});
      }
    },
    onAttachment: (identityKey, sender, payloadType, bytes, contentMetadata, options) => {
      if (session.groups.has(identityKey)) {
        noteConversationActivity(true, identityKey, sender, attachmentPreview(payloadType, contentMetadata), options || {});
        if (identityKey === activeGroupIdEl.value) {
          renderAttachment(groupMessagesEl, sender, payloadType, bytes, contentMetadata, options || {});
        }
        return;
      }
      const peerKey = resolveDirectPeerKey(identityKey);
      knownDirectPeers.add(peerKey);
      noteConversationActivity(false, peerKey, sender, attachmentPreview(payloadType, contentMetadata), options || {});
      if (peerKey === activeDirectPeer) {
        renderAttachment(messagesEl, sender, payloadType, bytes, contentMetadata, options || {});
      }
    },
    onPeerObserved: (peerUsername, fingerprint, state) => {
      // Only the open chat's header reflects an identity -- an
      // announcement for some OTHER peer used to overwrite it.
      if (peerUsername === activeDirectPeer) renderPeerIdentity(peerUsername);
    },
    // Phase 17: reflects connectionStatus's own "disconnected" |
    // "connecting" | "connected" | "reconnecting" states -- see
    // WebClientSession._setConnectionState().
    onConnectionState: (state) => {
      connectionStatusEl.textContent = state;
      connectionStatusEl.dataset.state = state;
      // Phase 19.24 -- Typing Indicator: a debounce/expiry timer that
      // legitimately outlives the socket (mirrors gui/chat_window.py's
      // identical _on_connection_changed_stop_typing_timers()) must be
      // proactively cancelled here rather than left to fire against a
      // closed connection.
      if (state === "disconnected") {
        clearTimeout(typingStopTimer);
        typingStopTimer = null;
        typingActive = false;
        for (const senders of typingSenders.values()) {
          for (const timeoutId of senders.values()) clearTimeout(timeoutId);
        }
        typingSenders.clear();
        resetTypingStatusDisplay();
      }
    },
    onGroupCreated: () => {
      renderGroupList();
      if (!groupInfoViewEl.hidden) renderGroupInfo();
    },
    // THIS account left a group (server-confirmed): close it if it was open.
    onDisplayNamesUpdated: () => refreshShownNames(),
    // A membership change in the OPEN group (live, or from history while it loads).
    onGroupEvent: (conversationId, event) => {
      if (activeGroupIdEl.value !== conversationId || groupChatViewEl.hidden) return;
      renderGroupEvent(groupMessagesEl, { ...event, conversationId });
    },
    onGroupLeft: (conversationId) => {
      if (activeGroupIdEl.value === conversationId) {
        activeGroupIdEl.value = "";
        setMainView("empty");
      }
      renderGroupList();
      toast("You left the group", "success");
    },
    // Phase 19.23 -- Issue 3: no longer rendered as chat-adjacent text
    // at all -- resolveOldestUnackedSentTick() (below) is now the only
    // user-visible effect, exactly matching Desktop/Android's own
    // identical removal of this text in favour of a tick update.
    onReadReceipt: (conversationId, reader) => {
      resolveOldestUnackedSentTick(reader, "read");
    },
    onMessageDelivered: (conversationId, receiver, messageId) => {
      resolveOldestUnackedSentTick(receiver, "delivered");
      resolveOldestPendingSentBubble(receiver, messageId);
    },
    onMessageQueued: (conversationId, receiver, messageId) => {
      resolveOldestUnackedSentTick(receiver, "sent");
      resolveOldestPendingSentBubble(receiver, messageId);
    },
    onHistoryLoaded: () => {}, // appendLog() in app.js already reports the count
    // Phase 19.24 (continued) -- Message Lifecycle Events UI: live
    // edit/delete/reaction notifications, applied to whichever bubble
    // bubblesByMessageId already has (a message from a conversation not
    // currently open has no bubble at all -- silently ignored here, the
    // next loadHistory() of that conversation already reflects it).
    onMessageEdited: (conversationId, messageId, newText, editor, editedAt, editVersion) => {
      const bubble = bubblesByMessageId.get(messageId);
      if (bubble) applyBubbleEdit(bubble, newText, editVersion);
    },
    onMessageDeleted: (conversationId, messageId, deletedBy, deletedAt) => {
      const bubble = bubblesByMessageId.get(messageId);
      if (bubble) markBubbleDeleted(bubble);
    },
    onReactionUpdated: (conversationId, messageId, actor, action, reaction) => {
      const bubble = bubblesByMessageId.get(messageId);
      if (!bubble) return;
      const reactions = (bubble._reactions || []).filter((entry) => entry.user !== actor);
      if (action === "add") reactions.push({ user: actor, reaction });
      updateBubbleReactions(bubble, reactions);
    },
    onMessagePinned: (conversationId, messageId, pinnedBy, pinnedAt) => {
      const bubble = bubblesByMessageId.get(messageId);
      if (bubble) setBubblePinned(bubble, true, pinnedBy);
    },
    onMessageUnpinned: (conversationId, messageId, unpinnedBy) => {
      const bubble = bubblesByMessageId.get(messageId);
      if (bubble) setBubblePinned(bubble, false);
    },
    onTypingIndicator: (conversationId, username, isTyping) => {
      onTypingIndicatorReceived(conversationId, username, isTyping);
    },
    onOnlineUsersChanged: () => {
      if (!groupInfoViewEl.hidden) renderGroupInfo();
      // Sidebar rows show each contact's presence dot.
      renderChatList();
      // Phase 19.24 -- Presence/Last Seen: the same server-pushed
      // event every other presence indicator in this file already
      // uses -- no polling added.
      if (!chatViewEl.hidden) {
        refreshPeerPresence(currentPeer());
      }
    },
    // Phase 19.18 -- only re-renders if the Inbox tab is actually the
    // one on screen right now -- a live update must not yank the user
    // away from whatever else they're doing (same reasoning as
    // mobile/app.py's own _inbox_open-gated refresh).
    onGroupKeyInstalled: () => {
      if (typeof groupInfoViewEl !== "undefined" && !groupInfoViewEl.hidden) renderGroupInfo();
    },
    onSecureConnection: (peer, state, detail) => {
      if (state === "ready") secureConnectionStatus.delete(peer);
      else secureConnectionStatus.set(peer, { state, detail });
      if (!chatViewEl.hidden && currentPeer() === peer) renderPeerIdentity(peer);
      if (state === "ready") toast(`Secure session established with ${nameOf(peer)}`, "success");
      else if (state === "failed") toast(`Could not secure the connection with ${nameOf(peer)}: ${detail}`, "error");
    },
    onInboxUpdated: (notification) => {
      if (notification && notification.type === "group_invitation") {
        if (notification.status === "pending" && notification.requester_username !== session?.username) {
          toast(`${nameOf(notification.requester_username)} invited you to \u201C${notification.group_name || "a group"}\u201D \u2014 open your Inbox to approve`, "success");
        } else if (notification.requester_username === session?.username) {
          const who = nameOf(notification.recipient_username || notification.candidate_username);
          if (notification.status === "approved") toast(`${who} approved and joined \u201C${notification.group_name || "the group"}\u201D`, "success");
          else if (notification.status === "denied") toast(`${who} declined to join \u201C${notification.group_name || "the group"}\u201D`, "error");
        }
      }
      refreshInboxBadge();
      // Phase 19.23 -- Issue 1: this is the ORIGINAL REQUESTER's own
      // notification that their earlier verification_request was just
      // approved -- add the approver to the sidebar immediately,
      // mirroring the approver's own identical addition in
      // renderInboxCard()'s respond() above.
      if (
        notification && notification.type === "verification_request"
        && notification.status === "approved"
        && notification.requester_username === session?.username
        && notification.recipient_username
      ) {
        knownDirectPeers.add(notification.recipient_username);
        renderChatList();
        toast(`${nameOf(notification.recipient_username)} approved your request`, "success");
        if (!chatViewEl.hidden && currentPeer() === notification.recipient_username) {
          renderPeerIdentity(notification.recipient_username);
        }
      } else if (
        notification && notification.type === "verification_request"
        && notification.status === "denied"
        && notification.requester_username === session?.username
      ) {
        toast("Your verification request was declined. Nothing was verified.", "error");
      }
      if (isInboxTabActive()) renderInboxList();
    },
  });

  // Exposed for automated testing only (tests/test_web_browser_e2e.py,
  // tests/test_web_persistence_reconnect.py, tests/test_web_feature_
  // completion_e2e.py read/drive this via Playwright) -- a read/call
  // handle on the real session object, not a second, weaker code path:
  // every call a test makes through window.__session is the exact
  // same method a button click above already invokes.
  window.__session = session;

  try {
    await session.authenticateCredentials(phoneNumber, password);
    // The authenticated username always comes from the server's own
    // auth_result (see WebClientSession._connectAndLoginInternal():
    // "this.username = authResult.username || username") -- this
    // argument is only ever a fallback for that missing case, exactly
    // like Desktop/Android never re-collecting it at login either.
    await session.connectAndLogin(undefined);
    // Phase 19.23 -- Issue 1: seed the sidebar from the server's own
    // conversation list (session.loadConversations(), now called
    // internally by connectAndLogin()) instead of starting every
    // fresh page load with an empty knownDirectPeers -- the same
    // "restore at login" step Desktop/Android already had.
    for (const peer of session._restoredDirectPeers || []) {
      knownDirectPeers.add(peer);
    }
    // Phase 19.24 -- Block User: seeds session.blockedUsernames (the
    // local cache renderChatList()/renderGroupList()'s own Block/
    // Unblock menu label reads) once at login -- mirrors gui/chat_
    // window.py's identical get_blocked_users() call alongside its
    // own load_conversations().
    await session.getBlockedUsers();
    renderGroupList();
    renderChatList();
    setMainView("empty");
    showAppShell();
    appendLog("Ready.");
  } catch (error) {
    authStatusEl.textContent = error.message;
    authStatusEl.classList.add("is-error");
    appendLog(`ERROR: ${error.message}`);
  } finally {
    connectBtn.disabled = false;
  }
});

document.getElementById("logoutBtn").addEventListener("click", () => {
  if (!session) return;
  session.disconnect();
  appendLog("Disconnected (logout) -- automatic reconnect will not occur.");
  screenApp.hidden = true;
  screenLogin.hidden = false;
  // Leave the login form clean: no stale "Connecting..." status and no
  // password left sitting in the field after signing out.
  authStatusEl.textContent = "";
  authStatusEl.classList.remove("is-error");
  document.getElementById("password").value = "";
  knownDirectPeers.clear();
  activeDirectPeer = null;
  for (const key of Object.keys(pendingSentTicksByPeer)) delete pendingSentTicksByPeer[key];
});

document.getElementById("confirmVerifiedBtn").addEventListener("click", () => {
  const peerUsername = currentPeer();
  // BUG FIX (Phase 19.24, continued): observedFingerprint is a single,
  // module-level slot overwritten by whichever peer's identity was
  // MOST RECENTLY (re-)observed over the wire (onPeerObserved fires
  // once per live identity announcement, not on demand) -- looking at
  // a DIFFERENT, already-previously-observed peer (e.g. switching from
  // Alice to Carol to verify a second contact, needed before Forward
  // can target both) never re-fires it, so it can silently still hold
  // an unrelated peer's fingerprint here, making confirmPeerVerified()
  // below reject with a mismatch. session.peers is the same, always-
  // current source openDirectChat()'s own fingerprint display already
  // reads per-peer (see its own "const known = session?.peers.get(...)"
  // step) -- read fresh from there instead, for exactly this peer.
  const observedPeer = session?.peers.get(peerUsername);
  try {
    session.confirmPeerVerified(peerUsername, observedPeer && observedPeer.fingerprint);
    appendLog(`${peerUsername} marked VERIFIED.`);
    toast(`${nameOf(peerUsername)} marked as verified`, "success");
    safetyDetailsRequested = false;
    document.getElementById("ownNumberPanel").hidden = true;
    document.getElementById("showOwnNumberBtn").textContent = "Show my safety number";
    document.getElementById("showOwnNumberBtn").setAttribute("aria-expanded", "false");
    renderPeerIdentity(peerUsername);
    // Phase 19.23 -- Issue 1: add this newly-verified peer to the
    // sidebar immediately, not just at this browser's next login.
    knownDirectPeers.add(peerUsername);
    renderChatList();
  } catch (error) {
    reportActionError(error);
  }
});

document.getElementById("requestVerificationBtn").addEventListener("click", async () => {
  const peerUsername = currentPeer();
  try {
    await session.requestVerification(peerUsername);
    appendLog(`Verification requested from ${peerUsername}.`);
    toast(`Verification request sent to ${nameOf(peerUsername)}`, "success");
  } catch (error) {
    reportActionError(error);
  }
});

document.getElementById("establishKeyBtn").addEventListener("click", async () => {
  const peerUsername = currentPeer();
  try {
    await session.establishSessionKey(peerUsername);
    appendLog(`Session key established with ${peerUsername}.`);
    toast(`Secure session established with ${nameOf(peerUsername)}`, "success");
    renderPeerIdentity(peerUsername);
  } catch (error) {
    reportActionError(error);
  }
});

document.getElementById("sendBtn").addEventListener("click", async () => {
  const peerUsername = currentPeer();
  const text = document.getElementById("messageText").value;
  if (!text.trim()) return;
  stopTypingImmediately();

  // Phase 19.24 (continued) -- edit-mode branch, mirrors gui/chat_
  // window.py::send_message()'s identical check.
  if (editingMessageId) {
    const messageId = editingMessageId;
    const expectedVersion = editingExpectedVersion;
    const conversationId = session?.directConversationIds.get(peerUsername);
    clearComposerContext();
    if (!conversationId) return;
    try {
      await session.editMessage(conversationId, messageId, text, expectedVersion);
      document.getElementById("messageText").value = "";
    } catch (error) {
      reportActionError(error);
    }
    return;
  }

  const replyToMessageId = pendingReplyMessageId;
  pendingReplyMessageId = null;
  document.getElementById("composerContext").hidden = true;

  // Phase 19.24 -- Message Retry: generated BEFORE the risky send
  // call, so it is still available to attach to the FAILED bubble
  // even when sendMessage() throws before ever returning -- mirrors
  // gui/chat_window.py::send_message()'s identical client_message_id
  // timing exactly.
  const clientMessageId = crypto.randomUUID();
  try {
    await session.sendMessage(peerUsername, text, replyToMessageId, clientMessageId);
    knownDirectPeers.add(peerUsername);
    renderTextMessage(messagesEl, "me", text, { replyToMessageId });
    noteConversationActivity(false, peerUsername, "me", text);
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
    renderFailedBubble(messagesEl, text, {
      replyToMessageId, clientMessageId, peerUsername, isGroup: false,
    });
  }
  document.getElementById("messageText").value = "";
});
// Settings → Chat: "Press Enter to send". A per-browser display
// preference stored exactly like the theme (localStorage only, never
// sent anywhere). Default ON is main.js's original behaviour, so
// nothing changes for a user who never opens Settings.
const ENTER_TO_SEND_KEY = "qrscs.enterToSend";
function enterToSendEnabled() {
  try { return localStorage.getItem(ENTER_TO_SEND_KEY) !== "0"; } catch (e) { return true; }
}
function syncEnterToSendControl() {
  const el = document.getElementById("enterToSendToggle");
  if (el) el.checked = enterToSendEnabled();
}
document.getElementById("enterToSendToggle")?.addEventListener("change", (event) => {
  try { localStorage.setItem(ENTER_TO_SEND_KEY, event.target.checked ? "1" : "0"); } catch (e) {}
});
syncEnterToSendControl();

document.getElementById("messageText").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey && !event.isComposing && enterToSendEnabled()) { event.preventDefault(); document.getElementById("sendBtn").click(); }
});

// The composers are multi-line: one row when empty, growing with the text up
// to a limit. Programmatic changes (sending, loading a draft, editing) set
// .value too, so the setter is wrapped as well as the input event.
function autosizeComposer(el) {
  el.style.height = "auto";
  el.style.height = `${Math.min(el.scrollHeight, 140)}px`;
}
for (const id of ["messageText", "groupMessageText"]) {
  const el = document.getElementById(id);
  const nativeValue = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value");
  Object.defineProperty(el, "value", {
    configurable: true,
    get() { return nativeValue.get.call(this); },
    set(v) { nativeValue.set.call(this, v); autosizeComposer(this); },
  });
  el.addEventListener("input", () => autosizeComposer(el));
}

document.getElementById("markReadBtn")?.addEventListener("click", async () => {
  const peerUsername = currentPeer();
  try {
    const conversationId = await session.openDirectConversation(peerUsername);
    session.markRead(conversationId);
    appendLog(`Marked ${conversationId} as read.`);
    toast("Marked as read", "success");
  } catch (error) {
    reportActionError(error);
  }
});

document.getElementById("loadHistoryBtn").addEventListener("click", async () => {
  const peerUsername = currentPeer();
  try {
    const conversationId = await session.openDirectConversation(peerUsername);
    await session.loadHistory(conversationId, false);
  } catch (error) {
    reportActionError(error);
  }
});

document.getElementById("wallpaperBtn").addEventListener("click", (event) => {
  const peerUsername = currentPeer();
  showWallpaperPicker(messagesEl, peerUsername, event);
});

// "Jump to latest" -- appears once the reader has scrolled well up from
// the newest message; one click (or Enter) glides back down.
function setupJumpToLatest(container) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "jump-latest";
  btn.hidden = true;
  btn.setAttribute("aria-label", "Jump to latest message");
  btn.title = "Jump to latest";
  btn.appendChild(icon("arrow-down"));
  container.after(btn);
  const update = () => {
    const distance = container.scrollHeight - container.scrollTop - container.clientHeight;
    const show = distance > 240;
    if (show) {
      // Pinned just above the scroller's bottom edge, whatever sits
      // below it (reply bar, typing line, composer).
      const view = container.parentElement.getBoundingClientRect();
      const box = container.getBoundingClientRect();
      btn.style.top = `${Math.round(box.bottom - view.top - 56)}px`;
    }
    btn.hidden = !show;
  };
  container.addEventListener("scroll", update, { passive: true });
  window.addEventListener("resize", update);
  btn.addEventListener("click", () => {
    container.scrollTo({ top: container.scrollHeight, behavior: "smooth" });
  });
}

setupJumpToLatest(messagesEl);
setupJumpToLatest(groupMessagesEl);

setupSearchBar(messagesEl, {
  toggleBtn: document.getElementById("searchBtn"),
  bar: document.getElementById("searchBar"),
  input: document.getElementById("searchInput"),
  resultLabel: document.getElementById("searchResultLabel"),
  prevBtn: document.getElementById("searchPrevBtn"),
  nextBtn: document.getElementById("searchNextBtn"),
  closeBtn: document.getElementById("searchCloseBtn"),
});

setupSearchBar(groupMessagesEl, {
  toggleBtn: document.getElementById("groupSearchBtn"),
  bar: document.getElementById("groupSearchBar"),
  input: document.getElementById("groupSearchInput"),
  resultLabel: document.getElementById("groupSearchResultLabel"),
  prevBtn: document.getElementById("groupSearchPrevBtn"),
  nextBtn: document.getElementById("groupSearchNextBtn"),
  closeBtn: document.getElementById("groupSearchCloseBtn"),
});

document.getElementById("pinnedBtn").addEventListener("click", (event) => {
  showPinnedMessagesPanel(messagesEl, event);
});

document.getElementById("groupPinnedBtn").addEventListener("click", (event) => {
  showPinnedMessagesPanel(groupMessagesEl, event);
});

document.getElementById("galleryBtn").addEventListener("click", (event) => {
  showMediaGallery(messagesEl, event);
});

document.getElementById("groupGalleryBtn").addEventListener("click", (event) => {
  showMediaGallery(groupMessagesEl, event);
});

for (const [inputId, sendId, isGroup] of [
  ["attachmentInput", "sendAttachmentBtn", false], ["groupAttachmentInput", "sendGroupAttachmentBtn", true],
]) {
  document.getElementById(sendId).addEventListener("click", async () => {
    const where = activeAttachmentTarget();
    const fileInput = document.getElementById(inputId);
    const file = fileInput.files && fileInput.files[0];
    if (!file) {
      appendLog("ERROR: no file selected.");
      toast("Choose a file to send first.", "error");
      return;
    }
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const mimeType = file.type || "application/octet-stream";
      // Rendered as what the pipeline classifies it as (voice/video/image/file) -- the same type
      // every other member's client will show.
      const renderType = classifyForRender(file.name, mimeType);
      await sendAttachmentTo(where, bytes, file.name, mimeType, renderType);
      fileInput.value = "";
      document.getElementById(sendId).hidden = true;
    } catch (error) {
      reportActionError(error);
    }
  });
}

// The type the encrypted pipeline gives an attachment (mirrors classifyAttachment() in app.js).
function classifyForRender(filename, mimeType) {
  if (mimeType.startsWith("audio/")) return "voice";
  if (mimeType.startsWith("video/")) return "video";
  if (mimeType.startsWith("image/")) return "image";
  return "file";
}

// ------------------------------------------------------------------
// Phase 1.5 -- Create group modal. The request is unchanged:
// session.createGroup(name, members) with the same name string and
// member username list the old inline form produced. Members are
// picked as chips (Enter/comma), from suggestions (people you already
// have a conversation with), or typed comma-separated as before.
// ------------------------------------------------------------------

const groupCreateModalEl = document.getElementById("groupCreateModal");
const groupMembersInputEl = document.getElementById("groupMembers");
let selectedGroupMembers = [];

function memberTokens(text) {
  return String(text || "").split(",").map((m) => m.trim()).filter(Boolean);
}

// A person entered by phone number is looked up first and shown by name (and @handle) in `lookupEl`;
// the Add button there calls `onAdd`. Resolves to {username, display_name} when someone was found.
async function previewMemberByPhone(phone, lookupEl, onAdd) {
  const say = (message, isError) => {
    lookupEl.hidden = false;
    lookupEl.classList.toggle("is-error", Boolean(isError));
    lookupEl.textContent = message;
  };
  say("Looking up\u2026", false);
  let found;
  try {
    found = await session.lookupUserByPhone(phone);
  } catch (error) {
    say(error.message || "Could not look that number up.", true);
    return null;
  }
  if (!found) {
    say("No account uses that phone number.", true);
    return null;
  }
  if (found.username === session.username) {
    say("That is your own number. You are added automatically.", false);
    return null;
  }
  const name = found.display_name || found.username;
  lookupEl.hidden = false;
  lookupEl.classList.remove("is-error");
  lookupEl.replaceChildren();
  const avatar = document.createElement("span");
  avatar.className = "avatar xs";
  avatar.dataset.tone = avatarTone(found.username);
  avatar.textContent = initialOf(name);
  const text = document.createElement("span");
  text.className = "member-lookup-text";
  const nameEl = document.createElement("span");
  nameEl.className = "member-lookup-name";
  nameEl.textContent = name;
  const handleEl = document.createElement("span");
  handleEl.className = "member-lookup-handle";
  handleEl.textContent = `@${found.username}`;
  text.append(nameEl, handleEl);
  // Where this person stands with this account decides whether a group key can reach them: a key
  // is only ever wrapped for, and accepted from, a VERIFIED identity.
  const known = session.peers.get(found.username);
  const verified = known && known.state === "VERIFIED";
  const stateEl = document.createElement("span");
  stateEl.className = "member-lookup-handle";
  stateEl.textContent = verified
    ? "Verified — they will receive the group key"
    : known
      ? "Not verified yet — they get the group key once you have verified each other"
      : "Not online — they get the group key once they are online and you have verified each other";
  text.append(stateEl);
  const add = document.createElement("button");
  add.type = "button";
  add.className = "btn btn-primary btn-xs";
  add.textContent = "Add";
  add.setAttribute("aria-label", `Add ${name}`);
  add.addEventListener("click", onAdd);
  lookupEl.append(avatar, text, add);
  if (!verified) {
    // A contact request without opening a conversation: it only asks; nothing is verified until
    // they approve.
    const ask = document.createElement("button");
    ask.type = "button";
    ask.className = "btn btn-ghost btn-xs";
    ask.textContent = "Ask to verify";
    ask.setAttribute("aria-label", `Ask ${name} to verify you`);
    ask.addEventListener("click", async () => {
      ask.disabled = true;
      try {
        await session.requestVerification(found.username);
        toast(`Verification request sent to ${name}`, "success");
      } catch (error) {
        reportActionError(error);
        ask.disabled = false;
      }
    });
    lookupEl.append(ask);
  }
  return found;
}

function addGroupMembers(names) {
  for (const name of names) {
    if (name && name !== session?.username && !selectedGroupMembers.includes(name)) {
      selectedGroupMembers.push(name);
    }
  }
  renderGroupMemberChips();
}

function renderGroupMemberChips() {
  const chips = document.getElementById("groupMemberChips");
  chips.replaceChildren();
  for (const name of selectedGroupMembers) {
    const chip = document.createElement("span");
    chip.className = "member-chip";
    chip.setAttribute("role", "listitem");
    const avatar = document.createElement("span");
    avatar.className = "avatar xxs";
    avatar.dataset.tone = avatarTone(name);
    avatar.textContent = initialOf(name);
    const label = document.createElement("span");
    label.textContent = nameOf(name);
    if (nameOf(name) !== name) label.title = `@${name}`;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "member-chip-remove";
    remove.setAttribute("aria-label", `Remove ${name}`);
    remove.appendChild(icon("x"));
    remove.addEventListener("click", () => {
      selectedGroupMembers = selectedGroupMembers.filter((m) => m !== name);
      renderGroupMemberChips();
      groupMembersInputEl.focus();
    });
    chip.append(avatar, label, remove);
    chips.appendChild(chip);
  }
  renderGroupMemberSuggestions();
}

function renderGroupMemberSuggestions() {
  const wrap = document.getElementById("groupMemberSuggestions");
  const list = document.getElementById("groupMemberSuggestionsList");
  const query = groupMembersInputEl.value.trim().toLowerCase();
  // Your existing conversations only -- never arbitrary online users.
  const pool = new Set(knownDirectPeers);
  const candidates = [...pool]
    .filter((name) => name && name !== session?.username && !selectedGroupMembers.includes(name))
    .filter((name) => !query || name.toLowerCase().includes(query))
    .sort((a, b) => a.localeCompare(b))
    .slice(0, 6);
  list.replaceChildren();
  for (const name of candidates) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "member-suggestion";
    const avatar = document.createElement("span");
    avatar.className = "avatar xxs";
    avatar.dataset.tone = avatarTone(name);
    avatar.textContent = initialOf(name);
    const label = document.createElement("span");
    label.textContent = name;
    btn.append(avatar, label, icon("plus"));
    btn.addEventListener("click", () => {
      addGroupMembers([name]);
      groupMembersInputEl.value = "";
      renderGroupMemberSuggestions();
      groupMembersInputEl.focus();
    });
    list.appendChild(btn);
  }
  wrap.hidden = candidates.length === 0;
}

function openGroupCreateModal() {
  closeAnyOpenPopup();
  groupCreateModalEl._returnFocus = document.activeElement;
  groupCreateModalEl.hidden = false;
  renderGroupMemberChips();
  document.getElementById("groupName").focus();
}

function closeGroupCreateModal() {
  if (groupCreateModalEl.hidden) return;
  groupCreateModalEl.hidden = true;
  const returnFocus = groupCreateModalEl._returnFocus;
  if (returnFocus && returnFocus.isConnected) returnFocus.focus({ preventScroll: true });
}

function resetGroupCreateForm() {
  document.getElementById("groupName").value = "";
  groupMembersInputEl.value = "";
  selectedGroupMembers = [];
  clearGroupLookup();
  renderGroupMemberChips();
}

// A phone number typed into the member box: looked up, shown by name, and only added on "Add"
// (or Enter again). `groupLookup` is that person while they wait.
let groupLookup = null;
const groupLookupEl = document.getElementById("groupMemberLookup");

function clearGroupLookup() {
  groupLookup = null;
  groupLookupEl.hidden = true;
  groupLookupEl.replaceChildren();
}

function confirmGroupLookup() {
  if (!groupLookup) return;
  const { phone, found } = groupLookup;
  const remaining = memberTokens(groupMembersInputEl.value).filter((token) => token !== phone);
  addGroupMembers([found.username]);
  groupMembersInputEl.value = remaining.join(", ");
  clearGroupLookup();
  renderGroupMemberSuggestions();
  groupMembersInputEl.focus();
}

async function lookupGroupPhone(phone) {
  groupLookup = null;
  const found = await previewMemberByPhone(phone, groupLookupEl, confirmGroupLookup);
  // Only if the box still holds what was looked up (the person may have kept typing).
  if (found && memberTokens(groupMembersInputEl.value).includes(phone)) groupLookup = { phone, found };
}

document.getElementById("openCreateGroupBtn").addEventListener("click", openGroupCreateModal);
document.getElementById("groupCreateCloseBtn").addEventListener("click", closeGroupCreateModal);
document.getElementById("groupCreateCancelBtn").addEventListener("click", closeGroupCreateModal);
groupCreateModalEl.addEventListener("click", (event) => {
  if (event.target === groupCreateModalEl) closeGroupCreateModal();
});
document.getElementById("groupMemberPicker").addEventListener("click", (event) => {
  if (event.target.id === "groupMemberPicker" || event.target.id === "groupMemberChips") groupMembersInputEl.focus();
});
groupMembersInputEl.addEventListener("keydown", (event) => {
  if ((event.key === "Enter" || event.key === ",") && groupMembersInputEl.value.trim()) {
    event.preventDefault();
    const tokens = memberTokens(groupMembersInputEl.value);
    const phones = tokens.filter(looksLikePhoneNumber);
    if (phones.length === 0) {
      addGroupMembers(tokens);
      groupMembersInputEl.value = "";
      renderGroupMemberSuggestions();
    } else if (event.key === "Enter" && groupLookup && groupLookup.phone === phones[0]) {
      confirmGroupLookup();  // Enter again on a person already shown by name adds them
    } else {
      // Usernames are added now; the first phone number is looked up and shown before it is added.
      addGroupMembers(tokens.filter((token) => !looksLikePhoneNumber(token)));
      groupMembersInputEl.value = phones.join(", ");
      lookupGroupPhone(phones[0]);
      renderGroupMemberSuggestions();
    }
  } else if (event.key === "Backspace" && !groupMembersInputEl.value && selectedGroupMembers.length) {
    selectedGroupMembers.pop();
    renderGroupMemberChips();
  }
});
groupMembersInputEl.addEventListener("input", () => {
  const value = groupMembersInputEl.value;
  if (!groupLookup || !memberTokens(value).includes(groupLookup.phone)) clearGroupLookup();
  if (value.includes(",")) {
    const parts = value.split(",");
    const remainder = parts.pop();
    addGroupMembers(memberTokens(parts.join(",")));
    groupMembersInputEl.value = remainder.trimStart();
  }
  renderGroupMemberSuggestions();
});
document.getElementById("groupName").addEventListener("keydown", (event) => {
  if (event.key === "Enter") { event.preventDefault(); groupMembersInputEl.focus(); }
});

document.getElementById("createGroupBtn").addEventListener("click", async () => {
  const name = document.getElementById("groupName").value;
  const leftover = memberTokens(groupMembersInputEl.value);
  if (leftover.some(looksLikePhoneNumber)) {
    // A phone number is never sent as if it were a username: look the person up and add them first.
    toast("Press Enter to look up that phone number and add the person, or clear it.", "error");
    groupMembersInputEl.focus();
    return;
  }
  const members = [...new Set([...selectedGroupMembers, ...leftover])];
  try {
    await session.createGroup(name, members, true);
    appendLog(`Requested group '${name}' with members: ${members.join(", ")}`);
    toast(
      members.length
        ? `Creating group \u201C${name}\u201D \u2014 ${members.length} invitation${members.length === 1 ? "" : "s"} sent. They join when they approve in their Inbox.`
        : `Creating group \u201C${name}\u201D\u2026`
    );
    resetGroupCreateForm();
    closeGroupCreateModal();
  } catch (error) {
    reportActionError(error);
  }
});

document.getElementById("sendGroupMessageBtn").addEventListener("click", async () => {
  const conversationId = activeGroupIdEl.value;
  const text = document.getElementById("groupMessageText").value;
  if (!text.trim()) return;
  stopTypingImmediately();

  // Phase 19.24 (continued) -- edit-mode branch, mirrors the direct
  // composer's identical check above.
  if (editingMessageId) {
    const messageId = editingMessageId;
    const expectedVersion = editingExpectedVersion;
    clearComposerContext();
    try {
      await session.editMessage(conversationId, messageId, text, expectedVersion);
      document.getElementById("groupMessageText").value = "";
    } catch (error) {
      reportActionError(error);
    }
    return;
  }

  const replyToMessageId = pendingReplyMessageId;
  pendingReplyMessageId = null;
  document.getElementById("groupComposerContext").hidden = true;

  // Phase 19.24 -- Message Retry: see the direct composer's identical
  // comment above.
  const clientMessageId = crypto.randomUUID();
  try {
    await session.sendGroupMessage(conversationId, text, replyToMessageId, clientMessageId);
    renderTextMessage(groupMessagesEl, "me", text, { replyToMessageId });
    noteConversationActivity(true, conversationId, "me", text);
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
    renderFailedBubble(groupMessagesEl, text, {
      replyToMessageId, clientMessageId, conversationId, isGroup: true,
    });
  }
  document.getElementById("groupMessageText").value = "";
});
document.getElementById("groupMessageText").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey && !event.isComposing && enterToSendEnabled()) { event.preventDefault(); document.getElementById("sendGroupMessageBtn").click(); }
});

document.getElementById("loadGroupHistoryBtn").addEventListener("click", async () => {
  const conversationId = activeGroupIdEl.value;
  try {
    await session.loadHistory(conversationId, true);
  } catch (error) {
    reportActionError(error);
  }
});

document.getElementById("groupWallpaperBtn").addEventListener("click", (event) => {
  showWallpaperPicker(groupMessagesEl, activeGroupIdEl.value, event);
});

// -------------------------------------------------------------
// Phase 18.5 -- Step 5: Device identity, a minimal usable UI over
// the already-implemented enrollDevice()/listDevices()/
// authorizeDevice()/revokeDevice()/bindDeviceSession()/
// syncConversationKeyToDevice() (Phase 18 Step 8) -- this file adds
// no new session logic, only DOM wiring, exactly like every other
// button handler above.
// -------------------------------------------------------------

function renderDeviceList(devices) {
  deviceListEl.innerHTML = "";
  for (const device of devices) {
    const row = document.createElement("div");
    row.className = "row-card";
    row.style.cursor = "default";
    row.innerHTML = `
      <div class="avatar sm">${escapeHtml(initialOf(device.device_name))}</div>
      <div class="row-main">
        <div class="row-title">${escapeHtml(device.device_name || "(unnamed)")} <span class="row-sub">[${escapeHtml(device.platform || "?")}]</span></div>
        <div class="row-sub">${escapeHtml(device.state)} • <span class="mono">${escapeHtml(device.device_id)}</span></div>
      </div>`;
    deviceListEl.appendChild(row);
  }
}

document.getElementById("enrollDeviceBtn").addEventListener("click", async () => {
  try {
    const result = await session.enrollDevice(
      document.getElementById("deviceName").value,
      document.getElementById("devicePlatform").value
    );
    myDeviceIdEl.textContent = `${session.deviceId} (${result.state})`;
  } catch (error) {
    reportActionError(error);
  }
});

document.getElementById("bindDeviceBtn").addEventListener("click", async () => {
  try {
    await session.bindDeviceSession();
    appendLog(`Bound this connection to device ${session.deviceId}.`);
    toast("Session bound to this device", "success");
  } catch (error) {
    reportActionError(error);
  }
});

document.getElementById("listDevicesBtn").addEventListener("click", async () => {
  try {
    const devices = await session.listDevices();
    renderDeviceList(devices);
    if (session.deviceId) myDeviceIdEl.textContent = session.deviceId;
  } catch (error) {
    reportActionError(error);
  }
});

document.getElementById("observeDeviceBtn").addEventListener("click", async () => {
  const targetDeviceId = document.getElementById("targetDeviceId").value;
  try {
    const devices = await session.listDevices();
    const target = devices.find((d) => d.device_id === targetDeviceId);
    if (!target) throw new Error(`No such device: ${targetDeviceId}`);
    const peer = await session.observeDevicePeerIdentity(
      targetDeviceId, target.kem_public_key, target.ml_dsa_public_key
    );
    observedDeviceFingerprint = peer.fingerprint;
    deviceFingerprintDisplayEl.textContent = `${targetDeviceId}: ${peer.fingerprint} [${peer.state}]`;
  } catch (error) {
    reportActionError(error);
  }
});

document.getElementById("authorizeDeviceBtn").addEventListener("click", async () => {
  const targetDeviceId = document.getElementById("targetDeviceId").value;
  try {
    session.confirmDevicePeerVerified(targetDeviceId, observedDeviceFingerprint);
    await session.authorizeDevice(targetDeviceId, observedDeviceFingerprint);
    appendLog(`Authorized device ${targetDeviceId}.`);
    toast("Device authorized", "success");
  } catch (error) {
    reportActionError(error);
  }
});

document.getElementById("revokeDeviceBtn").addEventListener("click", async () => {
  const targetDeviceId = document.getElementById("targetDeviceId").value;
  try {
    await session.revokeDevice(targetDeviceId);
    appendLog(`Revoked device ${targetDeviceId}.`);
    toast("Device revoked", "success");
  } catch (error) {
    reportActionError(error);
  }
});

document.getElementById("syncKeyBtn").addEventListener("click", async () => {
  const targetDeviceId = document.getElementById("targetDeviceId").value;
  const conversationId = document.getElementById("syncConversationId").value;
  try {
    await session.syncConversationKeyToDevice(targetDeviceId, conversationId, "direct");
    appendLog(`Synced conversation ${conversationId} to device ${targetDeviceId}.`);
    toast("Conversation key synced", "success");
  } catch (error) {
    reportActionError(error);
  }
});

// The login form starts disabled (index.html): main.js is a module with many
// imports, and a click that lands before the handlers above are attached is
// silently lost -- the person (or a test) sees nothing happen. Everything is
// wired by this point, so the form can be used.
for (const id of ["connectBtn", "toggleModeBtn"]) document.getElementById(id).disabled = false;
document.documentElement.dataset.appReady = "1";
