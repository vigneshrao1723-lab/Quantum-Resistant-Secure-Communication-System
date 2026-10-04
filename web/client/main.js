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
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("is-active"));
    document.querySelectorAll(".sidebar-panel").forEach((p) => p.classList.remove("is-active"));
    btn.classList.add("is-active");
    document.querySelector(`.sidebar-panel[data-panel="${btn.dataset.tab}"]`).classList.add("is-active");
    if (btn.dataset.tab === "inbox") renderInboxList();
  });
});

function isInboxTabActive() {
  const btn = document.querySelector('.tab-btn[data-tab="inbox"]');
  return !!btn && btn.classList.contains("is-active");
}

document.getElementById("chatBackBtn").addEventListener("click", () => setMainView("empty"));
document.getElementById("groupBackBtn").addEventListener("click", () => setMainView("empty"));

document.getElementById("settingsToggleBtn").addEventListener("click", () => {
  setMainView("settings");
  if (session) loadPeerAvatar(document.getElementById("myProfilePicAvatar"), session.username, initialOf(session.username));
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
  const newUsername = document.getElementById("newUsernameInput").value.trim();
  if (!newUsername || !session) return;
  try {
    const result = await session.changeUsername(newUsername);
    if (!result.success) throw new Error(result.error || "Could not change username.");
    hintEl.textContent = "Username changed.";
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

document.getElementById("profilePicChangeBtn").addEventListener("click", () => {
  document.getElementById("profilePicInput").click();
});
document.getElementById("profilePicInput").addEventListener("change", async () => {
  const input = document.getElementById("profilePicInput");
  const file = input.files && input.files[0];
  if (!file || !session) return;
  const hintEl = document.getElementById("myProfilePicHint");
  const originalHint = hintEl.textContent;
  hintEl.textContent = "Uploading...";
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    await session.uploadProfilePicture(bytes, file.type || "image/png");
    setAvatarImage(document.getElementById("myProfilePicAvatar"), bytes, file.type || "image/png");
    hintEl.textContent = "Visible to anyone who looks your account up.";
  } catch (error) {
    hintEl.textContent = `Upload failed: ${error.message}`;
  } finally {
    input.value = "";
  }
});

document.getElementById("settingsLogoutBtn").addEventListener("click", () => {
  document.getElementById("logoutBtn").click();
});

// Phase 19.24 -- Attachment Menu: one small, consistent menu exposing
// every attachment kind (Photo/File, Voice Message, Video Message) --
// mirrors gui/input_bar.py's/mobile/app.py's own identical three
// choices, so the feature looks and behaves like the same app across
// all three clients.
document.getElementById("attachBtn").addEventListener("click", (event) => {
  event.preventDefault();
  event.stopPropagation();
  closeAnyOpenPopup();
  const menu = document.createElement("div");
  menu.className = "bubble-context-menu";
  const options = [
    ["file", "\u{1F5BC}️ Photo / File"],
    ["voice", "\u{1F3A4} Voice Message"],
    ["video", "\u{1F3AC} Video Message"],
  ];
  for (const [choice, label] of options) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = label;
    btn.addEventListener("click", (clickEvent) => {
      clickEvent.stopPropagation();
      closeAnyOpenPopup();
      if (choice === "file") {
        document.getElementById("attachmentInput").click();
      } else {
        openMediaRecorderModal(choice);
      }
    });
    menu.appendChild(btn);
  }
  document.body.appendChild(menu);
  positionPopup(menu, event);
});
document.getElementById("attachmentInput").addEventListener("change", () => {
  const hasFile = document.getElementById("attachmentInput").files.length > 0;
  document.getElementById("sendAttachmentBtn").hidden = !hasFile;
});

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

function openMediaRecorderModal(mode) {
  const constraints = mode === "video" ? { audio: true, video: true } : { audio: true };
  navigator.mediaDevices.getUserMedia(constraints).then((stream) => {
    _buildMediaRecorderModal(mode, stream);
  }).catch((error) => {
    appendLog(
      `ERROR: could not access the ${mode === "video" ? "camera/microphone" : "microphone"}: ${error.message}`
    );
  });
}

function _buildMediaRecorderModal(mode, stream) {
  const overlay = document.createElement("div");
  overlay.className = "media-recorder-modal";
  const card = document.createElement("div");
  card.className = "media-recorder-card";
  overlay.appendChild(card);

  let previewEl = null;
  if (mode === "video") {
    previewEl = document.createElement("video");
    previewEl.className = "media-recorder-preview";
    previewEl.autoplay = true;
    previewEl.muted = true;
    previewEl.srcObject = stream;
    card.appendChild(previewEl);
  }

  const statusEl = document.createElement("div");
  statusEl.className = "media-recorder-status";
  statusEl.textContent = "Ready to record.";
  card.appendChild(statusEl);

  const timerEl = document.createElement("div");
  timerEl.className = "media-recorder-timer";
  timerEl.textContent = "00:00";
  card.appendChild(timerEl);

  const recordBtn = document.createElement("button");
  recordBtn.type = "button";
  recordBtn.className = "btn btn-primary btn-sm";
  recordBtn.textContent = "⏺ Record";
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

  document.body.appendChild(overlay);

  let recorder = null;
  let chunks = [];
  let recordedBlob = null;
  let elapsedSeconds = 0;
  let tickInterval = null;
  const maxSeconds = mode === "video" ? MAX_VIDEO_SECONDS : MAX_VOICE_SECONDS;

  function stopAllTracks() {
    stream.getTracks().forEach((track) => track.stop());
  }

  function cleanupAndClose() {
    if (tickInterval) clearInterval(tickInterval);
    stopAllTracks();
    overlay.remove();
  }

  function startRecording() {
    chunks = [];
    elapsedSeconds = 0;
    timerEl.textContent = "00:00";
    recorder = new MediaRecorder(stream);
    recorder.ondataavailable = (event) => {
      if (event.data && event.data.size > 0) chunks.push(event.data);
    };
    recorder.onstop = () => {
      recordedBlob = new Blob(
        chunks, { type: recorder.mimeType || (mode === "video" ? "video/webm" : "audio/webm") }
      );
      statusEl.textContent = "Recording ready to send.";
      sendBtn.disabled = false;
      recordBtn.textContent = "⏺ Record Again";
      if (mode === "video" && previewEl) {
        previewEl.srcObject = null;
        previewEl.muted = false;
        previewEl.controls = true;
        previewEl.src = URL.createObjectURL(recordedBlob);
      } else if (mode === "voice") {
        if (!previewEl) {
          previewEl = document.createElement("audio");
          previewEl.className = "media-recorder-preview";
          card.insertBefore(previewEl, statusEl);
        }
        previewEl.controls = true;
        previewEl.src = URL.createObjectURL(recordedBlob);
      }
    };
    recorder.start();
    statusEl.textContent = "Recording…";
    recordBtn.textContent = "⏹ Stop";
    sendBtn.disabled = true;
    tickInterval = setInterval(() => {
      elapsedSeconds += 1;
      timerEl.textContent =
        `${String(Math.floor(elapsedSeconds / 60)).padStart(2, "0")}:${String(elapsedSeconds % 60).padStart(2, "0")}`;
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

  sendBtn.addEventListener("click", async () => {
    if (!recordedBlob) return;
    sendBtn.disabled = true;
    const peerUsername = document.getElementById("peerUsername").value;
    const filename = mode === "video" ? "video-message.webm" : "voice-message.webm";
    try {
      const bytes = new Uint8Array(await recordedBlob.arrayBuffer());
      await session.sendAttachment({ peerUsername }, bytes, filename, recordedBlob.type);
      renderAttachment(messagesEl, "me", mode, bytes, {
        filename, mime_type: recordedBlob.type, size_bytes: bytes.length,
      });
      cleanupAndClose();
    } catch (error) {
      appendLog(`ERROR: ${error.message}`);
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

const TICK_TEXT = { sent: " ✓", queued: " ✓", delivered: " ✓✓", read: " ✓✓" };

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

function setComposerContext(text) {
  const els = activeComposerElements();
  if (!els) return;
  els.contextText.textContent = text;
  els.contextBar.hidden = false;
}

function clearComposerContext() {
  pendingReplyMessageId = null;
  editingMessageId = null;
  editingExpectedVersion = 0;
  for (const barId of ["composerContext", "groupComposerContext"]) {
    const bar = document.getElementById(barId);
    if (bar) bar.hidden = true;
  }
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

function closeAnyOpenPopup() {
  document.querySelectorAll(".bubble-context-menu, .bubble-popup").forEach((el) => el.remove());
}

document.addEventListener("click", closeAnyOpenPopup);

function positionPopup(el, event) {
  el.style.left = `${Math.min(event.clientX, window.innerWidth - 200)}px`;
  el.style.top = `${Math.min(event.clientY, window.innerHeight - 200)}px`;
}

function showBubbleContextMenu(bubble, event) {
  event.preventDefault();
  closeAnyOpenPopup();
  const actions = buildBubbleContextActions(bubble);
  if (!actions.length) return;
  const menu = document.createElement("div");
  menu.className = "bubble-context-menu";
  for (const [action, label, danger] of actions) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = label;
    if (danger) btn.classList.add("is-danger");
    btn.addEventListener("click", (clickEvent) => {
      clickEvent.stopPropagation();
      closeAnyOpenPopup();
      handleBubbleContextAction(action, bubble, clickEvent);
    });
    menu.appendChild(btn);
  }
  document.body.appendChild(menu);
  positionPopup(menu, event);
}

const REACTION_CHOICES = ["\u{1F44D}", "❤️", "\u{1F602}", "\u{1F62E}", "\u{1F622}", "\u{1F64F}"];

function showReactionPicker(bubble, event) {
  closeAnyOpenPopup();
  const popup = document.createElement("div");
  popup.className = "bubble-popup";
  const row = document.createElement("div");
  row.className = "bubble-popup-emoji-row";
  for (const emoji of REACTION_CHOICES) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = emoji;
    btn.addEventListener("click", (clickEvent) => {
      clickEvent.stopPropagation();
      closeAnyOpenPopup();
      sendReaction(bubble, emoji);
    });
    row.appendChild(btn);
  }
  popup.appendChild(row);
  document.body.appendChild(popup);
  positionPopup(popup, event);
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
  overlay.appendChild(card);

  const titleEl = document.createElement("div");
  titleEl.className = "confirm-modal-title";
  titleEl.textContent = title;
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
  confirmBtn.className = "btn btn-primary btn-sm";
  confirmBtn.textContent = confirmLabel;
  actionsRow.appendChild(cancelBtn);
  actionsRow.appendChild(confirmBtn);
  card.appendChild(actionsRow);

  cancelBtn.addEventListener("click", () => overlay.remove());
  confirmBtn.addEventListener("click", () => {
    overlay.remove();
    doAction();
  });

  document.body.appendChild(overlay);
}

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
  const menu = document.createElement("div");
  menu.className = "bubble-context-menu";
  for (const [action, label, danger] of buildMuteActions(key, isGroup)) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = label;
    if (danger) btn.classList.add("is-danger");
    btn.addEventListener("click", (clickEvent) => {
      clickEvent.stopPropagation();
      closeAnyOpenPopup();
      applyMuteAction(key, action);
      refresh();
    });
    menu.appendChild(btn);
  }
  document.body.appendChild(menu);
  positionPopup(menu, event);
}

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
  const menu = document.createElement("div");
  menu.className = "bubble-context-menu";
  const options = [[null, "Default"], ...Object.entries(WALLPAPER_PRESETS)];
  for (const [wallpaperId, label] of options) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = wallpaperId === current ? `✓ ${label}` : label;
    btn.addEventListener("click", (clickEvent) => {
      clickEvent.stopPropagation();
      closeAnyOpenPopup();
      if (!session || !conversationId) return;
      session.setConversationWallpaper(conversationId, wallpaperId);
      applyWallpaper(container, conversationId);
    });
    menu.appendChild(btn);
  }
  document.body.appendChild(menu);
  positionPopup(menu, event);
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
  const menu = document.createElement("div");
  menu.className = "bubble-context-menu";
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
        ? ` — ${pinnedEl.textContent.replace("\u{1F4CC} ", "")}` : "";
      const btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = `${shown}${by}`;
      btn.addEventListener("click", (clickEvent) => {
        clickEvent.stopPropagation();
        closeAnyOpenPopup();
        highlightSearchMatch(container, bubble);
      });
      menu.appendChild(btn);
    }
  }
  document.body.appendChild(menu);
  positionPopup(menu, event);
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
  const tile = document.createElement("div");
  tile.className = "gallery-tile";
  if (bubble.dataset.payloadType === "image") {
    const img = bubble.querySelector("img");
    if (img && img.src) {
      const thumb = document.createElement("img");
      thumb.src = img.src;
      thumb.className = "gallery-thumb";
      thumb.addEventListener("click", () => window.open(img.src, "_blank"));
      tile.appendChild(thumb);
      return tile;
    }
  }
  const label = document.createElement("div");
  label.className = "gallery-tile-label";
  label.textContent = bubble.dataset.payloadType === "video" ? "\u{1F3AC} Video" : "[Media]";
  tile.appendChild(label);
  tile.addEventListener("click", () => {
    overlay.remove();
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
  row.addEventListener("click", () => {
    overlay.remove();
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
  closeBtn.textContent = "✕";
  closeBtn.addEventListener("click", () => overlay.remove());
  header.appendChild(closeBtn);
  card.appendChild(header);

  const media = getMediaBubbles(container);

  if (!media.length) {
    const empty = document.createElement("div");
    empty.className = "confirm-modal-message";
    empty.textContent = "No media in this conversation yet.";
    card.appendChild(empty);
    document.body.appendChild(overlay);
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

  document.body.appendChild(overlay);
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
  const list = document.createElement("div");
  list.className = "bubble-popup-list";
  for (const target of targets) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = target.label;
    btn.addEventListener("click", (clickEvent) => {
      clickEvent.stopPropagation();
      closeAnyOpenPopup();
      forwardBubbleTo(bubble, target);
    });
    list.appendChild(btn);
  }
  popup.appendChild(list);
  document.body.appendChild(popup);
  positionPopup(popup, event);
}

async function handleBubbleContextAction(action, bubble, event) {
  const messageId = bubble.dataset.messageId;

  if (action === "reply") {
    pendingReplyMessageId = messageId;
    editingMessageId = null;
    const preview = bubble.dataset.text || "[Attachment]";
    setComposerContext(`Replying to: ${preview.length > 80 ? preview.slice(0, 77) + "…" : preview}`);
    return;
  }

  if (action === "copy") {
    if (bubble.dataset.text) {
      try { await navigator.clipboard.writeText(bubble.dataset.text); }
      catch (error) { appendLog(`ERROR: could not copy to clipboard: ${error.message}`); }
    }
    return;
  }

  if (action === "forward") {
    if (event) showForwardPicker(bubble, event);
    return;
  }

  if (action === "react") {
    if (event) showReactionPicker(bubble, event);
    return;
  }

  if (action === "edit") {
    if (bubble.dataset.supportsEdit !== "1" || bubble.dataset.mine !== "1") return;
    pendingReplyMessageId = null;
    editingMessageId = messageId;
    editingExpectedVersion = Number(bubble.dataset.editVersion || 0);
    setComposerContext("Editing message");
    const els = activeComposerElements();
    if (els) els.input.value = bubble.dataset.text || "";
    return;
  }

  if (action === "pin") {
    try {
      session.pinMessage(messageId);
    } catch (error) {
      appendLog(`ERROR: ${error.message}`);
      return;
    }
    // Optimistic local update, mirrors gui/chat_window.py's identical
    // immediate-feedback comment -- the eventual message_pinned
    // notification simply re-applies the same state, a harmless no-op
    // repeat.
    setBubblePinned(bubble, true, null);
    return;
  }

  if (action === "unpin") {
    try {
      session.unpinMessage(messageId);
    } catch (error) {
      appendLog(`ERROR: ${error.message}`);
      return;
    }
    setBubblePinned(bubble, false);
    return;
  }

  if (action === "delete_me") {
    try {
      session.deleteMessageForMe(messageId);
    } catch (error) {
      appendLog(`ERROR: ${error.message}`);
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
    appendLog(`ERROR: ${error.message}`);
  }
}

function sendReaction(bubble, emoji) {
  const conversationId = bubble.dataset.conversationId;
  if (!conversationId) return;
  try {
    session.addReaction(conversationId, bubble.dataset.messageId, emoji);
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
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
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
  }
}

function markBubbleDeleted(bubble) {
  bubble.dataset.deleted = "1";
  bubble.dataset.text = "";
  bubble.classList.add("is-deleted");
  // Remove any content already rendered for this bubble (attachment
  // preview/link, or a pre-existing text node) -- exactly one tombstone
  // node replaces it, regardless of the original payload type.
  bubble.querySelectorAll(".bubble-text, .msg-meta, .bubble-image, .msg-image-actions, .bubble-file, .bubble-reply-preview").forEach((el) => el.remove());
  const textEl = document.createElement("div");
  textEl.className = "bubble-text";
  textEl.textContent = "Message deleted";
  bubble.insertBefore(textEl, bubble.firstChild);
  updateBubbleReactions(bubble, []);
  setBubblePinned(bubble, false);
}

function applyBubbleEdit(bubble, newText, editVersion) {
  if (bubble.dataset.supportsEdit !== "1") return;
  bubble.dataset.text = newText;
  bubble.dataset.editVersion = String(editVersion);
  const textEl = bubble.querySelector(".bubble-text");
  if (textEl) textEl.textContent = `${newText} (edited)`;
}

function updateBubbleReactions(bubble, reactions) {
  bubble._reactions = reactions || [];
  let reactionsEl = bubble.querySelector(".bubble-reactions");
  if (!reactionsEl) {
    reactionsEl = document.createElement("div");
    reactionsEl.className = "bubble-reactions";
    bubble.appendChild(reactionsEl);
  }
  if (!bubble._reactions.length) {
    reactionsEl.textContent = "";
    reactionsEl.hidden = true;
    return;
  }
  const counts = new Map();
  for (const entry of bubble._reactions) {
    if (!entry.reaction) continue;
    counts.set(entry.reaction, (counts.get(entry.reaction) || 0) + 1);
  }
  reactionsEl.textContent = [...counts.entries()].map(([emoji, count]) => `${emoji}×${count}`).join("  ");
  reactionsEl.hidden = false;
}

function setBubblePinned(bubble, pinned, pinnedBy) {
  // Phase 19.24 -- Pinned Messages: shows/hides a small "📌 Pinned by
  // X" marker -- mirrors gui/message_widget.py::MessageBubble.set_
  // pinned() exactly. bubble.dataset.pinned drives buildBubbleContext
  // Actions()'s Pin/Unpin toggle above, and searchMatchingBubbles()/
  // a future "pinned messages" query both read bubble.dataset.text
  // unaffected by this.
  bubble.dataset.pinned = pinned ? "1" : "0";
  let pinnedEl = bubble.querySelector(".bubble-pinned");
  if (!pinned) {
    if (pinnedEl) pinnedEl.remove();
    return;
  }
  if (!pinnedEl) {
    pinnedEl = document.createElement("div");
    pinnedEl.className = "bubble-pinned";
    bubble.insertBefore(pinnedEl, bubble.firstChild);
  }
  pinnedEl.textContent = pinnedBy ? `\u{1F4CC} Pinned by ${pinnedBy}` : "\u{1F4CC} Pinned";
}

function setBubbleReplyPreview(bubble, previewText) {
  if (!previewText) return;
  let replyEl = bubble.querySelector(".bubble-reply-preview");
  if (!replyEl) {
    replyEl = document.createElement("div");
    replyEl.className = "bubble-reply-preview";
    bubble.insertBefore(replyEl, bubble.firstChild);
  }
  replyEl.textContent = previewText.length > 80 ? previewText.slice(0, 77) + "…" : previewText;
}

function setTickStatus(span, status) {
  span.dataset.status = status;
  span.textContent = TICK_TEXT[status] || "";
  // .tick-read already existed in style.css (color: var(--read-tick),
  // the same #59ADF7 Desktop's COLOR_READ_RECEIPT uses) but was never
  // actually applied by any JS in this file until now.
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

function bubbleShell(container, sender, options, extraClass) {
  const mine = sender === "me" || sender === session?.username;
  const row = document.createElement("div");
  row.className = `msg-row ${mine ? "is-mine" : "is-theirs"}${options.historical ? " is-historical" : ""}${extraClass ? " " + extraClass : ""}`;
  const bubble = document.createElement("div");
  bubble.className = "bubble";
  if (!mine) {
    const senderLabel = document.createElement("div");
    senderLabel.className = "bubble-sender";
    senderLabel.textContent = sender;
    bubble.appendChild(senderLabel);
  }
  row.appendChild(bubble);
  container.appendChild(row);
  container.scrollTop = container.scrollHeight;

  // Phase 19.24 (continued) -- Message Lifecycle Events UI.
  bubble.dataset.mine = mine ? "1" : "0";
  bubble.dataset.conversationId = currentConversationId(container) || "";
  bubble.addEventListener("contextmenu", (event) => showBubbleContextMenu(bubble, event));

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
  textEl.textContent = text + (options.historical ? "" : "");
  bubble.appendChild(textEl);
  const footer = document.createElement("div");
  footer.className = "bubble-footer";
  footer.textContent = options.historical ? "history" : new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
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
  if (options.replyToMessageId) {
    const referenced = bubblesByMessageId.get(options.replyToMessageId);
    if (referenced && referenced.dataset.text) setBubbleReplyPreview(bubble, referenced.dataset.text);
  }
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
  const row = document.createElement("div");
  row.className = "msg-row is-mine";
  const bubble = document.createElement("div");
  bubble.className = "bubble is-failed";
  bubble.dataset.mine = "1";
  bubble.dataset.text = text;

  const textEl = document.createElement("div");
  textEl.className = "bubble-text";
  textEl.textContent = text;
  bubble.appendChild(textEl);

  const footer = document.createElement("div");
  footer.className = "bubble-footer";
  footer.textContent = "Failed";
  bubble.appendChild(footer);

  const retryBtn = document.createElement("button");
  retryBtn.type = "button";
  retryBtn.className = "bubble-retry-btn";
  retryBtn.textContent = "Retry";
  retryBtn.addEventListener("click", () => {
    retryBtn.disabled = true;
    retryBtn.textContent = "Retrying…";
    const sendPromise = isGroup
      ? session.sendGroupMessage(conversationId, text, replyToMessageId, clientMessageId)
      : session.sendMessage(peerUsername, text, replyToMessageId, clientMessageId);
    sendPromise
      .then(() => {
        row.remove();
        renderTextMessage(container, "me", text, { replyToMessageId });
      })
      .catch((error) => {
        appendLog(`ERROR: ${error.message}`);
        retryBtn.disabled = false;
        retryBtn.textContent = "Retry";
      });
  });
  bubble.appendChild(retryBtn);

  row.appendChild(bubble);
  container.appendChild(row);
  container.scrollTop = container.scrollHeight;
  return bubble;
}

function _buildMediaSaveLink(objectUrl, filename) {
  const saveLink = document.createElement("a");
  saveLink.className = "btn btn-ghost btn-sm";
  saveLink.textContent = "Save";
  saveLink.href = objectUrl;
  saveLink.download = filename;
  saveLink.style.display = "inline-block";
  saveLink.style.marginTop = "4px";
  return saveLink;
}

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

  if (options.isDeleted) {
    markBubbleDeleted(bubble);
    const footer = document.createElement("div");
    footer.className = "bubble-footer";
    footer.textContent = options.historical ? "history" : new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    bubble.appendChild(footer);
    return;
  }
  if (options.reactions && options.reactions.length) updateBubbleReactions(bubble, options.reactions);
  if (options.isPinned) setBubblePinned(bubble, true, options.pinnedBy);

  const meta = document.createElement("div");
  meta.className = "msg-meta";
  meta.style.fontSize = "11px";
  meta.style.opacity = ".85";
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

  if (payloadType === "voice") {
    // Phase 19.24 -- Voice Messages: the browser's own native <audio>
    // element IS the real playback control -- no custom player code
    // needed, and it never touches disk (objectUrl is an in-memory
    // Blob URL, released the moment this bubble is gone).
    const audio = document.createElement("audio");
    audio.className = "bubble-media";
    audio.controls = true;
    audio.src = objectUrl;
    audio.style.maxWidth = "260px";
    bubble.appendChild(audio);
    bubble.appendChild(_buildMediaSaveLink(objectUrl, contentMetadata.filename || "voice-message"));
  } else if (payloadType === "video") {
    const video = document.createElement("video");
    video.className = "bubble-media";
    video.controls = true;
    video.src = objectUrl;
    video.style.maxWidth = "280px";
    video.style.borderRadius = "10px";
    bubble.appendChild(video);
    bubble.appendChild(_buildMediaSaveLink(objectUrl, contentMetadata.filename || "video-message"));
  } else if (payloadType === "image") {
    const img = document.createElement("img");
    img.className = "bubble-image msg-image";
    img.src = objectUrl;
    img.alt = contentMetadata.filename || "received image";
    img.addEventListener("click", () => openLightbox(objectUrl));
    bubble.appendChild(img);

    // Phase 19.23 -- Issue 4: explicit, always-visible View/Save
    // controls -- previously an image bubble offered no button at
    // all, only a click-to-zoom on the image itself with no save
    // affordance whatsoever (a file attachment already had its own
    // always-visible download link a few lines below; an image had
    // no equivalent). Plain, unstyled buttons render inline and
    // static by default -- nothing here is hidden behind :hover, and
    // none is added anywhere in this file's CSS.
    const actions = document.createElement("div");
    actions.className = "msg-image-actions";
    const viewBtn = document.createElement("button");
    viewBtn.type = "button";
    viewBtn.className = "btn btn-ghost btn-sm";
    viewBtn.textContent = "View";
    viewBtn.addEventListener("click", () => openLightbox(objectUrl));
    const saveLink = document.createElement("a");
    saveLink.className = "btn btn-ghost btn-sm";
    saveLink.textContent = "Save";
    saveLink.href = objectUrl;
    saveLink.download = contentMetadata.filename || "image";
    actions.appendChild(viewBtn);
    actions.appendChild(saveLink);
    bubble.appendChild(actions);
  } else {
    const link = document.createElement("a");
    link.className = "bubble-file msg-file";
    link.href = objectUrl;
    link.download = contentMetadata.filename || "download";
    link.innerHTML = `&#128206; Download (${(contentMetadata.size_bytes || bytes.length).toLocaleString()} bytes)`;
    bubble.appendChild(link);
  }

  const footer = document.createElement("div");
  footer.className = "bubble-footer";
  footer.textContent = options.historical ? "history" : new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  bubble.appendChild(footer);

  const mine = sender === "me" || sender === session?.username;
  if (mine) appendSentTick(footer, container, options.status);
}

function openLightbox(objectUrl) {
  const box = document.createElement("div");
  box.className = "lightbox";
  const img = document.createElement("img");
  img.src = objectUrl;
  box.appendChild(img);
  box.addEventListener("click", () => box.remove());
  document.body.appendChild(box);
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

// Best-effort: a peer with no uploaded picture, or a fetch failure
// (offline peer, transient error), silently keeps the initial-letter
// fallback that's already showing -- never blocks or errors the chat
// screen itself over a missing/failed avatar.
async function loadPeerAvatar(el, username, initial) {
  resetAvatarInitial(el, initial);
  if (!session) return;
  try {
    const picture = await session.fetchProfilePicture(username);
    if (picture) setAvatarImage(el, picture.bytes, picture.contentType);
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

function renderChatList() {
  chatListEl.innerHTML = "";
  const peers = Array.from(knownDirectPeers).filter(
    (peer) => Boolean(session?.isConversationArchived(peer)) === showArchivedChats
  );
  if (peers.length === 0) {
    chatListEl.innerHTML = showArchivedChats
      ? '<div class="empty-hint">No archived chats.</div>'
      : '<div class="empty-hint">Type a username above and press Enter to open a direct chat.</div>';
    return;
  }
  for (const peer of peers) {
    const row = document.createElement("div");
    row.className = `row-card${peer === activeDirectPeer ? " is-selected" : ""}`;
    const muted = session?.isConversationMuted(peer);
    row.innerHTML = `
      <div class="avatar">${initialOf(peer)}</div>
      <div class="row-main">
        <div class="row-title">${peer}</div>
        <div class="row-sub">Direct message</div>
      </div>
      <button type="button" class="row-mute-btn" title="${muted ? "Unmute" : "Mute"}">${muted ? "\u{1F515}" : "\u{1F514}"}</button>`;
    row.addEventListener("click", () => openDirectChat(peer));
    row.querySelector(".row-mute-btn").addEventListener("click", (event) => {
      showMuteMenu(peer, event, renderChatList);
    });
    chatListEl.appendChild(row);
  }
}

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
    return;
  }
  peerPresenceEl.textContent = "";
  try {
    const lastSeen = await session.fetchLastSeen(peerUsername);
    // The round trip is async -- the open chat may already be a
    // DIFFERENT peer by the time it resolves; never apply a stale
    // result to it.
    if (document.getElementById("peerUsername").value !== peerUsername) return;
    if (lastSeen) peerPresenceEl.textContent = _formatLastSeen(lastSeen);
  } catch (error) {
    appendLog(`ERROR: could not fetch last seen: ${error.message}`);
  }
}

function openDirectChat(peerUsername) {
  if (!peerUsername) return;
  saveCurrentDraftIfAny();
  stopTypingImmediately();
  resetTypingStatusDisplay();
  knownDirectPeers.add(peerUsername);
  activeDirectPeer = peerUsername;
  document.getElementById("peerUsername").value = peerUsername;
  chatTitleEl.childNodes[0].textContent = peerUsername + " ";
  loadPeerAvatar(chatAvatarEl, peerUsername, initialOf(peerUsername));

  // This peer's identity may already have been observed (e.g. the
  // network announcement arrived before the user searched for them) --
  // session.peers already has it in that case, and clearing the display
  // here would erase real data with nothing left to repopulate it, since
  // onPeerObserved only fires again on a NEW announcement. Reflect
  // whatever is already known instead of assuming "nothing yet".
  const known = session?.peers.get(peerUsername);
  if (known) {
    fingerprintEl.textContent = `${peerUsername}: ${known.fingerprint} [${known.state}]`;
    const verified = known.state === "VERIFIED";
    peerVerifiedBadgeEl.textContent = verified ? "verified" : known.state.toLowerCase();
    peerVerifiedBadgeEl.classList.toggle("is-unverified", !verified);
  } else {
    fingerprintEl.textContent = "";
    peerVerifiedBadgeEl.textContent = "unverified";
    peerVerifiedBadgeEl.classList.add("is-unverified");
  }

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
        session.forgetRenderedHistory(conversationId);
        return session.loadHistory(conversationId, false);
      })
      .catch((error) => appendLog(`ERROR: ${error.message}`));
  }
}

document.getElementById("peerUsername").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    openDirectChat(event.target.value.trim());
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
let peerUsernameDebounce = null;
document.getElementById("peerUsername").addEventListener("input", (event) => {
  clearTimeout(peerUsernameDebounce);
  const value = event.target.value.trim();
  peerUsernameDebounce = setTimeout(() => {
    if (value && value === activeDirectPeer) return;
    openDirectChat(value);
  }, 300);
});

// ------------------------------------------------------------------
// Sidebar: groups
// ------------------------------------------------------------------

function renderGroupList() {
  if (!session) return;
  groupListEl.innerHTML = "";
  const groups = Array.from(session.groups.entries()).filter(
    ([conversationId]) => session.isConversationArchived(conversationId) === showArchivedGroups
  );
  if (groups.length === 0) {
    groupListEl.innerHTML = showArchivedGroups
      ? '<div class="empty-hint">No archived groups.</div>'
      : '<div class="empty-hint">No groups yet -- create one above.</div>';
    return;
  }
  for (const [conversationId, group] of groups) {
    const row = document.createElement("div");
    row.className = `row-card${conversationId === activeGroupIdEl.value ? " is-selected" : ""}`;
    const muted = session.isConversationMuted(conversationId);
    row.innerHTML = `
      <div class="avatar" style="background:var(--accent);">${initialOf(group.name)}</div>
      <div class="row-main">
        <div class="row-title">${group.name}</div>
        <div class="row-sub">${group.members.length} members</div>
      </div>
      <button type="button" class="row-mute-btn" title="${muted ? "Unmute" : "Mute"}">${muted ? "\u{1F515}" : "\u{1F514}"}</button>`;
    row.addEventListener("click", () => openGroupChat(conversationId, group));
    row.querySelector(".row-mute-btn").addEventListener("click", (event) => {
      showMuteMenu(conversationId, event, renderGroupList, true);
    });
    groupListEl.appendChild(row);
  }
}

document.getElementById("archivedGroupsToggle").addEventListener("click", () => {
  showArchivedGroups = !showArchivedGroups;
  document.getElementById("archivedGroupsToggle").textContent = showArchivedGroups ? "Back to Groups" : "Archived";
  renderGroupList();
});

function openGroupChat(conversationId, group) {
  saveCurrentDraftIfAny();
  stopTypingImmediately();
  resetTypingStatusDisplay();
  activeGroupIdEl.value = conversationId;
  groupTitleEl.textContent = group.name;
  groupSubEl.textContent = `${group.members.length} members • ${group.members.join(", ")}`;
  groupAvatarEl.textContent = initialOf(group.name);
  setMainView("groupChat");
  renderGroupList();

  // See openDirectChat()'s own comment -- identical fix, group side.
  groupMessagesEl.innerHTML = "";
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
function renderGroupInfo() {
  const conversationId = activeGroupIdEl.value;
  const group = session?.groups.get(conversationId);
  if (!group) return;

  const onlineUsers = session.onlineUsers || new Set();
  const onlineCount = group.members.filter((m) => onlineUsers.has(m)).length;

  groupInfoNameEl.textContent = group.name;
  groupInfoSubEl.textContent = `${group.members.length} members • ${onlineCount} online`;

  // Phase 19.18 -- Group Info remove-member closure: admin-only, same
  // gating mobile/app.py::_open_group_members_dialog() already uses
  // (hiding Remove for a non-admin here is a convenience only --
  // server/client_handler.py::handle_group_remove_member() re-derives
  // the admin from the database on every call and rejects anyone
  // else, so this can never grant anything the server would refuse).
  const isSelfAdmin = group.admin && group.admin === session.username;

  groupInfoMembersEl.innerHTML = "";
  for (const username of group.members) {
    const isAdmin = group.admin && username === group.admin;
    const isOnline = onlineUsers.has(username);
    const roleText = isAdmin ? "Admin" : (isOnline ? "Online" : "Offline");
    const roleClass = isAdmin ? "" : (isOnline ? "is-online" : "is-offline");

    const row = document.createElement("div");
    row.className = "member-row";
    row.innerHTML = `
      <div class="avatar sm">${initialOf(username)}</div>
      <div class="row-title">${username}${username === session.username ? " (you)" : ""}</div>
      <div class="member-role ${roleClass}">${roleText}</div>`;

    if (isSelfAdmin && username !== session.username && !isAdmin) {
      const removeBtn = document.createElement("button");
      removeBtn.className = "btn btn-danger btn-sm";
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
          appendLog(`ERROR: ${error.message}`);
          removeBtn.disabled = false;
        }
      });
      row.appendChild(removeBtn);
    }

    groupInfoMembersEl.appendChild(row);
  }
}

// Mirrors the #peerUsername input listener above (see its comment for
// why "input" + debounce, not "change"): a completed conversation_id
// opens that group's chat view if it's already known, same as clicking
// its row-card.
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
  const requester = notification.requester_username || "Someone";
  const bodyText = isGroupRequest
    ? `${requester} wants to add ${notification.candidate_username || "a member"} to ${notification.group_name || "the group"}`
    : `${requester} wants to verify their identity`;

  const card = document.createElement("div");
  card.className = "card notif-card";
  card.innerHTML = `
    <div class="notif-title">${isGroupRequest ? "GROUP MEMBER REQUEST" : "VERIFICATION REQUEST"}</div>
    <div class="notif-body"></div>`;
  card.querySelector(".notif-body").textContent = bodyText;

  const isMine = requester === session.username;

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
        await session.respondToInbox(notification, approve);
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
    resolvedEl.textContent = {
      approved: "Approved", denied: "Denied", pending: "Waiting for a response...",
    }[notification.status] || notification.status || "";
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
  const sent = notifications.filter((n) => n.requester_username === myUsername && n.status !== "pending");

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

document.getElementById("connectBtn").addEventListener("click", async () => {
  const gatewayUrl = document.getElementById("gatewayUrl").value;
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
        renderTextMessage(groupMessagesEl, sender, text, options || {});
        return;
      }
      // Phase 19.17C -- #messages is one shared DOM node for every
      // direct peer; without this check, a live message from peer B
      // rendered directly into whatever peer A's chat you currently
      // have open (message-mixing between unrelated conversations).
      const peerKey = resolveDirectPeerKey(identityKey);
      knownDirectPeers.add(peerKey);
      renderChatList();
      if (peerKey === activeDirectPeer) {
        renderTextMessage(messagesEl, sender, text, options || {});
      }
    },
    onAttachment: (identityKey, sender, payloadType, bytes, contentMetadata, options) => {
      if (session.groups.has(identityKey)) {
        renderAttachment(groupMessagesEl, sender, payloadType, bytes, contentMetadata, options || {});
        return;
      }
      const peerKey = resolveDirectPeerKey(identityKey);
      knownDirectPeers.add(peerKey);
      renderChatList();
      if (peerKey === activeDirectPeer) {
        renderAttachment(messagesEl, sender, payloadType, bytes, contentMetadata, options || {});
      }
    },
    onPeerObserved: (peerUsername, fingerprint, state) => {
      fingerprintEl.textContent = `${peerUsername}: ${fingerprint} [${state}]`;
      const verified = state === "VERIFIED";
      peerVerifiedBadgeEl.textContent = verified ? "verified" : state.toLowerCase();
      peerVerifiedBadgeEl.classList.toggle("is-unverified", !verified);
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
      // Phase 19.24 -- Presence/Last Seen: the same server-pushed
      // event every other presence indicator in this file already
      // uses -- no polling added.
      if (!chatViewEl.hidden) {
        refreshPeerPresence(document.getElementById("peerUsername").value);
      }
    },
    // Phase 19.18 -- only re-renders if the Inbox tab is actually the
    // one on screen right now -- a live update must not yank the user
    // away from whatever else they're doing (same reasoning as
    // mobile/app.py's own _inbox_open-gated refresh).
    onInboxUpdated: (notification) => {
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
  knownDirectPeers.clear();
  activeDirectPeer = null;
  for (const key of Object.keys(pendingSentTicksByPeer)) delete pendingSentTicksByPeer[key];
});

document.getElementById("confirmVerifiedBtn").addEventListener("click", () => {
  const peerUsername = document.getElementById("peerUsername").value;
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
    peerVerifiedBadgeEl.textContent = "verified";
    peerVerifiedBadgeEl.classList.remove("is-unverified");
    // Phase 19.23 -- Issue 1: add this newly-verified peer to the
    // sidebar immediately, not just at this browser's next login.
    knownDirectPeers.add(peerUsername);
    renderChatList();
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
  }
});

document.getElementById("requestVerificationBtn").addEventListener("click", async () => {
  const peerUsername = document.getElementById("peerUsername").value;
  try {
    await session.requestVerification(peerUsername);
    appendLog(`Verification requested from ${peerUsername}.`);
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
  }
});

document.getElementById("establishKeyBtn").addEventListener("click", async () => {
  const peerUsername = document.getElementById("peerUsername").value;
  try {
    await session.establishSessionKey(peerUsername);
    appendLog(`Session key established with ${peerUsername}.`);
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
  }
});

document.getElementById("sendBtn").addEventListener("click", async () => {
  const peerUsername = document.getElementById("peerUsername").value;
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
      appendLog(`ERROR: ${error.message}`);
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
    renderTextMessage(messagesEl, "me", text, { replyToMessageId });
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
    renderFailedBubble(messagesEl, text, {
      replyToMessageId, clientMessageId, peerUsername, isGroup: false,
    });
  }
  document.getElementById("messageText").value = "";
});
document.getElementById("messageText").addEventListener("keydown", (event) => {
  if (event.key === "Enter") { event.preventDefault(); document.getElementById("sendBtn").click(); }
});

document.getElementById("markReadBtn")?.addEventListener("click", async () => {
  const peerUsername = document.getElementById("peerUsername").value;
  try {
    const conversationId = await session.openDirectConversation(peerUsername);
    session.markRead(conversationId);
    appendLog(`Marked ${conversationId} as read.`);
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
  }
});

document.getElementById("loadHistoryBtn").addEventListener("click", async () => {
  const peerUsername = document.getElementById("peerUsername").value;
  try {
    const conversationId = await session.openDirectConversation(peerUsername);
    await session.loadHistory(conversationId, false);
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
  }
});

document.getElementById("wallpaperBtn").addEventListener("click", (event) => {
  const peerUsername = document.getElementById("peerUsername").value;
  showWallpaperPicker(messagesEl, peerUsername, event);
});

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

document.getElementById("sendAttachmentBtn").addEventListener("click", async () => {
  const peerUsername = document.getElementById("peerUsername").value;
  const fileInput = document.getElementById("attachmentInput");
  const file = fileInput.files && fileInput.files[0];
  if (!file) {
    appendLog("ERROR: no file selected.");
    return;
  }
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    await session.sendAttachment({ peerUsername }, bytes, file.name, file.type || "application/octet-stream");
    renderAttachment(messagesEl, "me", bytes.length && file.type.startsWith("image/") ? "image" : "file", bytes, {
      filename: file.name, mime_type: file.type, size_bytes: bytes.length,
    });
    fileInput.value = "";
    document.getElementById("sendAttachmentBtn").hidden = true;
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
  }
});

document.getElementById("createGroupBtn").addEventListener("click", async () => {
  const name = document.getElementById("groupName").value;
  const members = document.getElementById("groupMembers").value
    .split(",").map((m) => m.trim()).filter(Boolean);
  try {
    await session.createGroup(name, members);
    appendLog(`Requested group '${name}' with members: ${members.join(", ")}`);
    document.getElementById("groupName").value = "";
    document.getElementById("groupMembers").value = "";
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
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
      appendLog(`ERROR: ${error.message}`);
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
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
    renderFailedBubble(groupMessagesEl, text, {
      replyToMessageId, clientMessageId, conversationId, isGroup: true,
    });
  }
  document.getElementById("groupMessageText").value = "";
});
document.getElementById("groupMessageText").addEventListener("keydown", (event) => {
  if (event.key === "Enter") { event.preventDefault(); document.getElementById("sendGroupMessageBtn").click(); }
});

document.getElementById("loadGroupHistoryBtn").addEventListener("click", async () => {
  const conversationId = activeGroupIdEl.value;
  try {
    await session.loadHistory(conversationId, true);
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
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
      <div class="avatar sm">${initialOf(device.device_name)}</div>
      <div class="row-main">
        <div class="row-title">${device.device_name || "(unnamed)"} <span class="row-sub">[${device.platform || "?"}]</span></div>
        <div class="row-sub">${device.state} • ${device.device_id}</div>
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
    appendLog(`ERROR: ${error.message}`);
  }
});

document.getElementById("bindDeviceBtn").addEventListener("click", async () => {
  try {
    await session.bindDeviceSession();
    appendLog(`Bound this connection to device ${session.deviceId}.`);
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
  }
});

document.getElementById("listDevicesBtn").addEventListener("click", async () => {
  try {
    const devices = await session.listDevices();
    renderDeviceList(devices);
    if (session.deviceId) myDeviceIdEl.textContent = session.deviceId;
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
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
    appendLog(`ERROR: ${error.message}`);
  }
});

document.getElementById("authorizeDeviceBtn").addEventListener("click", async () => {
  const targetDeviceId = document.getElementById("targetDeviceId").value;
  try {
    session.confirmDevicePeerVerified(targetDeviceId, observedDeviceFingerprint);
    await session.authorizeDevice(targetDeviceId, observedDeviceFingerprint);
    appendLog(`Authorized device ${targetDeviceId}.`);
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
  }
});

document.getElementById("revokeDeviceBtn").addEventListener("click", async () => {
  const targetDeviceId = document.getElementById("targetDeviceId").value;
  try {
    await session.revokeDevice(targetDeviceId);
    appendLog(`Revoked device ${targetDeviceId}.`);
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
  }
});

document.getElementById("syncKeyBtn").addEventListener("click", async () => {
  const targetDeviceId = document.getElementById("targetDeviceId").value;
  const conversationId = document.getElementById("syncConversationId").value;
  try {
    await session.syncConversationKeyToDevice(targetDeviceId, conversationId, "direct");
    appendLog(`Synced conversation ${conversationId} to device ${targetDeviceId}.`);
  } catch (error) {
    appendLog(`ERROR: ${error.message}`);
  }
});
