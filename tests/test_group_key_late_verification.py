"""
A person added to a group before they and the key holder have verified each other must still get
the group key once both sides have genuinely verified -- in either order -- and never before.

Root cause this pins down: ClientSession._distribute_group_key() skips a recipient that is not yet
verified (or whose identity has not been observed). The skip was silent and forgotten, so when the
holder verified that person later nothing re-sent the key; the member sat in the group, unable to
read it. Verification itself is unchanged: every step still goes through the explicit
confirm_*_verification calls, and the key is only ever wrapped for a VERIFIED identity.

Real server, real ClientSession objects (the same pattern as test_group_admin_and_inbox.py).
"""

import time

from tests.test_group_admin_and_inbox import (  # noqa: F401 -- fixtures and helpers reused
    _app,
    _new_session,
    _verify,
    _wait_for,
    running_server,
)
from utils.protocol import create_conversation_list_request_packet


def _group_id(session, name):
    for summary in session.conversation_store.get_all():
        if summary.is_group and summary.group_name == name:
            return summary.conversation_id
    return None


def _create_group(admin, name, members):
    admin.create_group_conversation(name, [m.username for m in members])
    assert _wait_for(lambda: _group_id(admin, name) is not None)
    return _group_id(admin, name)


def _quiet(seconds=0.8):
    end = time.time() + seconds
    while time.time() < end:
        _app.processEvents()
        time.sleep(0.05)


def test_a_member_verified_by_the_holder_after_the_group_exists_receives_the_key(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    try:
        _verify(member, admin)                       # the member already trusts the admin ...
        conversation_id = _create_group(admin, "Late A", [member])   # ... but the admin has not verified them
        _quiet()
        assert not member.key_manager.has_key(conversation_id)      # no key may be wrapped for an unverified identity

        _verify(admin, member)                       # the admin's explicit confirmation

        assert _wait_for(lambda: member.key_manager.has_key(conversation_id), attempts=200)
        assert member.key_manager.get_key(conversation_id) == admin.key_manager.get_key(conversation_id)
    finally:
        admin.disconnect()
        member.disconnect()


def test_the_key_waits_for_the_members_own_verification_of_the_holder_too(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    try:
        _verify(admin, member)                       # the admin trusts the member first ...
        conversation_id = _create_group(admin, "Late B", [member])
        _quiet()
        assert not member.key_manager.has_key(conversation_id)      # ... but the member rejects an unverified sender

        _verify(member, admin)                       # now the member verifies the admin

        assert _wait_for(lambda: member.key_manager.has_key(conversation_id), attempts=200)
    finally:
        admin.disconnect()
        member.disconnect()


def test_neither_side_verified_yet_then_both_do_in_turn(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    try:
        conversation_id = _create_group(admin, "Late C", [member])
        _quiet()
        assert not member.key_manager.has_key(conversation_id)

        _verify(admin, member)
        _quiet()
        assert not member.key_manager.has_key(conversation_id)      # still no: the member has not verified the admin
        _verify(member, admin)

        assert _wait_for(lambda: member.key_manager.has_key(conversation_id), attempts=200)
    finally:
        admin.disconnect()
        member.disconnect()


def test_a_member_added_later_by_the_admin_gets_the_key_after_both_verify(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    friend = _new_session(running_server, monkeypatch, "friend", tmp_path)
    newcomer = _new_session(running_server, monkeypatch, "newcomer", tmp_path)
    try:
        _verify(admin, friend)
        _verify(friend, admin)
        conversation_id = _create_group(admin, "Late D", [friend])
        assert _wait_for(lambda: friend.key_manager.has_key(conversation_id))

        admin.add_group_members(conversation_id, [newcomer.username])   # never spoken to, never verified
        assert _wait_for(lambda: newcomer.username in admin.conversation_store.get(conversation_id).participants)
        _quiet()
        assert not newcomer.key_manager.has_key(conversation_id)

        _verify(newcomer, admin)
        _verify(admin, newcomer)

        assert _wait_for(lambda: newcomer.key_manager.has_key(conversation_id), attempts=200)
        # The newcomer reads the CURRENT epoch's key -- the same one the others use.
        assert newcomer.key_manager.get_key(conversation_id) == admin.key_manager.get_key(conversation_id)
    finally:
        admin.disconnect()
        friend.disconnect()
        newcomer.disconnect()


def test_the_key_is_never_sent_to_someone_who_is_not_a_member(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    outsider = _new_session(running_server, monkeypatch, "outsider", tmp_path)
    try:
        conversation_id = _create_group(admin, "Late E", [member])
        _verify(admin, outsider)                     # verifying an outsider must not hand them anything
        _verify(outsider, admin)
        _verify(admin, member)
        _verify(member, admin)

        assert _wait_for(lambda: member.key_manager.has_key(conversation_id), attempts=200)
        _quiet()
        assert not outsider.key_manager.has_key(conversation_id)
    finally:
        admin.disconnect()
        member.disconnect()
        outsider.disconnect()


def test_group_info_shows_who_is_verified_and_why_the_group_cannot_be_read_yet(running_server, monkeypatch, tmp_path):
    from PySide6.QtWidgets import QLabel, QPushButton

    from gui.group_info_dialog import GroupInfoDialog

    def _rows(dialog):
        """The widgets of the rows currently IN the list (not rows replaced by a refresh)."""
        widgets = [dialog._member_list.itemWidget(dialog._member_list.item(i)) for i in range(dialog._member_list.count())]
        labels = [l.text() for w in widgets for l in w.findChildren(QLabel) if l.objectName() == "MemberTrust"]
        buttons = [b for w in widgets for b in w.findChildren(QPushButton) if b.objectName() == "MemberVerifyButton"]
        return labels, buttons

    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    try:
        conversation_id = _create_group(admin, "Info Group", [member])
        assert _wait_for(lambda: _group_id(member, "Info Group") is not None)
        dialog = GroupInfoDialog(member, conversation_id)
        try:
            dialog.show()
            _app.processEvents()
            assert dialog._key_notice.isVisible()                                  # no key yet, and it says why
            assert "do not have this group's key" in dialog._key_notice.text()
            trust, verify_buttons = _rows(dialog)
            assert trust == ["Not verified"] or trust == ["Not seen yet"]           # the admin, as this account sees them
            assert len(verify_buttons) == 1

            _verify(member, admin)
            _verify(admin, member)
            assert _wait_for(lambda: member.key_manager.has_key(conversation_id), attempts=200)
            dialog._refresh()
            _app.processEvents()

            assert not dialog._key_notice.isVisible()
            trust, verify_buttons = _rows(dialog)
            assert trust == ["✓ Verified"] and not verify_buttons
        finally:
            dialog._refresh_timer.stop()
            dialog.close()
    finally:
        admin.disconnect()
        member.disconnect()


def test_a_removed_member_never_receives_the_key_even_if_verified_afterwards(running_server, monkeypatch, tmp_path):
    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    friend = _new_session(running_server, monkeypatch, "friend", tmp_path)
    try:
        _verify(admin, friend)
        _verify(friend, admin)
        conversation_id = _create_group(admin, "Removed Late", [member, friend])
        _quiet()
        assert not member.key_manager.has_key(conversation_id)           # skipped: not yet verified

        response = admin.remove_group_member(conversation_id, member.username)
        assert response.get("success")
        _quiet()

        _verify(admin, member)                                           # verified only AFTER the removal ...
        _verify(member, admin)                                           # ... on both sides, and the member asks
        member._after_peer_verified(admin.username)
        _quiet(1.5)

        assert not member.key_manager.has_key(conversation_id)           # ... and still gets nothing
        # (the key they would have received at the current epoch also stays unreadable to them:
        # a rotation after the removal gave the remaining members a NEW epoch they never see.)
        assert friend.key_manager.has_key(conversation_id)
    finally:
        admin.disconnect()
        member.disconnect()
        friend.disconnect()


def test_only_an_active_member_can_ask_for_a_groups_key(running_server, monkeypatch, tmp_path):
    from utils.network import send_message
    from utils.protocol import create_group_key_request_packet

    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    member = _new_session(running_server, monkeypatch, "member", tmp_path)
    outsider = _new_session(running_server, monkeypatch, "outsider", tmp_path)
    try:
        conversation_id = _create_group(admin, "Ask Group", [member])
        asked = []
        original = admin.handle_group_key_rotation_required

        def _spy(packet):
            asked.append(list(packet.get("members", [])))
            return original(packet)

        monkeypatch.setattr(admin, "handle_group_key_rotation_required", _spy)

        # An outsider asking -- and a malformed id -- reach nobody.
        send_message(outsider.client_socket, create_group_key_request_packet(conversation_id))
        send_message(outsider.client_socket, create_group_key_request_packet("not-a-uuid"))
        _quiet(1.0)
        assert asked == []

        # A real member asking makes the admin (who holds the key) send it to THAT member only.
        send_message(member.client_socket, create_group_key_request_packet(conversation_id))
        assert _wait_for(lambda: asked == [[member.username]])
    finally:
        admin.disconnect()
        member.disconnect()
        outsider.disconnect()


def test_a_key_request_never_goes_to_a_member_who_may_not_hold_the_key(running_server, monkeypatch, tmp_path):
    """With the admin offline, another connected member is NOT asked: that member could be a late
    joiner without the key, and the rotation instruction would make them invent a new one."""
    from utils.network import send_message
    from utils.protocol import create_group_key_request_packet

    admin = _new_session(running_server, monkeypatch, "admin", tmp_path)
    first = _new_session(running_server, monkeypatch, "first", tmp_path)
    second = _new_session(running_server, monkeypatch, "second", tmp_path)
    try:
        conversation_id = _create_group(admin, "Admin Away", [first, second])
        asked = []
        original = first.handle_group_key_rotation_required

        def _spy(packet):
            asked.append(packet.get("members"))
            return original(packet)

        monkeypatch.setattr(first, "handle_group_key_rotation_required", _spy)
        admin.disconnect()
        _quiet(1.0)

        send_message(second.client_socket, create_group_key_request_packet(conversation_id))
        _quiet(1.5)

        assert asked == []
    finally:
        first.disconnect()
        second.disconnect()
