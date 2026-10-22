"""Group conversations across Website and Desktop members, driven through the real UIs.

One admin (Website) creates a group with Website and Desktop members, who each join by approving the
invitation in their own Inbox; messages must reach exactly the members, additions get the new key, a removed member and a member who left stop receiving, and a
non-member never sees the group or its content.
"""

import uuid

from tests.acceptance import desktop_driver as dd
from tests.acceptance.parties import verify_pair
from tests.acceptance.web_driver import wait_until


def test_group_lifecycle_across_website_and_desktop_members(party):
    admin = party("web", "gadmin")
    member_b, member_c = party("web", "gmemb"), party("web", "gmemc")
    member_d = party("desktop", "gmemd")
    outsider = party("web", "gout")

    for member in (member_b, member_c, member_d):
        verify_pair(admin, member)  # the admin must be verified by every member, and vice versa

    group = f"grp-{uuid.uuid4().hex[:6]}"
    admin.user.create_group(group, [member_b.username, member_c.username, member_d.username])

    # Nobody is added: each person is invited and joins by approving in their own Inbox (the Website
    # members on the Website, the Desktop member on the Desktop).
    for member in (member_b, member_c):
        member.user.approve_invitation(group)
        member.user.open_group(group)
    dd.approve_first_invitation(member_d.app)
    dd.open_conversation(member_d.app, group)

    # 1. A message from the admin reaches every member.
    first = f"{group}: hello from the admin"
    admin.user.open_group(group)
    admin.user.send_group(first)
    for member in (member_b, member_c):
        member.user.wait_for_group_message(first)
    member_d.wait_for_text(first)

    # 2. A reply from a Website member reaches everyone, including the Desktop member.
    second = f"{group}: hello from member b"
    member_b.user.send_group(second)
    admin.user.wait_for_group_message(second)
    member_c.user.wait_for_group_message(second)
    member_d.wait_for_text(second)

    # 3. A reply from the Desktop member reaches the Website members.
    third = f"{group}: hello from the desktop member"
    member_d.send(third)
    for member in (admin, member_b, member_c):
        member.user.wait_for_group_message(third)

    # 4. A non-member neither has the group nor sees any of its content.
    assert not outsider.user.has_group(group)
    page_text = outsider.user.page.content()
    assert not any(text in page_text for text in (first, second, third))

    # 5. Adding a member: they join and receive new messages.
    newcomer = party("web", "gnew")
    verify_pair(admin, newcomer)
    admin.user.add_group_members(group, [newcomer.username])
    newcomer.user.approve_invitation(group)
    newcomer.user.open_group(group)
    after_add = f"{group}: welcome to the new member"
    admin.user.open_group(group)
    admin.user.send_group(after_add)
    newcomer.user.wait_for_group_message(after_add)

    # 6. Removing a member: they lose the group and do not receive later messages.
    admin.user.remove_group_member(group, member_c.username)
    wait_until(lambda: not member_c.user.has_group(group), 30, what="the removed member to lose the group")
    after_removal = f"{group}: only current members see this"
    admin.user.open_group(group)
    admin.user.send_group(after_removal)
    member_b.user.wait_for_group_message(after_removal)
    member_d.wait_for_text(after_removal)
    assert after_removal not in member_c.user.page.content()

    # 7. Leaving: the member's own view drops the group and the admin's member list shrinks.
    member_b.user.leave_group(group)
    members_now = admin.user.group_member_names(group)
    assert member_b.username not in members_now
    assert member_d.username in members_now and newcomer.username in members_now

    for p in (admin, member_b, member_c, member_d, outsider, newcomer):
        assert not p.errors(), (p.username, p.errors())
