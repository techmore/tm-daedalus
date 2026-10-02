import unittest

from daedalus.live import LiveHub


class FakeWebSocket:
    def __init__(self):
        self.accepted = False
        self.close_call = None
        self.messages = []

    async def accept(self):
        self.accepted = True

    async def close(self, *, code, reason):
        self.close_call = (code, reason)

    async def send_json(self, message):
        self.messages.append(message)


class LiveHubTests(unittest.IsolatedAsyncioTestCase):
    async def test_revoke_closes_only_the_target_users_workspace_feed(self):
        hub = LiveHub()
        revoked_user_feed = FakeWebSocket()
        other_user_feed = FakeWebSocket()
        other_workspace_feed = FakeWebSocket()

        await hub.connect(organization_id=7, user_id=12, websocket=revoked_user_feed)
        await hub.connect(organization_id=7, user_id=13, websocket=other_user_feed)
        await hub.connect(organization_id=8, user_id=12, websocket=other_workspace_feed)

        await hub.revoke_user_access(organization_id=7, user_id=12)
        await hub.publish(7, {"type": "workspace_event"})
        await hub.publish(8, {"type": "other_workspace_event"})

        self.assertEqual(
            revoked_user_feed.close_call,
            (4403, "Workspace access revoked"),
        )
        self.assertEqual(revoked_user_feed.messages, [])
        self.assertEqual(other_user_feed.close_call, None)
        self.assertEqual(other_user_feed.messages, [{"type": "workspace_event"}])
        self.assertEqual(
            other_workspace_feed.messages,
            [{"type": "other_workspace_event"}],
        )

    async def test_private_membership_feeds_only_receive_targeted_workspace_decisions(self):
        hub = LiveHub()
        admin_feed = FakeWebSocket()
        other_member_feed = FakeWebSocket()
        requester_feed = FakeWebSocket()
        other_workspace_feed = FakeWebSocket()

        await hub.connect(7, 12, admin_feed)
        await hub.connect(7, 13, other_member_feed)
        await hub.connect(7, 14, requester_feed, receive_workspace_events=False)
        await hub.connect(8, 14, other_workspace_feed)

        await hub.publish(7, {"type": "workspace_event"})
        self.assertEqual(admin_feed.messages, [{"type": "workspace_event"}])
        self.assertEqual(other_member_feed.messages, [{"type": "workspace_event"}])
        self.assertEqual(requester_feed.messages, [])

        decision = {"type": "membership_decision", "status": "approved"}
        await hub.publish_to_user(7, 14, decision)
        self.assertEqual(requester_feed.messages, [decision])
        self.assertEqual(admin_feed.messages, [{"type": "workspace_event"}])
        self.assertEqual(other_member_feed.messages, [{"type": "workspace_event"}])
        self.assertEqual(other_workspace_feed.messages, [])

        await hub.revoke_user_access(7, 14)
        self.assertEqual(requester_feed.close_call, (4403, "Workspace access revoked"))

    async def test_targeted_workspace_publish_skips_other_users_and_other_workspaces(self):
        hub = LiveHub()
        target_first_session = FakeWebSocket()
        target_private_session = FakeWebSocket()
        other_user = FakeWebSocket()
        other_workspace = FakeWebSocket()
        await hub.connect(7, 14, target_first_session)
        await hub.connect(7, 14, target_private_session, receive_workspace_events=False)
        await hub.connect(7, 15, other_user)
        await hub.connect(8, 14, other_workspace)

        message = {"type": "membership_request_received"}
        await hub.publish_to_users(7, {14}, message)

        self.assertEqual(target_first_session.messages, [message])
        self.assertEqual(target_private_session.messages, [message])
        self.assertEqual(other_user.messages, [])
        self.assertEqual(other_workspace.messages, [])


if __name__ == "__main__":
    unittest.main()
