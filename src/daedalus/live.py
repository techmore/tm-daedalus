from __future__ import annotations

from collections import defaultdict

from fastapi import WebSocket


class LiveHub:
    def __init__(self) -> None:
        self._clients: dict[int, dict[WebSocket, int]] = defaultdict(dict)
        # Pending members may subscribe so they can receive their own decision,
        # but must not receive the workspace's general event stream.
        self._workspace_event_clients: set[WebSocket] = set()

    async def connect(
        self,
        organization_id: int,
        user_id: int,
        websocket: WebSocket,
        *,
        receive_workspace_events: bool = True,
    ) -> None:
        await websocket.accept()
        self._clients[organization_id][websocket] = user_id
        if receive_workspace_events:
            self._workspace_event_clients.add(websocket)

    def disconnect(self, organization_id: int, websocket: WebSocket) -> None:
        self._workspace_event_clients.discard(websocket)
        clients = self._clients.get(organization_id)
        if clients is None:
            return
        clients.pop(websocket, None)
        if not clients:
            self._clients.pop(organization_id, None)

    async def revoke_user_access(self, organization_id: int, user_id: int) -> None:
        clients = self._clients.get(organization_id, {})
        targets = [
            websocket
            for websocket, client_user_id in clients.items()
            if client_user_id == user_id
        ]
        for websocket in targets:
            try:
                await websocket.close(code=4403, reason="Workspace access revoked")
            except Exception:
                pass
            self.disconnect(organization_id, websocket)

    async def publish_to_users(
        self, organization_id: int, user_ids: set[int] | list[int], message: dict
    ) -> None:
        """Send an event only to authenticated users subscribed to this workspace."""
        recipients = set(user_ids)
        if not recipients:
            return
        stale: list[WebSocket] = []
        for websocket, user_id in tuple(self._clients.get(organization_id, {}).items()):
            if user_id not in recipients:
                continue
            try:
                await websocket.send_json(message)
            except Exception:
                stale.append(websocket)
        for websocket in stale:
            self.disconnect(organization_id, websocket)

    async def publish_to_user(
        self, organization_id: int, user_id: int, message: dict
    ) -> None:
        await self.publish_to_users(organization_id, {user_id}, message)

    async def publish(self, organization_id: int, message: dict) -> None:
        stale: list[WebSocket] = []
        for websocket in tuple(self._clients.get(organization_id, {})):
            if websocket not in self._workspace_event_clients:
                continue
            try:
                await websocket.send_json(message)
            except Exception:
                stale.append(websocket)
        for websocket in stale:
            self.disconnect(organization_id, websocket)


live_hub = LiveHub()
