from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

from .bridge import (
    InteractionCallbacks,
    PasswordXiaomiCloudConnector,
    QrCodeXiaomiCloudConnector,
    SERVERS,
    XiaomiCloudConnector,
    fetch_devices_for_servers,
)


class AuthenticationError(RuntimeError):
    """Raised when authentication against Xiaomi Cloud fails."""


class NotAuthenticatedError(RuntimeError):
    """Raised when actions requiring an authenticated connector are invoked before login."""


@dataclass(slots=True)
class DeviceFetchRequest:
    servers: Sequence[str]
    include_ble_keys: bool = True


class TokenExtractorService:
    """
    High-level facade that coordinates authentication and data retrieval while keeping the original library isolated.
    """

    def __init__(self, callbacks: InteractionCallbacks, include_ble_keys: bool = True) -> None:
        self._callbacks = callbacks
        self._include_ble_keys = include_ble_keys
        self._connector: Optional[XiaomiCloudConnector] = None

    @staticmethod
    def available_servers() -> List[str]:
        return list(SERVERS)

    def authenticate_with_password(self, username: str, password: str) -> None:
        connector = PasswordXiaomiCloudConnector(self._callbacks, username=username, password=password)
        if not connector.login():
            raise AuthenticationError("Unable to authenticate with Xiaomi Cloud.")
        self._connector = connector

    def authenticate_with_qr(self) -> None:
        connector = QrCodeXiaomiCloudConnector(self._callbacks)
        if not connector.login():
            raise AuthenticationError("Unable to authenticate using QR code.")
        self._connector = connector

    def fetch_devices(self, servers: Optional[Iterable[str]] = None, include_ble_keys: Optional[bool] = None):
        if not self._connector:
            raise NotAuthenticatedError("Authenticate before fetching devices.")
        target_servers = list(servers or SERVERS)
        include_ble = self._include_ble_keys if include_ble_keys is None else include_ble_keys
        return fetch_devices_for_servers(self._connector, target_servers, include_ble_keys=include_ble)

    def reset(self) -> None:
        self._connector = None



