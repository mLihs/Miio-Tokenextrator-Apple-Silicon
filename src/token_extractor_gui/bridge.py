from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional

import requests

try:
    from Crypto.Cipher import ARC4  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    from Cryptodome.Cipher import ARC4  # type: ignore

# The original project uses colorama for CLI output. We keep color constants so we can strip them later if needed.
try:
    from colorama import Fore, Style  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    class _Dummy:  # minimal fallback
        RESET_ALL = ""
        YELLOW = ""
        BLUE = ""
        GREEN = ""
        RED = ""
        BRIGHT = ""

    Fore = _Dummy()  # type: ignore
    Style = _Dummy()  # type: ignore


SERVERS = ["cn", "de", "us", "ru", "tw", "sg", "in", "i2"]

_LOGGER = logging.getLogger("token_extractor.gui")


@dataclass(slots=True)
class InteractionCallbacks:
    """
    Callbacks invoked by the bridge when user interaction or visualisation is required.
    All callables are optional; the bridge will fall back to best-effort behaviour if any are missing.
    """

    log: Callable[[str], None]
    request_captcha: Optional[Callable[[bytes, str], Optional[str]]] = None
    request_twofactor: Optional[Callable[[str], Optional[str]]] = None
    display_qr: Optional[Callable[[bytes, str, str], None]] = None


class XiaomiCloudConnector:
    """
    A GUI-friendly adaptation of the original XiaomiCloudConnector that removes the argparse dependency
    and replaces `print`/`input` calls with the injected InteractionCallbacks.
    """

    def __init__(self, callbacks: InteractionCallbacks, host_override: Optional[str] = None) -> None:
        self._callbacks = callbacks
        self._agent = self.generate_agent()
        self._device_id = self.generate_device_id()
        self._session = requests.session()
        self._ssecurity: Optional[str] = None
        self.userId: Optional[int] = None
        self._serviceToken: Optional[str] = None
        self._host_override = host_override or "127.0.0.1"

    def login(self) -> bool:  # pragma: no cover - overridden by subclasses
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Public Xiaomi Cloud API helpers
    # ------------------------------------------------------------------
    def get_homes(self, country: str):
        url = self.get_api_url(country) + "/v2/homeroom/gethome"
        params = {"data": '{"fg": true, "fetch_share": true, "fetch_share_dev": true, "limit": 300, "app_ver": 7}'}
        return self.execute_api_call_encrypted(url, params)

    def get_devices(self, country: str, home_id: int, owner_id: int):
        url = self.get_api_url(country) + "/v2/home/home_device_list"
        params = {
            "data": '{"home_owner": ' + str(owner_id)
            + ',"home_id": ' + str(home_id)
            + ',  "limit": 200,  "get_split_device": true, "support_smart_home": true}'
        }
        return self.execute_api_call_encrypted(url, params)

    def get_dev_cnt(self, country: str):
        url = self.get_api_url(country) + "/v2/user/get_device_cnt"
        params = {"data": '{ "fetch_own": true, "fetch_share": true}'}
        return self.execute_api_call_encrypted(url, params)

    def get_beaconkey(self, country: str, did: str):
        url = self.get_api_url(country) + "/v2/device/blt_get_beaconkey"
        params = {"data": '{"did":"' + did + '","pdid":1}'}
        return self.execute_api_call_encrypted(url, params)

    def execute_api_call_encrypted(self, url: str, params: Dict[str, str]):
        if not self._serviceToken or not self._ssecurity or self.userId is None:
            raise RuntimeError("Not authenticated")

        headers = {
            "Accept-Encoding": "identity",
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded",
            "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
            "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
        }
        cookies = {
            "userId": str(self.userId),
            "yetAnotherServiceToken": str(self._serviceToken),
            "serviceToken": str(self._serviceToken),
            "locale": "en_GB",
            "timezone": "GMT+02:00",
            "is_daylight": "1",
            "dst_offset": "3600000",
            "channel": "MI_APP_STORE",
        }
        millis = round(time.time() * 1000)
        nonce = self.generate_nonce(millis)
        signed_nonce = self.signed_nonce(nonce)
        fields = self.generate_enc_params(url, "POST", signed_nonce, nonce, params, self._ssecurity)
        response = self._session.post(url, headers=headers, cookies=cookies, params=fields)
        if response.status_code == 200:
            decoded = self.decrypt_rc4(self.signed_nonce(fields["_nonce"]), response.text)
            return json.loads(decoded)
        return None

    @staticmethod
    def get_api_url(country: str) -> str:
        return "https://" + ("" if country == "cn" else (country + ".")) + "api.io.mi.com/app"

    # ------------------------------------------------------------------
    # Cryptographic helpers (copied from upstream)
    # ------------------------------------------------------------------
    def signed_nonce(self, nonce: str) -> str:
        if not self._ssecurity:
            raise RuntimeError("Missing ssecurity")
        hash_object = hashlib.sha256(base64.b64decode(self._ssecurity) + base64.b64decode(nonce))
        return base64.b64encode(hash_object.digest()).decode("utf-8")

    @staticmethod
    def generate_nonce(millis: int) -> str:
        nonce_bytes = os.urandom(8) + (int(millis / 60000)).to_bytes(4, byteorder="big")
        return base64.b64encode(nonce_bytes).decode()

    @staticmethod
    def generate_agent() -> str:
        agent_id = "".join(map(lambda i: chr(i), [random.randint(65, 69) for _ in range(13)]))
        random_text = "".join(map(lambda i: chr(i), [random.randint(97, 122) for _ in range(18)]))
        return f"{random_text}-{agent_id} APP/com.xiaomi.mihome APPV/10.5.201"

    @staticmethod
    def generate_device_id() -> str:
        return "".join(map(lambda i: chr(i), [random.randint(97, 122) for _ in range(6)]))

    @staticmethod
    def generate_enc_signature(url: str, method: str, signed_nonce: str, params: Dict[str, str]) -> str:
        signature_params = [str(method).upper(), url.split("com")[1].replace("/app/", "/")]
        for k, v in params.items():
            signature_params.append(f"{k}={v}")
        signature_params.append(signed_nonce)
        signature_string = "&".join(signature_params)
        return base64.b64encode(hashlib.sha1(signature_string.encode("utf-8")).digest()).decode()

    @staticmethod
    def generate_enc_params(
        url: str, method: str, signed_nonce: str, nonce: str, params: Dict[str, str], ssecurity: str
    ) -> Dict[str, str]:
        params["rc4_hash__"] = XiaomiCloudConnector.generate_enc_signature(url, method, signed_nonce, params)
        for k, v in list(params.items()):
            params[k] = XiaomiCloudConnector.encrypt_rc4(signed_nonce, v)
        params.update(
            {
                "signature": XiaomiCloudConnector.generate_enc_signature(url, method, signed_nonce, params),
                "ssecurity": ssecurity,
                "_nonce": nonce,
            }
        )
        return params

    @staticmethod
    def encrypt_rc4(password: str, payload: str) -> str:
        r = ARC4.new(base64.b64decode(password))
        r.encrypt(bytes(1024))
        return base64.b64encode(r.encrypt(payload.encode())).decode()

    @staticmethod
    def decrypt_rc4(password: str, payload: str) -> bytes:
        r = ARC4.new(base64.b64decode(password))
        r.encrypt(bytes(1024))
        return r.encrypt(base64.b64decode(payload))

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------
    def _emit(self, message: str = "") -> None:
        try:
            self._callbacks.log(message)
        except Exception:  # pragma: no cover - defensive
            _LOGGER.debug("Log callback failed", exc_info=True)

class PasswordXiaomiCloudConnector(XiaomiCloudConnector):
    def __init__(self, callbacks: InteractionCallbacks, username: str, password: str) -> None:
        super().__init__(callbacks)
        self._username = username
        self._password = password
        self._sign: Optional[str] = None
        self._cUserId: Optional[str] = None
        self._passToken: Optional[str] = None
        self._location: Optional[str] = None
        self._code: Optional[int] = None

    # The following methods are adapted from the upstream project to remove CLI input/output
    def login(self) -> bool:
        self._emit(f"{Fore.BLUE}Logging in...{Style.RESET_ALL}")
        self._session.cookies.set("sdkVersion", "accountsdk-18.8.15", domain="mi.com")
        self._session.cookies.set("sdkVersion", "accountsdk-18.8.15", domain="xiaomi.com")
        self._session.cookies.set("deviceId", self._device_id, domain="mi.com")
        self._session.cookies.set("deviceId", self._device_id, domain="xiaomi.com")

        if not self.login_step_1():
            self._emit(f"{Fore.RED}Invalid username.")
            return False

        if not self.login_step_2():
            self._emit(f"{Fore.RED}Invalid login or password.")
            return False

        if self._location and not self._serviceToken and not self.login_step_3():
            self._emit(f"{Fore.RED}Unable to get service token.")
            return False

        return True

    def login_step_1(self) -> bool:
        url = "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true"
        headers = {"User-Agent": self._agent, "Content-Type": "application/x-www-form-urlencoded"}
        cookies = {"userId": self._username}
        response = self._session.get(url, headers=headers, cookies=cookies)
        if response.status_code == 200:
            json_resp = self.to_json(response.text)
            if "_sign" in json_resp:
                self._sign = json_resp["_sign"]
                return True
            if "ssecurity" in json_resp:
                self._ssecurity = json_resp["ssecurity"]
                self.userId = json_resp["userId"]
                self._cUserId = json_resp["cUserId"]
                self._passToken = json_resp["passToken"]
                self._location = json_resp["location"]
                self._code = json_resp["code"]
                return True
        return False

    def login_step_2(self) -> bool:
        url = "https://account.xiaomi.com/pass/serviceLoginAuth2"
        headers = {"User-Agent": self._agent, "Content-Type": "application/x-www-form-urlencoded"}
        fields = {
            "sid": "xiaomiio",
            "hash": hashlib.md5(str.encode(self._password)).hexdigest().upper(),
            "callback": "https://sts.api.io.mi.com/sts",
            "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
            "user": self._username,
            "_sign": self._sign,
            "_json": "true",
        }
        response = self._session.post(url, headers=headers, params=fields, allow_redirects=False)
        valid = response is not None and response.status_code == 200
        if valid:
            json_resp = self.to_json(response.text)
            if "captchaUrl" in json_resp and json_resp["captchaUrl"] is not None:
                captcha_code = self.handle_captcha(json_resp["captchaUrl"])
                if not captcha_code:
                    return False
                fields["captCode"] = captcha_code
                response = self._session.post(url, headers=headers, params=fields, allow_redirects=False)
                if response is not None and response.status_code == 200:
                    json_resp = self.to_json(response.text)
                else:
                    return False
                if "code" in json_resp and json_resp["code"] == 87001:
                    self._emit("Invalid captcha.")
                    return False
            valid = "ssecurity" in json_resp and len(str(json_resp["ssecurity"])) > 4
            if valid:
                self._ssecurity = json_resp["ssecurity"]
                self.userId = json_resp.get("userId")
                self._cUserId = json_resp.get("cUserId")
                self._passToken = json_resp.get("passToken")
                self._location = json_resp.get("location")
                self._code = json_resp.get("code")
            else:
                if "notificationUrl" in json_resp:
                    verify_url = json_resp["notificationUrl"]
                    return self.do_2fa_email_flow(verify_url)
                _LOGGER.error("login_step_2: Login failed, server returned: %s", json_resp)
        else:
            _LOGGER.error("login_step_2: HTTP status: %s; Response: %s", response.status_code, response.text[:500])
        return valid

    def login_step_3(self) -> bool:
        headers = {"User-Agent": self._agent, "Content-Type": "application/x-www-form-urlencoded"}
        response = self._session.get(self._location, headers=headers)
        if response.status_code == 200:
            self._serviceToken = response.cookies.get("serviceToken")
        return response.status_code == 200

    def handle_captcha(self, captcha_url: str) -> Optional[str]:
        if captcha_url.startswith("/"):
            captcha_url = "https://account.xiaomi.com" + captcha_url
        response = self._session.get(captcha_url, stream=False)
        if response.status_code != 200:
            _LOGGER.error("Unable to fetch captcha image.")
            return None
        self._emit(f"{Fore.YELLOW}Captcha verification required.")
        if self._callbacks.request_captcha:
            return self._callbacks.request_captcha(response.content, captcha_url)
        self._emit("Captcha callback not provided.")
        return None

    def do_2fa_email_flow(self, notification_url: str) -> bool:
        headers = {"User-Agent": self._agent, "Content-Type": "application/x-www-form-urlencoded"}
        r = self._session.get(notification_url, headers=headers)
        context = re.search(r"context=([^&]+)", notification_url)
        if not context:
            _LOGGER.error("Two-factor context missing in notification URL.")
            return False
        context_value = context.group(1)
        list_params = {"sid": "xiaomiio", "context": context_value, "_locale": "en_US"}
        self._session.get("https://account.xiaomi.com/identity/list", params=list_params, headers=headers)
        send_params = {
            "_dc": str(int(time.time() * 1000)),
            "sid": "xiaomiio",
            "context": list_params["context"],
            "mask": "0",
            "_locale": "en_US",
        }
        send_data = {"retry": "0", "icode": "", "_json": "true", "ick": self._session.cookies.get("ick", "")}
        self._session.post(
            "https://account.xiaomi.com/identity/auth/sendEmailTicket", params=send_params, data=send_data, headers=headers
        )
        code = None
        if self._callbacks.request_twofactor:
            code = self._callbacks.request_twofactor("Enter the two-factor code sent to your email.")
        if not code:
            return False
        verify_params = {
            "_flag": "8",
            "_json": "true",
            "sid": "xiaomiio",
            "context": list_params["context"],
            "mask": "0",
            "_locale": "en_US",
        }
        verify_data = {"_flag": "8", "ticket": code, "trust": "false", "_json": "true", "ick": self._session.cookies.get("ick", "")}
        r = self._session.post(
            "https://account.xiaomi.com/identity/auth/verifyEmail", params=verify_params, data=verify_data, headers=headers
        )
        if r.status_code != 200:
            _LOGGER.error("verifyEmail failed: status=%s body=%s", r.status_code, r.text[:500])
            return False
        try:
            jr = r.json()
            finish_loc = jr.get("location")
        except Exception:
            finish_loc = r.headers.get("Location")
            if not finish_loc and r.text:
                m = re.search(r'https://account\.xiaomi\.com/identity/result/check\?[^"\']+', r.text)
                if m:
                    finish_loc = m.group(0)
        if not finish_loc:
            _LOGGER.error("Unable to determine finish location after verifyEmail.")
            return False
        if "identity/result/check" in finish_loc:
            r = self._session.get(finish_loc, headers=headers, allow_redirects=False)
            end_url = r.headers.get("Location")
        else:
            end_url = finish_loc
        if not end_url:
            _LOGGER.error("Could not find Auth2/end URL in finish chain.")
            return False
        r = self._session.get(end_url, headers=headers, allow_redirects=False)
        if r.status_code == 200 and "Xiaomi Account - Tips" in r.text:
            r = self._session.get(end_url, headers=headers, allow_redirects=False)
        ext_prag = r.headers.get("extension-pragma")
        if ext_prag:
            try:
                ep_json = json.loads(ext_prag)
                ssec = ep_json.get("ssecurity")
                if ssec:
                    self._ssecurity = ssec
            except Exception:
                _LOGGER.debug("Failed to parse extension-pragma", exc_info=True)
        if not self._ssecurity:
            _LOGGER.error("extension-pragma header missing ssecurity; cannot continue.")
            return False
        sts_url = r.headers.get("Location")
        if not sts_url and r.text:
            idx = r.text.find("https://sts.api.io.mi.com/sts")
            if idx != -1:
                end = r.text.find('"', idx)
                if end == -1:
                    end = idx + 300
                sts_url = r.text[idx:end]
        if not sts_url:
            _LOGGER.error("Auth2/end did not provide STS redirect.")
            return False
        r = self._session.get(sts_url, headers=headers, allow_redirects=True)
        if r.status_code != 200:
            _LOGGER.error("STS did not complete: status=%s body=%s", r.status_code, r.text[:200])
            return False
        self._serviceToken = self._session.cookies.get("serviceToken", domain=".sts.api.io.mi.com")
        if not self._serviceToken:
            _LOGGER.error("Could not parse serviceToken; cannot complete login.")
            return False
        self.install_service_token_cookies(self._serviceToken)
        self.userId = self.userId or self._session.cookies.get("userId", domain=".xiaomi.com") or self._session.cookies.get(
            "userId", domain=".sts.api.io.mi.com"
        )
        self._cUserId = self._cUserId or self._session.cookies.get(
            "cUserId", domain=".xiaomi.com"
        ) or self._session.cookies.get("cUserId", domain=".sts.api.io.mi.com")
        return True

    def install_service_token_cookies(self, token: str) -> None:
        for d in [".api.io.mi.com", ".io.mi.com", ".mi.com"]:
            self._session.cookies.set("serviceToken", token, domain=d)
            self._session.cookies.set("yetAnotherServiceToken", token, domain=d)

    @staticmethod
    def to_json(response_text: str):
        return json.loads(response_text.replace("&&&START&&&", ""))


class QrCodeXiaomiCloudConnector(XiaomiCloudConnector):
    def __init__(self, callbacks: InteractionCallbacks, host_override: Optional[str] = None) -> None:
        super().__init__(callbacks, host_override=host_override)
        self._cUserId: Optional[str] = None
        self._pass_token: Optional[str] = None
        self._location: Optional[str] = None
        self._qr_image_url: Optional[str] = None
        self._login_url: Optional[str] = None
        self._long_polling_url: Optional[str] = None
        self._timeout: int = 120

    def login(self) -> bool:
        if not self.login_step_1():
            self._emit(f"{Fore.RED}Unable to get login message.")
            return False
        if not self.login_step_2():
            self._emit(f"{Fore.RED}Unable to get login QR Image.")
            return False
        if not self.login_step_3():
            self._emit(f"{Fore.RED}Unable to login.")
            return False
        if not self.login_step_4():
            self._emit(f"{Fore.RED}Unable to get service token.")
            return False
        return True

    def login_step_1(self) -> bool:
        url = "https://account.xiaomi.com/longPolling/loginUrl"
        data = {
            "_qrsize": "480",
            "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
            "callback": "https://sts.api.io.mi.com/sts",
            "_hasLogo": "false",
            "sid": "xiaomiio",
            "serviceParam": "",
            "_locale": "en_GB",
            "_dc": str(int(time.time() * 1000)),
        }
        response = self._session.get(url, params=data)
        if response.status_code == 200:
            response_data = PasswordXiaomiCloudConnector.to_json(response.text)
            if "qr" in response_data:
                self._qr_image_url = response_data["qr"]
                self._login_url = response_data["loginUrl"]
                self._long_polling_url = response_data["lp"]
                self._timeout = response_data["timeout"]
                return True
        return False

    def login_step_2(self) -> bool:
        if not self._qr_image_url:
            return False
        response = self._session.get(self._qr_image_url)
        if response is not None and response.status_code == 200:
            if self._callbacks.display_qr:
                self._callbacks.display_qr(response.content, self._login_url or "", self._qr_image_url)
            else:
                self._emit("QR image callback missing.")
            return True
        _LOGGER.error("login_step_2: HTTP status: %s; Response: %s", response.status_code, response.text[:500])
        return False

    def login_step_3(self) -> bool:
        if not self._long_polling_url:
            return False
        start_time = time.time()
        response = None
        while True:
            try:
                response = self._session.get(self._long_polling_url, timeout=10)
            except requests.exceptions.Timeout:
                if time.time() - start_time > self._timeout:
                    _LOGGER.debug("Long polling timed out after %s seconds.", self._timeout)
                    break
                continue
            except requests.exceptions.RequestException:
                _LOGGER.error("Error during QR long polling", exc_info=True)
                break
            if response.status_code == 200:
                break
        if not response or response.status_code != 200:
            return False
        response_data = PasswordXiaomiCloudConnector.to_json(response.text)
        self.userId = response_data["userId"]
        self._ssecurity = response_data["ssecurity"]
        self._cUserId = response_data["cUserId"]
        self._pass_token = response_data["passToken"]
        self._location = response_data["location"]
        return True

    def login_step_4(self) -> bool:
        if not self._location:
            return False
        response = self._session.get(self._location, headers={"content-type": "application/x-www-form-urlencoded"})
        if response.status_code != 200:
            return False
        self._serviceToken = response.cookies.get("serviceToken")
        return True


def fetch_devices_for_servers(
    connector: XiaomiCloudConnector,
    servers: Iterable[str],
    include_ble_keys: bool = True,
) -> List[Dict]:
    results: List[Dict] = []
    for current_server in servers:
        all_homes = []
        homes = connector.get_homes(current_server)
        if homes is not None:
            for h in homes["result"]["homelist"]:
                all_homes.append({"home_id": h["id"], "home_owner": connector.userId})
        dev_cnt = connector.get_dev_cnt(current_server)
        if dev_cnt is not None and dev_cnt["result"].get("share"):
            for h in dev_cnt["result"]["share"]["share_family"]:
                all_homes.append({"home_id": h["home_id"], "home_owner": h["home_owner"]})
        if len(all_homes) == 0:
            connector._emit(f'{Fore.RED}No homes found for server "{current_server}".')
        server_entry = {"server": current_server, "homes": []}
        for home in all_homes:
            devices = connector.get_devices(current_server, home["home_id"], home["home_owner"])
            home_entry = {"home_id": home["home_id"], "home_owner": home["home_owner"], "devices": []}
            if devices is not None:
                device_info = devices["result"].get("device_info") or []
                if len(device_info) == 0:
                    connector._emit(
                        f'{Fore.RED}No devices found for server "{current_server}" @ home "{home["home_id"]}".'
                    )
                    server_entry["homes"].append(home_entry)
                    continue
                connector._emit(f'Devices found for server "{current_server}" @ home "{home["home_id"]}":')
                for device in device_info:
                    device_data = {**device}
                    if include_ble_keys and "did" in device and "blt" in device["did"]:
                        beaconkey = connector.get_beaconkey(current_server, device["did"])
                        if beaconkey and "result" in beaconkey and "beaconkey" in beaconkey["result"]:
                            device_data["BLE_DATA"] = beaconkey["result"]
                    home_entry["devices"].append(device_data)
            else:
                connector._emit(f"{Fore.RED}Unable to get devices from server {current_server}.")
            server_entry["homes"].append(home_entry)
        results.append(server_entry)
    return results


