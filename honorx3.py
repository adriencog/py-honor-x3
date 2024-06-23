import base64
from collections import namedtuple
import hashlib
import json
import logging
import re

from requests import session

import crypto

_LOGGER = logging.getLogger(__name__)


class HonorX3Client:
    """API calls for HonorX3 routers."""

    Device = namedtuple(
        "Device",
        [
            "name",
            "hostname",
            "ip",
            "mac",
            "interface",
            "frequency",
            "mesh",
        ],
    )
    Status = namedtuple(
        "Status",
        [
            "up_time",
            "connection_status",
            "connection_status_ipv6",
            "status",
            "link_status",
            "gateway",
        ],
    )

    def __init__(self, host, username, password) -> None:
        """Initialize the client."""
        self.statusmsg = None
        self.host = host
        self.username = username
        self.password = password
        self.session = None
        self.login_data = None
        self.status = "off"
        self.device_info = None
        self._router_id = None
        self._is_connected = False
        self._up_time = None
        self._model = None
        self._firmware = None

    @property
    def firmware(self) -> str | None:
        """Return router firmware version."""
        return self._firmware

    @property
    def model(self) -> str | None:
        """Return router model."""
        return self._model

    @property
    def router_id(self) -> str | None:
        """Return router identifier."""
        return self._router_id

    @property
    def is_connected(self) -> str | None:
        """Return if user connected or not."""
        return self._is_connected

    @property
    def up_time(self) -> int | None:
        """Return router up time."""
        return self._up_time

    # REBOOT THE ROUTER
    def reboot(self) -> bool:
        """Call reboot API."""
        if not self.login:
            return False
        # REBOOT REQUEST
        _LOGGER.info("Requesting reboot")
        try:
            data = {
                "csrf": {
                    "csrf_param": self.login_data["csrf_param"],
                    "csrf_token": self.login_data["csrf_token"],
                }
            }
            r = self.session.post(
                f"https://{self.host}/api/service/reboot.cgi",
                data=json.dumps(data, separators=(",", ":")),
                verify=False,
            )
            data = json.loads(re.search("({.*?})", r.text).group(1))
            assert data["errcode"] == 0, data
            _LOGGER.info("Rebooting HG659")
            return True
        except Exception as e:
            _LOGGER.error("Failed to reboot: {0} with data {1}".format(e, data))
            return False
        finally:
            self.logout()

    # LOGIN PROCEDURE
    def login(self):
        """Try login max 5 times."""
        tries = 0
        self._is_connected = False
        while tries < 5 and not self._is_connected:
            self._is_connected = self._login()
            tries += 1
        if not self._is_connected:
            _LOGGER.debug("Failed to login")

    def _login(self) -> bool:
        """Login procedure using SCRAM challenge :return: true if the login has succeeded."""
        pass_hash = hashlib.sha256(self.password.encode()).hexdigest()
        pass_hash = base64.b64encode(pass_hash.encode()).decode()
        # INITIAL CSRF

        try:
            self.session = session()
            r = self.session.get(
                f"https://{self.host}/api/system/deviceinfo", verify=False
            )
            self.status = "on"
            device_info = r.json()
            assert (
                device_info["csrf_param"] and device_info["csrf_token"]
            ), "Empty csrf_param or csrf_token"
        except Exception as e:
            _LOGGER.error(f'Failed to get CSRF. error "{e}"')
            self.statusmsg = e.errorCategory
            self.status = "off"
            return False

        ## LOGIN ##
        try:
            pass_hash = (
                self.username
                + pass_hash
                + device_info["csrf_param"]
                + device_info["csrf_token"]
            )
            firstnonce = hashlib.sha256(pass_hash.encode()).hexdigest()
            data = {
                "csrf": {
                    "csrf_param": device_info["csrf_param"],
                    "csrf_token": device_info["csrf_token"],
                },
                "data": {"username": self.username, "firstnonce": firstnonce},
            }
            r = self.session.post(
                f"https://{self.host}/api/system/user_login_nonce",
                data=json.dumps(data, separators=(",", ":")),
                verify=False,
            )
            responsenonce = r.json()
            salt = responsenonce["salt"]
            servernonce = responsenonce["servernonce"]
            iterations = responsenonce["iterations"]
            client_proof = crypto.get_client_proof(
                firstnonce, servernonce, self.password, salt, iterations
            ).decode("UTF-8")

            data = {
                "csrf": {
                    "csrf_param": responsenonce["csrf_param"],
                    "csrf_token": responsenonce["csrf_token"],
                },
                "data": {"clientproof": client_proof, "finalnonce": servernonce},
            }
            r = self.session.post(
                f"https://{self.host}/api/system/user_login_proof",
                data=json.dumps(data, separators=(",", ":")),
                verify=False,
            )
            loginproof = r.json()

            assert loginproof["err"] == 0
            self.login_data = loginproof
            self.statusmsg = None
            return True
        except Exception as e:
            _LOGGER.debug(f"Failed to login: {e}")
            self.statusmsg = f"Failed login: {e}"
            self.login_data = None
            self.session.close()
            return False

    ## LOGOUT ##
    def logout(self):
        try:
            if self.login_data is None:
                return False
            data = {
                "csrf": {
                    "csrf_param": self.login_data["csrf_param"],
                    "csrf_token": self.login_data["csrf_token"],
                }
            }
            r = self.session.post(
                f"https://{self.host}/api/system/user_logout",
                data=json.dumps(data, separators=(",", ":")),
                verify=False,
            )
            data = r.json()
            assert r.ok, r
            _LOGGER.debug("Logged out")
        except Exception as e:
            _LOGGER.error(f"Failed to logout: {e}")
        finally:
            self.session.close()
            self.login_data = None

    def get_devices(self) -> list[Device]:
        """Get the raw string with the devices from the router."""
        try:
            query = f"https://{self.host}/api/system/HostInfo"
            r = self.session.get(query, verify=False)
            devices = r.json()
            self.statusmsg = "OK"
        except Exception as e:
            _LOGGER.error("Failed to get Devices: {} with query {}".format(e, query))
            self.statusmsg = e.errorCategory
            return False
        return [self._map_device(device) for device in devices]

    def _map_device(self, device) -> Device:
        return HonorX3Client.Device(
            name=device.get("ActualName"),
            hostname=device.get("HostName"),
            ip=device.get("IPAddress"),
            mac=device.get("MACAddress"),
            interface=device.get("InterfaceType"),
            frequency=device.get("Frequency"),
            mesh=device.get("IsSlave"),
        )

    def get_router_info(self):
        """Get the raw router info."""
        try:
            query = f"https://{self.host}/api/system/deviceinfo"
            r = self.session.get(query, verify=False)
            info = r.json()
            self._model = info.get("FriendlyName")
            self._router_id = info.get("uuid")
            self._firmware = info.get("SoftwareVersion")
        except Exception as e:
            _LOGGER.error(f"Failed to get info: {e} with query {query} rdev {r}")
            self.statusmsg = e.errorCategory

    def get_router_status(self):
        """Get the raw router status."""
        try:
            query = f"https://{self.host}/api/ntwk/wandiagnose"
            r = self.session.get(query, verify=False)
            diagnosis = r.json()
            return HonorX3Client.Status(
                up_time=diagnosis.get("UpTime"),
                connection_status=diagnosis.get("ConnectionStatus"),
                connection_status_ipv6=diagnosis.get("X_IPv6ConnectionStatus"),
                status=diagnosis.get("Status"),
                gateway=diagnosis.get("DefaultGateway"),
                link_status=diagnosis.get("LinkStatus"),
            )
        except Exception as e:
            _LOGGER.error(f"Failed to get Statuses: {e} with query {query} rdev {r}")
            self.statusmsg = e.errorCategory
