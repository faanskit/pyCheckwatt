"""Checkwatt module."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta
import json
import logging
import re

from aiohttp import ClientError, ClientResponseError, ClientSession

_LOGGER = logging.getLogger(__name__)


class CheckwattManager:
    """Checkwatt manager."""

    def __init__(self, username, password) -> None:
        """Initialize the checkwatt manager."""
        if username is None or password is None:
            raise ValueError("Username and password must be provided.")
        self.session = None
        self.base_url = "https://services.cnet.se/checkwattapi/v2"
        self.username = username
        self.password = password
        self.revenue = None
        self.fees = None
        self.jwt_token = None
        self.refresh_token = None
        self.customer_details = None
        self.battery_registration = None
        self.logbook_entries = None
        self.fcrd_state = None
        self.fcrd_percentage = None
        self.fcrd_timestamp = None

    async def __aenter__(self):
        """Asynchronous enter."""
        self.session = ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        """Asynchronous exit."""
        await self.session.close()

    def _get_headers(self):
        """Define common headers."""

        return {
            "accept": "application/json, text/plain, */*",
            "accept-language": "sv-SE,sv;q=0.9,en-SE;q=0.8,en;q=0.7,en-US;q=0.6",
            "content-type": "application/json",
            "sec-ch-ua": '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
            "wslog-os": "",
            "wslog-platform": "controlpanel",
        }

    def _extract_content_and_logbook(self, input_string):
        """Pull the registred information from the logbook."""

        # Define the pattern to match the content between the tags
        pattern = re.compile(
            r"#BEGIN_BATTERY_REGISTRATION(.*?)#END_BATTERY_REGISTRATION", re.DOTALL
        )

        # Find all matches in the input string
        matches = re.findall(pattern, input_string)

        # Extracted content
        extracted_content = ""
        if matches:
            extracted_content = matches[0].strip()
            battery_registration = json.loads(extracted_content)

        # Extract logbook entries
        logbook_entries = input_string.split("\n")

        # Filter out entries containing #BEGIN_BATTERY_REGISTRATION and #END_BATTERY_REGISTRATION
        logbook_entries = [
            entry.strip()
            for entry in logbook_entries
            if not (
                "#BEGIN_BATTERY_REGISTRATION" in entry
                or "#END_BATTERY_REGISTRATION" in entry
            )
        ]

        return battery_registration, logbook_entries

    def _extract_fcr_d_state(self):
        pattern = re.compile(r"\[ FCR-D (ACTIVATED|DEACTIVATE) \].*?(\d+,\d+/\d+,\d+/\d+,\d+ %).*?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
        for entry in self.logbook_entries:
            match = pattern.search(entry)
            if match:
                self.fcrd_state = match.group(1)  # FCR-D state: ACTIVATED or DEACTIVATED
                self.fcrd_percentage = match.group(2)  # Percentage, e.g., "99,0/2,9/97,7 %"
                self.fcrd_timestamp = match.group(3)  # Timestamp, e.g., "2023-12-20 00:11:45"


    async def handle_client_error(self, endpoint, headers, error):
        """Handle ClientError and log relevant information."""
        _LOGGER.error(
            "An error occurred during the request. URL: %s, Headers: %s. Error: %s",
            self.base_url + endpoint,
            headers,
            error,
        )
        return False

    async def login(self):
        """Login to Checkwatt."""
        try:
            credentials = f"{self.username}:{self.password}"
            encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode(
                "utf-8"
            )
            endpoint = "/user/LoginEiB?audience=eib"

            # Define headers with the encoded credentials
            headers = {
                **self._get_headers(),
                "authorization": f"Basic {encoded_credentials}",
            }

            async with self.session.get(
                self.base_url + endpoint, headers=headers
            ) as response:
                data = await response.json()
                if response.status == 200:
                    self.jwt_token = data.get("JwtToken")
                    self.refresh_token = data.get("RefreshToken")
                    return True

                if response.status == 401:
                    _LOGGER.error(
                        "Unauthorized: Check your checkwatt authentication credentials"
                    )
                    return False

                _LOGGER.error("Unexpected HTTP status code: %s", response.status)
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def get_customer_details(self):
        """Fetch customer details from Checkwatt."""
        try:
            endpoint = "/controlpanel/CustomerDetail"

            # Define headers with the JwtToken
            headers = {
                **self._get_headers(),
                "authorization": f"Bearer {self.jwt_token}",
            }

            async with self.session.get(
                self.base_url + endpoint, headers=headers
            ) as response:
                response.raise_for_status()
                if response.status == 200:
                    self.customer_details = await response.json()

                    meters = self.customer_details.get("Meter", [])
                    if meters:
                        soc_meter = next((meter for meter in meters if meter.get("InstallationType") == "SoC"), None)
                        if not soc_meter:
                            _LOGGER.error("No SoC meter found")
                            return False
                        logbook = soc_meter.get("Logbook")
                        if logbook:
                            (
                                self.battery_registration,
                                self.logbook_entries,
                            ) = self._extract_content_and_logbook(logbook)
                            self._extract_fcr_d_state()

                    return True

                _LOGGER.error(
                    "Obtaining data from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def get_fcrd_revenue(self):
        """Fetch FCR-D revenues from checkwatt."""
        try:
            from_date = datetime.now().strftime("%Y-%m-%d")
            end_date = datetime.now() + timedelta(days=2)
            to_date = end_date.strftime("%Y-%m-%d")

            endpoint = f"/ems/fcrd/revenue?fromDate={from_date}&toDate={to_date}"

            # Define headers with the JwtToken
            headers = {
                **self._get_headers(),
                "authorization": f"Bearer {self.jwt_token}",
            }

            # First fetch the revenue
            async with self.session.get(
                self.base_url + endpoint, headers=headers
            ) as response:
                response.raise_for_status()
                self.revenue = await response.json()
                if response.status == 200:
                    # Then fetch the service fees
                    endpoint = (
                        f"/ems/service/fees?fromDate={from_date}&toDate={to_date}"
                    )
                    async with self.session.get(
                        self.base_url + endpoint, headers=headers
                    ) as response:
                        response.raise_for_status()
                        self.fees = await response.json()
                        if response.status == 200:
                            return True

                _LOGGER.error(
                    "Obtaining data from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    @property
    def inverter_make_and_model(self):
        """Property for inverter make and model. Not used by HA integration.."""
        if (
            "Inverter" in self.battery_registration
            and "InverterModel" in self.battery_registration
        ):
            resp = f"{self.battery_registration['Inverter']}"
            resp += f" {self.battery_registration['InverterModel']}"
            return resp

    @property
    def battery_make_and_model(self):
        """Property for battery make and model. Not used by HA integration."""
        if (
            "BatteryModel" in self.battery_registration
            and "BatterySystem" in self.battery_registration
        ):
            resp = f"{self.battery_registration['BatterySystem']}"
            resp += f" {self.battery_registration['BatteryModel']}"
            resp += f" ({self.battery_registration['BatteryPowerKW']}kW, {self.battery_registration['BatteryCapacityKWh']}kWh)"
            return resp

    @property
    def exectricity_provider(self):
        """Property for electricity provides. Not used by HA integration."""
        if (
            "ElectricityCompany" in self.battery_registration
            and "Dso" in self.battery_registration
        ):
            resp = f"{self.battery_registration['ElectricityCompany']}"
            resp += f" via {self.battery_registration['Dso']}"
            resp += f" ({self.battery_registration['GridAreaId']} {self.battery_registration['Kommun']})"
            return resp

    @property
    def registred_owner(self):
        """Property for registred owner. Not used by HA integration.."""
        if "FirstName" in self.customer_details and "LastName" in self.customer_details:
            resp = f"{self.customer_details['FirstName']}"
            resp += f" {self.customer_details['LastName']}"
            resp += f" ({self.customer_details['StreetAddress']}"
            resp += f" {self.customer_details['ZipCode']}"
            resp += f" {self.customer_details['City']})"
            return resp
        return None

    @property
    def today_revenue(self):
        """Property for today's revenue."""
        revenue = 0
        fees = 0
        if self.revenue is not None:
            if len(self.revenue) > 0:
                if "Revenue" in self.revenue[0]:
                    revenue = self.revenue[0]["Revenue"]

        if self.fees is not None:
            if "FCRD" in self.fees:
                if len(self.fees["FCRD"]) > 0:
                    # Take note: It is called Revenue also in fees
                    if "Revenue" in self.fees["FCRD"][0]:
                        fees = self.fees["FCRD"][0]["Revenue"]

        return revenue - fees

    @property
    def tomorrow_revenue(self):
        """Property for tomorrow's revenue."""
        revenue = 0
        fees = 0
        if self.revenue is not None:
            if len(self.revenue) > 1:
                if "Revenue" in self.revenue[1]:
                    revenue = self.revenue[1]["Revenue"]

        if self.fees is not None:
            if "FCRD" in self.fees:
                if len(self.fees["FCRD"]) > 1:
                    # Take note: It is called Revenue also in fees
                    if "Revenue" in self.fees["FCRD"][1]:
                        fees = self.fees["FCRD"][1]["Revenue"]

        return revenue - fees

