"""Checkwatt module."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta
import json
import logging
import re

from aiohttp import ClientError, ClientSession

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

    async def __aenter__(self):
        """Asynchronous enter."""
        self.session = ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        """Asynchronous exit."""
        await self.session.close()

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
                "accept": "application/json, text/plain, */*",
                "accept-language": "sv-SE,sv;q=0.9,en-SE;q=0.8,en;q=0.7,en-US;q=0.6",
                "authorization": f"Basic {encoded_credentials}",
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

        except ClientError as e:
            _LOGGER.error("An error occurred during login: %s", e)
            return False

    async def get_customer_details(self):
        """Fetch customer details from Checkwatt."""
        try:
            endpoint = "/controlpanel/CustomerDetail"

            # Define headers with the JwtToken
            headers = {
                "accept": "application/json, text/plain, */*",
                "accept-language": "sv-SE,sv;q=0.9,en-SE;q=0.8,en;q=0.7,en-US;q=0.6",
                "authorization": f"Bearer {self.jwt_token}",
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

            async with self.session.get(
                self.base_url + endpoint, headers=headers
            ) as response:
                response.raise_for_status()
                self.customer_details = await response.json()

                meters = self.customer_details.get("Meter", [])
                if meters:
                    first_meter = meters[0]
                    logbook = first_meter.get("Logbook")
                    if logbook:
                        (
                            self.battery_registration,
                            self.logbook_entries,
                        ) = self._extract_content_and_logbook(logbook)

                return True

        except ClientError as e:
            _LOGGER.error("An error occurred during the CustomerDetail request: %s", e)
            return False

    async def get_fcrd_revenue(self):
        """Fetch FCR-D revenues from checkwatt."""
        try:
            fromDate = datetime.now().strftime("%Y-%m-%d")
            end_date = datetime.now() + timedelta(days=2)
            toDate = end_date.strftime("%Y-%m-%d")

            endpoint = f"/ems/fcrd/revenue?fromDate={fromDate}&toDate={toDate}"

            # Define headers with the JwtToken
            headers = {
                "accept": "application/json, text/plain, */*",
                "accept-language": "sv-SE,sv;q=0.9,en-SE;q=0.8,en;q=0.7,en-US;q=0.6",
                "authorization": f"Bearer {self.jwt_token}",
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

            # First fetch the revenue
            async with self.session.get(
                self.base_url + endpoint, headers=headers
            ) as response:
                response.raise_for_status()
                self.revenue = await response.json()

                # Then fetch the service fees
                endpoint = f"/ems/service/fees?fromDate={fromDate}&toDate={toDate}"
                async with self.session.get(
                    self.base_url + endpoint, headers=headers
                ) as response:
                    response.raise_for_status()
                    self.fees = await response.json()

                return True

        except ClientError as e:
            _LOGGER.error("An error occurred during the CustomerDetail request: %s", e)
            return False

    @property
    def inverter_make_and_model(self):
        """Docstring."""
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
            if len(self.revenue) != 0:
                if "Revenue" in self.revenue[0]:
                    revenue = self.revenue[0]["Revenue"]

        if self.fees is not None:
            if "FCRD" in self.fees:
                if len(self.fees["FCRD"]) != 0:
                    # Take note: It is called Revenue also in fees
                    if "Revenue" in self.fees["FCRD"][0]:
                        fees = self.fees["FCRD"][0]["Revenue"]

        return revenue - fees
