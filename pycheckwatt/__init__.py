"""
CheckwattManager module.
This module defines the CheckwattManager class, providing an interface for interacting
with the Checkwatt API to retrieve and manage power-related data.
Usage:
    To use this module, instantiate the CheckwattManager class with the required
    authentication credentials. Use the various methods and attributes to interact
    with the Checkwatt API and access power-related information.
Example:
    ```
    from checkwatt_manager import CheckwattManager
    # Instantiate the CheckwattManager class
    checkwatt_manager = CheckwattManager(username='your_username',
                                         password='your_password')
    # Access power-related data
    power_data = checkwatt_manager.power_data
    # Perform other operations as needed
    ```
"""

from __future__ import annotations

import base64
import json
import logging
import re
from datetime import datetime, timedelta

from aiohttp import ClientError, ClientResponseError, ClientSession
from dateutil.relativedelta import relativedelta

_LOGGER = logging.getLogger(__name__)


class CheckwattManager:
    """CheckWatt manager."""

    def __init__(self, username, password, application="pyCheckwatt") -> None:
        """Initialize the CheckWatt manager."""
        if username is None or password is None:
            raise ValueError("Username and password must be provided.")
        self.session = None
        self.base_url = "https://services.cnet.se/checkwattapi/v2"
        self.username = username
        self.password = password
        self.dailyaverage = 0
        self.monthestimate = 0
        self.revenue = None
        self.revenueyear = None
        self.revenueyeartotal = 0
        self.revenuemonth = 0
        self.jwt_token = None
        self.refresh_token = None
        self.customer_details = None
        self.battery_registration = None
        self.battery_charge_peak_ac = None
        self.battery_charge_peak_dc = None
        self.battery_discharge_peak_ac = None
        self.battery_discharge_peak_dc = None
        self.logbook_entries = None
        self.fcrd_state = None
        self.fcrd_info = None
        self.fcrd_timestamp = None
        self.power_data = None
        self.price_zone = None
        self.spot_prices = None
        self.energy_data = None
        self.header_identifier = application
        self.rpi_data = None
        self.meter_data = None

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
            "sec-ch-ua": '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',  # noqa: E501
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
            "wslog-os": "",
            "wslog-platform": "controlpanel",
            "X-pyCheckwatt-Application": self.header_identifier,
        }

    def _extract_content_and_logbook(self, input_string):
        """Pull the registered information from the logbook."""

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

        # Filter out entries containing
        # #BEGIN_BATTERY_REGISTRATION and #END_BATTERY_REGISTRATION
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
        pattern = re.compile(
            r"\[ FCR-D (ACTIVATED|DEACTIVATE|FAIL ACTIVATION) \](?:.*?(\d+,\d+/\d+,\d+/\d+,\d+ %))?(?:\s*(.*?))?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"  # noqa: E501
        )
        for entry in self.logbook_entries:
            match = pattern.search(entry)
            if match:
                self.fcrd_state = match.group(1)
                fcrd_percentage = (
                    match.group(2)
                    if self.fcrd_state in ["ACTIVATED", "FAIL ACTIVATION"]
                    else None
                )
                error_info = match.group(3) if self.fcrd_state == "DEACTIVATE" else None
                self.fcrd_timestamp = match.group(4)
                if fcrd_percentage is not None:
                    self.fcrd_info = fcrd_percentage
                elif error_info is not None:
                    self.fcrd_info = error_info
                else:
                    self.fcrd_info = None
            break  # stop so we get the first row in logbook

    async def handle_client_error(self, endpoint, headers, error):
        """Handle ClientError and log relevant information."""
        _LOGGER.error(
            "An error occurred during the request. URL: %s, Headers: %s. Error: %s",
            self.base_url + endpoint,
            headers,
            error,
        )
        return False

    async def _continue_kill_switch_not_enabled(self):
        """Check if CheckWatt has requested integrations to back-off."""
        try:
            url = "https://checkwatt.se/ha-killswitch.txt"
            headers = {**self._get_headers()}
            async with self.session.get(url, headers=headers) as response:
                data = await response.text()
                if response.status == 200:
                    kill = data.strip()  # Remove leading and trailing whitespaces
                    if kill == "0":
                        # We are OK to continue
                        _LOGGER.debug(
                            "CheckWatt accepted and not enabled the kill-switch"
                        )
                        return True

                    # Kill was requested
                    _LOGGER.error(
                        "CheckWatt has requested to back down by enabling the kill-switch"  # noqa: E501
                    )
                    return False

                if response.status == 401:
                    _LOGGER.error(
                        "Unauthorized: Check your CheckWatt authentication credentials"
                    )
                    return False

                _LOGGER.error("Unexpected HTTP status code: %s", response.status)
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(url, headers, error)

    async def login(self):
        """Login to CheckWatt."""
        try:
            if not await self._continue_kill_switch_not_enabled():
                # CheckWatt want us to back down.
                return False
            _LOGGER.debug("Kill-switch not enabled, continue")

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
        """Fetch customer details from CheckWatt."""
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
                        soc_meter = next(
                            (
                                meter
                                for meter in meters
                                if meter.get("InstallationType") == "SoC"
                            ),
                            None,
                        )

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

    async def get_battery_peak_data(self):
        """Fetch battery peak data from CheckWatt."""
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
                        charging_meter = next(
                            (
                                meter
                                for meter in meters
                                if meter.get("InstallationType") == "Charging"
                            ),
                            None,
                        )
                        discharging_meter = next(
                            (
                                meter
                                for meter in meters
                                if meter.get("InstallationType") == "Discharging"
                            ),
                            None,
                        )

                        if not charging_meter:
                            _LOGGER.error("No charging meter found")
                            return False
                        self.battery_charge_peak_ac = charging_meter.get("PeakAcKw")
                        print(self.battery_charge_peak_ac)
                        self.battery_charge_peak_dc = charging_meter.get("PeakDcKw")
                        self.battery_discharge_peak_ac = discharging_meter.get(
                            "PeakAcKw"
                        )
                        self.battery_discharge_peak_dc = discharging_meter.get(
                            "PeakDcKw"
                        )

                    return True

                _LOGGER.error(
                    "Obtaining data from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def get_fcrd_month_net_revenue(self):
        """Fetch FCR-D revenues from checkwatt."""
        misseddays = 0
        try:
            from_date = datetime.now().strftime("%Y-%m-01")
            to_date = datetime.now() + timedelta(days=1)
            #            to_date = datetime.now()
            to_date = to_date.strftime("%Y-%m-%d")
            lastday_date = datetime.now() + relativedelta(months=1)
            lastday_date = datetime(
                year=lastday_date.year, month=lastday_date.month, day=1
            )

            lastday_date = lastday_date - timedelta(days=1)

            lastday = lastday_date.strftime("%d")

            dayssofar = datetime.now()
            #            dayssofar = datetime.now() + timedelta(days=1)
            dayssofar = dayssofar.strftime("%d")

            daysleft = int(lastday) - int(dayssofar)
            endpoint = f"/ems/revenue?fromDate={from_date}&toDate={to_date}"

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
                revenue = await response.json()
                for each in revenue:
                    self.revenuemonth += each["NetRevenue"]
                    if each["NetRevenue"] == 0:
                        misseddays += 1
                dayswithmoney = int(dayssofar) - int(misseddays)
                if response.status == 200:
                    self.dailyaverage = self.revenuemonth / int(dayswithmoney)
                    self.monthestimate = (
                        self.dailyaverage * daysleft
                    ) + self.revenuemonth
                    return True

                _LOGGER.error(
                    "Obtaining data from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def get_fcrd_today_net_revenue(self):
        """Fetch FCR-D revenues from checkwatt."""
        try:
            from_date = datetime.now().strftime("%Y-%m-%d")
            end_date = datetime.now() + timedelta(days=2)
            to_date = end_date.strftime("%Y-%m-%d")

            endpoint = f"/ems/revenue?fromDate={from_date}&toDate={to_date}"

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
                    return True

                _LOGGER.error(
                    "Obtaining data from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def get_fcrd_year_net_revenue(self):
        """Fetch FCR-D revenues from CheckWatt."""
        yesterday_date = datetime.now() + timedelta(days=1)
        yesterday_date = yesterday_date.strftime("-%m-%d")
        months = ["-01-01", "-06-30", "-07-01", yesterday_date]
        loop = 0
        retval = False
        if yesterday_date <= "-07-01":
            try:
                year_date = datetime.now().strftime("%Y")
                to_date = year_date + yesterday_date
                from_date = year_date + "-01-01"
                endpoint = f"/ems/revenue?fromDate={from_date}&toDate={to_date}"
                # Define headers with the JwtToken
                headers = {
                    **self._get_headers(),
                    "authorization": f"Bearer {self.jwt_token}",
                }
                # First fetch the revenue
                async with self.session.get(
                    self.base_url + endpoint, headers=headers
                ) as responseyear:  # noqa: E501
                    responseyear.raise_for_status()
                    self.revenueyear = await responseyear.json()
                    for each in self.revenueyear:
                        self.revenueyeartotal += each["NetRevenue"]
                    if responseyear.status == 200:
                        retval = True
                    else:
                        _LOGGER.error(
                            "Obtaining data from URL %s failed with status code %d",
                            self.base_url + endpoint,
                            responseyear.status,
                        )
                return retval

            except (ClientResponseError, ClientError) as error:
                return await self.handle_client_error(endpoint, headers, error)
        else:
            try:
                while loop < 3:
                    year_date = datetime.now().strftime("%Y")
                    to_date = year_date + months[loop + 1]
                    from_date = year_date + months[loop]
                    endpoint = f"/ems/revenue?fromDate={from_date}&toDate={to_date}"  # noqa: E501
                    # Define headers with the JwtToken
                    headers = {
                        **self._get_headers(),
                        "authorization": f"Bearer {self.jwt_token}",
                    }
                    # First fetch the revenue
                    async with self.session.get(
                        self.base_url + endpoint, headers=headers
                    ) as responseyear:  # noqa: E501
                        responseyear.raise_for_status()
                        self.revenueyear = await responseyear.json()
                        for each in self.revenueyear:
                            self.revenueyeartotal += each["NetRevenue"]
                        if responseyear.status == 200:
                            loop += 2
                            retval = True
                        else:
                            _LOGGER.error(
                                "Obtaining data from URL %s failed with status code %d",  # noqa: E501
                                self.base_url + endpoint,
                                responseyear.status,
                            )
                return retval

            except (ClientResponseError, ClientError) as error:
                return await self.handle_client_error(endpoint, headers, error)

    def _build_series_endpoint(self, grouping):
        end_date = datetime.now() + timedelta(days=2)
        to_date = end_date.strftime("%Y")
        endpoint = (
            f"/datagrouping/series?grouping={grouping}&fromdate=1923&todate={to_date}"
        )

        meters = self.customer_details.get("Meter", [])
        if meters:
            for meter in meters:
                if "Id" in meter:
                    endpoint += f"&meterId={meter['Id']}"
            return endpoint
        else:
            return None

    async def get_power_data(self):
        """Fetch Power Data from checkwatt."""

        try:
            endpoint = self._build_series_endpoint(
                3
            )  # 0: Hourly, 1: Daily, 2: Monthly, 3: Yearly

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
                if response.status == 200:
                    self.power_data = await response.json()
                    return True

                _LOGGER.error(
                    "Obtaining data from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def get_energy_flow(self):
        """Fetch Power Data from CheckWatt."""

        try:
            endpoint = "/ems/energyflow"

            # Define headers with the JwtToken
            headers = {
                **self._get_headers(),
                "authorization": f"Bearer {self.jwt_token}",
            }

            # Fetch Energy Flows
            async with self.session.get(
                self.base_url + endpoint, headers=headers
            ) as response:
                response.raise_for_status()
                if response.status == 200:
                    self.energy_data = await response.json()
                    return True

                _LOGGER.error(
                    "Obtaining data from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def get_price_zone(self):
        """Fetch Price Zone from checkwatt."""

        try:
            endpoint = "/ems/pricezone"
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
                if response.status == 200:
                    self.price_zone = await response.text()
                    return True

                _LOGGER.error(
                    "Obtaining data from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def get_spot_price(self):
        """Fetch Spot Price from checkwatt."""

        try:
            from_date = datetime.now().strftime("%Y-%m-%d")
            end_date = datetime.now() + timedelta(days=1)
            to_date = end_date.strftime("%Y-%m-%d")
            if self.price_zone is None:
                await self.get_price_zone()
            endpoint = f"/ems/spotprice?zone={self.price_zone}&fromDate={from_date}&toDate={to_date}"  # noqa: E501
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
                if response.status == 200:
                    self.spot_prices = await response.json()
                    return True

                _LOGGER.error(
                    "Obtaining data from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def get_energy_trading_company(self, input_id):
        """Translate Energy Company Id to Energy Company Name."""
        try:
            endpoint = "/controlpanel/elhandelsbolag"

            # Define headers with the JwtToken
            headers = {
                **self._get_headers(),
            }

            async with self.session.get(
                self.base_url + endpoint, headers=headers
            ) as response:
                response.raise_for_status()
                if response.status == 200:
                    energy_trading_companies = await response.json()
                    for energy_trading_company in energy_trading_companies:
                        if energy_trading_company["Id"] == input_id:
                            return energy_trading_company["DisplayName"]

                    return None

                _LOGGER.error(
                    "Obtaining data from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return None

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, headers, error)

    async def get_rpi_data(self, rpi_serial=None):
        """Fetch RPi Data from CheckWatt."""

        try:
            if rpi_serial is None:
                rpi_serial = self.rpi_serial

            if rpi_serial is None:
                _LOGGER.error("Invalid RpiSerial")
                return False

            endpoint = f"/register/checkrpiv2?rpi={rpi_serial}"
            # First fetch the revenue
            async with self.session.get(
                self.base_url + endpoint,
            ) as response:
                response.raise_for_status()
                if response.status == 200:
                    self.rpi_data = await response.json()
                    return True

                _LOGGER.error(
                    "Obtaining data from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, "", error)

    async def get_meter_status(self, meter_id=None):
        """Fetch RPi Data from CheckWatt."""

        try:
            if meter_id is None:
                meter_id = self.meter_id

            if meter_id is None:
                _LOGGER.error("Invalid MeterId")
                return False

            endpoint = f"/asset/status?meterId={meter_id}"
            # First fetch the revenue
            async with self.session.get(
                self.base_url + endpoint,
            ) as response:
                response.raise_for_status()
                if response.status == 200:
                    self.meter_data = await response.json()
                    return True

                _LOGGER.error(
                    "Obtaining data from URL %s failed with status code %d",
                    self.base_url + endpoint,
                    response.status,
                )
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(endpoint, "", error)

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
            resp += f" ({self.battery_registration['BatteryPowerKW']}kW, {self.battery_registration['BatteryCapacityKWh']}kWh)"  # noqa: E501
            return resp
        else:
            return "Could not get any information about your battery"

    @property
    def battery_peak_data(self):
        """Property for battery peak."""
        battery_charge_peak_ac = 0
        battery_charge_peak_dc = 0
        battery_discharge_peak_ac = 0
        battery_discharge_peak_dc = 0
        if self.battery_charge_peak_ac is not None:
            battery_charge_peak_ac = self.battery_charge_peak_ac
        if self.battery_charge_peak_dc is not None:
            battery_charge_peak_dc = self.battery_charge_peak_dc
        if self.battery_discharge_peak_ac is not None:
            battery_discharge_peak_ac = self.battery_discharge_peak_ac
        if self.battery_discharge_peak_dc is not None:
            battery_discharge_peak_dc = self.battery_discharge_peak_dc

        return (
            battery_charge_peak_ac,
            battery_charge_peak_dc,
            battery_discharge_peak_ac,
            battery_discharge_peak_dc,
        )

    @property
    def electricity_provider(self):
        """Property for electricity provides. Not used by HA integration."""
        if (
            "ElectricityCompany" in self.battery_registration
            and "Dso" in self.battery_registration
        ):
            resp = f"{self.battery_registration['ElectricityCompany']}"
            resp += f" via {self.battery_registration['Dso']}"
        if "GridAreaId" in self.battery_registration:
            resp += f" ({self.battery_registration['GridAreaId']} {self.battery_registration['Kommun']})"  # noqa: E501
        return resp

    @property
    def registered_owner(self):
        """Property for registered owner. Not used by HA integration.."""
        if "FirstName" in self.customer_details and "LastName" in self.customer_details:
            resp = f"{self.customer_details['FirstName']}"
            resp += f" {self.customer_details['LastName']}"
            resp += f" ({self.customer_details['StreetAddress']}"
            resp += f" {self.customer_details['ZipCode']}"
            resp += f" {self.customer_details['City']})"
            return resp
        return None

    @property
    def fcrd_year_net_revenue(self):
        """Property for today's revenue."""
        revenueyear = 0
        if self.revenueyeartotal is not None:
            revenueyear = self.revenueyeartotal

        return revenueyear

    @property
    def fcrd_month_net_revenue(self):
        """Property for today's revenue."""
        revenuemonth = 0
        if self.revenuemonth is not None:
            revenuemonth = self.revenuemonth

        return revenuemonth

    @property
    def fcrd_month_net_estimate(self):
        """Property for today's revenue."""
        monthestimate = 0
        if self.monthestimate is not None:
            monthestimate = self.monthestimate

        return monthestimate

    @property
    def fcrd_daily_net_average(self):
        """Property for today's revenue."""
        dailyaverage = 0
        if self.dailyaverage is not None:
            dailyaverage = self.dailyaverage

        return dailyaverage

    @property
    def fcrd_today_net_revenue(self):
        """Property for today's revenue."""
        revenue = 0
        if self.revenue is not None:
            if len(self.revenue) > 0:
                if "NetRevenue" in self.revenue[0]:
                    revenue = self.revenue[0]["NetRevenue"]

        return revenue

    @property
    def fcrd_tomorrow_net_revenue(self):
        """Property for tomorrow's revenue."""
        revenue = 0
        if self.revenue is not None:
            if len(self.revenue) > 1:
                if "NetRevenue" in self.revenue[1]:
                    revenue = self.revenue[1]["NetRevenue"]

        return revenue

    def _get_meter_total(self, meter_type):
        """Solar, Charging, Discharging, EDIEL_E17, EDIEL_E18, Soc meter summary."""
        meter_total = 0
        meters = self.power_data.get("Meters", [])
        for meter in meters:
            if "InstallationType" in meter and "Measurements" in meter:
                if meter["InstallationType"] == meter_type:
                    for measurement in meter["Measurements"]:
                        if "Value" in measurement:
                            meter_total += measurement["Value"]  # to get answer to kWh
        return meter_total

    @property
    def total_solar_energy(self):
        """Property for Solar Energy."""
        return self._get_meter_total("Solar")

    @property
    def total_charging_energy(self):
        """Property for Battery Charging Energy."""
        return self._get_meter_total("Charging")

    @property
    def total_discharging_energy(self):
        """Property for Battery Discharging Energy."""
        return self._get_meter_total("Discharging")

    @property
    def total_import_energy(self):
        """Property for Imported (Bought) Energy."""
        return self._get_meter_total("EDIEL_E17")

    @property
    def total_export_energy(self):
        """Property for Exported (Sold) Energy."""
        return self._get_meter_total("EDIEL_E18")

    def get_spot_price_excl_vat(self, now_hour: int):
        """Property for current spot price."""
        spot_prices = self.spot_prices.get("Prices", [])
        if spot_prices and 0 <= now_hour < len(spot_prices):
            spot_price = spot_prices[now_hour]["Value"]
            _LOGGER.debug("Time is %d and spot price is %f", now_hour, spot_price)
            return spot_price

        _LOGGER.warning("Unable to retrieve spot price for the current hour")
        return None

    @property
    def battery_power(self):
        """Property for Battery Power."""
        if self.energy_data is not None:
            if "BatteryNow" in self.energy_data:
                return self.energy_data["BatteryNow"]

        _LOGGER.warning("Unable to retrieve Battery Power")
        return None

    @property
    def grid_power(self):
        """Property for Grid Power."""
        if self.energy_data is not None:
            if "GridNow" in self.energy_data:
                return self.energy_data["GridNow"]

        _LOGGER.warning("Unable to retrieve Grid Power")
        return None

    @property
    def solar_power(self):
        """Property for Solar Power."""
        if self.energy_data is not None:
            if "SolarNow" in self.energy_data:
                return self.energy_data["SolarNow"]

        _LOGGER.warning("Unable to retrieve Solar Power")
        return None

    @property
    def battery_soc(self):
        """Property for Battery SoC."""
        if self.energy_data is not None:
            if "BatterySoC" in self.energy_data:
                return self.energy_data["BatterySoC"]

        _LOGGER.warning("Unable to retrieve Battery SoC")
        return None

    @property
    def rpi_serial(self):
        """Property for Rpi Serial."""
        if self.rpi_data is not None:
            meters = self.rpi_data.get("Meters", [])
            for meter in meters:
                if "RPi" in meter:
                    return meter["RPi"].upper()

        if self.customer_details is not None:
            meters = self.customer_details.get("Meter", [])
            for meter in meters:
                if "RpiSerial" in meter:
                    return meter["RpiSerial"].upper()

        _LOGGER.warning("Unable to find RPi Serial")
        return None

    @property
    def meter_id(self):
        """Property for Meter Id."""
        if self.rpi_data is not None:
            meters = self.rpi_data.get("Meters", [])
            for meter in meters:
                if "Id" in meter:
                    return meter["Id"]

        if self.customer_details is not None:
            meters = self.customer_details.get("Meter", [])
            for meter in meters:
                if "InstallationType" in meter and "Id" in meter:
                    if meter["InstallationType"] == "SoC":
                        return meter["Id"]

        _LOGGER.warning("Unable to find Meter Id")
        return None

    @property
    def meter_status(self):
        """Property for Meter Status."""
        # First check if meter_data is available
        if self.meter_data is not None:
            if "Label" in self.meter_data:
                return self.meter_data["Label"]

        # Then check if rpi_data is available
        if self.rpi_data is not None:
            meters = self.rpi_data.get("Meters", [])
            for meter in meters:
                if "InstallationType" in meter and "Status" in meter:
                    if meter["InstallationType"] == "SoC":
                        return meter["Status"]

        _LOGGER.warning("Unable to find Meter Status")
        return None

    @property
    def meter_status_date(self):
        """Property for Meter Status Date."""
        if self.meter_data is not None:
            if "Date" in self.meter_data:
                return self.meter_data["Date"]

        _LOGGER.warning("Unable to find Meter Data for Status Date")
        return None

    @property
    def meter_value_w(self):
        """Property for Meter Value W."""
        if self.meter_data is not None:
            if "ValueW" in self.meter_data:
                return self.meter_data["ValueW"]

        _LOGGER.warning("Unable to find Meter Data for Value W")
        return None

    @property
    def meter_under_test(self):
        """Property to check if meter is being tested."""
        if self.meter_data and "Version" in self.meter_data:
            return self.meter_data["Version"].endswith(".83")

        _LOGGER.warning("Unable to find Meter Data for Meter Under Test")
        return None

    @property
    def meter_version(self):
        """Property for Meter Version."""
        if self.meter_data is not None:
            if "Version" in self.meter_data:
                version_string = self.meter_data["Version"]

                # Use regular expression to extract Major.Minor.Patch
                match = re.search(r"\d+\.\d+\.\d+", version_string)
                if match:
                    return match.group()

        _LOGGER.warning("Unable to find Meter Data for Meter Version")
        return None
