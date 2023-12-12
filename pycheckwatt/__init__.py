from __future__ import annotations
from aiohttp import ClientSession, ClientError, ContentTypeError
import logging
import base64
import re
import json

_LOGGER = logging.getLogger(__name__)

class CheckwattManager:
    def __init__(self, username, password):
        self.session = None
        self.base_url = "https://services.cnet.se/checkwattapi/v2"
        self.username = username
        self.password = password

    async def __aenter__(self):
        self.session = ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.session.close()

    def _extract_content_and_logbook(self, input_string):
        # Define the pattern to match the content between the tags
        pattern = re.compile(r'#BEGIN_BATTERY_REGISTRATION(.*?)#END_BATTERY_REGISTRATION', re.DOTALL)

        # Find all matches in the input string
        matches = re.findall(pattern, input_string)

        # Extracted content
        extracted_content = ""
        if matches:
            extracted_content = matches[0].strip()
            battery_registration = json.loads(extracted_content)

        # Extract logbook entries
        logbook_entries = input_string.split('\n')

        # Filter out entries containing #BEGIN_BATTERY_REGISTRATION and #END_BATTERY_REGISTRATION
        logbook_entries = [entry.strip() for entry in logbook_entries if not ('#BEGIN_BATTERY_REGISTRATION' in entry or '#END_BATTERY_REGISTRATION' in entry)]

        return battery_registration, logbook_entries

    async def login(self):
        try:
            credentials = f"{self.username}:{self.password}"
            encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
            endpoint = "/user/LoginEiB?audience=eib"

            # Define headers with the encoded credentials
            headers = {
                "accept": "application/json, text/plain, */*",
                "accept-language": "sv-SE,sv;q=0.9,en-SE;q=0.8,en;q=0.7,en-US;q=0.6",
                "authorization": f"Basic {encoded_credentials}",
                "content-type": "application/json",
                "sec-ch-ua": "\"Chromium\";v=\"112\", \"Google Chrome\";v=\"112\", \"Not:A-Brand\";v=\"99\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"Windows\"",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "cross-site",
                "wslog-os": "",
                "wslog-platform": "controlpanel"
            }

            async with self.session.get(self.base_url + endpoint, headers=headers) as response:
                data = await response.json()
                self.jwt_token = data.get("JwtToken")
                self.refresh_token = data.get("RefreshToken")
                return True

        except ClientError as e:
            _LOGGER.error(f"An error occurred during the request: {e}")
            return False

        except ContentTypeError as e:
            _LOGGER.error(f"Error parsing JSON: {e}")
            return False

    async def get_customer_details(self):
        try:
            endpoint = "/controlpanel/CustomerDetail"

            # Define headers with the JwtToken
            headers = {
                "accept": "application/json, text/plain, */*",
                "accept-language": "sv-SE,sv;q=0.9,en-SE;q=0.8,en;q=0.7,en-US;q=0.6",
                "authorization": f"Bearer {self.jwt_token}",
                "content-type": "application/json",
                "sec-ch-ua": "\"Chromium\";v=\"112\", \"Google Chrome\";v=\"112\", \"Not:A-Brand\";v=\"99\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"Windows\"",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "cross-site",
                "wslog-os": "",
                "wslog-platform": "controlpanel"
            }

            async with self.session.get(self.base_url + endpoint, headers=headers) as response:
                response.raise_for_status()
                self.customer_details = await response.json()


                meters = self.customer_details.get("Meter", [])
                if meters:
                    first_meter = meters[0]
                    logbook = first_meter.get("Logbook")
                    if logbook:
                        self.battery_registration, self.logbook_entries = self._extract_content_and_logbook(logbook)

                return self.customer_details['Id']

        except ClientError as e:
            _LOGGER.error(f"An error occurred during the request: {e}")
            return None

        except ContentTypeError as e:
            _LOGGER.error(f"Error parsing JSON: {e}")
            return None


    @property
    def inverter_make_and_model(self):
        if "Inverter" in self.battery_registration and "InverterModel" in self.battery_registration:
            resp = f"{self.battery_registration['Inverter']}"
            resp += f" {self.battery_registration['InverterModel']}"
            return resp

    @property
    def battery_make_and_model(self):
        if "BatteryModel" in self.battery_registration and "BatterySystem" in self.battery_registration:
            resp = f"{self.battery_registration['BatterySystem']}"
            resp += f" {self.battery_registration['BatteryModel']}"
            resp += f" ({self.battery_registration['BatteryPowerKW']}kW, {self.battery_registration['BatteryCapacityKWh']}kWh)"
            return resp
    
    @property
    def exectricity_provider(self):
        if "ElectricityCompany" in self.battery_registration and "Dso" in self.battery_registration:
            resp = f"{self.battery_registration['ElectricityCompany']}"
            resp += f" via {self.battery_registration['Dso']}"
            resp += f" ({self.battery_registration['GridAreaId']} {self.battery_registration['Kommun']})"
            return resp

    @property
    def registred_owner(self):
        if "FirstName" in self.customer_details and "LastName" in self.customer_details:
            resp = f"{self.customer_details['FirstName']}"
            resp += f" {self.customer_details['LastName']}"
            resp += f" ({self.customer_details['StreetAddress']}"
            resp += f" {self.customer_details['ZipCode']}"
            resp += f" {self.customer_details['City']})"
            return resp
