"""Pulls historical data from CheckWatt EnergyInBalance and push it to CheckWattRank"""

from pycheckwatt import CheckwattManager
import json
import aiohttp

START_DATE = "2023-09-01"
END_DATE = "2024-01-31"

EIB_USERNAME = ""
EIB_PASSWORD = ""
DISPLAY_NAME_OVERRIDE = ""


def get_display_name(cw):
    """Pull DisplayName from CW Data"""
    if DISPLAY_NAME_OVERRIDE != "":
        return DISPLAY_NAME_OVERRIDE

    meters = cw.customer_details.get("Meter", [])
    if meters:
        soc_meter = next(
            (meter for meter in meters if meter.get("InstallationType") == "SoC"),
            None,
        )

        if not soc_meter:
            print("No SoC meter found")
            return False

        return soc_meter["DisplayName"]


def get_reseller_id(cw):
    """Pull ResellerId from CW Data"""
    meters = cw.customer_details.get("Meter", [])
    if meters:
        soc_meter = next(
            (meter for meter in meters if meter.get("InstallationType") == "SoC"),
            None,
        )

        if not soc_meter:
            print("No SoC meter found")
            return False

        return soc_meter["ResellerId"]


async def main():
    """Main function."""
    if EIB_USERNAME == "" or EIB_PASSWORD == "":
        print("You need to update EIB_USERNAME/EIB_PASSWORD")
        return

    async with CheckwattManager(EIB_USERNAME, EIB_PASSWORD, "cwTest") as cw:
        try:
            # Login to EnergyInBalance
            if await cw.login():
                # Fetch customer detail
                await cw.get_customer_details()
                await cw.get_price_zone()
                hd = await cw.fetch_and_return_net_revenue(START_DATE, END_DATE)

                data = {
                    "display_name": get_display_name(cw),
                    "dso": cw.battery_registration["Dso"],
                    "electricity_area": cw.price_zone,
                    "installed_power": cw.battery_charge_peak_ac,
                    "electricity_company": cw.battery_registration[
                        "ElectricityCompany"
                    ],
                    "reseller_id": get_reseller_id(cw),
                    "reporter": "CheckWattRank",
                    "historical_data": hd,
                }
                print(f"{json.dumps(data, indent=4)}")

                # Post data to Netlify function
                BASE_URL = "https://checkwattrank.netlify.app/"
                netlify_function_url = BASE_URL + "/.netlify/functions/publishHistory"
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        netlify_function_url, json=data
                    ) as response:
                        if response.status == 200:
                            print("Data posted successfully to Netlify function.")
                        else:
                            print(
                                f"Failed to post data. Status code: {response.status}"
                            )

        except Exception as e:
            print(f"An error occurred: {e}")


if __name__ == "__main__":
    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main())
