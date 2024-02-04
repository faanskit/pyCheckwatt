"""Pulls historical data from CheckWatt EnergyInBalance and push it to CheckWattRank"""

import aiohttp

from pycheckwatt import CheckwattManager

START_DATE = "2023-09-01"
END_DATE = "2024-01-31"

EIB_USERNAME = ""
EIB_PASSWORD = ""
DISPLAY_NAME_OVERRIDE = ""

BASE_URL = "https://checkwattrank.netlify.app/"


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
                if not await cw.get_customer_details():
                    print("Failed to fetch customer details")
                    return

                if not await cw.get_price_zone():
                    print("Failed to fetch prize zone")
                    return

                hd = await cw.fetch_and_return_net_revenue(START_DATE, END_DATE)
                if hd is None:
                    print("Failed to fetch revenues")
                    return

                energy_provider = await cw.get_energy_trading_company(
                    cw.energy_provider_id
                )
                if energy_provider is None:
                    print("Failed to fetch electricity compan")
                    return

                data = {
                    "display_name": (
                        DISPLAY_NAME_OVERRIDE
                        if DISPLAY_NAME_OVERRIDE != ""
                        else cw.display_name
                    ),
                    "dso": cw.battery_registration["Dso"],
                    "electricity_area": cw.price_zone,
                    "installed_power": cw.battery_charge_peak_ac,
                    "electricity_company": energy_provider,
                    "reseller_id": cw.reseller_id,
                    "reporter": "CheckWattRank",
                    "historical_data": hd,
                }

                # Post data to Netlify function
                netlify_function_url = BASE_URL + "/.netlify/functions/publishHistory"
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        netlify_function_url, json=data
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            count = result.get("count", 0)
                            total = result.get("total", 0)
                            print(f"Data posted successfully. Count: {count}/{total}")
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
