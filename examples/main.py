"""Test-module for pyCheckwatt."""
import argparse
import json
import os

from dotenv import load_dotenv

from pycheckwatt import CheckwattManager

load_dotenv()


async def main(show_details=False):
    """Fetch username and password from environment variables."""
    username = os.getenv("CHECKWATT_USERNAME")
    password = os.getenv("CHECKWATT_PASSWORD")

    # Create the async class
    async with CheckwattManager(username, password) as check_watt_instance:
        try:
            # Login to EnergyInBalance
            if await check_watt_instance.login():
                # Fetch customer detail
                customer_id = await check_watt_instance.get_customer_details()

                # Do a sample
                print("Customer Details\n================")
                print(check_watt_instance.registered_owner)

                print("\nSystem\n======")
                print("Charge peak", check_watt_instance.battery_charge_peak)
                print("Discharge peak", check_watt_instance.battery_discharge_peak)
                print(check_watt_instance.battery_make_and_model)
                print(check_watt_instance.electricity_provider)

                print("\nLogbook Entries\n===============")
                for entry in check_watt_instance.logbook_entries:
                    print(entry)

                await check_watt_instance.get_fcrd_revenue()
                await check_watt_instance.get_fcrd_revenueyear()
                await check_watt_instance.get_fcrd_revenuemonth()
                print("\nFCR-D\n=====")
                print(f"FCR-D State: {check_watt_instance.fcrd_state}")
                print(f"FCR-D Percentage: {check_watt_instance.fcrd_percentage}")
                print(f"FCR-D Date: {check_watt_instance.fcrd_timestamp}")
                print("\n")
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Daily average:",
                        int(check_watt_instance.month_revenue[2]),
                        "kr",
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Month estimate:",
                        int(check_watt_instance.month_revenue[3]),
                        "kr",
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Month compensation:",
                        int(check_watt_instance.month_revenue[0]),
                        "kr",
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Month fee:", int(check_watt_instance.month_revenue[1]), "kr"
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Month revenue:",
                        int(
                            check_watt_instance.month_revenue[0]
                            - check_watt_instance.month_revenue[1]
                        ),
                        "kr",
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Year compensation:",
                        int(check_watt_instance.year_revenue[0]),
                        "kr",
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Year fee:", int(check_watt_instance.year_revenue[1]), "kr"
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Year revenue:",
                        int(
                            check_watt_instance.year_revenue[0]
                            - check_watt_instance.year_revenue[1]
                        ),
                        "kr",
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Today compensation:",
                        int(check_watt_instance.today_revenue[0]),
                        "kr",
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Today fee:", int(check_watt_instance.today_revenue[1]), "kr"
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Today revenue:",
                        int(
                            check_watt_instance.today_revenue[0]
                            - check_watt_instance.today_revenue[1]
                        ),
                        "kr",
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Tomorrow compensation:",
                        int(check_watt_instance.tomorrow_revenue[0]),
                        "kr",
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Tomorrow fee:",
                        int(check_watt_instance.tomorrow_revenue[1]),
                        "kr",
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Tomorrow revenue:",
                        int(
                            check_watt_instance.tomorrow_revenue[0]
                            - check_watt_instance.tomorrow_revenue[1]
                        ),
                        "kr",
                    )
                )

                await check_watt_instance.get_power_data()
                print("\nEnergy\n======")
                print(f"Solar: {check_watt_instance.total_solar_energy/1000} kWh")
                print(f"Charging: {check_watt_instance.total_charging_energy/1000} kWh")
                print(
                    f"Discharging: {check_watt_instance.total_discharging_energy/1000} kWh"
                )
                print(f"Import: {check_watt_instance.total_import_energy/1000} kWh")
                print(f"Export: {check_watt_instance.total_export_energy/1000} kWh")

                if show_details:
                    print("\nCustomer Details\n===============")
                    print(json.dumps(check_watt_instance.customer_details, indent=2))

        except Exception as e:
            print(f"An error occurred: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Checkwatt Information")
    parser.add_argument(
        "-d", "--details", action="store_true", help="Show system details"
    )
    args = parser.parse_args()

    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main(args.details))
