"""Test-module for pyCheckwatt."""
import argparse
import json

from dotenv import load_dotenv

from pycheckwatt import CheckwattManager

load_dotenv()


async def main(show_details=False):
    """Fetch username and password from environment variables."""
    username = ""
    password = ""

    # Create the async class
    async with CheckwattManager(username, password) as check_watt_instance:
        try:
            # Login to EnergyInBalance and check kill switch
            if await check_watt_instance.login():
                # Fetch customer detail
                await check_watt_instance.get_customer_details()
                await check_watt_instance.get_battery_peak_data()

                # Do a sample
                print("Customer Details\n================")
                print(check_watt_instance.registered_owner)

                print("\nSystem\n======")
                print("Charge peak AC", check_watt_instance.battery_peak_data[0])
                print("Charge peak DC", check_watt_instance.battery_peak_data[1])
                print("Discharge peak AC", check_watt_instance.battery_peak_data[2])
                print("Discharge peak DC", check_watt_instance.battery_peak_data[3])
                print(check_watt_instance.battery_make_and_model)
                print(check_watt_instance.electricity_provider)

                print("\nLogbook Entries\n===============")
                for entry in check_watt_instance.logbook_entries:
                    print(entry)

                await check_watt_instance.get_fcrd_today_net_revenue()
                await check_watt_instance.get_fcrd_year_net_revenue()
                await check_watt_instance.get_fcrd_month_net_revenue()
                print("\nFCR-D\n=====")
                print(f"FCR-D State: {check_watt_instance.fcrd_state}")
                print(f"FCR-D Percentage: {check_watt_instance.fcrd_info}")
                print(f"FCR-D Date: {check_watt_instance.fcrd_timestamp}")

                print("\nRevenue\n======")
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Daily average:",
                        int(check_watt_instance.fcrd_daily_net_average),
                        "kr",
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Month estimate:",
                        int(check_watt_instance.fcrd_month_net_estimate),
                        "kr",
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Month revenue:",
                        int(check_watt_instance.fcrd_month_net_revenue),
                        "kr",
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Year revenue:",
                            int(check_watt_instance.fcrd_year_net_revenue),
                        "kr",
                    )
                )
                print(
                    "{:<24}  {:>6}  {:>0}".format(
                        "Today revenue:",
                            int(check_watt_instance.fcrd_today_net_revenue),
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
