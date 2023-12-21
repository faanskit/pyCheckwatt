import argparse
import os
import json
from pycheckwatt import CheckwattManager
from dotenv import load_dotenv

load_dotenv()


async def main(show_details=False):
    # Fetch username and password from environment variables
    username = os.getenv("CHECKWATT_USERNAME")
    password = os.getenv("CHECKWATT_PASSWORD")

    # Create the asynch class
    async with CheckwattManager(username, password) as check_watt_instance:
        try:
            # Login to EnergyInBalance
            if await check_watt_instance.login():
                # Fetch customer detail
                customer_id = await check_watt_instance.get_customer_details()

                # Do a sample
                print("Customer Details\n================")
                print(check_watt_instance.registred_owner)

                print("\nSystem\n======")
                print(check_watt_instance.inverter_make_and_model)
                print(check_watt_instance.battery_make_and_model)
                print(check_watt_instance.exectricity_provider)

                print("\nLogbook Entries\n===============")
                for entry in check_watt_instance.logbook_entries:
                    print(entry)

                await check_watt_instance.get_fcrd_revenue()
                print("\nFCR-D\n=====")
                print(f"FCR-D State: {check_watt_instance.fcrd_state}")
                print(f"FCR-D Percentage: {check_watt_instance.fcrd_percentage}")
                print(f"FCR-D Date: {check_watt_instance.fcrd_timestamp}")
                print(f"\nToday revenue: {round(check_watt_instance.today_revenue, 2)}")
                print(f"Tomorrow revenue: {round(check_watt_instance.tomorrow_revenue, 2)}")


                if show_details:
                    print("\nCustomer Details\n===============")
                    print(json.dumps(check_watt_instance.customer_details, indent=2))

        except Exception as e:
            print(f"An error occurred: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Checkwatt Information")
    parser.add_argument("-d", "--details", action="store_true", help="Show system details")
    args = parser.parse_args()

    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main(args.details))
