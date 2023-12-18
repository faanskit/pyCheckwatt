import os
from pycheckwatt import CheckwattManager
from dotenv import load_dotenv

load_dotenv()


async def main():
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
                print(f"Today revenue: {check_watt_instance.today_revenue}")

        except Exception as e:
            print(f"An error occurred: {e}")


if __name__ == "__main__":
    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main())
