import os
import json
from pycheckwatt import CheckwattManager
from dotenv import load_dotenv
load_dotenv()

# Example usage:
async def main():
    # Fetch username and password from environment variables
    username = os.getenv("CHECKWATT_USERNAME")
    password = os.getenv("CHECKWATT_PASSWORD")

    # Create the asynch class
    async with CheckwattManager(username, password) as check_watt_instance:
        #response = await check_watt_instance.make_async_request("/some_endpoint")
        if await check_watt_instance.login():
            id = await check_watt_instance.get_customer_details()
            print("Customer Details")
            print("================")
            print(check_watt_instance.registred_owner)

            print("\nSystem\n======")
            print(check_watt_instance.inverter_make_and_model)
            print(check_watt_instance.battery_make_and_model)
            print(check_watt_instance.exectricity_provider)

            print("\nLogbook Entries\n===============")
            for entry in check_watt_instance.logbook_entries:
                print(entry)


if __name__ == "__main__":
    import asyncio
    asyncio.get_event_loop().run_until_complete(main())