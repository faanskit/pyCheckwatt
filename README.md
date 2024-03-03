# pyCheckwatt

Python package for communicating with [CheckWatt](https://checkwatt.se/) [EnergyInBalance](https://energyinbalance.se/) targeted for  [Home Assistant](https://home-assistant.io) integrations and other use-cases.

## Warning
This library is provided **as-is** and is not supported or approved by CheckWatt. CheckWatt can implement breaking changes at any time that renders this module useless. The module may not be updated promptly, or not at all if the changes are not possible to reverse engineer.

## Status
The library is **experimental** and pulls basic info from [EnergyInBalance](https://energyinbalance.se/).
Use with care as it loads the servers of CheckWatt

## Example
The following example will login to [EnergyInBalance](https://energyinbalance.se/) and retrieve basic information. 

Create a file called `example.py` that looks like this:
```python
"""Test-module for pyCheckwatt."""

import argparse
import json

from pycheckwatt import CheckwattManager


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
                    f"Discharging: {check_watt_instance.total_discharging_energy/1000} kWh"  # noqa: E501
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
```

Create a virtual environment and install pyCheckwatt:
```bash
$ python -m venv venv
$ ./venv/Scripts/activate
$ pip install pycheckwatt
```
Run a simple test:
```
$ python example.py
```

Watch the output:
```
System
======
First-name Last-name (Address Zip City)
Solax power T30 12.0 (12.3kW, 12.0kWh)

FCR-D
=====
FCR-D State: ACTIVATED
FCR-D Percentage: 99,0/2,9/97,7 %
FCR-D Date: 2023-12-20 00:11:45
```

## Comprehensive Example
A comprehensive example can can found in the [examples](https://github.com/faanskit/pyCheckwatt/tree/master/examples) folder. This example use additional modules, such as `dotenv` and `argparse`.
These modules needs to be installed before the `main.py` is executed.

```bash
$ python -m venv venv
$ ./venv/Scripts/activate
$ pip install pycheckwatt python-dotenv argparse
```

Run the comprehensive test:
```
$ python main.py
```
# Acknowledgements
This module was developed as a team effort by the following contributors.

- [@faanskit](https://github.com/faanskit) : Developer
- [@flopp999](https://github.com/flopp999) : Developer
- [@angoyd](https://github.com/angoyd) : CI/CD

This integration could not have been made without the excellent work done by the Home Assistant team.

If you like what have been done here and want to help I would recommend that you firstly look into supporting Home Assistant.

You can do this by purchasing some swag from their [store](https://home-assistant-store.creator-spring.com/) or paying for a Nabu Casa subscription. None of this could happen without them.

# Licenses
The integration is provided as-is without any warranties and published under [The MIT License](https://opensource.org/license/mit/).
