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
"""Example file to test pyCheckwatt"""
from pycheckwatt import CheckwattManager
EIB_USERNAME="eib_username"
EIB_PASSWORD="eib_password"

async def main():
    """Test function for pyCheckwatt."""
    async with CheckwattManager(EIB_USERNAME, EIB_PASSWORD) as cw_instance:
        try:
            # Login to EnergyInBalance
            if await cw_instance.login():
                # Fetch customer detail
                await cw_instance.get_customer_details()
                print("System\n======")
                print(cw_instance.registered_owner)
                print(cw_instance.battery_make_and_model)
                print("\nFCR-D\n=====")
                print(f"FCR-D State: {cw_instance.fcrd_state}")
                print(f"FCR-D Percentage: {cw_instance.fcrd_percentage}")
                print(f"FCR-D Date: {cw_instance.fcrd_timestamp}")

        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":

    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(main())
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