# pyCheckwatt

Python package for communicating with [CheckWatt](https://checkwatt.se/) [EnergyInBalance](https://energyinbalance.se/) targeted for  [Home Assistant](https://home-assistant.io) integration.

## Warning
This library is provided as-is, is not supported or sanctioned by CheckWatt.

## Status
The library is **expermental** and does nothing but to pull some basic info from [EnergyInBalance](https://energyinbalance.se/).
Use with care as it loads the servers of CheckWatt

## Example
In the examples folder exist en example file that make use of this library.

### Using the example
Create a `.env` file that looks like this and contain your credentials to [EnergyInBalance](https://energyinbalance.se/).
```
CHECKWATT_USERNAME=<username>
CHECKWATT_PASSWORD=<password>
```

Run a simple test:
```
> python main.py
```

Watch the output:
```
Customer Details
================
Firstname Lastname (Adress Zip City)

System
======
Inverter Brand Model
Battery Brand Model (12.3kW, 12.0kWh)
Energy supplier via Dso (BLE City)

Logbook Entries
===============
#9999 Hugo 2023-01-01
20230101-1100-CET - Hugo - test:pass, timestamp:pass, lan-router:pass, 4G:pass, simnumber:pass
20230101-1120-CET - Silas - unpacked
```
