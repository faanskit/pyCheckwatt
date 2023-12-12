[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/faanskit/) [![Donate](https://img.shields.io/badge/Donate-BuyMeCoffe-green.svg)](https://www.buymeacoffee.com/faanskit)

# Pycheckwatt

Python package for communicating with [CheckWatt](https://checkwatt.se/) [EnergyInBalance](https://energyinbalance.se/) eventually targeted for [Home Assistant](https://home-assistant.io)

## Warning
This library is provided as-is, is not supported or sanctioned by CheckWatt.

## Status
The library is **expermental** and does nothing but to pull some basic info from [EnergyInBalance](https://energyinbalance.se/)

## Usage
Create a `.env` file that looks like this and contain your credentials to [EnergyInBalance](https://energyinbalance.se/).
```
CHECKWATT_USERNAME=<username>
CHECKWATT_PASSWORD=<passwored>
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

## TODO
1. The main.py should likely be moved to a ./test directory
2. Add more API calls, in particular the /fees and /revenue endpoints
3. Make Home Assistant component and publish to HACS
4. Drink beer...

### GET /fees
```
fetch("https://services.cnet.se/checkwattapi/v2/ems/service/fees?fromDate=2023-12-01&toDate=2024-01-01", {
  "headers": {
    "accept": "application/json, text/plain, */*",
    "accept-language": "sv-SE,sv;q=0.9,en-SE;q=0.8,en;q=0.7,en-US;q=0.6",
    "authorization": "Bearer TBD",
    "content-type": "application/json",
    "sec-ch-ua": "\"Chromium\";v=\"112\", \"Google Chrome\";v=\"112\", \"Not:A-Brand\";v=\"99\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "cross-site",
    "wslog-os": "",
    "wslog-platform": "controlpanel"
  },
  "referrer": "https://energyinbalance.se/",
  "referrerPolicy": "strict-origin-when-cross-origin",
  "body": null,
  "method": "GET",
  "mode": "cors",
  "credentials": "include"
});
```

### GET /revenue
```
fetch("https://services.cnet.se/checkwattapi/v2/ems/fcrd/revenue?fromDate=2023-12-01&toDate=2024-01-01", {
  "headers": {
    "accept": "application/json, text/plain, */*",
    "accept-language": "sv-SE,sv;q=0.9,en-SE;q=0.8,en;q=0.7,en-US;q=0.6",
    "authorization": "Bearer TBD",
    "content-type": "application/json",
    "sec-ch-ua": "\"Chromium\";v=\"112\", \"Google Chrome\";v=\"112\", \"Not:A-Brand\";v=\"99\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "cross-site",
    "wslog-os": "",
    "wslog-platform": "controlpanel"
  },
  "referrer": "https://energyinbalance.se/",
  "referrerPolicy": "strict-origin-when-cross-origin",
  "body": null,
  "method": "GET",
  "mode": "cors",
  "credentials": "include"
});
```