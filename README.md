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
# Donations
I mainly did this project as a learning experience for myself and have no expectations from anyone.

If you like what have been done here and want to help I would recommend that you firstly look into supporting Home
Assistant. 

You can do this by purchasing some swag from their [store](https://teespring.com/stores/home-assistant-store)
or paying for a Nabu Casa subscription. None of this could happen without them.

After you have done that if you still feel this work has been valuable to you I welcome your support through BuyMeACoffee or Paypal.

<a href="https://www.buymeacoffee.com/faanskit"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a coffee&emoji=&slug=faanskit&button_colour=FFDD00&font_colour=000000&font_family=Poppins&outline_colour=000000&coffee_colour=ffffff"></a> [![Paypal](https://www.paypalobjects.com/digitalassets/c/website/marketing/apac/C2/logos-buttons/optimize/44_Yellow_PayPal_Pill_Button.png)](https://paypal.me/faanskit)
