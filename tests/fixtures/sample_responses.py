"""Sample API responses based on REAL CheckWatt API data."""

# Real login response structure (anonymized)
SAMPLE_LOGIN_RESPONSE = {
    "LoggedIn": True,
    "Role": None,
    "User": "test@example.com",
    "JwtToken": "eyJhbGciOiJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNobWFjLXNoYTI1NiIsInR5cCI6IkpXVCJ9.test_jwt_token",
    "RefreshToken": "test-refresh-token-uuid",
    "RefreshTokenExpires": "2025-08-28T13:19:31.595+00:00",
    "AdditionalProperties": None,
    "ClientId": None,
    "CesarId": None,
    "ResellerId": None,
    "Country": "",
    "Elhandelsbolag": None,
    "Koncern": None,
    "IsAdmin": False
}

# Real FCR-D revenue response structure (anonymized)
SAMPLE_FCRD_RESPONSE = {
    "SiteId": 12345,
    "Currency": "SEK",
    "Resolution": "Day",
    "Revenue": [
        {
            "ServiceName": "FCR-D",
            "Date": "2025-08-08",
            "NetRevenue": 20.11,
            "Estimate": True
        },
        {
            "ServiceName": "FCR-D",
            "Date": "2025-08-09",
            "NetRevenue": 20.13,
            "Estimate": True
        },
        {
            "ServiceName": "FCR-D",
            "Date": "2025-08-10",
            "NetRevenue": 21.07,
            "Estimate": True
        },
        {
            "ServiceName": "Savings",
            "Date": "2025-08-08",
            "NetRevenue": 0.13,
            "Estimate": True
        }
    ]
}

# Real power data response structure (anonymized, simplified)
SAMPLE_POWER_DATA_RESPONSE = {
    "DateFrom": "1925",
    "DateTo": "2025",
    "Grouping": "year",
    "Meters": [
        {
            "MeterId": 100001,
            "InstallationType": "Solar",
            "DatastreamId": "test1234abcd_energyPv",
            "DateFromUTC": "0001-01-01T00:00:00",
            "DateToUTC": "0001-01-01T00:00:00",
            "DateFromLocal": "0001-01-01T00:00:00",
            "DateToLocal": "0001-01-01T00:00:00",
            "Measurements": [
                {
                    "Value": 2848509.0,  # Real-scale solar energy in Wh
                    "Date": "2024"
                },
                {
                    "Value": 8276270.0,  # Real-scale solar energy in Wh
                    "Date": "2025"
                }
            ]
        },
        {
            "MeterId": 100002,
            "InstallationType": "Charging",
            "DatastreamId": "test1234abcd_energyCharge",
            "DateFromUTC": "0001-01-01T00:00:00",
            "DateToUTC": "0001-01-01T00:00:00",
            "DateFromLocal": "0001-01-01T00:00:00",
            "DateToLocal": "0001-01-01T00:00:00",
            "Measurements": [
                {
                    "Value": 1500000.0,  # Realistic charging energy in Wh
                    "Date": "2024"
                },
                {
                    "Value": 3200000.0,
                    "Date": "2025"
                }
            ]
        },
        {
            "MeterId": 100003,
            "InstallationType": "Discharging",
            "DatastreamId": "test1234abcd_energyDischarge",
            "DateFromUTC": "0001-01-01T00:00:00",
            "DateToUTC": "0001-01-01T00:00:00",
            "DateFromLocal": "0001-01-01T00:00:00",
            "DateToLocal": "0001-01-01T00:00:00",
            "Measurements": [
                {
                    "Value": 1200000.0,  # Realistic discharging energy in Wh
                    "Date": "2024"
                },
                {
                    "Value": 2800000.0,
                    "Date": "2025"
                }
            ]
        },
        {
            "MeterId": 100004,
            "InstallationType": "EDIEL_E17",  # Import
            "DatastreamId": "test1234abcd_energyImport",
            "DateFromUTC": "0001-01-01T00:00:00",
            "DateToUTC": "0001-01-01T00:00:00",
            "DateFromLocal": "0001-01-01T00:00:00",
            "DateToLocal": "0001-01-01T00:00:00",
            "Measurements": [
                {
                    "Value": 3104554.0,  # Real import energy from your data
                    "Date": "2024"
                },
                {
                    "Value": 4994288.0,
                    "Date": "2025"
                }
            ]
        },
        {
            "MeterId": 100005,
            "InstallationType": "EDIEL_E18",  # Export
            "DatastreamId": "test1234abcd_energyExport",
            "DateFromUTC": "0001-01-01T00:00:00",
            "DateToUTC": "0001-01-01T00:00:00",
            "DateFromLocal": "0001-01-01T00:00:00",
            "DateToLocal": "0001-01-01T00:00:00",
            "Measurements": [
                {
                    "Value": 2899531.0,  # Real export energy from your data
                    "Date": "2024"
                },
                {
                    "Value": 5141207.0,
                    "Date": "2025"
                }
            ]
        }
    ]
}

# Real EMS settings response
SAMPLE_EMS_SETTINGS_RESPONSE = ["fcrd"]

# Customer details with realistic logbook (from previous real data)
REALISTIC_LOGBOOK = """[ FCR-D ACTIVATED ] test@example.com --12345-- 96,5/4,0/106,3 % (10,0/10,0 kW) 2025-01-01 00:04:45 API-BACKEND
[ FCR-D DEACTIVATE ]  UP 49,83 Hz 0,0 %  (10 kW) - 2024-12-31 17:58:07 API-BACKEND
[ FCR-D ACTIVATED ] test@example.com --12345-- 97,7/0,5/99,3 % (7 kW) 2024-07-07 00:08:19 API-BACKEND
System configuration entry
Test system activation
#BEGIN_BATTERY_REGISTRATION{"Dso":"Test Energy Distribution AB","ElectricityCompany":"Test Energy AB","ElectricityCompanyId":66,"Inverter":"Test Inverter","InverterModel":"X3 Hybrid G4","InverterPowerKW":"15","InverterAmount":"1","BatterySystem":"Test Battery System","BatteryModel":"T58 30kWh","BatteryAmount":"1","Timestamp":"2023-01-01 10:14","HasBattery":true,"FuseSizeA":20,"SolarPeakKWp":"4.3","BatteryPowerKW":"15","BatteryCapacityKWh":"30","BatteryPeakKW":"15","OperationDate":"2023-01-01","Comment":"Test battery system configuration","GridArea":3,"GridAreaId":"TST","Kommun":"Test Municipality","City":"TEST CITY"}#END_BATTERY_REGISTRATION"""

# Customer details with realistic structure
SAMPLE_CUSTOMER_DETAILS_JSON = {
    "Id": 12345,
    "FirstName": "John",
    "LastName": "Doe",
    "CompanyName": "",
    "Email": "john.doe@example.com",
    "Notification": 1,
    "Telephone": "+46701234567",
    "StreetAddress": "Test Street 123",
    "ZipCode": "12345",
    "City": "Test City",
    "PersonalNumber": "800101-1234",
    "OrganizationNumber": None,
    "BankName": "Test Bank",
    "BankAccount": "1234,567890123",
    "PayMessage": None,
    "EcCesarAccount": None,
    "UgCesarAccount": None,
    "QuotaDuty": False,
    "Logbook": "Customer level logbook entry",
    "ExtraInfo": "{\n  \"TestDocument\": \"https://example.com/test-document.pdf\"\n}",
    "Created": "2023-01-01T10:00:00Z",
    "AuthType": 0,
    "KoncernId": None,
    "LoginKoncernId": None,
    "LoginCesarAdminId": None,
    "LoginElhandelsbolagId": None,
    "LoginResellerId": None,
    "LoginRole": None,
    "Meter": [
        {
            "Id": 100001,
            "InstallationType": "SoC",
            "PeakAcKw": None,
            "PeakDcKw": None,
            "FacilityId": "734012530000123456",
            "RpiSerial": "test1234abcd",
            "RpiModel": "CM4-X500-MINI",
            "Comments": "Test system configuration\\nBattery expanded to 30 kWh",
            "Logbook": REALISTIC_LOGBOOK,
            "DisplayName": "John Doe, Test Street 123",
            "ClientId": 12345,
            "ResellerId": 123,
            "ElhandelsbolagId": 66,
            "DatastreamId": "test1234abcd_SoC",
            "BatteryCapacityKwh": 30.0,
            "Created": "2023-01-01T10:00:00Z"
        },
        {
            "Id": 100002,
            "InstallationType": "Charging",
            "PeakAcKw": 15.0,
            "PeakDcKw": 15.0,
            "RpiSerial": "test1234abcd",
            "ClientId": 12345,
            "DatastreamId": "test1234abcd_energyCharge"
        },
        {
            "Id": 100003,
            "InstallationType": "Discharging",
            "PeakAcKw": 15.0,
            "PeakDcKw": 15.0,
            "RpiSerial": "test1234abcd",
            "ClientId": 12345,
            "DatastreamId": "test1234abcd_energyDischarge"
        },
        {
            "Id": 100004,
            "InstallationType": "EDIEL_E17",
            "PeakAcKw": 13.8,
            "PeakDcKw": 13.8,
            "RpiSerial": "test1234abcd",
            "ClientId": 12345,
            "DatastreamId": "test1234abcd_energyImport"
        },
        {
            "Id": 100005,
            "InstallationType": "EDIEL_E18",
            "PeakAcKw": 13.8,
            "PeakDcKw": 13.8,
            "RpiSerial": "test1234abcd",
            "ClientId": 12345,
            "DatastreamId": "test1234abcd_energyExport"
        },
        {
            "Id": 100006,
            "InstallationType": "Solar",
            "PeakAcKw": 4.3,
            "PeakDcKw": 4.3,
            "RpiSerial": "test1234abcd",
            "ClientId": 12345,
            "DatastreamId": "test1234abcd_energyPv"
        }
    ]
}
