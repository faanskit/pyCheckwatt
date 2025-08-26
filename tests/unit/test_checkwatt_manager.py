import os
import sys
from unittest.mock import AsyncMock, Mock, patch

import pytest
import pytest_asyncio

# Add project root to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from pycheckwatt import CheckwattManager
from tests.fixtures.sample_responses import (
    SAMPLE_CUSTOMER_DETAILS_JSON,
    SAMPLE_EMS_SETTINGS_RESPONSE,
    SAMPLE_FCRD_RESPONSE,
    SAMPLE_LOGIN_RESPONSE,
    SAMPLE_POWER_DATA_RESPONSE,
)


class TestCheckwattManagerInitialization:
    """Test initialization and basic setup."""

    def test_manager_creation_with_valid_credentials(self):
        """Test that manager can be created with username and password."""
        manager = CheckwattManager("test_user", "test_pass")

        assert manager.username == "test_user"
        assert manager.password == "test_pass"
        assert manager.session is None  # Not initialized until async context
        assert manager.jwt_token is None  # Not set until login

    def test_manager_creation_with_invalid_credentials(self):
        """Test that manager creation fails with invalid credentials."""
        with pytest.raises(ValueError, match="Username and password must be provided"):
            CheckwattManager(None, "password")

        with pytest.raises(ValueError, match="Username and password must be provided"):
            CheckwattManager("username", None)

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        """Test that manager works as async context manager."""
        async with CheckwattManager("test_user", "test_pass") as manager:
            assert manager.session is not None
            assert hasattr(manager.session, "get")  # Verify it's an aiohttp session


class TestAuthentication:
    """Test authentication workflow and JWT token management."""

    @pytest.mark.asyncio
    async def test_login_success(self):
        """Test successful login flow."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            with patch("aiohttp.ClientSession.post") as mock_post, patch(
                "aiohttp.ClientSession.get"
            ) as mock_get:

                # Mock kill switch check (always called first)
                mock_killswitch = AsyncMock()
                mock_killswitch.status = 200
                mock_killswitch.text = AsyncMock(return_value="0")
                mock_get.return_value.__aenter__.return_value = mock_killswitch

                # Mock login response
                mock_login = AsyncMock()
                mock_login.status = 200
                mock_login.json = AsyncMock(return_value=SAMPLE_LOGIN_RESPONSE)
                mock_post.return_value.__aenter__.return_value = mock_login

                # Test login
                result = await manager.login()

                assert result is True
                assert manager.jwt_token == SAMPLE_LOGIN_RESPONSE["JwtToken"]
                assert manager.refresh_token == SAMPLE_LOGIN_RESPONSE["RefreshToken"]

    @pytest.mark.asyncio
    async def test_login_requires_kill_switch_check(self):
        """Test that login checks kill switch first."""
        async with CheckwattManager("test_user", "test_pass") as manager:
            initial_jwt = manager.jwt_token  # Capture initial value

            with patch("aiohttp.ClientSession.get") as mock_get:
                # Mock kill switch as enabled (should block login)
                mock_killswitch = AsyncMock()
                mock_killswitch.status = 200
                mock_killswitch.text = AsyncMock(return_value="1")  # Enabled
                mock_get.return_value.__aenter__.return_value = mock_killswitch

                result = await manager.login()

                assert result is False
                # JWT token should remain unchanged from initial value
                assert manager.jwt_token == initial_jwt


class TestCustomerDataRetrieval:
    """Test customer data retrieval and parsing."""

    @pytest.mark.asyncio
    async def test_get_customer_details_success(self):
        """Test successful customer details retrieval."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            manager.jwt_token = "test_token"

            with patch.object(manager, '_request') as mock_request, \
                 patch.object(manager, 'ensure_authenticated', return_value=True):
                mock_request.return_value = SAMPLE_CUSTOMER_DETAILS_JSON

                result = await manager.get_customer_details()

                assert result is True
                assert manager.customer_details is not None
                assert manager.customer_details == SAMPLE_CUSTOMER_DETAILS_JSON

    @pytest.mark.asyncio
    async def test_customer_details_populates_battery_registration(self):
        """Test that customer details parsing extracts battery registration."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            manager.jwt_token = "test_token"
            
            with patch.object(manager, '_request') as mock_request, \
                 patch.object(manager, 'ensure_authenticated', return_value=True):
                mock_request.return_value = SAMPLE_CUSTOMER_DETAILS_JSON
                
                await manager.get_customer_details()

                # Verify battery registration was extracted from logbook
                assert manager.battery_registration is not None
                assert isinstance(manager.battery_registration, dict)
                assert "BatterySystem" in manager.battery_registration
                assert "ElectricityCompany" in manager.battery_registration

    @pytest.mark.asyncio
    async def test_customer_details_extracts_fcrd_state(self):
        """Test that customer details parsing extracts FCR-D state from logbook."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            manager.jwt_token = "test_token"
            
            with patch.object(manager, '_request') as mock_request, \
                 patch.object(manager, 'ensure_authenticated', return_value=True):
                mock_request.return_value = SAMPLE_CUSTOMER_DETAILS_JSON
                
                await manager.get_customer_details()

                # Verify FCR-D state was extracted
                assert manager.fcrd_state is not None
                assert manager.fcrd_power is not None
                assert manager.fcrd_timestamp is not None


class TestPropertyAccess:
    """Test property access and their dependencies."""

    @pytest_asyncio.fixture
    async def authenticated_manager(self):
        """Fixture providing an authenticated manager with customer details loaded."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            manager.jwt_token = "test_token"
            
            with patch.object(manager, '_request') as mock_request, \
                 patch.object(manager, 'ensure_authenticated', return_value=True):
                mock_request.return_value = SAMPLE_CUSTOMER_DETAILS_JSON
                
                await manager.get_customer_details()

            yield manager

    @pytest.mark.asyncio
    async def test_customer_properties_after_data_load(self, authenticated_manager):
        """Test customer-related properties work after data is loaded."""
        manager = authenticated_manager

        # These depend on get_customer_details()
        assert manager.registered_owner is not None
        assert "John Doe" in manager.registered_owner
        assert "Test Street 123" in manager.registered_owner

        assert manager.battery_peak_data == (15.0, 15.0, 15.0, 15.0)

        assert manager.battery_make_and_model is not None
        assert "Test Battery System" in manager.battery_make_and_model

        assert manager.electricity_provider is not None
        assert "Test Energy AB" in manager.electricity_provider

    @pytest.mark.asyncio
    async def test_fcrd_properties_after_data_load(self, authenticated_manager):
        """Test FCR-D properties work after customer details are loaded."""
        manager = authenticated_manager

        # FCR-D state properties should be populated from logbook
        assert manager.fcrd_state == "ACTIVATED"
        assert manager.fcrd_power == "10,0/10,0"
        assert manager.fcrd_timestamp == "2025-01-01 00:04:45"
        assert manager.fcrd_percentage_up == "96,5"
        assert manager.fcrd_percentage_down == "106,3"

    def test_properties_fail_without_data(self):
        """Test that properties fail appropriately when data isn't loaded."""
        manager = CheckwattManager("test_user", "test_pass")

        # These should fail before get_customer_details()
        with pytest.raises(TypeError, match="NoneType"):
            _ = manager.registered_owner

        with pytest.raises(TypeError, match="NoneType"):
            _ = manager.battery_make_and_model

        with pytest.raises(AttributeError, match="NoneType"):
            _ = manager.total_solar_energy


class TestEnergyDataRetrieval:
    """Test energy data retrieval and energy property access."""

    @pytest.mark.asyncio
    async def test_get_power_data_success(self):
        """Test successful power data retrieval."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            manager.jwt_token = "test_token"
            manager.customer_details = SAMPLE_CUSTOMER_DETAILS_JSON  # Needed for endpoint building


            with patch.object(manager, '_request') as mock_request, \
                 patch.object(manager, 'ensure_authenticated', return_value=True):
                mock_request.return_value = SAMPLE_POWER_DATA_RESPONSE

                result = await manager.get_power_data()

                assert result is True
                assert manager.power_data is not None
                assert manager.power_data == SAMPLE_POWER_DATA_RESPONSE

    @pytest.mark.asyncio
    async def test_energy_properties_after_power_data_load(self):
        """Test energy properties work after power data is loaded."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            manager.jwt_token = "test_token"
            manager.customer_details = SAMPLE_CUSTOMER_DETAILS_JSON

            with patch.object(manager, '_request') as mock_request, \
                 patch.object(manager, 'ensure_authenticated', return_value=True):
                mock_request.return_value = SAMPLE_POWER_DATA_RESPONSE

                await manager.get_power_data()

                assert manager.total_solar_energy == 11124779.0  # 2848509.0 + 8276270.0
                assert manager.total_charging_energy == 4700000.0  # 1500000.0 + 3200000.0
                assert manager.total_discharging_energy == 4000000.0  # 1200000.0 + 2800000.0
                assert manager.total_import_energy == 8098842.0  # 3104554.0 + 4994288.0
                assert manager.total_export_energy == 8040738.0  # 2899531.0 + 5141207.0


class TestFCRDRevenue:
    """Test FCR-D revenue methods and properties."""

    @pytest.mark.asyncio
    async def test_fcrd_revenue_methods_require_site_id(self):
        """Test that FCR-D revenue methods require RPI serial for site ID lookup."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            manager.jwt_token = "test_token"

            # Without customer details (no RPI serial)
            result = await manager.get_fcrd_today_net_revenue()
            assert result is False

    @pytest.mark.asyncio
    async def test_fcrd_revenue_methods_success(self):
        """Test successful FCR-D revenue retrieval."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            manager.jwt_token = "test_token"

            # Load customer details first (provides RPI serial)
            with patch.object(manager, '_request') as mock_request, \
                 patch.object(manager, 'ensure_authenticated', return_value=True):
                mock_request.return_value = SAMPLE_CUSTOMER_DETAILS_JSON

                await manager.get_customer_details()

            # Mock FCR-D revenue calls
            with patch.object(manager, 'get_site_id', return_value="test_site_123"), \
                 patch.object(manager, '_request') as mock_request, \
                 patch.object(manager, 'ensure_authenticated', return_value=True):

                mock_request.return_value = SAMPLE_FCRD_RESPONSE

                # Test revenue methods
                result = await manager.get_fcrd_today_net_revenue()
                assert result is True

                result = await manager.get_fcrd_year_net_revenue()
                assert result is True

                result = await manager.get_fcrd_month_net_revenue()
                assert result is True

                assert manager.revenue is not None
                assert manager.revenueyear is not None
                assert manager.revenuemonth == 61.44  # Sum of FCR-D revenues: 20.11 + 20.13 + 21.07 + 0.13


class TestEMSSettings:
    """Test EMS settings retrieval."""

    @pytest.mark.asyncio
    async def test_get_ems_settings_success(self):
        """Test successful EMS settings retrieval."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            manager.jwt_token = "test_token"
            manager.customer_details = SAMPLE_CUSTOMER_DETAILS_JSON

            with patch.object(manager, '_request') as mock_request, \
                 patch.object(manager, 'ensure_authenticated', return_value=True):
                mock_request.return_value = SAMPLE_EMS_SETTINGS_RESPONSE

                result = await manager.get_ems_settings()

                assert result is True
                assert manager.ems is not None
                assert manager.ems == SAMPLE_EMS_SETTINGS_RESPONSE





class TestFCRDStateExtraction:
    """Test FCR-D state extraction from logbook entries."""

    def setup_method(self):
        """Set up test fixtures."""
        self.manager = CheckwattManager("test_user", "test_pass")

    def test_fail_activation_with_retry_count_and_complex_power(self):
        """Test parsing of FAIL ACTIVATION entries with retry count and complex power format."""
        log_entry = "[ FCR-D FAIL ACTIVATION ] 54x test@example.com --12345-- 85,9/0,6/97,0 % (10,0/10,0 kW) 2025-04-24 00:02:57 API-BACKEND"
        
        self.manager.logbook_entries = [log_entry]
        self.manager._extract_fcr_d_state()
        
        assert self.manager.fcrd_state == "FAIL ACTIVATION"
        assert self.manager.fcrd_percentage_up == "85,9"
        assert self.manager.fcrd_percentage_response == "0,6"
        assert self.manager.fcrd_percentage_down == "97,0"
        assert self.manager.fcrd_power == "10,0/10,0"
        assert self.manager.fcrd_timestamp == "2025-04-24 00:02:57"

    def test_activated_with_complex_power_format(self):
        """Test parsing of ACTIVATED entries with complex power format."""
        log_entry = "[ FCR-D ACTIVATED ] test@example.com --12345-- 96,5/4,0/106,3 % (10,0/10,0 kW) 2025-08-07 00:04:45 API-BACKEND"
        
        self.manager.logbook_entries = [log_entry]
        self.manager._extract_fcr_d_state()
        
        assert self.manager.fcrd_state == "ACTIVATED"
        assert self.manager.fcrd_percentage_up == "96,5"
        assert self.manager.fcrd_percentage_response == "4,0"
        assert self.manager.fcrd_percentage_down == "106,3"
        assert self.manager.fcrd_power == "10,0/10,0"
        assert self.manager.fcrd_timestamp == "2025-08-07 00:04:45"

    def test_deactivate_with_frequency_up_hz(self):
        """Test parsing of DEACTIVATE entries with UP frequency."""
        log_entry = "[ FCR-D DEACTIVATE ]  UP 49,83 Hz 0,0 %  (10 kW) - 2025-08-06 17:58:07 API-BACKEND"
        
        self.manager.logbook_entries = [log_entry]
        self.manager._extract_fcr_d_state()
        
        assert self.manager.fcrd_state == "DEACTIVATE"
        # For DEACTIVATE, the percentage info goes to fcrd_info
        assert self.manager.fcrd_power == "10"
        assert self.manager.fcrd_timestamp == "2025-08-06 17:58:07"

    def test_multiple_entries_first_match_used(self):
        """Test that only the first matching entry is processed."""
        log_entries = [
            "[ FCR-D ACTIVATED ] test@example.com --12345-- 97,7/0,5/99,3 % (7 kW) 2024-07-07 00:08:19 API-BACKEND",
            "[ FCR-D FAIL ACTIVATION ] 54x test@example.com --12345-- 85,9/0,6/97,0 % (10,0/10,0 kW) 2025-04-24 00:02:57 API-BACKEND",
        ]
        
        self.manager.logbook_entries = log_entries
        self.manager._extract_fcr_d_state()
        
        # Should use the first entry (ACTIVATED)
        assert self.manager.fcrd_state == "ACTIVATED"
        assert self.manager.fcrd_power == "7"
        assert self.manager.fcrd_timestamp == "2024-07-07 00:08:19"
