import os
import sys
from unittest.mock import AsyncMock, Mock, patch

import pytest
import pytest_asyncio

from pycheckwatt import CheckwattManager
from tests.fixtures.sample_responses import (
    SAMPLE_CUSTOMER_DETAILS_JSON,
    SAMPLE_EMS_SETTINGS_RESPONSE,
    SAMPLE_FCRD_RESPONSE,
    SAMPLE_LOGIN_RESPONSE,
    SAMPLE_POWER_DATA_RESPONSE,
)

# Add project root to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


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

            with patch("aiohttp.ClientSession.get") as mock_get:
                # Mock kill switch as enabled (should block login)
                mock_killswitch = AsyncMock()
                mock_killswitch.status = 200
                mock_killswitch.text = AsyncMock(return_value="1")  # Enabled
                mock_get.return_value.__aenter__.return_value = mock_killswitch

                result = await manager.login()

                assert result is False
                assert manager.jwt_token is None


class TestCustomerDataRetrieval:
    """Test customer data retrieval and parsing."""

    @pytest.mark.asyncio
    async def test_get_customer_details_success(self):
        """Test successful customer details retrieval."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            manager.jwt_token = "test_token"

            with patch("aiohttp.ClientSession.get") as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(
                    return_value=SAMPLE_CUSTOMER_DETAILS_JSON
                )
                mock_response.raise_for_status = Mock()
                mock_get.return_value.__aenter__.return_value = mock_response

                result = await manager.get_customer_details()

                assert result is True
                assert manager.customer_details is not None
                assert manager.customer_details == SAMPLE_CUSTOMER_DETAILS_JSON

    @pytest.mark.asyncio
    async def test_customer_details_populates_battery_registration(self):
        """Test that customer details parsing extracts battery registration."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            manager.jwt_token = "test_token"

            with patch("aiohttp.ClientSession.get") as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(
                    return_value=SAMPLE_CUSTOMER_DETAILS_JSON
                )
                mock_response.raise_for_status = Mock()
                mock_get.return_value.__aenter__.return_value = mock_response

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

            with patch("aiohttp.ClientSession.get") as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(
                    return_value=SAMPLE_CUSTOMER_DETAILS_JSON
                )
                mock_response.raise_for_status = Mock()
                mock_get.return_value.__aenter__.return_value = mock_response

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

            with patch("aiohttp.ClientSession.get") as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(
                    return_value=SAMPLE_CUSTOMER_DETAILS_JSON
                )
                mock_response.raise_for_status = Mock()
                mock_get.return_value.__aenter__.return_value = mock_response

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
        assert manager.fcrd_power == "7"
        assert manager.fcrd_timestamp == "2024-07-07 00:08:19"
        assert manager.fcrd_percentage_up == "97,7"
        assert manager.fcrd_percentage_down == "99,3"

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
            manager.customer_details = (
                SAMPLE_CUSTOMER_DETAILS_JSON  # Needed for endpoint building
            )

            with patch("aiohttp.ClientSession.get") as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value=SAMPLE_POWER_DATA_RESPONSE)
                mock_response.raise_for_status = Mock()
                mock_get.return_value.__aenter__.return_value = mock_response

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

            with patch("aiohttp.ClientSession.get") as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value=SAMPLE_POWER_DATA_RESPONSE)
                mock_response.raise_for_status = Mock()
                mock_get.return_value.__aenter__.return_value = mock_response

                await manager.get_power_data()

                # Test energy properties with sums of all measurements
                assert manager.total_solar_energy == 11124779.0  # 2848509.0 + 8276270.0
                assert manager.total_import_energy == 8098842.0  # 3104554.0 + 4994288.0
                assert manager.total_export_energy == 8040738.0  # 2899531.0 + 5141207.0

                solar_kwh = manager.total_solar_energy / 1000
                assert solar_kwh == 11124.779


class TestFCRDRevenue:
    """Test FCR-D revenue methods and properties."""

    @pytest.mark.asyncio
    async def test_fcrd_revenue_methods_require_site_id(self):
        """Test that FCR-D revenue methods require RPI serial for site ID lookup."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            manager.jwt_token = "test_token"

            # Without customer details (no RPI serial)
            with pytest.raises(ValueError, match="RPI serial not available"):
                await manager.get_fcrd_today_net_revenue()

    @pytest.mark.asyncio
    async def test_fcrd_revenue_methods_success(self):
        """Test successful FCR-D revenue retrieval."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            manager.jwt_token = "test_token"

            # Load customer details first (provides RPI serial)
            with patch("aiohttp.ClientSession.get") as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(
                    return_value=SAMPLE_CUSTOMER_DETAILS_JSON
                )
                mock_response.raise_for_status = Mock()
                mock_get.return_value.__aenter__.return_value = mock_response

                await manager.get_customer_details()

            # Mock FCR-D revenue calls
            with patch.object(
                manager, "get_site_id", return_value="test_site_123"
            ), patch("aiohttp.ClientSession.get") as mock_get:

                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value=SAMPLE_FCRD_RESPONSE)
                mock_response.raise_for_status = Mock()
                mock_get.return_value.__aenter__.return_value = mock_response

                # Test revenue methods
                result = await manager.get_fcrd_today_net_revenue()
                assert result is True

                result = await manager.get_fcrd_month_net_revenue()
                assert result is True

                result = await manager.get_fcrd_year_net_revenue()
                assert result is True


class TestEMSSettings:
    """Test EMS settings retrieval."""

    @pytest.mark.asyncio
    async def test_get_ems_settings_success(self):
        """Test successful EMS settings retrieval."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            manager.jwt_token = "test_token"
            manager.customer_details = SAMPLE_CUSTOMER_DETAILS_JSON

            with patch("aiohttp.ClientSession.get") as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(
                    return_value=SAMPLE_EMS_SETTINGS_RESPONSE
                )
                mock_response.raise_for_status = Mock()
                mock_get.return_value.__aenter__.return_value = mock_response

                result = await manager.get_ems_settings()

                assert result is True
                assert manager.ems is not None
                assert manager.ems == SAMPLE_EMS_SETTINGS_RESPONSE
                assert manager.ems_settings == "Currently optimized (CO)"


class TestCompleteWorkflow:
    """Test the complete workflow."""

    @pytest.mark.asyncio
    async def test_example_py_workflow(self):
        """Test the complete happy path workflow."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            # Step 1: Login
            with patch("aiohttp.ClientSession.post") as mock_post, patch(
                "aiohttp.ClientSession.get"
            ) as mock_get_ks:

                mock_killswitch = AsyncMock()
                mock_killswitch.status = 200
                mock_killswitch.text = AsyncMock(return_value="0")
                mock_get_ks.return_value.__aenter__.return_value = mock_killswitch

                mock_login = AsyncMock()
                mock_login.status = 200
                mock_login.json = AsyncMock(return_value=SAMPLE_LOGIN_RESPONSE)
                mock_post.return_value.__aenter__.return_value = mock_login

                login_result = await manager.login()
                assert login_result is True

            # Step 2: Get customer details
            with patch("aiohttp.ClientSession.get") as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(
                    return_value=SAMPLE_CUSTOMER_DETAILS_JSON
                )
                mock_response.raise_for_status = Mock()
                mock_get.return_value.__aenter__.return_value = mock_response

                await manager.get_customer_details()

            # Step 3: Get FCR-D revenue data
            with patch.object(manager, "get_site_id", return_value="test_site"), patch(
                "aiohttp.ClientSession.get"
            ) as mock_get:

                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value=SAMPLE_FCRD_RESPONSE)
                mock_response.raise_for_status = Mock()
                mock_get.return_value.__aenter__.return_value = mock_response

                await manager.get_fcrd_today_net_revenue()
                await manager.get_fcrd_year_net_revenue()
                await manager.get_fcrd_month_net_revenue()

            # Step 4: Get EMS settings
            with patch("aiohttp.ClientSession.get") as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(
                    return_value=SAMPLE_EMS_SETTINGS_RESPONSE
                )
                mock_response.raise_for_status = Mock()
                mock_get.return_value.__aenter__.return_value = mock_response

                await manager.get_ems_settings()

            # Step 5: Get power data
            with patch("aiohttp.ClientSession.get") as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value=SAMPLE_POWER_DATA_RESPONSE)
                mock_response.raise_for_status = Mock()
                mock_get.return_value.__aenter__.return_value = mock_response

                await manager.get_power_data()

            # Verify all properties used in example.py work
            assert manager.registered_owner is not None
            assert manager.battery_peak_data == (15.0, 15.0, 15.0, 15.0)
            assert manager.battery_make_and_model is not None
            assert manager.electricity_provider is not None
            assert manager.fcrd_state == "ACTIVATED"
            assert manager.ems_settings == "Currently optimized (CO)"
            assert manager.total_solar_energy == 11124779.0
            assert manager.total_export_energy == 8040738.0


class TestMethodCallDependencies:
    """Test and document method call order dependencies."""

    @pytest.mark.asyncio
    async def test_customer_properties_require_get_customer_details(self):
        """Test that customer properties require get_customer_details()
        to be called first."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            # Before get_customer_details()
            with pytest.raises((TypeError, AttributeError)):
                _ = manager.registered_owner

            # After get_customer_details()
            manager.jwt_token = "test_token"
            with patch("aiohttp.ClientSession.get") as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(
                    return_value=SAMPLE_CUSTOMER_DETAILS_JSON
                )
                mock_response.raise_for_status = Mock()
                mock_get.return_value.__aenter__.return_value = mock_response

                await manager.get_customer_details()

            assert manager.registered_owner is not None

    @pytest.mark.asyncio
    async def test_energy_properties_require_get_power_data(self):
        """Test that energy properties require get_power_data() to be called first."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            # Before get_power_data()
            with pytest.raises(AttributeError):
                _ = manager.total_solar_energy

            # After get_power_data()
            manager.jwt_token = "test_token"
            manager.customer_details = SAMPLE_CUSTOMER_DETAILS_JSON

            with patch("aiohttp.ClientSession.get") as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value=SAMPLE_POWER_DATA_RESPONSE)
                mock_response.raise_for_status = Mock()
                mock_get.return_value.__aenter__.return_value = mock_response

                await manager.get_power_data()

            assert manager.total_solar_energy == 11124779.0  # Sum of all measurements

    @pytest.mark.asyncio
    async def test_ems_settings_property_requires_get_ems_settings(self):
        """Test that ems_settings property requires get_ems_settings()
        to be called first."""
        async with CheckwattManager("test_user", "test_pass") as manager:

            # Before get_ems_settings()
            with pytest.raises(TypeError):
                _ = manager.ems_settings

            # After get_ems_settings()
            manager.jwt_token = "test_token"
            manager.customer_details = SAMPLE_CUSTOMER_DETAILS_JSON

            with patch("aiohttp.ClientSession.get") as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(
                    return_value=SAMPLE_EMS_SETTINGS_RESPONSE
                )
                mock_response.raise_for_status = Mock()
                mock_get.return_value.__aenter__.return_value = mock_response

                await manager.get_ems_settings()

            assert manager.ems_settings == "Currently optimized (CO)"
