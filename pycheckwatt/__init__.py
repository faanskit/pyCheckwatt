"""
CheckwattManager module.
This module defines the CheckwattManager class, providing an interface for interacting
with the Checkwatt API to retrieve and manage power-related data.
Usage:
    To use this module, instantiate the CheckwattManager class with the required
    authentication credentials. Use the various methods and attributes to interact
    with the Checkwatt API and access power-related information.
Example:
    ```
    from checkwatt_manager import CheckwattManager
    # Instantiate the CheckwattManager class
    checkwatt_manager = CheckwattManager(username='your_username',
                                         password='your_password')
    # Access power-related data
    power_data = checkwatt_manager.power_data
    # Perform other operations as needed
    ```
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import random
import re
from datetime import date, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Optional, Union

from aiohttp import ClientError, ClientResponseError, ClientSession
from dateutil.relativedelta import relativedelta

_LOGGER = logging.getLogger(__name__)


class CheckwattManager:
    """CheckWatt manager."""

    def __init__(
        self, 
        username, 
        password, 
        application="pyCheckwatt",
        *,
        max_retries_429: int = 3,
        backoff_base: float = 0.5,
        backoff_factor: float = 2.0,
        backoff_max: float = 30.0,
        clock_skew_seconds: int = 10,
        max_concurrent_requests: int = 5,
        killswitch_ttl_seconds: int = 900,
        enhanced_error_logging: bool = True,
        error_log_level: int = logging.ERROR
    ) -> None:
        """Initialize the CheckWatt manager."""
        if username is None or password is None:
            raise ValueError("Username and password must be provided.")
        
        # Core session and configuration
        self.session = None
        self.base_url = "https://api.checkwatt.se"
        self.username = username
        self.password = password
        self.header_identifier = application
        
        # Authentication state
        self.jwt_token = None
        self.refresh_token = None
        self.refresh_token_expires = None
        
        # Concurrency control
        self._auth_lock = asyncio.Lock()
        self._req_semaphore = asyncio.Semaphore(max_concurrent_requests)
        
        # Configuration knobs
        self.max_retries_429 = max_retries_429
        self.backoff_base = backoff_base
        self.backoff_factor = backoff_factor
        self.backoff_max = backoff_max
        self.clock_skew_seconds = clock_skew_seconds
        self.max_concurrent_requests = max_concurrent_requests
        self.killswitch_ttl_seconds = killswitch_ttl_seconds
        
        # Enhanced error logging configuration
        self.enhanced_error_logging = enhanced_error_logging
        self.error_log_level = error_log_level
        
        # Kill-switch cache
        self._killswitch_cache = {"enabled": None, "last_check": 0}
        
        # Data properties (existing)
        self.dailyaverage = 0
        self.monthestimate = 0
        self.revenue = None
        self.revenueyear = None
        self.revenueyeartotal = 0
        self.revenuemonth = 0
        self.customer_details = None
        self.battery_registration = None
        self.battery_charge_peak_ac = None
        self.battery_charge_peak_dc = None
        self.battery_discharge_peak_ac = None
        self.battery_discharge_peak_dc = None
        self.logbook_entries = None
        self.comments = None
        self.fcrd_state = None
        self.fcrd_info = None
        self.fcrd_percentage_up = None
        self.fcrd_percentage_response = None
        self.fcrd_percentage_down = None
        self.fcrd_power = None
        self.fcrd_timestamp = None
        self.power_data = None
        self.price_zone = None
        self.spot_prices = None
        self.energy_data = None
        self.rpi_data = None
        self.meter_data = None
        self.display_name = None
        self.reseller_id = None
        self.energy_provider_id = None
        self.month_peak_effect = None
        self.ems = None
        self.site_id = None

    async def __aenter__(self):
        """Asynchronous enter."""
        self.session = ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        """Asynchronous exit."""
        await self.session.close()

    def _get_headers(self):
        """Define common headers."""

        return {
            "accept": "application/json, text/plain, */*",
            "accept-language": "sv-SE,sv;q=0.9,en-SE;q=0.8,en;q=0.7,en-US;q=0.6",
            "content-type": "application/json",
            "sec-ch-ua": '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',  # noqa: E501
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
            "wslog-os": "",
            "wslog-platform": "controlpanel",
            "X-pyCheckwatt-Application": self.header_identifier,
        }

    def _jwt_is_valid(self) -> bool:
        """Check if JWT token is valid and not expiring soon."""
        if not self.jwt_token:
            return False
        
        try:
            # Simple JWT expiration check - decode the payload part
            parts = self.jwt_token.split('.')
            if len(parts) != 3:
                return False
            
            # Decode the payload (second part)
            payload = base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8')
            claims = json.loads(payload)
            
            exp = claims.get('exp')
            if not exp:
                return False
            
            # Check if token expires within clock skew
            now = datetime.utcnow().timestamp()
            return now < (exp - self.clock_skew_seconds)
            
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError, TypeError):
            # If we can't decode, treat as unknown validity
            return False

    def _refresh_is_valid(self) -> bool:
        """Check if refresh token is valid and not expired."""
        if not self.refresh_token or not self.refresh_token_expires:
            return False
        
        try:
            # Parse the expiration timestamp
            expires = datetime.fromisoformat(self.refresh_token_expires.replace('Z', '+00:00'))
            now = datetime.now(expires.tzinfo) if expires.tzinfo else datetime.utcnow()
            
            # Add some buffer (5 minutes) to avoid edge cases
            return now < (expires - timedelta(minutes=5))
            
        except (ValueError, TypeError):
            # If we can't parse, treat as unknown validity
            return False

    async def _refresh(self) -> bool:
        """Refresh the JWT token using the refresh token."""
        if not self.refresh_token:
            return False
        
        try:
            endpoint = "/user/RefreshToken?audience=eib"
            headers = {
                **self._get_headers(),
                "authorization": f"RefreshToken {self.refresh_token}",
            }
            
            async with self.session.get(
                self.base_url + endpoint, 
                headers=headers,
                timeout=10
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Update tokens
                    self.jwt_token = data.get("JwtToken")
                    if "RefreshToken" in data:
                        self.refresh_token = data.get("RefreshToken")
                    if "RefreshTokenExpires" in data:
                        self.refresh_token_expires = data.get("RefreshTokenExpires")
                    
                    _LOGGER.info("Successfully refreshed JWT token")
                    return True
                
                elif response.status == 401:
                    _LOGGER.warning("Refresh token expired or invalid")
                    return False
                
                else:
                    _LOGGER.error("Unexpected status code during refresh: %d", response.status)
                    return False
                    
        except (ClientResponseError, ClientError) as error:
            _LOGGER.error("Error during token refresh: %s", error)
            return False

    async def _ensure_token(self) -> bool:
        """Ensure we have a valid JWT token, refreshing or logging in if needed."""
        # Quick check without lock
        if self.jwt_token and self._jwt_is_valid():
            return True
        
        # Need to acquire lock for auth operations
        async with self._auth_lock:
            # Double-check after acquiring lock
            if self.jwt_token and self._jwt_is_valid():
                return True
            
            # Try refresh first
            if self.refresh_token and self._refresh_is_valid():
                if await self._refresh():
                    return True
            
            # Fall back to login
            _LOGGER.info("Performing password login")
            return await self.login()

    def _get_calling_method_name(self) -> Optional[str]:
        """Get the name of the calling method for enhanced error logging."""
        if not self.enhanced_error_logging:
            return None
        
        try:
            import inspect
            # Get the call stack and find the first method that's not internal
            frame = inspect.currentframe()
            while frame:
                frame = frame.f_back
                if frame and frame.f_code.co_name in [
                    '_request', 'handle_client_error', '_get_calling_method_name'
                ]:
                    continue
                if frame and frame.f_code.co_name.startswith('_'):
                    continue
                if frame and frame.f_code.co_name in [
                    'get_customer_details', 'get_site_id', 'get_fcrd_month_net_revenue',
                    'get_fcrd_today_net_revenue', 'get_fcrd_year_net_revenue',
                    'fetch_and_return_net_revenue', 'get_power_data', 'get_energy_flow',
                    'get_ems_settings', 'get_price_zone', 'get_spot_price',
                    'get_battery_month_peak_effect', 'get_energy_trading_company',
                    'get_rpi_data', 'get_meter_status'
                ]:
                    return frame.f_code.co_name
                if frame:
                    frame = frame.f_back
        except Exception:
            # If we can't determine the method name, fall back to None
            pass
        
        return None

    async def _request(
        self, 
        method: str, 
        endpoint: str, 
        *, 
        headers: Optional[Dict[str, str]] = None,
        auth_required: bool = True,
        retry_on_401: bool = True,
        retry_on_429: bool = True,
        timeout: int = 10,
        method_name: Optional[str] = None,
        **kwargs
    ) -> Union[Dict[str, Any], str, bool, None]:
        """
        Centralized request wrapper with authentication and retry logic.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            headers: Additional headers to merge with common headers
            auth_required: Whether authentication is required
            retry_on_401: Whether to retry on 401 (with refresh/login)
            retry_on_429: Whether to retry on 429 (with backoff)
            timeout: Request timeout in seconds
            method_name: Name of the calling API method for enhanced error logging
            **kwargs: Additional arguments for the request
            
        Returns:
            Response data (dict for JSON, str for text) or boolean for success/failure
        """
        # Ensure we have a valid token if auth is required
        if auth_required:
            if not await self._ensure_token():
                return False
        
        # Auto-detect method name if not provided
        if method_name is None:
            method_name = self._get_calling_method_name()
        
        # Prepare headers
        final_headers = {**self._get_headers(), **(headers or {})}
        if auth_required and self.jwt_token:
            final_headers["authorization"] = f"Bearer {self.jwt_token}"
        
        # Remove sensitive headers from logging
        safe_headers = {k: v for k, v in final_headers.items() 
                       if k.lower() not in ['authorization', 'cookie']}
        
        # Apply concurrency control
        async with self._req_semaphore:
            # Perform request with retry logic
            for attempt in range(self.max_retries_429 + 1):
                try:
                    _LOGGER.debug("Making %s request to %s (attempt %d)", 
                                 method, endpoint, attempt + 1)
                    
                    async with self.session.request(
                        method,
                        self.base_url + endpoint,
                        headers=final_headers,
                        timeout=timeout,
                        **kwargs
                    ) as response:
                        # Handle 401 (Unauthorized)
                        if response.status == 401 and retry_on_401 and auth_required:
                            _LOGGER.warning("Received 401, attempting token refresh")
                            
                            # Try refresh first
                            if await self._refresh():
                                # Retry the original request once
                                continue
                            
                            # If refresh failed, try login
                            _LOGGER.warning("Refresh failed, attempting login")
                            if await self.login():
                                # Retry the original request once
                                continue
                            
                            # Both refresh and login failed
                            _LOGGER.error("Authentication failed after refresh and login attempts")
                            return False
                        
                        # Handle 429 (Too Many Requests)
                        if response.status == 429 and retry_on_429 and attempt < self.max_retries_429:
                            retry_after = response.headers.get('Retry-After')
                            
                            if retry_after:
                                try:
                                    # Try to parse as seconds
                                    wait_time = int(retry_after)
                                except ValueError:
                                    try:
                                        # Try to parse as HTTP date
                                        retry_date = parsedate_to_datetime(retry_after)
                                        wait_time = (retry_date - datetime.utcnow()).total_seconds()
                                        wait_time = max(0, wait_time)
                                    except (ValueError, TypeError):
                                        wait_time = self.backoff_base
                            else:
                                # Use exponential backoff with jitter
                                wait_time = min(
                                    self.backoff_base * (self.backoff_factor ** attempt),
                                    self.backoff_max
                                )
                                # Add jitter (0 to 0.25s)
                                wait_time += random.uniform(0, 0.25)
                            
                            # Enhanced logging for rate limiting
                            if self.enhanced_error_logging and method_name:
                                _LOGGER.log(
                                    self.error_log_level,
                                    "API call '%s' rate limited (HTTP 429 Too Many Requests), "
                                    "waiting %.2f seconds before retry %d/%d",
                                    method_name, wait_time, attempt + 1, self.max_retries_429 + 1
                                )
                            else:
                                _LOGGER.info("Rate limited (429), waiting %.2f seconds before retry", wait_time)
                            
                            await asyncio.sleep(wait_time)
                            continue
                        
                        # Handle other status codes
                        response.raise_for_status()
                        
                        # Parse response based on content type
                        content_type = response.headers.get('Content-Type', '').lower()
                        
                        if 'application/json' in content_type:
                            return await response.json()
                        else:
                            return await response.text()
                            
                except ClientResponseError as e:
                    if e.status == 401 and retry_on_401 and auth_required:
                        # This will be handled in the next iteration
                        continue
                    elif e.status == 429 and retry_on_429 and attempt < self.max_retries_429:
                        # This will be handled in the next iteration
                        continue
                    else:
                        # Enhanced error logging for HTTP errors
                        if self.enhanced_error_logging and method_name:
                            _LOGGER.log(
                                self.error_log_level,
                                "API call '%s' failed: HTTP %d %s",
                                method_name, e.status, e.message or "Unknown Error"
                            )
                        else:
                            _LOGGER.error("Request failed with status %d: %s", e.status, e)
                        
                        return await self.handle_client_error(endpoint, safe_headers, e)
                        
                except (ClientError, asyncio.TimeoutError) as error:
                    # Enhanced error logging for network/connection errors
                    if self.enhanced_error_logging and method_name:
                        _LOGGER.log(
                            self.error_log_level,
                            "API call '%s' failed: %s",
                            method_name, error
                        )
                    else:
                        _LOGGER.error("Request failed: %s", error)
                    
                    return await self.handle_client_error(endpoint, safe_headers, error)
            
            # If we get here, we've exhausted all retries
            if self.enhanced_error_logging and method_name:
                _LOGGER.log(
                    self.error_log_level,
                    "API call '%s' failed after %d attempts",
                    method_name, self.max_retries_429 + 1
                )
            else:
                _LOGGER.error("Request failed after %d attempts", self.max_retries_429 + 1)
            return False

    async def _continue_kill_switch_not_enabled(self):
        """Check if CheckWatt has requested integrations to back-off."""
        now = datetime.utcnow().timestamp()
        
        # Check cache first
        if (self._killswitch_cache["enabled"] is not None and 
            now - self._killswitch_cache["last_check"] < self.killswitch_ttl_seconds):
            return self._killswitch_cache["enabled"]
        
        try:
            url = "https://checkwatt.se/ha-killswitch.txt"
            headers = {**self._get_headers()}
            
            async with self.session.get(url, headers=headers) as response:
                data = await response.text()
                if response.status == 200:
                    kill = data.strip()  # Remove leading and trailing whitespaces
                    enabled = kill == "0"
                    
                    # Update cache
                    self._killswitch_cache["enabled"] = enabled
                    self._killswitch_cache["last_check"] = now
                    
                    if enabled:
                        _LOGGER.debug("CheckWatt accepted and not enabled the kill-switch")
                    else:
                        _LOGGER.error("CheckWatt has requested to back down by enabling the kill-switch")
                    
                    return enabled

                if response.status == 401:
                    _LOGGER.error("Unauthorized: Check your CheckWatt authentication credentials")
                    return False

                _LOGGER.error("Unexpected HTTP status code: %s", response.status)
                return False

        except (ClientResponseError, ClientError) as error:
            return await self.handle_client_error(url, headers, error)

    async def handle_client_error(self, endpoint, headers, error):
        """Handle ClientError and log relevant information."""
        # Remove sensitive headers from logging
        safe_headers = {k: v for k, v in headers.items() 
                       if k.lower() not in ['authorization', 'cookie']}
        
        # Auto-detect method name for enhanced error logging
        method_name = self._get_calling_method_name()
        
        # Enhanced error logging with method identification
        if self.enhanced_error_logging and method_name:
            # Extract HTTP status code and reason if available
            if hasattr(error, 'status'):
                status_code = error.status
                reason_phrase = getattr(error, 'message', 'Unknown Error')
                _LOGGER.log(
                    self.error_log_level,
                    "API call '%s' failed: HTTP %d %s - URL: %s",
                    method_name, status_code, reason_phrase, self.base_url + endpoint
                )
            else:
                _LOGGER.log(
                    self.error_log_level,
                    "API call '%s' failed: %s - URL: %s",
                    method_name, error, self.base_url + endpoint
                )
        else:
            _LOGGER.error(
                "An error occurred during the request. URL: %s, Headers: %s. Error: %s",
                self.base_url + endpoint,
                safe_headers,
                error,
            )
        return False

    async def login(self):
        """Login to CheckWatt."""
        try:
            if not await self._continue_kill_switch_not_enabled():
                # CheckWatt want us to back down.
                return False
            _LOGGER.debug("Kill-switch not enabled, continue")

            credentials = f"{self.username}:{self.password}"
            encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode(
                "utf-8"
            )
            endpoint = "/user/Login?audience=eib"
            # Define headers with the encoded credentials
            headers = {
                **self._get_headers(),
                "authorization": f"Basic {encoded_credentials}",
            }
            payload = {
                "OneTimePassword": "",
            }

            timeout_seconds = 10
            try:
                async with self.session.post(
                    self.base_url + endpoint,
                    headers=headers,
                    json=payload,
                    timeout=timeout_seconds,
                ) as response:
                    data = await response.json()
                    if response.status == 200:
                        self.jwt_token = data.get("JwtToken")
                        self.refresh_token = data.get("RefreshToken")
                        self.refresh_token_expires = data.get("RefreshTokenExpires")
                        _LOGGER.info("Successfully logged in to CheckWatt")
                        return True

                    if response.status == 401:
                        if self.enhanced_error_logging:
                            _LOGGER.log(
                                self.error_log_level,
                                "API call 'login' failed: HTTP 401 Unauthorized"
                            )
                        else:
                            _LOGGER.error(
                                "Unauthorized: Check your CheckWatt authentication credentials"
                            )
                        return False

                    if response.status == 429:
                        if self.enhanced_error_logging:
                            _LOGGER.log(
                                self.error_log_level,
                                "API call 'login' rate limited: HTTP 429 Too Many Requests"
                            )
                        else:
                            _LOGGER.error("Rate limited: HTTP 429 Too Many Requests")
                        return False

                    if self.enhanced_error_logging:
                        _LOGGER.log(
                            self.error_log_level,
                            "API call 'login' failed: HTTP %d Unknown Error",
                            response.status
                        )
                    else:
                        _LOGGER.error("Unexpected HTTP status code: %s", response.status)
                    return False

            except (ClientResponseError, ClientError) as error:
                if self.enhanced_error_logging:
                    if hasattr(error, 'status'):
                        _LOGGER.log(
                            self.error_log_level,
                            "API call 'login' failed: HTTP %d %s",
                            error.status, getattr(error, 'message', 'Unknown Error')
                        )
                    else:
                        _LOGGER.log(
                            self.error_log_level,
                            "API call 'login' failed: %s",
                            error
                        )
                return await self.handle_client_error(endpoint, headers, error)
            except asyncio.TimeoutError as error:
                if self.enhanced_error_logging:
                    _LOGGER.log(
                        self.error_log_level,
                        "API call 'login' failed: %s",
                        error
                    )
                return await self.handle_client_error(endpoint, headers, error)
            except Exception as error:
                if self.enhanced_error_logging:
                    _LOGGER.log(
                        self.error_log_level,
                        "API call 'login' failed: %s",
                        error
                    )
                return await self.handle_client_error(endpoint, headers, error)

        except Exception as error:
            if self.enhanced_error_logging:
                _LOGGER.log(
                    self.error_log_level,
                    "API call 'login' failed: %s",
                    error
                )
            return await self.handle_client_error(endpoint, headers, error)

    async def get_customer_details(self):
        """Fetch customer details from CheckWatt."""
        try:
            endpoint = "/controlpanel/CustomerDetail"
            
            result = await self._request("GET", endpoint, auth_required=True)
            if result is False:
                return False
            
            self.customer_details = result

            meters = self.customer_details.get("Meter", [])
            if meters:
                soc_meter = next(
                    (
                        meter
                        for meter in meters
                        if meter.get("InstallationType") == "SoC"
                    ),
                    None,
                )

                if not soc_meter:
                    _LOGGER.error("No SoC meter found")
                    return False

                self.display_name = soc_meter.get("DisplayName")
                self.reseller_id = soc_meter.get("ResellerId")
                self.energy_provider_id = soc_meter.get("ElhandelsbolagId")
                self.comments = soc_meter.get("Comments")
                logbook = soc_meter.get("Logbook")
                if logbook:
                    (
                        self.battery_registration,
                        self.logbook_entries,
                    ) = self._extract_content_and_logbook(logbook)
                    self._extract_fcr_d_state()

                charging_meter = next(
                    (
                        meter
                        for meter in meters
                        if meter.get("InstallationType") == "Charging"
                    ),
                    None,
                )
                if charging_meter:
                    self.battery_charge_peak_ac = charging_meter.get("PeakAcKw")
                    self.battery_charge_peak_dc = charging_meter.get("PeakDcKw")

                discharge_meter = next(
                    (
                        meter
                        for meter in meters
                        if meter.get("InstallationType") == "Discharging"
                    ),
                    None,
                )
                if discharge_meter:
                    self.battery_discharge_peak_ac = discharge_meter.get(
                        "PeakAcKw"
                    )
                    self.battery_discharge_peak_dc = discharge_meter.get(
                        "PeakDcKw"
                    )

            return True

        except Exception as error:
            _LOGGER.error("Error in get_customer_details: %s", error)
            return False

    async def get_site_id(self):
        """Get site ID from RPI serial number."""
        if self.site_id is not None:
            return self.site_id

        if self.rpi_serial is None:
            raise ValueError(
                "RPI serial not available. Call get_customer_details() first."
            )

        try:
            endpoint = f"/Site/SiteIdBySerial?serial={self.rpi_serial}"
            
            result = await self._request("GET", endpoint, auth_required=True)
            if result is False:
                return False
            
            if isinstance(result, dict) and "SiteId" in result:
                self.site_id = str(result["SiteId"])
                _LOGGER.debug("Successfully extracted site ID: %s", self.site_id)
                return self.site_id
            
            _LOGGER.error("Unexpected response format for site ID: %s", result)
            return False

        except Exception as error:
            _LOGGER.error("Error in get_site_id: %s", error)
            return False

    async def debug_revenue_workflow(self):
        """Debug method to diagnose revenue workflow issues."""
        _LOGGER.info("=== Revenue Workflow Debug ===")
        _LOGGER.info("Customer details loaded: %s", self.customer_details is not None)
        _LOGGER.info("RPI data loaded: %s", self.rpi_data is not None)
        _LOGGER.info("Site ID cached: %s", self.site_id)
        
        if self.customer_details:
            meters = self.customer_details.get("Meter", [])
            _LOGGER.info("Number of meters: %d", len(meters))
            for i, meter in enumerate(meters):
                _LOGGER.info("Meter %d: Type=%s, RpiSerial=%s", 
                            i, meter.get("InstallationType"), meter.get("RpiSerial"))
        
        rpi_serial = self.rpi_serial
        _LOGGER.info("RPI Serial: %s", rpi_serial)
        
        if rpi_serial:
            _LOGGER.info("Attempting to get site ID...")
            site_id = await self.get_site_id()
            _LOGGER.info("Site ID result: %s", site_id)
        else:
            _LOGGER.error("Cannot get site ID - RPI serial is None")
        
        _LOGGER.info("=== End Debug ===")

    async def get_fcrd_month_net_revenue(self):
        """Fetch FCR-D revenues from CheckWatt."""
        misseddays = 0
        try:
            site_id = await self.get_site_id()
            if site_id is False:
                _LOGGER.error("Failed to get site ID for FCR-D month revenue")
                return False
            
            if not site_id:
                _LOGGER.error("Site ID is empty or None for FCR-D month revenue")
                return False
                
            _LOGGER.debug("Using site ID %s for FCR-D month revenue", site_id)
            
            from_date = datetime.now().strftime("%Y-%m-01")
            to_date = datetime.now() + timedelta(days=1)
            to_date = to_date.strftime("%Y-%m-%d")
            lastday_date = datetime.now() + relativedelta(months=1)
            lastday_date = datetime(
                year=lastday_date.year, month=lastday_date.month, day=1
            )

            lastday_date = lastday_date - timedelta(days=1)

            lastday = lastday_date.strftime("%d")

            dayssofar = datetime.now()
            dayssofar = dayssofar.strftime("%d")

            daysleft = int(lastday) - int(dayssofar)
            endpoint = (
                f"/revenue/{site_id}?from={from_date}&to={to_date}&resolution=day"
            )
            _LOGGER.debug("FCR-D month revenue endpoint: %s", endpoint)

            result = await self._request("GET", endpoint, auth_required=True)
            if result is False:
                _LOGGER.error("Failed to retrieve FCR-D month revenue from endpoint: %s", endpoint)
                return False
            
            revenue = result
            for each in revenue["Revenue"]:
                self.revenuemonth += each["NetRevenue"]
                if each["NetRevenue"] == 0:
                    misseddays += 1
            dayswithmoney = int(dayssofar) - int(misseddays)
            
            if dayswithmoney > 0:
                self.dailyaverage = self.revenuemonth / int(dayswithmoney)
            else:
                self.dailyaverage = 0
            self.monthestimate = (
                self.dailyaverage * daysleft
            ) + self.revenuemonth
            _LOGGER.info("Successfully retrieved FCR-D month revenue")
            return True

        except Exception as error:
            _LOGGER.error("Error in get_fcrd_month_net_revenue: %s", error)
            return False

    async def get_fcrd_today_net_revenue(self):
        """Fetch FCR-D revenues from CheckWatt."""
        try:
            site_id = await self.get_site_id()
            if site_id is False:
                _LOGGER.error("Failed to get site ID for FCR-D today revenue")
                return False
            
            if not site_id:
                _LOGGER.error("Site ID is empty or None for FCR-D today revenue")
                return False
                
            _LOGGER.debug("Using site ID %s for FCR-D today revenue", site_id)
            
            from_date = datetime.now().strftime("%Y-%m-%d")
            end_date = datetime.now() + timedelta(days=2)
            to_date = end_date.strftime("%Y-%m-%d")

            endpoint = (
                f"/revenue/{site_id}?from={from_date}&to={to_date}&resolution=day"
            )
            _LOGGER.debug("FCR-D today revenue endpoint: %s", endpoint)

            result = await self._request("GET", endpoint, auth_required=True)
            if result is False:
                _LOGGER.error("Failed to retrieve FCR-D today revenue from endpoint: %s", endpoint)
                return False
            
            self.revenue = result
            _LOGGER.info("Successfully retrieved FCR-D today revenue")
            return True

        except Exception as error:
            _LOGGER.error("Error in get_fcrd_today_net_revenue: %s", error)
            return False

    async def get_fcrd_year_net_revenue(self):
        """Fetch FCR-D revenues from CheckWatt."""
        site_id = await self.get_site_id()
        if site_id is False:
            _LOGGER.error("Failed to get site ID for FCR-D year revenue")
            return False
        
        if not site_id:
            _LOGGER.error("Site ID is empty or None for FCR-D year revenue")
            return False
            
        _LOGGER.debug("Using site ID %s for FCR-D year revenue", site_id)
        
        yesterday_date = datetime.now() + timedelta(days=1)
        yesterday_date = yesterday_date.strftime("-%m-%d")
        months = ["-01-01", "-06-30", "-07-01", yesterday_date]
        loop = 0
        retval = False
        if yesterday_date <= "-07-01":
            try:
                year_date = datetime.now().strftime("%Y")
                to_date = year_date + yesterday_date
                from_date = year_date + "-01-01"
                endpoint = (
                    f"/revenue/{site_id}?from={from_date}&to={to_date}&resolution=day"
                )
                _LOGGER.debug("FCR-D year revenue endpoint (first half): %s", endpoint)
                
                result = await self._request("GET", endpoint, auth_required=True)
                if result is False:
                    _LOGGER.error("Failed to retrieve FCR-D year revenue from endpoint: %s", endpoint)
                    return False
                
                self.revenueyear = result
                for each in self.revenueyear["Revenue"]:
                    self.revenueyeartotal += each["NetRevenue"]
                retval = True
                _LOGGER.info("Successfully retrieved FCR-D year revenue (first half)")
                return retval

            except Exception as error:
                _LOGGER.error("Error in get_fcrd_year_net_revenue (first half): %s", error)
                return False
        else:
            try:
                while loop < 3:
                    year_date = datetime.now().strftime("%Y")
                    to_date = year_date + months[loop + 1]
                    from_date = year_date + months[loop]
                    endpoint = f"/revenue/{site_id}?from={from_date}&to={to_date}&resolution=day"
                    _LOGGER.debug("FCR-D year revenue endpoint (period %d): %s", loop, endpoint)
                    
                    result = await self._request("GET", endpoint, auth_required=True)
                    if result is False:
                        _LOGGER.error("Failed to retrieve FCR-D year revenue from endpoint: %s", endpoint)
                        return False
                    
                    self.revenueyear = result
                    for each in self.revenueyear["Revenue"]:
                        self.revenueyeartotal += each["NetRevenue"]
                    loop += 2
                    retval = True
                    
                _LOGGER.info("Successfully retrieved FCR-D year revenue (multiple periods)")
                return retval

            except Exception as error:
                _LOGGER.error("Error in get_fcrd_year_net_revenue (multiple periods): %s", error)
                return False

    async def fetch_and_return_net_revenue(self, from_date, to_date):
        """Fetch FCR-D revenues from CheckWatt as per provided range."""
        try:
            site_id = await self.get_site_id()
            if site_id is False:
                _LOGGER.error("Failed to get site ID for custom revenue range")
                return None
            
            if not site_id:
                _LOGGER.error("Site ID is empty or None for custom revenue range")
                return None
                
            _LOGGER.debug("Using site ID %s for custom revenue range", site_id)
            
            # Validate date format and ensure they are dates
            date_format = "%Y-%m-%d"
            try:
                from_date = datetime.strptime(from_date, date_format).date()
                to_date = datetime.strptime(to_date, date_format).date()
            except ValueError:
                raise ValueError(
                    "Input dates must be valid dates with the format YYYY-MM-DD."
                )

            # Validate from_date and to_date
            today = date.today()
            six_months_ago = today - relativedelta(months=6)

            if not (six_months_ago <= from_date <= today):
                raise ValueError(
                    "From date must be within the last 6 months and not beyond today."
                )

            if not (six_months_ago <= to_date <= today):
                raise ValueError(
                    "To date must be within the last 6 months and not beyond today."
                )

            if from_date >= to_date:
                raise ValueError("From date must be before To date.")

            # Extend to_date by one day
            to_date += timedelta(days=1)

            endpoint = (
                f"/revenue/{site_id}?from={from_date}&to={to_date}&resolution=day"
            )
            _LOGGER.debug("Custom revenue range endpoint: %s", endpoint)

            result = await self._request("GET", endpoint, auth_required=True)
            if result is False:
                _LOGGER.error("Failed to retrieve custom revenue range from endpoint: %s", endpoint)
                return None
            
            _LOGGER.info("Successfully retrieved custom revenue range")
            return result

        except Exception as error:
            _LOGGER.error("Error in fetch_and_return_net_revenue: %s", error)
            return None

    def _extract_content_and_logbook(self, input_string):
        """Pull the registered information from the logbook."""
        battery_registration = None

        # Define the pattern to match the content between the tags
        pattern = re.compile(
            r"#BEGIN_BATTERY_REGISTRATION(.*?)#END_BATTERY_REGISTRATION", re.DOTALL
        )

        # Find all matches in the input string
        matches = re.findall(pattern, input_string)

        # Extracted content
        extracted_content = ""
        if matches:
            extracted_content = matches[0].strip()
            battery_registration = json.loads(extracted_content)

        # Extract logbook entries
        logbook_entries = input_string.split("\n")

        # Filter out entries containing
        # #BEGIN_BATTERY_REGISTRATION and #END_BATTERY_REGISTRATION
        logbook_entries = [
            entry.strip()
            for entry in logbook_entries
            if not (
                "#BEGIN_BATTERY_REGISTRATION" in entry
                or "#END_BATTERY_REGISTRATION" in entry
            )
        ]

        return battery_registration, logbook_entries

    def _extract_fcr_d_state(self):
        pattern = re.compile(
            r"\[ FCR-D (ACTIVATED|DEACTIVATE|FAIL ACTIVATION) \] (\S+) --(\d+)-- ((\d+,\d+)/(\d+,\d+)/(\d+,\d+) %) \((\d+) kW\) (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"  # noqa: E501
        )
        for entry in self.logbook_entries:
            match = pattern.search(entry)
            if match:
                self.fcrd_state = match.group(1)
                fcrd_percentage = (
                    match.group(4)
                    if self.fcrd_state in ["ACTIVATED", "FAIL ACTIVATION"]
                    else None
                )
                self.fcrd_percentage_up = (
                    match.group(5)
                    if self.fcrd_state in ["ACTIVATED", "FAIL ACTIVATION"]
                    else None
                )
                self.fcrd_percentage_response = (
                    match.group(6)
                    if self.fcrd_state in ["ACTIVATED", "FAIL ACTIVATION"]
                    else None
                )
                self.fcrd_percentage_down = (
                    match.group(7)
                    if self.fcrd_state in ["ACTIVATED", "FAIL ACTIVATION"]
                    else None
                )
                error_info = match.group(4) if self.fcrd_state == "DEACTIVATE" else None
                self.fcrd_power = match.group(8)
                self.fcrd_timestamp = match.group(9)
                if fcrd_percentage is not None:
                    self.fcrd_info = fcrd_percentage
                elif error_info is not None:
                    error_info = error_info.split("]", 1)[0].strip()
                    self.fcrd_info = error_info.strip("[]").strip()
                else:
                    self.fcrd_info = None
                break  # stop so we get the first row in logbook







    async def fetch_and_return_net_revenue(self, from_date, to_date):
        """Fetch FCR-D revenues from CheckWatt as per provided range."""
        try:
            site_id = await self.get_site_id()
            # Validate date format and ensure they are dates
            date_format = "%Y-%m-%d"
            try:
                from_date = datetime.strptime(from_date, date_format).date()
                to_date = datetime.strptime(to_date, date_format).date()
            except ValueError:
                raise ValueError(
                    "Input dates must be valid dates with the format YYYY-MM-DD."
                )

            # Validate from_date and to_date
            today = date.today()
            six_months_ago = today - relativedelta(months=6)

            if not (six_months_ago <= from_date <= today):
                raise ValueError(
                    "From date must be within the last 6 months and not beyond today."
                )

            if not (six_months_ago <= to_date <= today):
                raise ValueError(
                    "To date must be within the last 6 months and not beyond today."
                )

            if from_date >= to_date:
                raise ValueError("From date must be before To date.")

            # Extend to_date by one day
            to_date += timedelta(days=1)

            endpoint = (
                f"/revenue/{site_id}?from={from_date}&to={to_date}&resolution=day"
            )

            result = await self._request("GET", endpoint, auth_required=True)
            if result is False:
                return None
            
            return result

        except Exception as error:
            _LOGGER.error("Error in fetchand_return_net_revenue: %s", error)
            return None



    def _build_series_endpoint(self, grouping):
        end_date = datetime.now() + timedelta(days=2)
        to_date = end_date.strftime("%Y")
        endpoint = (
            f"/datagrouping/series?grouping={grouping}&fromdate=1923&todate={to_date}"
        )

        meters = self.customer_details.get("Meter", [])
        if meters:
            for meter in meters:
                if "Id" in meter:
                    endpoint += f"&meterId={meter['Id']}"
            return endpoint
        else:
            return None

    async def get_power_data(self):
        """Fetch Power Data from CheckWatt."""

        try:
            endpoint = self._build_series_endpoint(
                3
            )  # 0: Hourly, 1: Daily, 2: Monthly, 3: Yearly

            result = await self._request("GET", endpoint, auth_required=True)
            if result is False:
                return False
            
            self.power_data = result
            return True

        except Exception as error:
            _LOGGER.error("Error in get_power_data: %s", error)
            return False

    async def get_energy_flow(self):
        """Fetch Power Data from CheckWatt."""

        try:
            endpoint = "/ems/energyflow"

            result = await self._request("GET", endpoint, auth_required=True)
            if result is False:
                return False
            
            self.energy_data = result
            return True

        except Exception as error:
            _LOGGER.error("Error in get_energy_flow: %s", error)
            return False

    async def get_ems_settings(self, rpi_serial=None):
        """Fetch EMS settings from CheckWatt."""

        try:
            if rpi_serial is None:
                rpi_serial = self.rpi_serial

            if rpi_serial is None:
                _LOGGER.error("Invalid RpiSerial")
                return False

            endpoint = f"/ems/service/Pending?Serial={rpi_serial}"

            result = await self._request("GET", endpoint, auth_required=True)
            if result is False:
                return False
            
            self.ems = result
            return True

        except Exception as error:
            _LOGGER.error("Error in get_ems_settings: %s", error)
            return False

    async def get_price_zone(self):
        """Fetch Price Zone from CheckWatt."""

        try:
            endpoint = "/ems/pricezone"
            
            result = await self._request("GET", endpoint, auth_required=True)
            if result is False:
                return False
            
            self.price_zone = result
            return True

        except Exception as error:
            _LOGGER.error("Error in get_price_zone: %s", error)
            return False

    async def get_spot_price(self):
        """Fetch Spot Price from CheckWatt."""

        try:
            from_date = datetime.now().strftime("%Y-%m-%d")
            end_date = datetime.now() + timedelta(days=1)
            to_date = end_date.strftime("%Y-%m-%d")
            if self.price_zone is None:
                await self.get_price_zone()
            endpoint = f"/ems/spotprice?zone={self.price_zone}&fromDate={from_date}&toDate={to_date}"  # noqa: E501
            
            result = await self._request("GET", endpoint, auth_required=True)
            if result is False:
                return False
            
            self.spot_prices = result
            return True

        except Exception as error:
            _LOGGER.error("Error in get_spot_price: %s", error)
            return False

    async def get_battery_month_peak_effect(self):
        """Fetch Price Zone from CheckWatt."""
        month = datetime.now().strftime("%Y-%m")

        try:
            endpoint = f"/ems/PeakBoughtMonth?month={month}"
            
            result = await self._request("GET", endpoint, auth_required=True)
            if result is False:
                return False
            
            if "HourPeak" in result:
                self.month_peak_effect = result["HourPeak"]
                return True
            
            return False

        except Exception as error:
            _LOGGER.error("Error in get_battery_month_peak_effect: %s", error)
            return False

    async def get_energy_trading_company(self, input_id):
        """Translate Energy Company Id to Energy Company Name."""
        try:
            endpoint = "/controlpanel/elhandelsbolag"

            result = await self._request("GET", endpoint, auth_required=False)
            if result is False:
                return None
            
            energy_trading_companies = result
            for energy_trading_company in energy_trading_companies:
                if energy_trading_company["Id"] == input_id:
                    return energy_trading_company["DisplayName"]

            return None

        except Exception as error:
            _LOGGER.error("Error in get_energy_trading_company: %s", error)
            return None

    async def get_rpi_data(self, rpi_serial=None):
        """Fetch RPi Data from CheckWatt."""

        try:
            if rpi_serial is None:
                rpi_serial = self.rpi_serial

            if rpi_serial is None:
                _LOGGER.error("Invalid RpiSerial")
                return False

            endpoint = f"/register/checkrpiv2?rpi={rpi_serial}"
            
            result = await self._request("GET", endpoint, auth_required=False)
            if result is False:
                return False
            
            self.rpi_data = result
            return True

        except Exception as error:
            _LOGGER.error("Error in get_rpi_data: %s", error)
            return False

    async def get_meter_status(self, meter_id=None):
        """Fetch RPi Data from CheckWatt."""

        try:
            if meter_id is None:
                meter_id = self.meter_id

            if meter_id is None:
                _LOGGER.error("Invalid MeterId")
                return False

            endpoint = f"/asset/status?meterId={meter_id}"
            
            result = await self._request("GET", endpoint, auth_required=False)
            if result is False:
                return False
            
            self.meter_data = result
            return True

        except Exception as error:
            _LOGGER.error("Error in get_meter_status: %s", error)
            return False

    @property
    def ems_settings(self):
        """Property for inverter make and model. Not used by HA integration.."""
        ems = f"{self.ems[0]}"
        if ems == "fcrd":
            resp = "Currently optimized (CO)"
        elif ems == "sc":
            resp = "Self Consumption (SC)"
        else:
            resp = "Please report this on Github " + ems
        return resp

    @property
    def inverter_make_and_model(self):
        """Property for inverter make and model. Not used by HA integration.."""
        if (
            "Inverter" in self.battery_registration
            and "InverterModel" in self.battery_registration
        ):
            resp = f"{self.battery_registration['Inverter']}"
            resp += f" {self.battery_registration['InverterModel']}"
            return resp

    @property
    def battery_make_and_model(self):
        """Property for battery make and model. Not used by HA integration."""
        if (
            "BatteryModel" in self.battery_registration
            and "BatterySystem" in self.battery_registration
        ):
            resp = f"{self.battery_registration['BatterySystem']}"
            resp += f" {self.battery_registration['BatteryModel']}"
            resp += f" ({self.battery_registration['BatteryPowerKW']}kW, {self.battery_registration['BatteryCapacityKWh']}kWh)"  # noqa: E501
            return resp
        else:
            return "Could not get any information about your battery"

    @property
    def battery_peak_data(self):
        """Property for battery peak."""
        battery_charge_peak_ac = 0
        battery_charge_peak_dc = 0
        battery_discharge_peak_ac = 0
        battery_discharge_peak_dc = 0
        if self.battery_charge_peak_ac is not None:
            battery_charge_peak_ac = self.battery_charge_peak_ac
        if self.battery_charge_peak_dc is not None:
            battery_charge_peak_dc = self.battery_charge_peak_dc
        if self.battery_discharge_peak_ac is not None:
            battery_discharge_peak_ac = self.battery_discharge_peak_ac
        if self.battery_discharge_peak_dc is not None:
            battery_discharge_peak_dc = self.battery_discharge_peak_dc

        return (
            battery_charge_peak_ac,
            battery_charge_peak_dc,
            battery_discharge_peak_ac,
            battery_discharge_peak_dc,
        )

    @property
    def electricity_provider(self):
        """Property for electricity provides. Not used by HA integration."""
        if (
            "ElectricityCompany" in self.battery_registration
            and "Dso" in self.battery_registration
        ):
            resp = f"{self.battery_registration['ElectricityCompany']}"
            resp += f" via {self.battery_registration['Dso']}"
        if "GridAreaId" in self.battery_registration:
            resp += f" ({self.battery_registration['GridAreaId']} {self.battery_registration['Kommun']})"  # noqa: E501
        return resp

    @property
    def registered_owner(self):
        """Property for registered owner. Not used by HA integration.."""
        if "FirstName" in self.customer_details and "LastName" in self.customer_details:
            resp = f"{self.customer_details['FirstName']}"
            resp += f" {self.customer_details['LastName']}"
            resp += f" ({self.customer_details['StreetAddress']}"
            resp += f" {self.customer_details['ZipCode']}"
            resp += f" {self.customer_details['City']})"
            return resp
        return None

    @property
    def fcrd_year_net_revenue(self):
        """Property for today's revenue."""
        revenueyear = 0
        if self.revenueyeartotal is not None:
            revenueyear = self.revenueyeartotal

        return revenueyear

    @property
    def fcrd_month_net_revenue(self):
        """Property for today's revenue."""
        revenuemonth = 0
        if self.revenuemonth is not None:
            revenuemonth = self.revenuemonth

        return revenuemonth

    @property
    def fcrd_month_net_estimate(self):
        """Property for today's revenue."""
        monthestimate = 0
        if self.monthestimate is not None:
            monthestimate = self.monthestimate

        return monthestimate

    @property
    def fcrd_daily_net_average(self):
        """Property for today's revenue."""
        dailyaverage = 0
        if self.dailyaverage is not None:
            dailyaverage = self.dailyaverage

        return dailyaverage

    @property
    def fcrd_today_net_revenue(self):
        """Property for today's revenue."""
        revenue = 0
        if self.revenue is not None:
            if len(self.revenue["Revenue"]) > 0:
                if "NetRevenue" in self.revenue["Revenue"][0]:
                    revenue = self.revenue["Revenue"][0]["NetRevenue"]

        return revenue

    @property
    def fcrd_tomorrow_net_revenue(self):
        """Property for tomorrow's revenue."""
        revenue = 0
        if self.revenue is not None:
            if len(self.revenue["Revenue"]) > 1:
                if "NetRevenue" in self.revenue["Revenue"][1]:
                    revenue = self.revenue["Revenue"][1]["NetRevenue"]

        return revenue

    def _get_meter_total(self, meter_type):
        """Solar, Charging, Discharging, EDIEL_E17, EDIEL_E18, Soc meter summary."""
        meter_total = 0
        meters = self.power_data.get("Meters", [])
        for meter in meters:
            if "InstallationType" in meter and "Measurements" in meter:
                if meter["InstallationType"] == meter_type:
                    for measurement in meter["Measurements"]:
                        if "Value" in measurement:
                            meter_total += measurement["Value"]  # to get answer to kWh
        return meter_total

    @property
    def total_solar_energy(self):
        """Property for Solar Energy."""
        return self._get_meter_total("Solar")

    @property
    def total_charging_energy(self):
        """Property for Battery Charging Energy."""
        return self._get_meter_total("Charging")

    @property
    def total_discharging_energy(self):
        """Property for Battery Discharging Energy."""
        return self._get_meter_total("Discharging")

    @property
    def total_import_energy(self):
        """Property for Imported (Bought) Energy."""
        return self._get_meter_total("EDIEL_E17")

    @property
    def total_export_energy(self):
        """Property for Exported (Sold) Energy."""
        return self._get_meter_total("EDIEL_E18")

    def get_spot_price_excl_vat(self, now_hour: int):
        """Property for current spot price."""
        spot_prices = self.spot_prices.get("Prices", [])
        if spot_prices and 0 <= now_hour < len(spot_prices):
            spot_price = spot_prices[now_hour]["Value"]
            _LOGGER.debug("Time is %d and spot price is %f", now_hour, spot_price)
            return spot_price

        _LOGGER.warning("Unable to retrieve spot price for the current hour")
        return None

    @property
    def battery_power(self):
        """Property for Battery Power."""
        if self.energy_data is not None:
            if "BatteryNow" in self.energy_data:
                return self.energy_data["BatteryNow"]

        _LOGGER.warning("Unable to retrieve Battery Power")
        return None

    @property
    def grid_power(self):
        """Property for Grid Power."""
        if self.energy_data is not None:
            if "GridNow" in self.energy_data:
                return self.energy_data["GridNow"]

        _LOGGER.warning("Unable to retrieve Grid Power")
        return None

    @property
    def solar_power(self):
        """Property for Solar Power."""
        if self.energy_data is not None:
            if "SolarNow" in self.energy_data:
                return self.energy_data["SolarNow"]

        _LOGGER.warning("Unable to retrieve Solar Power")
        return None

    @property
    def battery_soc(self):
        """Property for Battery SoC."""
        if self.energy_data is not None:
            if "BatterySoC" in self.energy_data:
                return self.energy_data["BatterySoC"]

        _LOGGER.warning("Unable to retrieve Battery SoC")
        return None

    @property
    def rpi_serial(self):
        """Property for Rpi Serial."""
        if self.rpi_data is not None:
            meters = self.rpi_data.get("Meters", [])
            for meter in meters:
                if "RPi" in meter:
                    return meter["RPi"].upper()

        if self.customer_details is not None:
            meters = self.customer_details.get("Meter", [])
            for meter in meters:
                if "RpiSerial" in meter:
                    return meter["RpiSerial"].upper()

        _LOGGER.warning("Unable to find RPi Serial")
        return None

    @property
    def meter_id(self):
        """Property for Meter Id."""
        if self.rpi_data is not None:
            meters = self.rpi_data.get("Meters", [])
            for meter in meters:
                if "Id" in meter:
                    return meter["Id"]

        if self.customer_details is not None:
            meters = self.customer_details.get("Meter", [])
            for meter in meters:
                if "InstallationType" in meter and "Id" in meter:
                    if meter["InstallationType"] == "SoC":
                        return meter["Id"]

        _LOGGER.warning("Unable to find Meter Id")
        return None

    @property
    def meter_status(self):
        """Property for Meter Status."""
        # First check if meter_data is available
        if self.meter_data is not None:
            if "Label" in self.meter_data:
                return self.meter_data["Label"]

        # Then check if rpi_data is available
        if self.rpi_data is not None:
            meters = self.rpi_data.get("Meters", [])
            for meter in meters:
                if "InstallationType" in meter and "Status" in meter:
                    if meter["InstallationType"] == "SoC":
                        return meter["Status"]

        _LOGGER.warning("Unable to find Meter Status")
        return None

    @property
    def meter_status_date(self):
        """Property for Meter Status Date."""
        if self.meter_data is not None:
            if "Date" in self.meter_data:
                return self.meter_data["Date"]

        _LOGGER.warning("Unable to find Meter Data for Status Date")
        return None

    @property
    def meter_value_w(self):
        """Property for Meter Value W."""
        if self.meter_data is not None:
            if "ValueW" in self.meter_data:
                return self.meter_data["ValueW"]

        _LOGGER.warning("Unable to find Meter Data for Value W")
        return None

    @property
    def meter_under_test(self):
        """Property to check if meter is being tested."""
        if self.meter_data and "Version" in self.meter_data:
            return self.meter_data["Version"].endswith(".83")

        _LOGGER.warning("Unable to find Meter Data for Meter Under Test")
        return None

    @property
    def meter_version(self):
        """Property for Meter Version."""
        if self.meter_data is not None:
            if "Version" in self.meter_data:
                version_string = self.meter_data["Version"]

                # Use regular expression to extract Major.Minor.Patch
                match = re.search(r"\d+\.\d+\.\d+", version_string)
                if match:
                    return match.group()

        _LOGGER.warning("Unable to find Meter Data for Meter Version")
        return None

    # Properties for debugging token state
    @property
    def jwt_expires_at(self) -> Optional[datetime]:
        """Get JWT expiration time for debugging."""
        if not self.jwt_token:
            return None
        
        try:
            parts = self.jwt_token.split('.')
            if len(parts) != 3:
                return None
            
            payload = base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8')
            claims = json.loads(payload)
            
            exp = claims.get('exp')
            if not exp:
                return None
            
            return datetime.fromtimestamp(exp)
            
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError, TypeError):
            return None

    @property
    def refresh_expires_at(self) -> Optional[datetime]:
        """Get refresh token expiration time for debugging."""
        if not self.refresh_token_expires:
            return None
        
        try:
            return datetime.fromisoformat(
                self.refresh_token_expires.replace('Z', '+00:00')
            )
        except (ValueError, TypeError):
            return None


class CheckWattRankManager:
    def __init__(self) -> None:
        self.session = None
        self.base_url = "https://checkwattrank.netlify.app"

    async def __aenter__(self):
        """Asynchronous enter."""
        self.session = ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        """Asynchronous exit."""
        await self.session.close()

    async def push_to_checkwatt_rank(
        self,
        display_name,
        dso,
        electricity_company,
        electricity_area,
        installed_power,
        today_net_income,
        reseller_id,
        reporter,
    ):
        """Push Data to CheckWattRank."""

        headers = {
            "Content-Type": "application/json",
        }
        url = self.base_url + "/.netlify/functions/publishToSheet"

        payload = {
            "display_name": display_name,
            "dso": dso,
            "electricity_company": electricity_company,
            "electricity_area": electricity_area,
            "installed_power": installed_power,
            "today_net_income": today_net_income,
            "reseller_id": reseller_id,
            "reporter": reporter,
        }

        timeout_seconds = 10
        async with ClientSession() as session:
            try:
                async with session.post(
                    url, headers=headers, json=payload, timeout=timeout_seconds
                ) as response:
                    response.raise_for_status()
                    content_type = response.headers.get("Content-Type", "").lower()
                    _LOGGER.debug(
                        "CheckWattRank Push Response Content-Type: %s",
                        content_type,
                    )

                    if "application/json" in content_type:
                        result = await response.json()
                        _LOGGER.debug("CheckWattRank Push Response: %s", result)
                        return True
                    elif "text/plain" in content_type:
                        result = await response.text()
                        _LOGGER.debug("CheckWattRank Push Response: %s", result)
                        return True
                    else:
                        _LOGGER.warning("Unexpected Content-Type: %s", content_type)
                        result = await response.text()
                        _LOGGER.debug("CheckWattRank Push Response: %s", result)

            except ClientError as e:
                _LOGGER.error("API call 'push_to_checkwatt_rank' failed: %s", e)

            except TimeoutError:
                _LOGGER.error(
                    "API call 'push_to_checkwatt_rank' timed out after %s seconds",
                    timeout_seconds,
                )
        return False

    async def push_history_to_checkwatt_rank(
        self,
        display_name,
        dso,
        electricity_company,
        electricity_area,
        installed_power,
        reseller_id,
        reporter,
        historical_data,
    ):
        headers = {
            "Content-Type": "application/json",
        }
        url = self.base_url + "/.netlify/functions/publishHistory"

        payload = {
            "display_name": display_name,
            "dso": dso,
            "electricity_company": electricity_company,
            "electricity_area": electricity_area,
            "installed_power": installed_power,
            "reseller_id": reseller_id,
            "reporter": reporter,
            "historical_data": historical_data,
        }
        timeout_seconds = 10
        stored_items = 0
        total_items = 0
        status = None
        async with ClientSession() as session:
            try:
                async with session.post(
                    url, headers=headers, json=payload, timeout=timeout_seconds
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        stored_items = result.get("count", 0)
                        total_items = result.get("total", 0)
                        status = result.get("message", 0)
                    else:
                        _LOGGER.debug(
                            "Failed to post data. Status code: %s",
                            response.status,
                        )
                        status = f"Failed to post data. Status code: {response.status}"

            except ClientError as e:
                _LOGGER.error("API call 'push_history_to_checkwatt_rank' failed: %s", e)
                status = f"Failed to push historical data. Error {e}"

            except TimeoutError:
                _LOGGER.error(
                    "API call 'push_history_to_checkwatt_rank' timed out after %s seconds",
                    timeout_seconds,
                )
                status = "Timeout pushing historical data."

        return (
            status,
            stored_items,
            total_items,
        )
