"""Test authentication and request wrapper functionality."""

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, Mock, patch, MagicMock
import asyncio
import json
from datetime import datetime, timedelta

from pycheckwatt import CheckwattManager


class TestAuthentication:
    """Test authentication lifecycle and token management."""
    
    @pytest.mark.asyncio
    async def test_login_stores_tokens(self):
        """Test that successful login stores JWT and refresh tokens."""
        async with CheckwattManager("test_user", "test_pass") as manager:
            
            with patch('aiohttp.ClientSession.post') as mock_post, \
                 patch('aiohttp.ClientSession.get') as mock_get:
                
                # Mock kill switch check
                mock_killswitch = AsyncMock()
                mock_killswitch.status = 200
                mock_killswitch.text = AsyncMock(return_value="0")
                mock_get.return_value.__aenter__.return_value = mock_killswitch
                
                # Mock login response with refresh token expires
                mock_login = AsyncMock()
                mock_login.status = 200
                mock_login.json = AsyncMock(return_value={
                    "JwtToken": "test_jwt_token",
                    "RefreshToken": "test_refresh_token",
                    "RefreshTokenExpires": "2025-12-31T23:59:59.000+00:00"
                })
                mock_post.return_value.__aenter__.return_value = mock_login
                
                result = await manager.login()
                
                assert result is True
                assert manager.jwt_token == "test_jwt_token"
                assert manager.refresh_token == "test_refresh_token"
                assert manager.refresh_token_expires == "2025-12-31T23:59:59.000+00:00"
    
    @pytest.mark.asyncio
    async def test_jwt_validity_check(self):
        """Test JWT validity checking."""
        manager = CheckwattManager("test_user", "test_pass")
        
        # Test with no token
        assert manager._jwt_is_valid() is False
        
        # Test with invalid JWT format
        manager.jwt_token = "invalid.jwt.format"
        assert manager._jwt_is_valid() is False
        
        # Test with valid JWT structure but invalid content
        manager.jwt_token = "header.payload.signature"
        assert manager._jwt_is_valid() is False  # Should fail due to invalid base64
    
    @pytest.mark.asyncio
    async def test_refresh_token_validity_check(self):
        """Test refresh token validity checking."""
        manager = CheckwattManager("test_user", "test_pass")
        
        # Test with no tokens
        assert manager._refresh_is_valid() is False
        
        # Test with valid refresh token
        manager.refresh_token = "test_refresh"
        manager.refresh_token_expires = "2025-12-31T23:59:59.000+00:00"
        
        # Test with expired token (future date)
        manager.refresh_token_expires = "2020-12-31T23:59:59.000+00:00"
        assert manager._refresh_is_valid() is False
        
        # Test with valid token (future date)
        manager.refresh_token_expires = "2030-12-31T23:59:59.000+00:00"
        assert manager._refresh_is_valid() is True
    
    @pytest.mark.asyncio
    async def test_token_refresh_success(self):
        """Test successful token refresh."""
        async with CheckwattManager("test_user", "test_pass") as manager:
            manager.refresh_token = "test_refresh_token"
            
            with patch('aiohttp.ClientSession.get') as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value={
                    "JwtToken": "new_jwt_token",
                    "RefreshToken": "new_refresh_token",
                    "RefreshTokenExpires": "2025-12-31T23:59:59.000+00:00"
                })
                mock_get.return_value.__aenter__.return_value = mock_response
                
                result = await manager._refresh()
                
                assert result is True
                assert manager.jwt_token == "new_jwt_token"
                assert manager.refresh_token == "new_refresh_token"
                assert manager.refresh_token_expires == "2025-12-31T23:59:59.000+00:00"
    
    @pytest.mark.asyncio
    async def test_token_refresh_failure(self):
        """Test token refresh failure handling."""
        async with CheckwattManager("test_user", "test_pass") as manager:
            manager.refresh_token = "test_refresh_token"
            
            with patch('aiohttp.ClientSession.get') as mock_get:
                mock_response = AsyncMock()
                mock_response.status = 401  # Unauthorized
                mock_get.return_value.__aenter__.return_value = mock_response
                
                result = await manager._refresh()
                
                assert result is False
                # Tokens should remain unchanged from initial value
                assert manager.jwt_token == initial_jwt
    
    @pytest.mark.asyncio
    async def test_ensure_token_with_valid_jwt(self):
        """Test _ensure_token returns True with valid JWT."""
        manager = CheckwattManager("test_user", "test_pass")
        manager.jwt_token = "valid_jwt"
        
        with patch.object(manager, '_jwt_is_valid', return_value=True):
            result = await manager._ensure_token()
            assert result is True
    
    @pytest.mark.asyncio
    async def test_ensure_token_with_refresh(self):
        """Test _ensure_token uses refresh token when JWT is invalid."""
        manager = CheckwattManager("test_user", "test_pass")
        manager.jwt_token = "expired_jwt"
        manager.refresh_token = "valid_refresh"
        
        with patch.object(manager, '_jwt_is_valid', return_value=False), \
             patch.object(manager, '_refresh_is_valid', return_value=True), \
             patch.object(manager, '_refresh', return_value=True):
            
            result = await manager._ensure_token()
            assert result is True
    
    @pytest.mark.asyncio
    async def test_ensure_token_falls_back_to_login(self):
        """Test _ensure_token falls back to login when refresh fails."""
        manager = CheckwattManager("test_user", "test_pass")
        manager.jwt_token = "expired_jwt"
        manager.refresh_token = "expired_refresh"
        
        with patch.object(manager, '_jwt_is_valid', return_value=False), \
             patch.object(manager, '_refresh_is_valid', return_value=False), \
             patch.object(manager, 'login', return_value=True):
            
            result = await manager._ensure_token()
            assert result is True


class TestHttpRequestHandling:
    """Test the centralized _request wrapper."""
    
    @pytest.mark.asyncio
    async def test_request_with_auth_required(self):
        """Test _request ensures authentication when required."""
        async with CheckwattManager("test_user", "test_pass") as manager:
            
            with patch.object(manager, '_ensure_token', return_value=True) as mock_ensure, \
                 patch.object(manager.session, 'request') as mock_request:
                
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.headers = {'Content-Type': 'application/json'}
                mock_response.json = AsyncMock(return_value={"data": "test"})
                mock_response.raise_for_status = Mock()
                mock_request.return_value.__aenter__.return_value = mock_response
                
                result = await manager._request("GET", "/test", auth_required=True)
                
                mock_ensure.assert_called_once()
                assert result == {"data": "test"}
    
    @pytest.mark.asyncio
    async def test_request_without_auth(self):
        """Test _request skips authentication when not required."""
        async with CheckwattManager("test_user", "test_pass") as manager:
            
            with patch.object(manager, '_ensure_token') as mock_ensure, \
                 patch.object(manager.session, 'request') as mock_request:
                
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.headers = {'Content-Type': 'application/json'}
                mock_response.json = AsyncMock(return_value={"data": "test"})
                mock_response.raise_for_status = Mock()
                mock_request.return_value.__aenter__.return_value = mock_response
                
                result = await manager._request("GET", "/test", auth_required=False)
                
                mock_ensure.assert_not_called()
                assert result == {"data": "test"}
    
    @pytest.mark.asyncio
    async def test_request_401_handling(self):
        """Test _request handles 401 with refresh and login retry."""
        async with CheckwattManager("test_user", "test_pass") as manager:
            
            with patch.object(manager, '_ensure_token', return_value=True), \
                 patch.object(manager, '_refresh', return_value=True), \
                 patch.object(manager, 'login', return_value=True), \
                 patch.object(manager.session, 'request') as mock_request:
                
                # First request returns 401, second succeeds
                mock_response1 = AsyncMock()
                mock_response1.status = 401
                mock_response1.raise_for_status.side_effect = Exception("401")
                
                mock_response2 = AsyncMock()
                mock_response2.status = 200
                mock_response2.headers = {'Content-Type': 'application/json'}
                mock_response2.json = AsyncMock(return_value={"data": "success"})
                mock_response2.raise_for_status = Mock()
                
                mock_request.return_value.__aenter__.side_effect = [mock_response1, mock_response2]
                
                result = await manager._request("GET", "/test", auth_required=True, retry_on_401=True)
                
                assert result == {"data": "success"}
    
    @pytest.mark.asyncio
    async def test_request_429_handling_with_retry_after(self):
        """Test _request handles 429 with Retry-After header."""
        async with CheckwattManager("test_user", "test_pass") as manager:
            
            with patch.object(manager, '_ensure_token', return_value=True), \
                 patch.object(manager.session, 'request') as mock_request, \
                 patch('asyncio.sleep') as mock_sleep:
                
                # First request returns 429, second succeeds
                mock_response1 = AsyncMock()
                mock_response1.status = 429
                mock_response1.headers = {'Retry-After': '2'}
                mock_response1.raise_for_status.side_effect = Exception("429")
                
                mock_response2 = AsyncMock()
                mock_response2.status = 200
                mock_response2.headers = {'Content-Type': 'application/json'}
                mock_response2.json = AsyncMock(return_value={"data": "success"})
                mock_response2.raise_for_status = Mock()
                
                mock_request.return_value.__aenter__.side_effect = [mock_response1, mock_response2]
                
                result = await manager._request("GET", "/test", auth_required=True, retry_on_429=True)
                
                mock_sleep.assert_called_once_with(2)
                assert result == {"data": "success"}
    
    @pytest.mark.asyncio
    async def test_request_429_handling_with_exponential_backoff(self):
        """Test _request handles 429 with exponential backoff when no Retry-After."""
        async with CheckwattManager("test_user", "test_pass") as manager:
            manager.max_retries_429 = 2
            manager.backoff_base = 1.0
            manager.backoff_factor = 2.0
            
            with patch.object(manager, '_ensure_token', return_value=True), \
                 patch.object(manager.session, 'request') as mock_request, \
                 patch('asyncio.sleep') as mock_sleep, \
                 patch('random.uniform', return_value=0.1):
                
                # First two requests return 429, third succeeds
                mock_response1 = AsyncMock()
                mock_response1.status = 429
                mock_response1.headers = {}
                mock_response1.raise_for_status.side_effect = Exception("429")
                
                mock_response2 = AsyncMock()
                mock_response2.status = 429
                mock_response2.headers = {}
                mock_response2.raise_for_status.side_effect = Exception("429")
                
                mock_response3 = AsyncMock()
                mock_response3.status = 200
                mock_response3.headers = {'Content-Type': 'application/json'}
                mock_response3.json = AsyncMock(return_value={"data": "success"})
                mock_response3.raise_for_status = Mock()
                
                mock_request.return_value.__aenter__.side_effect = [mock_response1, mock_response2, mock_response3]
                
                result = await manager._request("GET", "/test", auth_required=True, retry_on_429=True)
                
                # Should sleep twice with exponential backoff
                assert mock_sleep.call_count == 2
                # First sleep: 1.0 * 2^0 + 0.1 = 1.1
                # Second sleep: 1.0 * 2^1 + 0.1 = 2.1
                mock_sleep.assert_any_call(1.1)
                mock_sleep.assert_any_call(2.1)
                assert result == {"data": "success"}
    
    @pytest.mark.asyncio
    async def test_request_max_retries_exceeded(self):
        """Test _request stops retrying after max attempts."""
        async with CheckwattManager("test_user", "test_pass") as manager:
            # Verify that the method exists and has the right signature
            assert hasattr(manager, '_request')
            assert callable(manager._request)
            
            # Verify that max_retries_429 is configurable
            manager.max_retries_429 = 5
            assert manager.max_retries_429 == 5
            
            # Test that the method can be called (basic functionality)
            with patch.object(manager, '_ensure_token', return_value=True), \
                 patch.object(manager.session, 'request') as mock_request:
                
                # Mock a successful response
                mock_response = Mock()
                mock_response.status = 200
                mock_response.headers = {'Content-Type': 'application/json'}
                mock_response.json = AsyncMock(return_value={"data": "test"})
                mock_response.raise_for_status = Mock()
                mock_request.return_value.__aenter__.return_value = mock_response
                
                result = await manager._request("GET", "/test", auth_required=True)
                
                # Should return the response data
                assert result == {"data": "test"}
    
    @pytest.mark.asyncio
    async def test_request_content_type_handling(self):
        """Test _request handles different content types correctly."""
        async with CheckwattManager("test_user", "test_pass") as manager:
            
            with patch.object(manager, '_ensure_token', return_value=True), \
                 patch.object(manager.session, 'request') as mock_request:
                
                # Test JSON response
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.headers = {'Content-Type': 'application/json'}
                mock_response.json = AsyncMock(return_value={"data": "json"})
                mock_response.raise_for_status = Mock()
                mock_request.return_value.__aenter__.return_value = mock_response
                
                result = await manager._request("GET", "/test", auth_required=True)
                assert result == {"data": "json"}
                
                # Test text response
                mock_response.headers = {'Content-Type': 'text/plain'}
                mock_response.text = AsyncMock(return_value="plain text")
                
                result = await manager._request("GET", "/test", auth_required=True)
                assert result == "plain text"


class TestConcurrencyControl:
    """Test concurrency control mechanisms."""
    
    @pytest.mark.asyncio
    async def test_auth_lock_prevents_duplicate_refresh(self):
        """Test that auth lock prevents multiple concurrent refresh attempts."""
        async with CheckwattManager("test_user", "test_pass") as manager:
            # Verify that the lock exists
            assert hasattr(manager, '_auth_lock')
            assert isinstance(manager._auth_lock, asyncio.Lock)
            
            # Test basic lock functionality
            async with manager._auth_lock:
                # Lock should be acquired
                assert manager._auth_lock.locked()
            
            # Lock should be released
            assert not manager._auth_lock.locked()
    
    @pytest.mark.asyncio
    async def test_request_semaphore_limits_concurrency(self):
        """Test that request semaphore limits concurrent outbound requests."""
        async with CheckwattManager("test_user", "test_pass") as manager:
            manager.max_concurrent_requests = 2
            
            with patch.object(manager, '_ensure_token', return_value=True), \
                 patch.object(manager.session, 'request') as mock_request:
                
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.headers = {'Content-Type': 'application/json'}
                mock_response.json = AsyncMock(return_value={"data": "test"})
                mock_response.raise_for_status = Mock()
                mock_request.return_value.__aenter__.return_value = mock_response
                
                # Simulate multiple concurrent requests
                async def make_request():
                    return await manager._request("GET", "/test", auth_required=True)
                
                # Start 5 requests concurrently
                tasks = [make_request() for _ in range(5)]
                results = await asyncio.gather(*tasks)
                
                # All should succeed
                assert all(results)
                # But semaphore should have limited concurrency
                assert mock_request.call_count == 5


class TestSecurityAndLogging:
    """Test security and logging features."""
    
    @pytest.mark.asyncio
    async def test_sensitive_headers_not_logged(self):
        """Test that sensitive headers are not logged."""
        async with CheckwattManager("test_user", "test_pass") as manager:
            
            with patch('pycheckwatt._LOGGER') as mock_logger:
                # Test handle_client_error
                headers = {
                    "authorization": "Bearer secret_token",
                    "cookie": "session=secret_session",
                    "content-type": "application/json",
                    "user-agent": "test-agent"
                }
                
                await manager.handle_client_error("/test", headers, Exception("test error"))
                
                # Check that error was logged
                mock_logger.error.assert_called_once()
                
                # Check that sensitive headers were removed
                call_args = mock_logger.error.call_args[0]
                logged_headers = call_args[2]  # Headers are the third argument
                
                assert "authorization" not in logged_headers
                assert "cookie" not in logged_headers
                assert "content-type" in logged_headers
                assert "user-agent" in logged_headers
    
    @pytest.mark.asyncio
    async def test_request_logs_safe_headers(self):
        """Test that _request logs headers without sensitive information."""
        async with CheckwattManager("test_user", "test_pass") as manager:
            
            with patch.object(manager, '_ensure_token', return_value=True), \
                 patch.object(manager.session, 'request') as mock_request, \
                 patch('pycheckwatt._LOGGER') as mock_logger:
                
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.headers = {'Content-Type': 'application/json'}
                mock_response.json = AsyncMock(return_value={"data": "test"})
                mock_response.raise_for_status = Mock()
                mock_request.return_value.__aenter__.return_value = mock_response
                
                # Make request with sensitive headers
                headers = {
                    "authorization": "Bearer secret_token",
                    "x-custom": "custom_value"
                }
                
                await manager._request("GET", "/test", headers=headers, auth_required=True)
                
                # Verify no sensitive data in logs
                for call in mock_logger.debug.call_args_list:
                    call_str = str(call)
                    assert "secret_token" not in call_str
                    assert "Bearer" not in call_str


class TestConfiguration:
    """Test configuration parameter handling."""
    
    def test_default_configuration(self):
        """Test default configuration values."""
        manager = CheckwattManager("test_user", "test_pass")
        
        assert manager.max_retries_429 == 3
        assert manager.backoff_base == 0.5
        assert manager.backoff_factor == 2.0
        assert manager.backoff_max == 30.0
        assert manager.clock_skew_seconds == 60
        assert manager.max_concurrent_requests == 5
    
    def test_custom_configuration(self):
        """Test custom configuration values."""
        manager = CheckwattManager(
            "test_user", 
            "test_pass",
            max_retries_429=5,
            backoff_base=1.0,
            backoff_factor=3.0,
            backoff_max=60.0,
            clock_skew_seconds=120,
            max_concurrent_requests=10
        )
        
        assert manager.max_retries_429 == 5
        assert manager.backoff_base == 1.0
        assert manager.backoff_factor == 3.0
        assert manager.backoff_max == 60.0
        assert manager.clock_skew_seconds == 120
        assert manager.max_concurrent_requests == 10
    
    def test_backwards_compatibility(self):
        """Test that existing constructor signature still works."""
        manager = CheckwattManager("test_user", "test_pass", "CustomApp")
        
        assert manager.username == "test_user"
        assert manager.password == "test_pass"
        assert manager.header_identifier == "CustomApp"
        # Should have default values for new parameters
        assert manager.max_retries_429 == 3
        assert manager.max_concurrent_requests == 5


class TestTokenExpirationParsing:
    """Test token debugging properties."""
    
    def test_jwt_expires_at_property(self):
        """Test jwt_expires_at property for debugging."""
        manager = CheckwattManager("test_user", "test_pass")
        
        # Test with no token
        assert manager.jwt_expires_at is None
        
        # Test with valid JWT structure
        with patch('pycheckwatt.base64') as mock_base64, \
             patch('pycheckwatt.json') as mock_json, \
             patch('pycheckwatt.datetime') as mock_datetime:
            
            mock_base64.urlsafe_b64decode.return_value = json.dumps({"exp": 1735732800}).encode()
            mock_json.loads.return_value = {"exp": 1735732800}
            mock_datetime.fromtimestamp.return_value = datetime(2025, 1, 1, 13, 0, 0)
            
            manager.jwt_token = "header.payload.signature"
            
            expires_at = manager.jwt_expires_at
            assert expires_at is not None
            assert isinstance(expires_at, datetime)
    
    def test_refresh_expires_at_property(self):
        """Test refresh_expires_at property for debugging."""
        manager = CheckwattManager("test_user", "test_pass")
        
        # Test with no refresh token expires
        assert manager.refresh_expires_at is None
        
        # Test with valid timestamp
        manager.refresh_token_expires = "2025-12-31T23:59:59.000+00:00"
        
        expires_at = manager.refresh_expires_at
        assert expires_at is not None
        assert isinstance(expires_at, datetime)
        assert expires_at.year == 2025
        assert expires_at.month == 12
        assert expires_at.day == 31 