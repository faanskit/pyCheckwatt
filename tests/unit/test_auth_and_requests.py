"""Test authentication and request wrapper functionality."""

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, Mock, patch, MagicMock
import asyncio
import json
from datetime import datetime, timedelta
import logging

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
                # Tokens should remain unchanged
                assert manager.jwt_token is None
    
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

    @pytest.mark.asyncio
    async def test_auth_statistics_tracking(self):
        """Test that authentication statistics are properly tracked."""
        manager = CheckwattManager("test_user", "test_pass")
        
        # Check initial stats
        stats = manager.get_auth_statistics()
        assert stats["password_logins"] == 0
        assert stats["token_refreshes"] == 0
        assert stats["requests_with_jwt"] == 0
        assert stats["requests_with_password"] == 0
        assert stats["total_requests"] == 0
        assert stats["last_auth_method"] is None
        
        # Simulate some authentication activity
        manager._auth_stats["password_logins"] = 2
        manager._auth_stats["token_refreshes"] = 1
        manager._auth_stats["requests_with_jwt"] = 15
        manager._auth_stats["requests_with_password"] = 3
        manager._auth_stats["total_requests"] = 20
        manager._auth_stats["last_auth_method"] = "jwt"
        
        # Check updated stats
        stats = manager.get_auth_statistics()
        assert stats["password_logins"] == 2
        assert stats["token_refreshes"] == 1
        assert stats["requests_with_jwt"] == 15
        assert stats["requests_with_password"] == 3
        assert stats["total_requests"] == 20
        assert stats["last_auth_method"] == "jwt"
        
        # Test reset functionality
        manager.reset_auth_statistics()
        stats = manager.get_auth_statistics()
        assert stats["password_logins"] == 0
        assert stats["token_refreshes"] == 0
        assert stats["requests_with_jwt"] == 0
        assert stats["requests_with_password"] == 0
        assert stats["total_requests"] == 0
        assert stats["last_auth_method"] is None

    @pytest.mark.asyncio
    async def test_auth_state_logging(self):
        """Test that authentication state logging methods work correctly."""
        manager = CheckwattManager("test_user", "test_pass")
        
        # Test with no tokens
        manager._log_auth_state("Empty state")
        
        # Test with valid tokens
        manager.jwt_token = "test.jwt.token"
        manager.refresh_token = "test_refresh_token"
        manager.refresh_token_expires = "2025-12-31T23:59:59.000+00:00"
        
        manager._log_auth_state("With tokens")
        
        # Test statistics logging
        manager._log_auth_stats("Initial stats") 