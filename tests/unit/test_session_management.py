"""
Test enhanced authentication functionality for CheckwattManager.

This module tests the new authentication enhancement features including:
- Automatic authentication management
- Session persistence
- Token refresh
- Encryption/decryption
"""

import asyncio
import json
import os
import tempfile
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Try to import the required dependencies
try:
    from cryptography.fernet import Fernet
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

try:
    import aiofiles
    AIOFILES_AVAILABLE = True
except ImportError:
    AIOFILES_AVAILABLE = False

from pycheckwatt import CheckwattManager


class TestSessionPersistence:
    """Test enhanced authentication functionality."""

    @pytest.fixture
    def temp_session_file(self):
        """Create a temporary session file for testing."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as f:
            yield f.name
        # Clean up only if file still exists
        try:
            os.unlink(f.name)
        except FileNotFoundError:
            pass

    @pytest.fixture
    def manager(self):
        """Create a CheckwattManager instance for testing."""
        return CheckwattManager(
            username="testuser",
            password="testpass",
            persist_sessions=True,
            session_file="/tmp/test_session.json"
        )

    @pytest.fixture
    def mock_session(self):
        """Mock aiohttp session."""
        session = AsyncMock()
        session.request = AsyncMock()
        return session

    def test_enhanced_auth_initialization(self, manager):
        """Test enhanced authentication initialization."""
        assert manager._auth_state is not None
        assert 'jwt_token' in manager._auth_state
        assert 'refresh_token' in manager._auth_state
        assert 'jwt_expires_at' in manager._auth_state
        assert 'refresh_expires_at' in manager._auth_state
        assert 'last_auth_time' in manager._auth_state
        assert 'auth_method' in manager._auth_state
        
        assert manager._session_config is not None
        assert 'persist_sessions' in manager._session_config
        assert 'session_file' in manager._session_config
        assert 'encrypt_sessions' in manager._session_config

    def test_session_config_without_dependencies(self):
        """Test session configuration when dependencies are missing."""
        with patch('pycheckwatt.aiofiles', None):
            with patch('pycheckwatt.CRYPTOGRAPHY_AVAILABLE', False):
                manager = CheckwattManager(
                    username="testuser",
                    password="testpass",
                    persist_sessions=True
                )
                
                assert not manager._session_config['persist_sessions']
                assert not manager._session_config['encrypt_sessions']



    @pytest.mark.asyncio
    async def test_ensure_authenticated_with_valid_jwt(self, manager, mock_session):
        """Test ensure_authenticated with valid JWT."""
        manager.session = mock_session
        
        # Set up valid JWT
        future_time = datetime.now() + timedelta(hours=1)
        manager._auth_state['jwt_token'] = 'valid_token'
        manager._auth_state['jwt_expires_at'] = future_time
        
        result = await manager.ensure_authenticated()
        assert result is True

    @pytest.mark.asyncio
    async def test_ensure_authenticated_with_refresh(self, manager, mock_session):
        """Test ensure_authenticated with refresh token."""
        manager.session = mock_session
        
        # Set up expired JWT but valid refresh
        past_time = datetime.now() - timedelta(hours=1)
        future_time = datetime.now() + timedelta(hours=1)
        
        manager._auth_state['jwt_token'] = 'expired_token'
        manager._auth_state['jwt_expires_at'] = past_time
        manager._auth_state['refresh_token'] = 'valid_refresh'
        manager._auth_state['refresh_expires_at'] = future_time
        
        # Mock successful refresh
        with patch.object(manager, '_refresh_tokens', return_value=True):
            result = await manager.ensure_authenticated()
            assert result is True

    @pytest.mark.asyncio
    async def test_ensure_authenticated_with_login(self, manager, mock_session):
        """Test ensure_authenticated with password login."""
        manager.session = mock_session
        
        # Set up expired tokens
        past_time = datetime.now() - timedelta(hours=1)
        manager._auth_state['jwt_token'] = 'expired_token'
        manager._auth_state['jwt_expires_at'] = past_time
        manager._auth_state['refresh_token'] = 'expired_refresh'
        manager._auth_state['refresh_expires_at'] = past_time
        
        # Mock successful login
        with patch.object(manager, '_perform_login', return_value=True):
            result = await manager.ensure_authenticated()
            assert result is True









    @pytest.mark.skipif(not AIOFILES_AVAILABLE, reason="aiofiles not available")
    @pytest.mark.asyncio
    async def test_save_session_success(self, manager, temp_session_file):
        """Test successful session saving."""
        manager._session_config['session_file'] = temp_session_file
        
        # Set up auth state
        future_time = datetime.now() + timedelta(hours=1)
        manager._auth_state.update({
            'jwt_token': 'test_token',
            'refresh_token': 'test_refresh',
            'jwt_expires_at': future_time,
            'refresh_expires_at': future_time,
            'last_auth_time': datetime.now(),
            'auth_method': 'password'
        })
        
        result = await manager._save_session()
        assert result is True
        
        # Verify file was created
        assert os.path.exists(temp_session_file)

    @pytest.mark.skipif(not AIOFILES_AVAILABLE, reason="aiofiles not available")
    @pytest.mark.asyncio
    async def test_load_session_success(self, manager, temp_session_file):
        """Test successful session loading."""
        manager._session_config['session_file'] = temp_session_file
        
        # Create test session data
        future_time = datetime.now() + timedelta(hours=1)
        session_data = {
            'version': '1.0',
            'username': 'testuser',
            'auth_state': {
                'jwt_token': 'loaded_token',
                'refresh_token': 'loaded_refresh',
                'jwt_expires_at': future_time,
                'refresh_expires_at': future_time,
                'last_auth_time': datetime.now(),
                'auth_method': 'password'
            },
            'timestamp': datetime.now().isoformat()
        }
        
        # Save session data - always encrypted when cryptography is available
        encrypted_data = manager._encrypt_session_data(session_data)
        
        with open(temp_session_file, 'w') as f:
            f.write(encrypted_data)
        
        # Load session
        result = await manager._load_session()
        assert result is True
        
        # Verify state was restored
        assert manager._auth_state['jwt_token'] == 'loaded_token'
        assert manager._auth_state['refresh_token'] == 'loaded_refresh'

    @pytest.mark.asyncio
    async def test_clear_session(self, manager, temp_session_file):
        """Test session clearing."""
        manager._session_config['session_file'] = temp_session_file
        
        # Set up auth state
        manager._auth_state.update({
            'jwt_token': 'test_token',
            'refresh_token': 'test_refresh',
            'jwt_expires_at': datetime.now() + timedelta(hours=1),
            'refresh_expires_at': datetime.now() + timedelta(hours=1),
            'last_auth_time': datetime.now(),
            'auth_method': 'password'
        })
        
        # Create session file
        with open(temp_session_file, 'w') as f:
            f.write('test')
        
        await manager._clear_session()
        
        # Verify state was cleared
        assert manager._auth_state['jwt_token'] is None
        assert manager._auth_state['refresh_token'] is None
        
        # Verify file was removed
        assert not os.path.exists(temp_session_file)



    @pytest.mark.asyncio
    async def test_public_session_methods(self, manager, temp_session_file):
        """Test public session management methods."""
        # Test load_session
        result = await manager.load_session(temp_session_file)
        assert result is False  # No file exists yet
        
        # Test save_session - should fail if no auth state and no aiofiles
        if not AIOFILES_AVAILABLE:
            result = await manager.save_session(temp_session_file)
            assert result is False  # No aiofiles available
        else:
            # Set up some auth state to test saving
            future_time = datetime.now() + timedelta(hours=1)
            manager._auth_state.update({
                'jwt_token': 'test_token',
                'jwt_expires_at': future_time,
                'refresh_expires_at': future_time,
                'last_auth_time': datetime.now(),
                'auth_method': 'password'
            })
            result = await manager.save_session(temp_session_file)
            assert result is True  # Should succeed with auth state
        
        # Test clear_session
        await manager.clear_session()  # Should not raise
        
        # Test get_session_info
        info = manager.get_session_info()
        assert isinstance(info, dict)
        assert 'authenticated' in info





    def test_backward_compatibility(self):
        """Test that existing functionality still works."""
        # Test constructor without new parameters
        manager = CheckwattManager(username="testuser", password="testpass")
        
        # Verify default values - these depend on whether dependencies are available
        if not AIOFILES_AVAILABLE:
            assert manager._session_config['persist_sessions'] is False
            assert manager._session_config['session_file'] is None
        else:
            assert manager._session_config['persist_sessions'] is True
            # With our new default session file logic, session_file will have a default path
            assert manager._session_config['session_file'] is not None
        
        # Encryption is always enabled when cryptography is available
        if CRYPTOGRAPHY_AVAILABLE:
            assert manager._session_config['encrypt_sessions'] is True
        else:
            assert manager._session_config['encrypt_sessions'] is False
        
        # Verify existing attributes still exist
        assert hasattr(manager, 'jwt_token')
        assert hasattr(manager, 'refresh_token')
        assert hasattr(manager, 'refresh_token_expires')
        assert hasattr(manager, '_ensure_token')  # Old method still exists
