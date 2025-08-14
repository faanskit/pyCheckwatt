# pyCheckwatt Authentication Upgrade

This document describes the new refresh-token authentication and 429 backoff functionality added to pyCheckwatt.

## Overview

The upgrade adds a robust authentication layer that:
- Uses refresh tokens to minimize password logins
- Handles 429 rate limiting with intelligent backoff
- Provides centralized request handling with automatic retries
- Maintains full backwards compatibility

## New Features

### 1. Refresh Token Authentication

Instead of logging in with username/password for every request, the system now:
- Stores JWT and refresh tokens after successful login
- Automatically refreshes JWT tokens when they expire
- Falls back to password login only when refresh tokens are invalid
- Uses an authentication lock to prevent duplicate refresh attempts

### 2. Intelligent 429 Handling

When the API returns 429 (Too Many Requests), the system:
- Honors `Retry-After` headers if present
- Uses exponential backoff with jitter when no retry-after is specified
- Configurable retry limits and backoff parameters
- Prevents aggressive spinning during rate limiting

### 3. Centralized Request Wrapper

All API calls now go through a unified `_request` method that:
- Automatically handles authentication
- Manages retries and backoff
- Provides consistent error handling
- Supports both authenticated and public endpoints

### 4. Concurrency Control

- Authentication operations are protected by an async lock
- Configurable semaphore limits concurrent outbound requests
- Prevents thundering herd during token refresh

## Configuration

### New Constructor Parameters

All new parameters are optional with sensible defaults:

```python
CheckwattManager(
    username, 
    password, 
    application="pyCheckwatt",
    *,  # Keyword-only arguments
    max_retries_429: int = 3,           # Max retries on 429
    backoff_base: float = 0.5,          # Base delay for exponential backoff
    backoff_factor: float = 2.0,        # Multiplier for exponential backoff
    backoff_max: float = 30.0,          # Maximum backoff delay
    clock_skew_seconds: int = 60,       # JWT expiration buffer
    max_concurrent_requests: int = 5,   # Max concurrent API requests
    killswitch_ttl_seconds: int = 900   # Kill switch cache TTL (15 min)
)
```

### Default Values

- **max_retries_429**: 3 attempts
- **backoff_base**: 0.5 seconds
- **backoff_factor**: 2.0 (doubles each retry)
- **backoff_max**: 30.0 seconds
- **clock_skew_seconds**: 60 seconds
- **max_concurrent_requests**: 5
- **killswitch_ttl_seconds**: 900 seconds (15 minutes)

## Usage Examples

### Basic Usage (No Changes Required)

```python
# Existing code continues to work unchanged
async with CheckwattManager("username", "password") as cw:
    await cw.login()           # Now uses refresh tokens after first run
    await cw.get_customer_details()
    await cw.get_price_zone()
```

### Custom Configuration

```python
# Configure for high-traffic scenarios
async with CheckwattManager(
    "username", 
    "password",
    max_retries_429=5,              # More retries
    backoff_base=1.0,               # Higher base delay
    max_concurrent_requests=10      # More concurrent requests
) as cw:
    # Your code here
```

### Debug Token Information

```python
manager = CheckwattManager("username", "password")

# Check token expiration times (for debugging)
if manager.jwt_expires_at:
    print(f"JWT expires at: {manager.jwt_expires_at}")
    
if manager.refresh_expires_at:
    print(f"Refresh token expires at: {manager.refresh_expires_at}")
```

## Authentication Flow

### 1. Initial Login
```
User Login → Store JWT + Refresh Token + Expiration
```

### 2. Subsequent Requests
```
Check JWT validity
├─ Valid → Use JWT
├─ Expired → Try Refresh Token
│   ├─ Success → Update tokens, retry request
│   └─ Failed → Fall back to password login
```

### 3. 401 Handling
```
Request returns 401
├─ Try refresh token → Retry request
├─ Refresh fails → Try password login → Retry request
└─ All fail → Return error
```

### 4. 429 Handling
```
Request returns 429
├─ Check Retry-After header
│   ├─ Present → Wait specified time
│   └─ Missing → Use exponential backoff
└─ Retry up to max_retries_429 times
```

## Backwards Compatibility

### What Still Works
- All existing constructor signatures
- All public methods and their signatures
- All existing properties and attributes
- Home Assistant integration code

### What's New
- Additional constructor parameters (all optional)
- New internal methods (prefixed with `_`)
- New debugging properties
- Enhanced error handling and logging

## Performance Improvements

### Reduced Server Load
- **Before**: Password login on every session
- **After**: Password login only when refresh tokens expire
- **Expected reduction**: >90% fewer password logins

### Better Rate Limit Handling
- **Before**: Immediate failure on 429
- **After**: Intelligent retry with backoff
- **Result**: Higher success rates during peak usage

### Concurrency Optimization
- **Before**: Uncontrolled concurrent requests
- **After**: Configurable concurrency limits
- **Benefit**: Smoother API interaction, reduced server stress

## Security Features

### Token Management
- JWT tokens are validated before use
- Refresh tokens have expiration checks
- Automatic fallback to password authentication

### Secure Logging
- Authorization headers are never logged
- Sensitive tokens are scrubbed from error messages
- Debug information excludes sensitive data

### Kill Switch Integration
- Cached kill switch status with TTL
- Prevents unnecessary network calls
- Respects server-side rate limiting requests

## Error Handling

### Network Errors
- Automatic retry with exponential backoff
- Configurable retry limits
- Graceful degradation on persistent failures

### Authentication Errors
- Automatic token refresh on 401
- Fallback to password login
- Clear error messages without sensitive data

### Rate Limiting
- Respects server Retry-After headers
- Intelligent backoff when no guidance provided
- Prevents aggressive retry loops

## Monitoring and Debugging

### Logging Levels
- **INFO**: Authentication state changes (login/refresh)
- **WARNING**: Retry attempts, rate limiting
- **ERROR**: Authentication failures, network errors
- **DEBUG**: Request details, timing information

### Debug Properties
```python
# Check token status
print(f"JWT valid: {manager._jwt_is_valid()}")
print(f"Refresh valid: {manager._refresh_is_valid()}")

# Check expiration times
print(f"JWT expires: {manager.jwt_expires_at}")
print(f"Refresh expires: {manager.refresh_expires_at}")
```

## Migration Guide

### For Existing Users
**No changes required.** All existing code continues to work exactly as before.

### For New Integrations
Consider configuring parameters based on your use case:

```python
# High-frequency polling (e.g., Home Assistant)
manager = CheckwattManager(
    username, password,
    max_concurrent_requests=3,      # Conservative concurrency
    backoff_base=0.5               # Quick retries
)

# Batch processing
manager = CheckwattManager(
    username, password,
    max_concurrent_requests=10,     # Higher concurrency
    backoff_base=1.0               # Slower retries
)
```

## Testing

### Unit Tests
Comprehensive test coverage for:
- Authentication lifecycle
- Token validation
- Request retry logic
- Concurrency control
- Security features

### Integration Testing
- Real API interaction tests
- Rate limiting simulation
- Error condition handling

## Troubleshooting

### Common Issues

#### JWT Decoding Errors
- **Symptom**: `_jwt_is_valid()` returns False
- **Cause**: Malformed JWT or unsupported format
- **Solution**: System falls back to refresh/login automatically

#### Refresh Token Failures
- **Symptom**: Frequent password logins
- **Cause**: Refresh token expired or invalid
- **Solution**: Check server-side refresh token validity

#### Rate Limiting
- **Symptom**: Requests taking longer than expected
- **Cause**: 429 responses triggering backoff
- **Solution**: Adjust `max_retries_429` and backoff parameters

### Debug Mode
Enable debug logging to see detailed request flow:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Future Enhancements

### Phase 2 (Planned)
- Extract auth logic into separate classes
- Add token persistence across sessions
- Implement connection pooling
- Add metrics and monitoring

### Configuration Management
- Environment variable support
- Configuration file loading
- Runtime parameter adjustment

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review debug logs for detailed information
3. Verify configuration parameters
4. Test with minimal configuration

## Changelog

### Version 0.3.0
- Added refresh token authentication
- Implemented 429 backoff handling
- Added centralized request wrapper
- Enhanced concurrency control
- Improved security and logging
- Maintained full backwards compatibility 