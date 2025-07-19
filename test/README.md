# Automated Sharekhan Authentication

This directory contains scripts for automating the Sharekhan API authentication process using TOTP (Time-based One-Time Password).

## Files Overview

- **`automated_auth.py`** - Core automated authentication script with TOTP support
- **`complete_test.py`** - Complete test suite with both manual and automated authentication
- **`config_template.py`** - Template for configuration file
- **`test.py`** - Original test file (updated to support both auth methods)

## Setup Instructions

### 1. Install Required Dependencies

```bash
pip install pyotp
```

Or install from requirements.txt:
```bash
pip install -r requirements.txt
```

### 2. Get Your TOTP Secret Key

1. Login to your Sharekhan account manually
2. Go to **Security** > **Two-Factor Authentication** settings
3. When setting up TOTP/2FA, you'll see:
   - A QR code 
   - A secret key (text string)
4. **Save the secret key** - it looks like: `JBSWY3DPEHPK3PXP` (base32 encoded)
5. You can scan the QR code with an authenticator app, but we need the text secret for automation

### 3. Configure Credentials

1. Copy `config_template.py` to `config.py`:
   ```bash
   cp config_template.py config.py
   ```

2. Edit `config.py` and update with your actual credentials:
   ```python
   API_KEY = "your_actual_api_key"
   SECRET_KEY = "your_actual_secret_key"
   USERNAME = "your_sharekhan_username"
   PASSWORD = "your_sharekhan_password"
   TOTP_SECRET = "your_totp_secret_key"  # The base32 string from step 2
   ```

### 4. Test the Setup

Run the complete test suite:
```bash
python complete_test.py
```

Or test just the automated authentication:
```bash
python automated_auth.py
```

## How It Works

### Automated Authentication Flow

1. **Generate Login URL** - Creates the OAuth login URL
2. **Submit Credentials** - Posts username/password to login endpoint
3. **Handle TOTP** - Generates and submits the TOTP code automatically
4. **Extract Request Token** - Parses the response to get the request_token
5. **Generate Session** - Uses existing SDK methods to create session
6. **Get Access Token** - Obtains the final access token for API calls

### Key Features

- **Automatic TOTP Generation** - No manual intervention needed
- **Error Handling** - Graceful fallback to manual authentication
- **Debugging Output** - Detailed logs for troubleshooting
- **Flexible Configuration** - Supports vendor keys and version IDs

## Usage Examples

### Simple Automated Authentication

```python
from automated_auth import automated_sharekhan_login

access_token = automated_sharekhan_login(
    api_key="your_api_key",
    secret_key="your_secret_key", 
    username="your_username",
    password="your_password",
    totp_secret="your_totp_secret"
)

if access_token:
    # Use access_token for API calls
    sharekhan = SharekhanConnect(api_key=api_key, access_token=access_token)
```

### Integration with Existing Code

```python
from SharekhanApi.sharekhanConnect import SharekhanConnect

# Try automated auth first, fall back to manual
try:
    from automated_auth import automated_sharekhan_login
    access_token = automated_sharekhan_login(...)
    if access_token:
        sharekhan = SharekhanConnect(api_key=api_key, access_token=access_token)
    else:
        # Fall back to manual authentication
        # ... manual login flow
except:
    # Manual authentication as backup
    # ... manual login flow
```

## Troubleshooting

### Common Issues

1. **TOTP Secret Invalid**
   - Ensure you copied the complete base32 string
   - Check that 2FA is properly enabled on your account

2. **Login Endpoints Not Working**
   - Sharekhan might use different URLs than assumed
   - Check the network logs when logging in manually
   - Update the endpoint URLs in `automated_auth.py`

3. **Request Token Not Found**
   - The token extraction logic might need adjustment
   - Check the response format by examining the debug output

4. **Import Errors**
   - Make sure `pyotp` is installed: `pip install pyotp`
   - Ensure `config.py` is created from the template

### Debug Mode

Enable detailed logging by checking the debug output in `automated_auth.py`. The script prints:
- Response status codes
- Response headers  
- Response body (truncated)
- Token extraction attempts

### Manual Fallback

If automated authentication fails, the scripts fall back to manual authentication using hardcoded tokens. This ensures your trading operations can continue while you troubleshoot the automation.

## Security Considerations

- **Store credentials securely** - Don't commit `config.py` to version control
- **Use environment variables** - Consider using environment variables for production
- **Regular token refresh** - Access tokens expire, implement refresh logic
- **Network security** - Use secure networks, consider VPN for trading

## Next Steps

1. Test with small API calls first (like getting account info)
2. Implement token refresh logic for long-running applications  
3. Add logging and monitoring for production use
4. Consider implementing session persistence to reduce login frequency

## Support

If you encounter issues:
1. Check the debug output for error details
2. Verify your credentials are correct
3. Test manual login through the browser first
4. Check Sharekhan's API documentation for endpoint changes
