"""
Automated Sharekhan Authentication with TOTP

This script automates the Sharekhan login process using TOTP (Time-based One-Time Password).

SETUP INSTRUCTIONS:
1. Install required package: pip install pyotp
2. Get your TOTP secret key:
   - Login to your Sharekhan account manually
   - Go to security/2FA settings
   - When setting up TOTP, you'll get a QR code AND a secret key
   - Save that secret key (it's a base32 encoded string like "JBSWY3DPEHPK3PXP")
3. Replace the credentials below with your actual values

IMPORTANT NOTES:
- This script assumes Sharekhan's login flow follows standard OAuth patterns
- You may need to adjust the login endpoints based on actual Sharekhan API documentation
- The script includes error handling and debugging output
- Test with a small API call first before using for trading
"""

import pyotp
import requests
import re
import json
import time
from urllib.parse import parse_qs, urlparse, unquote
from SharekhanApi.sharekhanConnect import SharekhanConnect

def generate_totp_code(totp_secret):
    """Generate TOTP code from secret"""
    try:
        totp = pyotp.TOTP(totp_secret)
        return totp.now()
    except Exception as e:
        print(f"Error generating TOTP: {e}")
        return None

def extract_request_token_from_response(response):
    """
    Extract request_token from various possible locations in the response
    """
    print(f"Response status: {response.status_code}")
    print(f"Response headers: {dict(response.headers)}")
    
    # Check redirect location first
    if 'Location' in response.headers:
        location = response.headers['Location']
        print(f"Redirect location: {location}")
        
        # Parse URL parameters
        parsed = urlparse(location)
        params = parse_qs(parsed.query)
        
        if 'request_token' in params:
            token = params['request_token'][0]
            print(f"Found request_token in redirect: {token}")
            return unquote(token)
    
    # Check response text
    response_text = response.text
    print(f"Response text (first 500 chars): {response_text[:500]}")
    
    # Look for various token patterns
    token_patterns = [
        r'request_token["\']?\s*[:=]\s*["\']([^"\'&\s]+)',
        r'requestToken["\']?\s*[:=]\s*["\']([^"\'&\s]+)',
        r'token["\']?\s*[:=]\s*["\']([^"\'&\s]+)',
        r'<input[^>]*name=["\']?request_token["\']?[^>]*value=["\']([^"\']+)',
        r'value=["\']([^"\']*request_token[^"\']*)["\']',
    ]
    
    for pattern in token_patterns:
        matches = re.findall(pattern, response_text, re.IGNORECASE)
        for match in matches:
            if len(match) > 10:  # Reasonable token length
                print(f"Found potential token with pattern '{pattern}': {match}")
                return match
    
    return None

def automated_sharekhan_login(api_key, secret_key, username, password, totp_secret, vendor_key="", version_id=""):
    """
    Automated login to Sharekhan and get access token
    
    Args:
        api_key: Your API key
        secret_key: Your secret key
        username: Your Sharekhan username  
        password: Your Sharekhan password
        totp_secret: Your TOTP secret key
        vendor_key: Optional vendor key
        version_id: Optional version ID
        
    Returns:
        access_token or None if failed
    """
    
    print("=== Starting Automated Sharekhan Login ===")
    
    try:
        # Initialize SharekhanConnect
        sharekhan = SharekhanConnect(api_key)
        
        # Get login URL
        login_url = sharekhan.login_url(vendor_key, version_id)
        print(f"Login URL: {login_url}")
        
        # Create session for maintaining cookies
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Step 1: Get the login page
        print("\n1. Accessing login page...")
        login_page_response = session.get(login_url)
        
        if login_page_response.status_code != 200:
            print(f"Failed to access login page: {login_page_response.status_code}")
            return None
        
        # Step 2: Prepare login data
        print("\n2. Preparing login credentials...")
        login_data = {
            'username': username,
            'password': password,
            'api_key': api_key,
            'state': '12345'
        }
        
        if vendor_key:
            login_data['vendor_key'] = vendor_key
        if version_id:
            login_data['version_id'] = version_id
            
        print(f"Login data (without password): {dict((k, v) for k, v in login_data.items() if k != 'password')}")
        
        # Step 3: Submit login credentials
        print("\n3. Submitting login credentials...")
        
        # Try the main login endpoint
        login_submit_url = "https://api.sharekhan.com/skapi/auth/login"
        login_response = session.post(
            login_submit_url,
            data=login_data,
            allow_redirects=True,
            timeout=30
        )
        
        print(f"Login response status: {login_response.status_code}")
        
        # Check if TOTP is required
        needs_totp = any(keyword in login_response.text.lower() for keyword in ['otp', 'authentication', 'verify', 'token'])
        
        if needs_totp or login_response.status_code in [302, 401, 403]:
            print("\n4. TOTP verification required...")
            
            # Generate TOTP code
            totp_code = generate_totp_code(totp_secret)
            if not totp_code:
                print("Failed to generate TOTP code")
                return None
                
            print(f"Generated TOTP: {totp_code}")
            
            # Submit TOTP
            totp_data = login_data.copy()
            totp_data['otp'] = totp_code
            
            # Try different TOTP endpoints
            totp_endpoints = [
                "https://api.sharekhan.com/skapi/auth/verify-otp",
                "https://api.sharekhan.com/skapi/auth/totp",
                "https://api.sharekhan.com/skapi/auth/verify"
            ]
            
            totp_success = False
            final_response = None
            
            for endpoint in totp_endpoints:
                try:
                    print(f"Trying TOTP endpoint: {endpoint}")
                    totp_response = session.post(
                        endpoint,
                        data=totp_data,
                        allow_redirects=True,
                        timeout=30
                    )
                    
                    if totp_response.status_code == 200:
                        final_response = totp_response
                        totp_success = True
                        print(f"TOTP successful with endpoint: {endpoint}")
                        break
                        
                except requests.exceptions.RequestException as e:
                    print(f"TOTP endpoint {endpoint} failed: {e}")
                    continue
            
            if not totp_success:
                print("All TOTP endpoints failed")
                final_response = login_response
        else:
            final_response = login_response
        
        # Step 5: Extract request_token
        print("\n5. Extracting request_token...")
        request_token = extract_request_token_from_response(final_response)
        
        if not request_token:
            print("Failed to extract request_token")
            print("Please check the login flow manually and update the token extraction logic")
            return None
            
        print(f"Extracted request_token: {request_token[:50]}...")
        
        # Step 6: Generate session and access token
        print("\n6. Generating session and access token...")
        
        try:
            if version_id:
                print("Using version_id method...")
                session_token = sharekhan.generate_session(request_token, secret_key)
                access_response = sharekhan.get_access_token(api_key, session_token, 12345, versionId=version_id)
            else:
                print("Using method without version_id...")
                session_token = sharekhan.generate_session_without_versionId(request_token, secret_key)
                access_response = sharekhan.get_access_token(api_key, session_token, 12345)
            
            print(f"Access token response: {access_response}")
            
            # Extract access token
            if isinstance(access_response, dict):
                access_token = access_response.get('access_token') or access_response.get('accessToken')
            else:
                access_token = access_response
                
            if access_token:
                print(f"\n✅ SUCCESS! Access token obtained: {access_token[:50]}...")
                return access_token
            else:
                print("❌ Failed to extract access token from response")
                return None
                
        except Exception as e:
            print(f"❌ Error during session generation: {e}")
            return None
            
    except Exception as e:
        print(f"❌ Automated login failed: {e}")
        return None

def main():
    """
    Main function - Replace the credentials below with your actual values
    """
    
    # === CONFIGURATION - REPLACE WITH YOUR ACTUAL VALUES ===
    api_key = "LOicbnwvRSVTxk3wtZqvD1MSdbFFrxya"
    secret_key = "PCbEDV4QGR4oE1nlh4TLpo1ZWo8LxdRX"
    
    # REPLACE THESE WITH YOUR ACTUAL CREDENTIALS
    username = "sandeepv1973"           # Your Sharekhan username
    password = "Lakshya@2001"           # Your Sharekhan password  
    totp_secret = "JTRVZYSMCRJBPSPI"     # Your TOTP secret key (base32 format)
    
    # Optional parameters
    vendor_key = ""    # Leave empty if not using vendor login
    version_id = ""    # Leave empty or use "1005"/"1006" if required
    
    # === SAFETY CHECK ===
    if username == "YOUR_USERNAME" or password == "YOUR_PASSWORD" or totp_secret == "YOUR_TOTP_SECRET":
        print("❌ Please update the credentials in the script before running!")
        print("\nTo get your TOTP secret:")
        print("1. Login to Sharekhan manually")
        print("2. Go to Security/2FA settings")
        print("3. When setting up TOTP, save the secret key (base32 string)")
        print("4. Update the variables in this script")
        return
    
    # === AUTOMATED LOGIN ===
    access_token = automated_sharekhan_login(
        api_key=api_key,
        secret_key=secret_key,
        username=username,
        password=password,
        totp_secret=totp_secret,
        vendor_key=vendor_key,
        version_id=version_id
    )
    
    if access_token:
        print("\n🎉 Authentication successful!")
        
        # Initialize SharekhanConnect with access token
        sharekhan = SharekhanConnect(api_key=api_key, access_token=access_token)
        
        # Test the connection
        print("\n=== Testing API Connection ===")
        headers = sharekhan.requestHeaders()
        print(f"Request headers: {headers}")
        
        # You can now use all the API methods from your original test.py
        print("\n✅ Ready for API operations!")
        print("You can now use sharekhan.funds(), sharekhan.placeOrder(), etc.")
        
        # Example usage (uncomment and modify as needed):
        # try:
        #     # Test with actual customer ID
        #     customer_id = "YOUR_CUSTOMER_ID"
        #     exchange = "MX"
        #     fund_details = sharekhan.funds(exchange, customer_id)
        #     print(f"Fund details: {fund_details}")
        # except Exception as e:
        #     print(f"API test failed: {e}")
        
    else:
        print("\n❌ Authentication failed!")
        print("Please check your credentials and try again.")

if __name__ == "__main__":
    main()
