import pyotp
import requests
import re
from urllib.parse import parse_qs, urlparse
from SharekhanApi.sharekhanConnect import SharekhanConnect
import time

class AutomatedSharekhanAuth:
    def __init__(self, api_key, secret_key, username, password, totp_secret):
        """
        Initialize automated authentication
        
        Args:
            api_key: Your API key
            secret_key: Your secret key  
            username: Your Sharekhan username
            password: Your Sharekhan password
            totp_secret: Your TOTP secret key (base32 encoded string)
        """
        self.api_key = api_key
        self.secret_key = secret_key
        self.username = username
        self.password = password
        self.totp_secret = totp_secret
        self.session = requests.Session()
        self.sharekhan_connect = SharekhanConnect(api_key)
        
    def generate_totp(self):
        """Generate TOTP code using the secret key"""
        totp = pyotp.TOTP(self.totp_secret)
        return totp.now()
    
    def automated_login(self, vendor_key="", version_id=""):
        """
        Perform automated login and return access token
        
        Args:
            vendor_key: Vendor key (optional)
            version_id: Version ID (optional)
            
        Returns:
            access_token: The access token for API calls
        """
        try:
            # Step 1: Get login URL
            login_url = self.sharekhan_connect.login_url(vendor_key, version_id)
            print(f"Login URL: {login_url}")
            
            # Step 2: Navigate to login page
            response = self.session.get(login_url)
            if response.status_code != 200:
                raise Exception(f"Failed to access login page: {response.status_code}")
            
            # Step 3: Extract any necessary form data or tokens from the login page
            # This might include CSRF tokens or other hidden form fields
            login_page_content = response.text
            
            # Step 4: Prepare login data
            login_data = {
                'username': self.username,
                'password': self.password,
                'api_key': self.api_key
            }
            
            # Add vendor_key if provided
            if vendor_key:
                login_data['vendor_key'] = vendor_key
                
            # Add version_id if provided  
            if version_id:
                login_data['version_id'] = version_id
                
            # Add state parameter
            login_data['state'] = '12345'
            
            # Step 5: Submit login credentials
            login_response = self.session.post(
                "https://api.sharekhan.com/skapi/auth/login",
                data=login_data,
                allow_redirects=False
            )
            
            # Step 6: Handle TOTP if required
            if login_response.status_code == 302 or 'otp' in login_response.text.lower():
                # Generate TOTP
                totp_code = self.generate_totp()
                print(f"Generated TOTP: {totp_code}")
                
                # Submit TOTP
                totp_data = {
                    'otp': totp_code,
                    'api_key': self.api_key,
                    'state': '12345'
                }
                
                if vendor_key:
                    totp_data['vendor_key'] = vendor_key
                if version_id:
                    totp_data['version_id'] = version_id
                    
                totp_response = self.session.post(
                    "https://api.sharekhan.com/skapi/auth/verify-otp",  # Adjust URL as needed
                    data=totp_data,
                    allow_redirects=False
                )
                
                final_response = totp_response
            else:
                final_response = login_response
            
            # Step 7: Extract request_token from redirect or response
            request_token = self.extract_request_token(final_response)
            
            if not request_token:
                raise Exception("Failed to extract request_token from login response")
                
            print(f"Extracted request_token: {request_token}")
            
            # Step 8: Generate session and access token
            if version_id:
                session = self.sharekhan_connect.generate_session(request_token, self.secret_key)
                access_token_response = self.sharekhan_connect.get_access_token(
                    self.api_key, session, 12345, versionId=version_id
                )
            else:
                session = self.sharekhan_connect.generate_session_without_versionId(request_token, self.secret_key)
                access_token_response = self.sharekhan_connect.get_access_token(
                    self.api_key, session, 12345
                )
            
            # Extract access token from response
            if isinstance(access_token_response, dict) and 'access_token' in access_token_response:
                access_token = access_token_response['access_token']
            else:
                access_token = access_token_response
                
            print(f"Access token obtained: {access_token}")
            return access_token
            
        except Exception as e:
            print(f"Authentication failed: {str(e)}")
            return None
    
    def extract_request_token(self, response):
        """
        Extract request_token from login response
        
        Args:
            response: HTTP response object
            
        Returns:
            request_token: The extracted request token
        """
        # Method 1: Check redirect location
        if 'Location' in response.headers:
            redirect_url = response.headers['Location']
            parsed_url = urlparse(redirect_url)
            query_params = parse_qs(parsed_url.query)
            if 'request_token' in query_params:
                return query_params['request_token'][0]
        
        # Method 2: Check response body for token
        response_text = response.text
        
        # Look for request_token in various formats
        patterns = [
            r'request_token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'requestToken["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'<input[^>]*name=["\']request_token["\'][^>]*value=["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Method 3: Check if token is in URL fragment
        if '#' in response.url:
            fragment = response.url.split('#')[1]
            fragment_params = parse_qs(fragment)
            if 'request_token' in fragment_params:
                return fragment_params['request_token'][0]
        
        return None


def main():
    # Configuration - Replace with your actual credentials
    api_key = "LOicbnwvRSVTxk3wtZqvD1MSdbFFrxya"
    secret_key = "PCbEDV4QGR4oE1nlh4TLpo1ZWo8LxdRX"
    
    # Replace these with your actual credentials
    username = "your_username"  # Your Sharekhan username
    password = "your_password"  # Your Sharekhan password
    totp_secret = "YOUR_TOTP_SECRET_KEY"  # Your TOTP secret key (base32 format)
    
    # Create automated auth instance
    auth = AutomatedSharekhanAuth(api_key, secret_key, username, password, totp_secret)
    
    # Perform automated login
    access_token = auth.automated_login()
    
    if access_token:
        print("Authentication successful!")
        
        # Initialize SharekhanConnect with the obtained access token
        sharekhan = SharekhanConnect(api_key=api_key, access_token=access_token)
        print(sharekhan.requestHeaders())
        
        # Test API calls
        try:
            # You can now use all the API methods as in the original test.py
            print("\n=== Testing API calls ===")
            
            # Example: Get fund details (replace with actual customerId)
            # exchange = "MX"
            # customerId = "your_customer_id"
            # fund_details = sharekhan.funds(exchange, customerId)
            # print(f"Fund Details: {fund_details}")
            
            print("Ready for API operations!")
            
        except Exception as e:
            print(f"API call failed: {str(e)}")
    else:
        print("Authentication failed!")


if __name__ == "__main__":
    main()
