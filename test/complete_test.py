
import os
import sys
from SharekhanApi.sharekhanConnect import SharekhanConnect

def load_config():
    """Load configuration from config.py if it exists"""
    try:
        import config as config
        return config
    except ImportError:
        print("❌ config.py not found. Please copy config_template.py to config.py and update credentials.")
        return None

def test_automated_authentication(config):
    """Test automated authentication with TOTP"""
    try:
        from SharekhanApi.automated_auth import automated_sharekhan_login
        
        print("🔄 Attempting automated authentication...")
        
        access_token = automated_sharekhan_login(
            api_key=config.API_KEY,
            secret_key=config.SECRET_KEY,
            username=config.USERNAME,
            password=config.PASSWORD,
            totp_secret=config.TOTP_SECRET,
            vendor_key=config.VENDOR_KEY,
            version_id=config.VERSION_ID
        )
        
        if access_token:
            print("✅ Automated authentication successful!")
            return config.API_KEY, access_token
        else:
            print("❌ Automated authentication failed")
            return None, None
            
    except ImportError:
        print("❌ automated_auth.py not found")
        return None, None
    except Exception as e:
        print(f"❌ Automated authentication error: {e}")
        return None, None

def test_manual_authentication(config):
    """Test manual authentication (fallback)"""
    print("🔄 Using manual authentication...")
    
    # Use hardcoded token for testing (replace with actual token from login flow)
    access_token = "eyJ0eXAiOiJzZWMiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI4Z0dNS0FKNFJJbFlNdEd5SU8zOHhlcThkRDVPQVNUTFZlK3poRXFSQTd1ZXVza3laRm8xeVF5dnJkcGdYb0MwU2lMT3dLREtMbi9henh0VXNqOXhUOGZaMWZzWWp0eG83SXU1OW5YUFhsa2l0cGRXOTdsTlJ4TGNWOVFDMzVHMGN5SlNlaWltQ2VDVWlNOVNNQXlCd1pNWUtzTjFiaDRhcFd0ZDg5L0lJWlU9IiwiaWF0IjoxNzUyOTExMTI5LCJleHAiOjE3NTI5NDk3OTl9.B1dlH4udZHcVTQhvWL3BfksF1sXd1KNm0l1P_EREJmQ"
    
    print("ℹ️  Using hardcoded access token for manual testing")
    print("ℹ️  For live trading, get a fresh token from the login flow")
    
    return config.API_KEY, access_token

def test_api_functions(sharekhan):
    """Test various API functions"""
    
    print("\n=== Testing API Functions ===")
    
    # Test 1: Request Headers
    print("\n1. Testing request headers...")
    try:
        headers = sharekhan.requestHeaders()
        print(f"✅ Request headers: {headers}")
    except Exception as e:
        print(f"❌ Request headers failed: {e}")
    
    # Test 2: Place Order (with dummy data)
    print("\n2. Testing place order (dummy data)...")
    try:
        orderparams = {
            "customerId": "XXXXXXX",
            "scripCode": 2475,
            "tradingSymbol": "ONGC",
            "exchange": "NC",
            "transactionType": "B",
            "quantity": 1,
            "disclosedQty": 0,
            "price": "149.5",
            "triggerPrice": "0",
            "rmsCode": "ANY",
            "afterHour": "N",
            "orderType": "NORMAL",
            "channelUser": "XXXXXXX",
            "validity": "GFD",
            "requestType": "NEW",
            "productType": "INVESTMENT"
        }
        
        # Note: This will likely fail with dummy data, but tests the API call structure
        order = sharekhan.placeOrder(orderparams)
        print(f"✅ Place order response: {order}")
    except Exception as e:
        print(f"⚠️  Place order failed (expected with dummy data): {e}")
    
    # Test 3: Script Master
    print("\n3. Testing script master...")
    try:
        exchange = "MX"
        master_data = sharekhan.master(exchange)
        print(f"✅ Script master response (first 200 chars): {str(master_data)[:200]}...")
    except Exception as e:
        print(f"❌ Script master failed: {e}")
    
    print("\n=== API Testing Complete ===")

def main():
    print("🚀 Starting Sharekhan API Test Suite")
    print("=" * 50)
    
    # Load configuration
    config = load_config()
    if not config:
        return
    
    # Check if credentials are configured
    if (config.USERNAME == "YOUR_USERNAME" or 
        config.PASSWORD == "YOUR_PASSWORD" or 
        config.TOTP_SECRET == "YOUR_TOTP_SECRET_KEY"):
        
        print("⚠️  Credentials not configured for automated auth")
        print("⚠️  Using manual authentication with hardcoded token")
        use_automated = False
    else:
        use_automated = True
    
    # Try authentication
    api_key = None
    access_token = None
    
    if use_automated:
        # Try automated authentication first
        api_key, access_token = test_automated_authentication(config)
    
    if not access_token:
        # Fall back to manual authentication
        api_key, access_token = test_manual_authentication(config)
    
    if not access_token:
        print("❌ All authentication methods failed!")
        return
    
    # Initialize SharekhanConnect
    print(f"\n✅ Authentication successful!")
    sharekhan = SharekhanConnect(api_key=api_key, access_token=access_token)
    
    # Test API functions
    test_api_functions(sharekhan)
    
    # WebSocket test
    print("\n=== WebSocket Test ===")
    try:
        from SharekhanApi.sharekhanWebsocket import SharekhanWebSocket
        
        print("✅ WebSocket class imported successfully")
        print("ℹ️  WebSocket testing requires market hours and valid subscriptions")
        
        # Basic WebSocket initialization test
        sws = SharekhanWebSocket(access_token)
        print("✅ WebSocket initialized successfully")
        
    except Exception as e:
        print(f"❌ WebSocket test failed: {e}")
    
    print("\n🎉 Test suite completed!")
    print("\nNext steps:")
    print("1. Configure real customer IDs for fund/position queries")
    print("2. Use live market data for testing WebSocket feeds")
    print("3. Test order placement with small quantities first")

if __name__ == "__main__":
    main()
