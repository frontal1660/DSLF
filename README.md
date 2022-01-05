# DSLF
`DSLF` stands for (D)arth (S)ide of the (L)og4j (F)orce.

It is the ultimate log4j vulnerabilities assessor. It comes with four individual Python3 modules:
- Passive Callback  Module aka `PCM`
- Active  Callback  Module aka `ACM`
- Active  Scanner   Module aka `ASM`
- Payload Generator Module aka `PGM`

It covers CVE-2021-44228 and CVE-2021-45046.


# Description
`PCM` is a callback manager that only listens to a specified TCP port (LDAP, DNS, HTTP, etc.) to get the target requests.

![](https://github.com/frontal1660/DSLF/blob/main/screenshots/pcm01.png)  
  
  
`ACM` is a callback manager that starts LDAP and HTTP server on specified TCP ports. The LDAP server gets the target requests. The HTTP server serves a malcious java class file to the target. 

![](https://github.com/frontal1660/DSLF/blob/main/screenshots/acm01.png)



`ASM` is a scanner very flexible and efficient log4j scanner. Depending on what Callback Module it is coupled it can scan targets or push a malicious java class file to the target. 

This screenshot shows `ASM` used with `PCM`: 

![](https://github.com/frontal1660/DSLF/blob/main/screenshots/asm01.png)


`ASM` is able to crawl URL.

This screenshot shows a crawl on a non vulnerable URL.

![](https://github.com/frontal1660/DSLF/blob/main/screenshots/asm02.png)


`ASM` can be used with netcat command.

This screenshort shows `ASM` used with `ACM` and netcat command:

![](https://github.com/frontal1660/DSLF/blob/main/screenshots/netcat01.png)



`PGM` is a payload generator which can create hundreds of thousands of log4j pattern combinations.

This screenshot shows `PGM` generating log4j LDAP payloads:

![](https://github.com/frontal1660/DSLF/blob/main/screenshots/pgm01.png)

`PGM` is based on the following patterns (for example: the "j" character of "JNDI" string):
* j
* ${::-j}
* ${lower:j}
* ${upper:j}

# Features
`ASM`

Callback:
* ldap: use LDAP callback
* dns: use DNS callback
* http: use HTTP callback

Crawl:
* no: crawl the URL
* yes: do not crawl the URL

Method:
* get: use GET method
* post: use POST method
* both: use GET method and then POST method

Param:
* none: do not add payload in URL parameters
* classic: add payload in URL parameters

Header:
* none: do not push payload in any header except User-agent with random UA
* classic: push payload in classic headers
* noua: do not push payload in User-agent header but use random UA

Data:
* classic: post payload in all inputs at same time
* full: classic option plus post payload in input one by one

Payload:
* classic: use generic CVE-2021-44228 and CVE-2021-45046 payloads
* full: use all payloads derived from both CVE (to bypass WAF)

# Usage
`PCM`
```python
01:40:43[> root@redteam[> /root/[> python3 pcm.py -h
usage: pcm.py [-h] --tcp_port TCP_PORT

optional arguments:
  -h, --help           show this help message and exit
  --tcp_port TCP_PORT  TCP port of the "LDAP" listening socket
```



`ACM`
```python
01:42:00[> root@redteam[> /root/[> python3 acm.py -h
usage: acm.py [-h] --ip IP [--http_port HTTP_PORT] [--ldap_port LDAP_PORT] [--nc_port NC_PORT]

optional arguments:
  -h, --help            show this help message and exit
  --ip IP               IP address of the WEB server, the LDAP servers and the reverse shell
  --http_port HTTP_PORT
                        TCP port of the WEB server
  --ldap_port LDAP_PORT
                        TCP port of the LDAP server
  --nc_port NC_PORT     TCP port for the reverse shell (netcat use)
```



`ASM`
```python
01:38:10[> root@redteam[> /root/[> python3 asm.py -h
usage: asm.py [-h] --url URL --evil_site EVILSITE --evil_port EVILPORT [--callback CALLBACK] [--crawl CRAWL] [--method METHOD]
              [--param PARAM] [--header HEADER] [--data DATA] [--payload PAYLOAD]

optional arguments:
  -h, --help            show this help message and exit
  --url URL             URL or file with URL to scan
  --evil_site EVILSITE  IP or FQDN for the callback
  --evil_port EVILPORT  TCP port for the callback
  --callback CALLBACK   ldap, http or dns
  --crawl CRAWL         no or yes
  --method METHOD       get, post or both
  --param PARAM         none or classic
  --header HEADER       none, classic or noua
  --data DATA           classic or full
  --payload PAYLOAD     classic or full
```

# Requierements
The `DSLF` Modules uses few Python libraries:

- `PCM`
```python
import argparse, subprocess, time, threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from termcolor import cprint
```


- `ACM`
```python
import argparse, socket, sys, threading, time
from datetime import datetime
from termcolor import cprint
```


- `ASM`
```python
import argparse, random, requests, string, sys, time, urllib3
from bs4 import BeautifulSoup
from datetime import datetime
from termcolor import cprint
from urllib.parse import urljoin
```


- `PGM`
```python
import time
from termcolor import cprint
```

For `ACM` you need to download a vulnerable JDK version (for example: jdk1.8.0_20) from Oracle website, decompress it and then put all the files in acm/java/jdk/ directory. 

![](https://github.com/frontal1660/DSLF/blob/main/screenshots/acm02.png)


# Todo
This list is non exhaustive:
* Update PGM to use the latest WAF bypass payload combitations
* Handle 401 response codes
* Handle more form inputs combinations
* Proxy integration
* Many more things

# Legal Disclaimer
This project is made for educational and ethical testing purposes only. Usage of log4j-scan for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

# License
This project is licensed under GNU General Public License.

# Author
Julien GARAVET
