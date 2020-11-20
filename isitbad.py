#!/usr/bin/env python3
# Name:  IP checklist
# REF: https://github.com/jgamblin/isthisipbad/blob/master/isthisipbad.py
# Imporvements: 2-8s
# Cached perform: ~.8s
# Corrected, and improved by mr_sudo. Revision 3.0
#NEW: Updated feeds (3/15/2020), Threat scoring system base on threat feed source.
#Import default modules/constants----------------------------------------------------------------------------------------------#
#new
try:
  from sys import version,argv
  from argparse import ArgumentParser
  from re import findall,sub
  from socket import getfqdn
  from os import path,mkdir,stat
  from time import time
  from multiprocessing import Pool
  from collections import namedtuple
except:
  print("Unable to import default modules: sys, argparse, re, or socket.")
  exit()
if "3." not in version[0:3]:
  print("Program ran with Python %s. Please run with Python 3.x!" % version[0:5])
  exit()

cachedir = '.isitbadcache'
parser = ArgumentParser('to parse ip address')
GOOD = 0
BAD = 0
splash = "    _/_/_/            _/_/_/    _/      _/_/_/                    _/  _/_/          \n"
splash+= "     _/      _/_/_/    _/    _/_/_/_/  _/    _/    _/_/_/    _/_/_/      _/         \n"
splash+= "    _/    _/_/        _/      _/      _/_/_/    _/    _/  _/    _/  _/_/            \n"
splash+= "   _/        _/_/    _/      _/      _/    _/  _/    _/  _/    _/                   \n"
splash+= "_/_/_/  _/_/_/    _/_/_/      _/_/  _/_/_/      _/_/_/    _/_/_/  _/                \n"

#--------------------------------------------------------------------------------------------------------------------#
#Installer for failed modules----------------------------------------------------------------------------------------#
def installer(program):
  print("Unable to import module %s. Would you like to install it?" % program)
  resp = input("(y/n) ")
  try:
    if str(resp.lower()) == 'y':
      from pip import main as pipmain
      pipmain(['install', program])
      print("Install successful. Exiting")
      exit()
  except:
    print("Unable to install %s with pip3" % program)
    exit()
#--------------------------------------------------------------------------------------------------------------------#
#Import non-standard modules-----------------------------------------------------------------------------------------#
try:
  from termcolor import colored
  splash = colored(splash, 'blue')
except:
  installer("termcolor")
try:
  from dns import resolver
except:
  installer("dnspython")
try:
  from ipaddress import ip_address,ip_network
except:
  installer("ipaddress")
try:
  from urllib3 import PoolManager,exceptions,disable_warnings
  disable_warnings(exceptions.InsecureRequestWarning)
except:
  installer("urllib3")
try:
  from certifi import where as certs
  http = PoolManager(ca_certs=certs())
except:
  installer("certifi")
#--------------------------------------------------------------------------------------------------------------------#
#Print Results
def printResults(answer, name, score):
  global GOOD
  global BAD
  if answer:
    print(colored('%s is listed in %s' % (badip, name), 'red'))
    BAD = BAD + 1
    return (answer, score)
  else:
    print(colored('%s is not listed in %s' % (badip, name), 'green'))
    GOOD = GOOD + 1
    return (answer, 0)
#--------------------------------------------------------------------------------------------------------------------#
#Fetch IP lists by vendor--------------------------------------------------------------------------------------------#

def get_ipset(set):
  url = set.url
  name = set.name
  score= set.score
  isCache = cacheDetct(name, cachedir)
  if isCache:
    answer = cacheReturn(url, name)
    return printResults(answer, name, score)
  try:
    request = http.request("GET", url)
    html_content = request.data.decode()
  except:
    print("Could not connect to %s" % url)
    return printResults(False, name, score)
  if name == 'SANS DShield':
      print("[*] Regexing dsheild non-standard ip listing")
      html_content = sub(r'>00','>',html_content)
      html_content = sub(r'>0','>',html_content)
      html_content = sub(r'\.00','.',html_content)
      html_content = sub(r'\.0','.',html_content)
  if not isCache:
    cache(html_content, name)
  matches = findall(badip, html_content)
  answer = bool(len(matches))
  return printResults(answer, name, score)

#--------------------------------------------------------------------------------------------------------------------#
#Caching system -----------------------------------------------------------------------------------------------------#

def cacheDetct(name, cachedir):
  fname = '%s/%s' % (cachedir,name)
  if path.isdir(cachedir) and path.isfile(fname):
    ftime = stat(fname).st_mtime
    if ((time() - ftime) >= 86400):
      return False
    return True
  elif path.isdir(cachedir) is False:
    mkdir(cachedir)
    return False
  else:
    return False

def cacheReturn(url, name):
  fname = '%s/%s' % (cachedir,name)
  f = open(fname, 'r')
  file = f.read()
  f.close()
  matches = findall(sub('\.', '\.', badip), file)
  return bool(len(matches))

def cache(html_content, name):
  fname = '%s/%s' % (cachedir,name)
  with open(fname, 'w') as file:
    file.write(html_content)
#--------------------------------------------------------------------------------------------------------------------#
#Datasets-----------------------------------------------------------------------------------------------------------#
bls = (
  "b.barracudacentral.org", "bl.spamcop.net","blacklist.woody.ch", "cbl.abuseat.org",
  "combined.abuse.ch", "combined.rbl.msrbl.net", "db.wpbl.info","ubl.lashback.com",
  "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net","dnsbl-3.uceprotect.net",
  "dnsbl.sorbs.net", "drone.abuse.ch", "drone.abuse.ch","duinv.aupads.org",
  "dul.dnsbl.sorbs.net", "dul.ru","dyna.spamrats.com", "dynip.rothen.com",
  "http.dnsbl.sorbs.net", "images.rbl.msrbl.net","ips.backscatterer.org",
  "ix.dnsbl.manitu.net","korea.services.net", "misc.dnsbl.sorbs.net","noptr.spamrats.com",
  "ohps.dnsbl.net.au", "omrs.dnsbl.net.au","orvedb.aupads.org", "osps.dnsbl.net.au",
  "osrs.dnsbl.net.au","owfs.dnsbl.net.au", "pbl.spamhaus.org", "phishing.rbl.msrbl.net",
  "probes.dnsbl.net.au", "proxy.bl.gweep.ca", "rbl.interserver.net","rdts.dnsbl.net.au",
  "relays.bl.gweep.ca", "relays.nether.net","residential.block.transip.nl",
  "ricn.dnsbl.net.au","rmst.dnsbl.net.au", "smtp.dnsbl.sorbs.net","socks.dnsbl.sorbs.net",
  "spam.dnsbl.sorbs.net","spam.rbl.msrbl.net", "spam.spamrats.com", "spamrbl.imp.ch",
  "t3direct.dnsbl.net.au", "tor.dnsbl.sectoor.de","torserver.tor.dnsbl.sectoor.de",
  "ubl.lashback.com","ubl.unsubscore.com", "virus.rbl.msrbl.net",
  "web.dnsbl.sorbs.net", "wormrbl.imp.ch", "xbl.spamhaus.org",
  "zen.spamhaus.org")

URL = namedtuple('URL', 'url name score')
urls = (
URL(url='http://blocklist.greensnow.co/greensnow.txt', name='Green Snow Bruteforcers', score=30),
URL(url='https://openphish.com/feed.txt', name='Open Phish', score=15),
URL(url='https://report.rutgers.edu/DROP/attackers', name='Rutgers Attackers IP List', score=50),
URL(url='https://urlhaus.abuse.ch/downloads/text/', name='URLhaus malware IoC list', score=30),
URL(url='http://rules.emergingthreats.net/blockrules/emerging-tor.rules', name='Emerging threats TorNode list', score=10),
URL(url='https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-nodes.lst', name='SecOps TorNode list', score=10),
URL(url='http://iplists.firehol.org/files/et_tor.ipset', name='FireHol TorNode', score=10),
URL(url='http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt', name='EmergingThreats IP blocks', score=30),
URL(url='http://reputation.alienvault.com/reputation.data', name='AlienVault', score=30),
URL(url='http://www.ciarmy.com/list/ci-badguys.txt', name='Collective Intel BadGuy List', score=50),
URL(url='http://isc.sans.edu/api/sources/attacks/1000/limit=1000&sortby=lastseen', name='SANS DShield', score=30),
URL(url='http://malc0de.com/bl/IP_Blacklist.txt', name='malc0de', score=30),
URL(url='http://www.proxylists.net/proxylists.xml', name='Known proxies (proxylist)', score=10),
URL(url='http://labs.snort.org/feeds/ip-filter.blf', name='Snort IP filters', score=30),
URL(url='http://lists.blocklist.de/lists/apache.txt', name='Apache DDOS (blocklist.de)', score=10),
URL(url='http://lists.blocklist.de/lists/bots.txt', name='blocklist.de bot ips', score=10),
URL(url='http://lists.blocklist.de/lists/bruteforcelogin.txt', name='blocklist.de bruteforce ips', score=30),
URL(url='http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules', name='Emerging Threats Bots', score=10),
URL(url='http://www.malwaredomainlist.com/hostslist/ip.txt', name='blocklist.de bruteforce ips', score=30),
URL(url='https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_net_ua.ipset', name='firehol ipblock list', score=10)
)
#--------------------------------------------------------------------------------------------------------------------#
#Grab Public IP------------------------------------------------------------------------------------------------------#
def getPublicIP():
  try:
    r = http.request("GET", "http://icanhazip.com")
    ip = r.data.decode()
    if ip:
      return ip.rstrip()
    else:
      print("Unable to connect to get public IP, and no arguments given. Exiting...")
      exit()
  except:
    print("Unable to connect to get public IP, and no arguments given. Exiting...")
    exit()
#--------------------------------------------------------------------------------------------------------------------#
#DNS Query for IP(reverse)-------------------------------------------------------------------------------------------#
def dns_query(bl):
  global GOOD
  global BAD
  try:
    my_resolver = resolver.Resolver()
    query = '.'.join(reversed(str(badip).split("."))) + "." + bl
    my_resolver.timeout = 5
    my_resolver.lifetime = 5
    answers = my_resolver.query(query, "A")
    answer_txt = my_resolver.query(query, "TXT")
    print(colored(badip + ' is listed in ' + bl, 'red') + ' (%s: %s)' % (answers[0], answer_txt[0]))
    BAD = BAD + 1
    return (True, 5)
  except:
      print (colored('%s is not listed in %s' % (badip,bl), 'green'))
      GOOD = GOOD + 1
      return (False, 0)

#--------------------------------------------------------------------------------------------------------------------#
#Run Main------------------------------------------------------------------------------------------------------------#
def main(badip, t):
  global GOOD
  global BAD
  try:
    if '/32' not in str(ip_network(badip)):
      pass
    elif bool(len(str(ip_address(badip)))):
      pass
  except:
    print("[*] Unable to use address %s as it is not valid." % badip)
    exit()

  print(colored('Check IP against popular IP and DNS blacklists', 'blue'))
  reversed_dns = getfqdn(badip)
  r = http.request("GET", ('http://api.hackertarget.com/geoip/?q=' + badip))
  geoip = r.data.decode()
  print(colored("""
The FQDN for %s is %s\nGeolocation IP Information:\n%s
""" % (badip, reversed_dns, geoip), 'blue'))
  pool = Pool(t)
  urlResult = pool.map(get_ipset, urls)
  dnsResult = pool.map(dns_query, bls)
  RESULT = sum(int(x) for x,y in urlResult)
  RESULT+= sum(int(x) for x,y in dnsResult)
  THREAT_SCORE = sum(int(y) for x,y in urlResult)
  THREAT_SCORE+= sum(int(y) for x,y in dnsResult)
  if THREAT_SCORE >= 100:
    THREAT_SCORE = 100
  if THREAT_SCORE <= 0:
    print(colored("\n\nPotentially not a threat. Score %s/100" % THREAT_SCORE, 'green'))
  elif THREAT_SCORE > 0 and THREAT_SCORE < 40:
    print(colored("\n\nWARNING: Suspicious IP. Threat %s/100" % THREAT_SCORE, 'red'))
  elif THREAT_SCORE >= 40:
    print(colored("\n\nWARNING: Malicious IP. Threat %s/100" % (THREAT_SCORE), 'red'))
  TOTAL = len(urls) + len(bls)
  print(colored('\n{0} is on {1}/{2} blacklists.\n'.format(badip, RESULT, TOTAL)))
  from py_compile import compile
  compile(argv[0])
#--------------------------------------------------------------------------------------------------------------------#
print(splash)
if len(argv) == 1:
  my_ip = getPublicIP()
  print(colored('Your public IP address is {0}'.format(my_ip), 'blue'))
  resp = input('Would you like to check your public ip? (y/n) ')
  if resp.lower() in ["yes", "y"]:
    badip = my_ip
    main(badip, 4)
  else:
    exit()
else:
  try:
    parser.add_argument('-i', '--ip', type=str, help='-i/--ip [ip]', required=True)
    parser.add_argument('-t', '--threads', type=int, help='-t/--threads [count]', required=False)
    args = parser.parse_args()
    if args.ip and args.threads:
      badip = args.ip
      t = args.threads
      main(badip, t)
    elif args.ip:
      badip = args.ip
      main(badip, 4)
    else:
      exit()
  except:
    exit()
