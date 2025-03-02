import whois
import dns.resolver
import shodan
import requests
import argparse
import sys
import socket

argparse = argparse.ArgumentParser(description="This is a basic info gathering tool.", usage="python3 info_gathering.py -d DOMAIN [-s IP]")
argparse.add_argument("-d","--domain",help="Enter the domain name for footprinting.",required=True)
argparse.add_argument("-s","--shodan",help="Enter the IP for shodan search.")

args = argparse.parse_args()
domain = args.domain
ip = args.shodan

# whois module
print("[+] Getting whois info..")
# using whois library, creating instance
try:
   py = whois.whois(domain)
   print("[+] whois info found.")
   print("Name: {}".format(py.name))
   print("Registrar: {}".format(py.registrar))
   print("Creation Date: {}".format(py.creation_date))
   print("Expiration date: {}".format(py.expiration_date))
   print("Registrant: {}".format(py.registrant))
   print("registrant country: {}".format(py.registrant_country))
except:
    pass

#DNS module
print("[+] Getting DNS info..")
#implementing dns.resolver from dnspython
try:
   for a in dns.resolver.resolve(domain, 'A'):
       print("[+] A Record: {}".format(a.to_text()))
   for ns in dns.resolver.resolve(domain, 'NS'):
       print("[+] NS Record: {}".format(ns.to_text()))
   for mx in dns.resolver.resolve(domain, 'MX'):
       print("[+] MX Record: {}".format(mx.to_text()))
   for txt in dns.resolver.resolve(domain, 'TXT'):
       print("[+] TXT Record: {}".format(txt.to_text()))
except:
   pass

#Geolocation module
print("[+] Getting geolocation info..")
#implementing requests for web request
try:
    response = requests.request('GET', "https://geolocation-db.com/json/" + socket.gethostbyname(domain))
    print("[+] Country: {}".format(response['country_name']))
    print("[+] Latitude: {}".format(response['latitude']))
    print("[+] Longitude: {}".format(response['longitude']))
    print("[+] City: {}".format(response['city']))
    print("[+] State: {}".format(response['state']))
except:
    pass

#shodan module
if ip:
    print("[+] Getting info from Shodan for IP {}".format(ip))
    #shodan API
    api = shodan.Shodan("YtBIkC9aHJKdVpIRAlalfdDS57UKBQOe")
    try:
        results = api.search(ip)
        print("[+] Results found: {}".format(results['total']))
        for result in results['matches']:
            print("[+] IP: {}".format(result['ip_str']))
            print("[+] Data: \n{}".format(result['data']))
            print()
    except:
        print("[-] Shodan search error.")