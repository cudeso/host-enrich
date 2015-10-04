#!/usr/bin/python

# Enrich host data with information from various open information sources
#
# Koen Van Impe
#   20151004
#   
# Usage : host_enricher.py <myip>
#
# Configuration : copy config.cfg.default to config.cfg and add your API keys
#
# Current output to file (in SAVE_OUTPUT_PATH) and console
#   todo:   - summarized json and csv output
#           - import to enrich MISP event
#
# Make sure there's simplejson : apt-get install python-simplejson
# Install Shodan : easy_install shodan

import simplejson
import urllib
import urllib2
from optparse import OptionParser
import json
import hashlib
import glob,os
import sys
import shodan

import xml.etree.ElementTree as ET

import ConfigParser

'''
 IBM X-Force Exchange interface
 inspired by https://github.com/johestephan/ibmxforceex.checker.py
'''

'''
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
'''
def xforce_gettoken():
    '''
        Get a token an write it to disk
    '''
    HOME = os.path.dirname(os.path.realpath(__file__))
    TOKEN = "token"
    if os.path.isfile("./" + TOKEN):
        tokenf = open(HOME + "/" + TOKEN ,"r")
        token = tokenf.readline()
    else:
        data = urllib2.urlopen( XFORCE_URL + "/auth/anonymousToken" )
        t = json.load(data)
        token = str(t['token'])
        tokenf = open(HOME + "/token","w")
        tokenf.write(token)
    return token

def xforce_request(url, request, token):
    try:
        furl = url + urllib.quote(request)
        if PRINT_API_URL:
            print furl
        htoken = "Bearer "+ token
        headers = {'Authorization': htoken,}
        request = urllib2.Request(furl, None, headers)
        data = urllib2.urlopen(request)
        return json.dumps(json.loads(data.read()), sort_keys=True, indent=3, separators=(',', ': '))
    except urllib2.HTTPError, e:
        print str(e)

def xforce_exchange(SEARCH_IP, ipr = True, history = True, malware = True, passivedns = True):
    token = xforce_gettoken()
    result_ipr = None
    result_history = None
    result_malware = None
    result_passivedns = None
    if ipr:
        result_ipr = json.loads(xforce_request( XFORCE_URL + "/ipr/", SEARCH_IP, token))
    if history:
        result_history = json.loads(xforce_request( XFORCE_URL + "/ipr/history/", SEARCH_IP, token))
    if malware:
        result_malware = json.loads(xforce_request( XFORCE_URL + "/ipr/malware/", SEARCH_IP, token))
    if passivedns:
        result_passivedns =  json.loads(xforce_request( XFORCE_URL + "/resolve/", SEARCH_IP, token))

    if SAVE_OUTPUT:
        write_output( 'xforce_ipr.json', result_ipr )
        write_output( 'xforce_history.json', result_history )
        write_output( 'xforce_malware.json', result_malware )
        write_output( 'xforce_passivedns.json', result_passivedns )
    return { 'ipr': result_ipr, 'history':result_history, 'malware': result_malware, 'passivedns': result_passivedns}

def xforce_parse_ipr(result_ipr):
    if result_ipr:
        categories = []
        country = result_ipr["geo"]["country"]
        countrycode = result_ipr["geo"]["countrycode"]
        subnet = result_ipr["subnets"][0]["subnet"]
        score = result_ipr["score"]
        if result_ipr["cats"]:
            for description, percentage in result_ipr["cats"].iteritems():
                categories.append(str(description))
        return { 'country': country, 'countrycode': countrycode, 'subnet': subnet, 'categories': categories, 'score': score}
    else:
        return False

def xforce_parse_history(result_history):
    if result_history:
        history = result_history["history"]
        ip_history = []
        for historyel in history:
            if historyel["cats"]:
                tmpcat = []
                for description, percentage in historyel["cats"].iteritems():
                    tmpcat.append(str(description))
                ip_history.append({'last': historyel["created"], 'title': "", 'description': "", 'details_url': "",'categories': tmpcat, 'type': "XForce"})
        return ip_history
    else:
        return False

def xforce_parse_malware(result_malware):
    if result_malware:
        malware = []
        return malware
    else:
        return False

def xforce_parse_passivedns(result_passivedns):
    if result_passivedns:
        records = result_passivedns["Passive"]["records"]
        dns_records = []
        if records:
            for record in records:
                dns_records.append({'last': record["last"], 'host': record["value"], 'type': "XForce"})
        return dns_records
    else:
        return False

def shodan_request(SEARCH_IP):
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(SEARCH_IP)
        if host["data"]:
            shodan_ports = []
            banners = host["data"]
            for el in banners:
                if el["port"]:
                    port = el["port"]
                    transport = el.get('transport', '?') 
                    timestamp = el.get('timestamp', '?')
                    product = el.get('product', '?')
                    location = el.get('location', '')
                    if location:
                        country = location["country_name"]
                        countrycode = location['country_code']
                    shodan_ports.append({'transport': transport, 'port': port, 'timestamp': timestamp, 'product': product})
            if SAVE_OUTPUT:
                write_output( 'shodan_host.json', host )

            return {'country': country, 'countrycode': countrycode, 'ports': shodan_ports}
        else:
            return False
    except:
        return False
def virustotal_request(SEARCH_IP):
    parameters = {'ip': SEARCH_IP, 'apikey': VIRUSTOTAL_API}
    response = json.loads(urllib.urlopen('%s?%s' % (VT_URL, urllib.urlencode(parameters))).read())
    if PRINT_API_URL:
        print VT_URL
    if response:
        dns_records = []
        urls = []
        if 'undetected_downloaded_samples' in response:
            undetected_downloaded_samples = response["undetected_downloaded_samples"]
        else:
            undetected_downloaded_samples = {}
        if 'detected_downloaded_samples' in response:
            detected_downloaded_samples = response["detected_downloaded_samples"]
        else:
            detected_downloaded_samples = {}

        if 'detected_urls' in response:
            detected_urls = response["detected_urls"]
            for url in detected_urls:
                urls.append({'url': url["url"], 'last': url["scan_date"], 'positives': url["positives"], 'total': url["total"], 'type': "VirusTotal"})
        else:
            detected_urls = {}
            urls = {}
        if 'resolutions' in response:
            passive_dns = response["resolutions"]
            for dns in passive_dns:
                dns_records.append({'last': dns["last_resolved"], 'host': dns["hostname"], 'type': "VirusTotal"})
        else:
            passive_dns = {}
            dns_records = {}

        if SAVE_OUTPUT:
            write_output( 'vt_undetected_downloaded_samples.json', undetected_downloaded_samples )
            write_output( 'vt_detected_downloaded_samples.json', detected_downloaded_samples )
            write_output( 'vt_detected_urls.json', detected_urls )
            write_output( 'vt_passive_dns.json', passive_dns )

        return { 'passivedns': dns_records, 'urls': urls}
    else:
        return False

def sans_request(SEARCH_IP):
    url = "%s/%s" % (SANS_URL, SEARCH_IP)
    if PRINT_API_URL:
        print url
    tree = ET.parse(urllib.urlopen(url))
    root = tree.getroot()
    if SAVE_OUTPUT:
        write_output( 'sans.xml', ET.tostring(root) )

    try:
        asabusecontact = root.findall("asabusecontact")[0].text
        attacks = root.findall("attacks")[0].text
        count = root.findall("count")[0].text
        asn = root.findall("as")[0].text
        maxdate = root.findall("maxdate")[0].text
        mindate = root.findall("mindate")[0].text
        updated = root.findall("updated")[0].text
        comment = root.findall("comment")[0].text
        if count is None:
            count = 0
        if attacks is None:
            attacks = 0
        return {'count': count, 'attacks': attacks, 'asabusecontact': asabusecontact, 'as': asn, 'comment': comment, 'maxdate': maxdate, 'mindate': mindate, 'updated': updated}
    except:
        return {'count': 0, 'attacks': 0, 'asabusecontact': "", 'as': "", 'comment': "No results", 'maxdate': "", 'mindate': "", 'updated': ""}

def cymon_request(url):
    if PRINT_API_URL:
        print url
    htoken = "Token "+ CYMON_API
    headers = {'Authorization': htoken,}
    request = urllib2.Request(url, None, headers)
    data = urllib2.urlopen(request)

    return json.dumps(json.loads(data.read()), sort_keys=True, indent=3, separators=(',', ': '))

def cymon(SEARCH_IP, cymon_events):    
    result_events = None
    if cymon_events:
        furl = CYMON_URL + "/" + urllib.quote(SEARCH_IP) + "/events/"
        result_events = json.loads(cymon_request( furl ))

        furl = CYMON_URL + "/" + urllib.quote(SEARCH_IP) + "/domains/"
        result_passivedns = json.loads(cymon_request( furl ))

        furl = CYMON_URL + "/" + urllib.quote(SEARCH_IP) + "/urls/"
        result_urls = json.loads(cymon_request( furl ))

        if SAVE_OUTPUT:
            write_output( 'cymon_events.json', result_events )
            write_output( 'cymon_domains.json', result_passivedns )
            write_output( 'cymon_urls.json', result_urls )

    return {'events': result_events, 'passivedns': result_passivedns, 'urls': result_urls}

def cymon_parse_events(cymon_events):
    if cymon_events:
        data = cymon_events["results"]
        events = []
        for event in data:
            event["type"] = "CyMon"
            event["last"] = event["updated"]
            event["categories"] = event["tag"]
            events.append(event)
        return events
    else:
        return False

def cymon_parse_passivedns(cymon_events):
    if cymon_events:
        data = cymon_events["results"]
        dns = []
        for event in data:
            event["type"] = "CyMon"
            event["last"] = event["updated"]
            event["host"] = event["name"]
            dns.append(event)
        return dns
    else:
        return False

def cymon_parse_urls(cymon_events):
    if cymon_events:
        data = cymon_events["results"]
        urls = []
        for event in data:
            event["type"] = "CyMon"
            event["last"] = event["updated"]
            event["url"] = event["location"]
            event["positives"] = 0
            event["total"] = 0
            urls.append(event)
        return urls
    else:
        return False

def host_summary(SEARCH_IP, xforce_data, vt_data, shodan_data, sans_data, cymon_data, output = 'console'):
    summary = {}
    # Put all data in summary[] so that we can later on pass it to different output formats
    summary["country"] = xforce_data["ipr"]["country"]
    summary["countrycode"] = xforce_data["ipr"]["countrycode"]
    summary["score"] = xforce_data["ipr"]["score"]
    summary["categories"] = xforce_data["ipr"]["categories"]
    summary["malware"] = xforce_data["malware"]

    summary["asn"] = sans_data["as"]
    summary["asabusecontact"] = sans_data["asabusecontact"]
    summary["sansattacks"] = sans_data["attacks"]
    summary["sanscount"] = sans_data["count"]
    summary["sanscomment"] = sans_data["comment"]
    summary["sansmindate"] = sans_data["mindate"]
    summary["sansmaxdate"] = sans_data["maxdate"]
    summary["sansupdated"] = sans_data["updated"]

    sorted_passive_dns = merge_passive_dns(xforce_data["passivedns"], vt_data["passivedns"])
    sorted_passive_dns = merge_passive_dns(sorted_passive_dns , cymon_data["passivedns"])
    sorted_passive_dns = sorted(sorted_passive_dns, key=getSortKey)
    summary["passivedns"] = sorted_passive_dns

    sorted_events = sorted(merge_events_history(xforce_data["history"], cymon_data["events"]), key=getSortKey)
    summary["history"] = sorted_events

    if shodan_data:
        if 'ports' in shodan_data:
            summary["ports"] = shodan_data["ports"]
        else:
            summary["ports"] = {}
    else:
        summary["ports"] = {}
    sorted_urls = sorted(merge_urls( vt_data["urls"], cymon_data["urls"]), key=getSortKey)
    summary["urls"] = sorted_urls

    if output == 'console':
        #print summary
        print "======================================================================"
        print "| Results for %s" % SEARCH_IP
        print "======================================================================"
        print
        print "Country: %s - %s [XForce]" % (summary["countrycode"], summary["country"])
        print "ASN: %s" % summary["asn"]
        print "Abusecontact: %s" % summary["asabusecontact"]
        print
        print "Reputation score: %s [XForce]" % (str(summary["score"]))
        print "Sans count: %s " % summary["sanscount"]
        print "Sans attacks: %s " % summary["sansattacks"]
        if summary["sanscomment"]:
            print "Sans comment: %s" % summary["sanscomment"]
        if summary["sansupdated"]:
            print "Sans First: %s Max: %s Updated: %s" % (summary["sansmindate"],summary["sansmaxdate"],summary["sansupdated"])
        print
        print "Found in categories: [XForce]"
        for c in summary["categories"]:
            print " %s" % c
        print            
        print "Open ports [Shodan]:"
        for p in summary["ports"]:
            print " %s/%s (%s , %s)" % (p["transport"], p["port"], p["product"], p["timestamp"])
        print
        if summary["history"]:
            print "History"
            for historyelement in summary["history"]:
                cats = ""
                #print historyelement
                if historyelement["type"] == "XForce":
                    for cat in historyelement["categories"]:
                            cats = cats + cat + " "
                else:
                    cats = historyelement["categories"]
                print " %s %s (%s) [%s]" % (cats, historyelement["title"], historyelement["last"], historyelement["type"])
                if historyelement["type"] == "CyMon":
                    print "    \ %s " % (historyelement["details_url"])
        print
        if summary["malware"]:
            print "Malware [XForce]"
        print
        if summary["passivedns"]:
            print "Passive DNS"
            for dns in summary["passivedns"]:
                print " %s %s [%s]" % (dns["host"], dns["last"], dns["type"])
        print
        if summary["urls"]:
            print "Detected URLs"
            for url in summary["urls"]:
                print " %s (%s) (%s out of %s) [%s]" % (url["url"], url["last"], url["positives"], url["total"], url["type"])

def getSortKey(item):
    return item["last"]

def merge_passive_dns(a, b):
    for item in b:
        a.append({ 'last': item["last"], 'host': item["host"], 'type': item["type"]})
    return a

def merge_events_history(a, b):
    for item in b:
        a.append({ 'last': item["last"], 'type': item["type"], 'categories': item["categories"], \
                'title': item["title"], \
                'description': item["description"], 'details_url': item["details_url"]})
    return a

def merge_urls(a, b):
    for item in b:
        a.append({ 'last': item["last"], 'positives': item["positives"], 'total': item["total"], \
                    'url': item["url"], 'type': item["type"]})
    return a

def write_output(fname, content):
    if SAVE_OUTPUT:
        filename = SAVE_OUTPUT_PATH + "/" + fname
        f = open( filename , "w")
        f.write( str(content) )
        f.close()
    else:
        return False

def read_config():
    global SHODAN_API_KEY, VIRUSTOTAL_API, PRINT_API_URL, XFORCE_URL, SANS_URL, VT_URL, CYMON_API, CYMON_URL, SAVE_OUTPUT, SAVE_OUTPUT_PATH, CLEAR_OUTPUT_PATH
    Config = ConfigParser.ConfigParser()
    Config.read("config.cfg")

    SHODAN_API_KEY = Config.get("API", "SHODAN_API_KEY")
    VIRUSTOTAL_API = Config.get("API", "VIRUSTOTAL_API")
    CYMON_API = Config.get("API", "CYMON_API")

    PRINT_API_URL = Config.get("Use", "PRINT_API_URL")
    SAVE_OUTPUT = Config.get("Use", "SAVE_OUTPUT")
    SAVE_OUTPUT_PATH = Config.get("Use", "SAVE_OUTPUT_PATH")
    CLEAR_OUTPUT_PATH = Config.get("Use", "CLEAR_OUTPUT_PATH")

    XFORCE_URL = Config.get("URL", "XFORCE_URL")
    SANS_URL = Config.get("URL", "SANS_URL")
    VT_URL = Config.get("URL", "VT_URL")
    CYMON_URL = Config.get("URL", "CYMON_URL")

    if CLEAR_OUTPUT_PATH and len(SAVE_OUTPUT_PATH) > 0:
        p = SAVE_OUTPUT_PATH + "/*"
        to_remove = glob.glob(p)
        for f in to_remove:
            os.remove( f )


# Read external configuration file with API and URLs
read_config()

#SEARCH_IP = "211.202.2.97"
#SEARCH_IP = "91.225.28.60"

parser = OptionParser()
#parser.add_option("-i", "--ip", dest="s_ip" , default=None, help="ip to be checked", metavar="ipaddress")
(options, args) = parser.parse_args()

SEARCH_IP = args[0]

# CyMon : http://docs.cymon.io/
cymon_data = cymon(SEARCH_IP, True)
cymon_events = {'events': cymon_parse_events( cymon_data["events"]), \
                'passivedns': cymon_parse_passivedns( cymon_data["passivedns"] ), \
                'urls' : cymon_parse_urls( cymon_data["urls"]) }

# Sans : https://isc.sans.edu/api/
sans_data = sans_request(SEARCH_IP)

# VirusTotal : https://www.virustotal.com/nl/documentation/public-api/#response-basics
vt_data = virustotal_request(SEARCH_IP)

# Shodan : https://shodan.readthedocs.org/en/latest/tutorial.html#looking-up-a-host
shodan_data = shodan_request(SEARCH_IP)

# XForce : https://api.xforce.ibmcloud.com/doc/
xforce_feed = xforce_exchange(SEARCH_IP,True, True, True, True)
xforce_data = {'ipr': xforce_parse_ipr( xforce_feed["ipr"]), 'history': xforce_parse_history( xforce_feed["history"]), \
    'malware': xforce_parse_malware( xforce_feed["malware"]), 'passivedns': xforce_parse_passivedns( xforce_feed["passivedns"] ) }

host_summary(SEARCH_IP, xforce_data, vt_data, shodan_data, sans_data, cymon_events)
