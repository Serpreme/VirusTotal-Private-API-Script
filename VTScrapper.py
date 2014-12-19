#!/usr/bin/python
import argparse
import json
import requests
import sqlite3
import sys, getopt
"""
Defining the command line arguements.
"""
parser = argparse.ArgumentParser(description=' This script is used for analyszing data from VT with the Private API.')
parser.add_argument('-e','--engines', help='Specify your search critera')
parser.add_argument('-t','--table',help='This will specify the tables to be made.')
parser.add_argument('-a','--iteramount',help='This is how many hashes, in increments of 300 you want to go back.', type=int, required=True)
parser.add_argument('-ip','--ipaddsearch',help='Use this if you want to search an IP for basic information')
args = parser.parse_args()
"""
This section is used to setup insert statements based off the table name.
"""
tudp = '%sUDP' % args.table
ttcp = '%sTCP' % args.table
turl = '%sURL' % args.table
"""
This line determines how many increments of 300 you want to search for.
"""
ia = '%s' % args.iteramount
ipsearch = 0
ipsearch = '%s' % args.ipaddsearch
totalcnter = '%s' % args.totalcnter
"""
Initializing counters.
"""
ia = int(ia)
excerrorcnt = 0
urlerrorcnt = 0
tcperrorcnt = 0
udperrorcnt = 0
ipquerycnt = 0
"""
This line is used for filtering out traffic we are not concerned with.
"""
fil2 = ('10.', '172.16.', '172.31.', '192.168','255.255.','137.170.185.211','239.255.255.250','65.55.56.206','64.4.10.33','8.8.8.8','213.186.33.99')
"""
Initializing more variables.
"""
udpmainex = []
tcpmainex = []
urlex = []
bighashlist = []
offsetter = []
"""
Checks if you supplied an IP and will want to search for that instead of the standard search.
"""
if ttcp == 'NoneIP':
  print 'Must be doing something other then normal search'
else:
 params = {'apikey': '<APIKEY>', 'query': '%s' % args.engines} 
 response = requests.get('https://www.virustotal.com/vtapi/v2/file/search', params=params)
 hd = response.json()
 for z in hd['hashes']:
  bighashlist.append([z])
"""
This checks if you want more then 300 hashes processed. It will send back the offset amount for additional hashes in increments of 300
"""
 if ia >= 1:
  try:
   for x in range(ia):
    offsetter = hd['offset']
    print offsetter 
    params = {'apikey': '<APIKEY>', 'query': '%s' % args.engines, 'offset': offsetter}
    response2 = requests.get('https://www.virustotal.com/vtapi/v2/file/search', params=params)
    hd = response2.json()
    for y in hd['hashes']:
     bighashlist.append([y])
  except:
   print "No offset"
 else:
  print "iter amount was less then 1"
"""
Below starts requesting behaviour information for each hash in the list. 
"""
 print "How many hashes were pulled:"
 print len(bighashlist)
 for [hashlistitem] in bighashlist:
  params = {'apikey': '<APIKEY>', 'hash': hashlistitem}
  response = requests.get('https://www.virustotal.com/vtapi/v2/file/behaviour', params=params)
  jdata = response.json()
  try:
"""
This part pulls TCP information from the hashes
"""
    tcpunique = []
    for block in jdata['network']['tcp']:
     if not [block['dst'], block['dport']] in tcpunique:
      tcpunique.append([block['dst'], block['dport']])
      tcpunique = [ip for ip in tcpunique if not ip[0].startswith(fil2)]
    tcpuniquelen = len(tcpunique)
"""
    This part does a length check before appending the valid entries to the main variable that will be used to insert into the database.
"""
    if tcpuniquelen > 0:
     for x in tcpunique:
      x.insert(0,hashlistitem)
      tcpmainex.append(x)
    else: 
     tcperrorcnt += 1
    udpunique = []
"""
   This part pulls UDP information from the hashes
"""
    for block in jdata['network']['udp']:
     if not [block['dst'], block['dport']] in udpunique:
      udpunique.append([block['dst'], block['dport']])
      udpunique = [ip for ip in udpunique if not ip[0].startswith(fil2)]
    udpuniquelen = len(udpunique)
"""
    This part does a length check before appending the valid entries to the main variable that will be used to insert into the database.
"""
    if udpuniquelen > 0:
     for x in udpunique:
      x.insert(0,hashlistitem)
      udpmainex.append(x)
    else: 
     udperrorcnt += 1
    urllist = []
"""
   This part pulls URL information from the hashes
"""
    for block2 in jdata['network']['http']:
     if not [block2['uri']] in urllist:
      urllist.append([block2['uri']])
    urllen = len(urllist)
"""
    This part does a length check before appending the valid entries to the main variable that will be used to insert into the database.
"""
    if urllen > 0:
     for x2 in urllist:
      x2.insert(0,hashlistitem)
      urlex.append(x2)
    else:
     urlerrorcnt += 1
  except:
   excerrorcnt = excerrorcnt + 1
if ipsearch =='None':
 print "Skipping IP Search"
else:
 conn = sqlite3.connect(':memory:')
 c = conn.cursor()
 ipreso = []
 ipdurls = []
 ipdcs = []
 params = {'ip': '%s' % args.ipaddsearch, 'apikey': '<APIKEY>'}
 response = requests.get('https://www.virustotal.com/vtapi/v2/ip-address/report', params=params)
 ipdata = response.json()
 iphoslen = len(ipdata['resolutions'])
 ipdulen = len(ipdata['detected_urls'])
 poschecklen = len(ipdata['detected_communicating_samples'])
 if iphoslen > 0:
  for iphos in ipdata['resolutions']:
   if not [iphos['hostname']] in ipreso:
    ipreso.append([iphos['hostname']])
 else:
   print "No host information"
 if ipdulen > 0:
  for ipdu in ipdata['detected_urls']:
   if not [ipdu['url']] in ipdurls:
    ipdurls.append([ipdu['url']])
 else: 
  print "No detected URLs"
 if poschecklen > 0:
  for dcs in ipdata['detected_communicating_samples']:
   for poscheck in  ipdata['detected_communicating_samples']:
    if poscheck['positives'] > 15:
     if not [dcs['sha256']] in ipdcs:
      ipdcs.append([dcs['sha256']])
 else:
  print "no detected hashes" 
if ipsearch == "None":
 conn = sqlite3.connect('hashes.db')
 c = conn.cursor()
 c.execute('drop table if exists %sTCP;' % args.table)
 c.execute('drop table if exists %sURL;' % args.table)
 c.execute('drop table if exists %sUDP;' % args.table)
 c.execute('create table %sTCP (hashes int,dst varchar(20),dport int);' % args.table)
 c.execute('create table %sUDP (hashes int, dst varchar(20), dport int);' % args.table)
 c.execute('create table %sURL (hashes int,url varchar(20));' % args.table)
 c.executemany('INSERT INTO SalityURL VALUES (?,?)', urlex)
 c.executemany('INSERT INTO SalityUDP VALUES (?,?,?)', udpmainex)
 c.executemany('INSERT INTO SalityTCP VALUES (?,?,?)', tcpmainex)
 #Format the data
 sqltudp = 'select dst,dport, count(dst) from {} group by dport,dst order by 3 desc limit 50;'.format(tudp)
 sqlttcp = 'select dst,dport, count(dst) from {} group by dport,dst order by 3 desc limit 50;'.format(ttcp)
 sqlURL = 'select substr(url,7,50), count(*) from {} group by url order by 2 desc limit 50;'.format(turl)
 c.execute(sqlttcp)
 arrow = c.fetchall()
 template = "{0:15}|{1:5}|{2:5}" # column widths: 8, 10, 15
 print template.format("Destination IP", "TCP Port", "Count") # header
 for rec in arrow:
  print template.format(*rec)
 c.execute(sqltudp)
 arrow = c.fetchall()
 template = "{0:15}|{1:5}|{2:5}" # column widths: 8, 10, 15
 print template.format("Destination IP", "UDP Port", "Count") # header
 for rec in arrow:
  print template.format(*rec)
 c.execute(sqlURL)
 arrow = c.fetchall()
 template = "{0:75}|{1:5}" # column widths: 8, 10, 15
 print template.format("URL", "Count") # header
 for rec in arrow:
  print template.format(*rec)
 conn.commit()
 conn.close()  
else:
  ipquerycnt += 1
  print "IP query mode"
