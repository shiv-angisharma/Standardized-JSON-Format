import json

myjsonfile = open('nmap_basic.json', 'r')
jsondata = myjsonfile.read()
obj = json.loads(jsondata)
abc={}
abc['address'] = obj['host']['address']['@addr']
abc['host'] = obj['host']['hostnames']['hostname']['@name']
abc['ports'] = {}
abc['ports'] ['open_ports_count'] = int(len(obj['host']['ports']['port']))
abc['ports'] ['closed_ports_count'] = int(obj['host']['ports']['extraports']['@count'])
abc['ports'] ['Total_ports_count'] = int(obj['scaninfo']['@numservices'])
abc['open_ports'] = []
for i in range(len(obj['host']['ports']['port'])):
    open_ports = {}
    open_ports['protocol'] = obj['host']['ports']['port'][i]['@protocol']
    open_ports['portid'] = obj['host']['ports']['port'][i]['@portid']
    open_ports['service'] = obj['host']['ports']['port'][i]['service']['@name']
    abc['open_ports'].append(open_ports)

myjsonfile2 = open('nmap_os_version.json', 'r')
jsondata2 = myjsonfile2.read()
obj2 = json.loads(jsondata2)
pqr={}
pqr['os'] = obj2['host']['os']['osmatch']['@name']

# new = {**abc, **pqr}

# print(new)
# object2 = json.dumps(pqr, indent=4)
# with open("standard_report.json", "w") as outfile:
#     outfile.write(object2)


myjsonfile3 = open('nikto_scans.json', 'r')
jsondata3 = myjsonfile3.read()
obj3 = json.loads(jsondata3)
stu={}
stu['quickscan'] = []
for i in range(len(obj3['niktoscan']['scandetails']['item'])):
    item_details = {}
    item_details['id'] = obj3['niktoscan']['scandetails']['item'][i]['@id']
    item_details['method'] = obj3['niktoscan']['scandetails']['item'][i]['@method']
    item_details['description'] = obj3['niktoscan']['scandetails']['item'][i]['description']
    item_details['uri'] = obj3['niktoscan']['scandetails']['item'][i]['uri']
    item_details['namelink'] = obj3['niktoscan']['scandetails']['item'][i]['namelink']
    item_details['iplink'] = obj3['niktoscan']['scandetails']['item'][i]['iplink']
    stu['quickscan'].append(item_details)
# print(stu)
# object3 = json.dumps(stu, indent=4)
# with open("standard_report.json", "w") as outfile:
#     outfile.write(object3)

myjsonfile4 = open('owasp_zap.json', 'r')
jsondata4 = myjsonfile4.read()
obj4 = json.loads(jsondata4)
efg={}
efg['detailed_scan'] = []
for i in range(len(obj4['site'])):
    for j in range(len(obj4['site'][i]['alerts'])):
        alerts = {}
        alerts['alert_reference'] = obj4['site'][i]['alerts'][j]['alertRef']
        alerts['alert_name'] = obj4['site'][i]['alerts'][j]['name']
        alerts['risk_level'] = obj4['site'][i]['alerts'][j]['riskdesc']
        alerts['description'] = obj4['site'][i]['alerts'][j]['desc']
        alerts['instances_count'] = obj4['site'][i]['alerts'][j]['count']
        alerts['solution'] = obj4['site'][i]['alerts'][j]['solution']
        alerts['other_information'] = obj4['site'][i]['alerts'][j]['otherinfo']
        alerts['references'] = obj4['site'][i]['alerts'][j]['reference']
        alerts['instances'] = []
        for k in range(len(obj4['site'][i]['alerts'][j]['instances'])):
            instances = {}
            instances['evidence'] = obj4['site'][i]['alerts'][j]['instances'][k]['evidence']
            instances['uri'] = obj4['site'][i]['alerts'][j]['instances'][k]['uri']
            alerts['instances'].append(instances)
        efg['detailed_scan'].append(alerts)
# print(efg)

new = {**abc, **pqr, **stu, **efg}
print(new)

object4 = json.dumps(new, indent=4)
with open("standard_report.json", "w") as outfile:
    outfile.write(object4)



