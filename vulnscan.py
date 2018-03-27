from pyvas import Client
import os, nmap, re
from collections import OrderedDict
from simplemenus import IdentifierMenu

sensor = "localhost"
username = "admin"
password = ""
pname = os.path.basename(os.getcwd())
    
def get_hosts(filename):

  hosts = [] 
  nm = nmap.PortScanner()

  with open("./"+filename, "r") as fd:
    content = fd.read()
    nm.analyse_nmap_xml_scan(content)

    hosts = nm.all_hosts()

  print("[*] " + str(len(hosts)) + " hosts identified." )
  return hosts


def get_ports(filename):
  ports = []
  nm = nmap.PortScanner()

  with open("./"+filename, "r") as fd:
    content = fd.read()
    nm.analyse_nmap_xml_scan(content)

    for host in nm.all_hosts():
        for port in nm[host].all_tcp():
           if nm[host]['tcp'][port]['name'] !='tcpwrapped':
             ports.append(port)

  uniqports = list(OrderedDict.fromkeys(ports))
  
  if len(uniqports) == 0:
     print("[!] No ports identified.... exitting")
     exit()


  print("[*] " + str(len(uniqports)) + " unique ports identified.")
  print("[!] " + ",".join(map(str,uniqports))) 

  return uniqports


def do_vulnscan(pname, hosts, ports):
    print("[*] Starting Openvas loading...")
   
    with Client(sensor, username=username, password=password) as cli:
      comment = "Automatically generated"
      port_range=",".join(map(str, ports)) 

      #create a portlist, based on the ports detected in the nmap scan
      print("[*] .... created port list")
      cli.create_port_list(name=pname, port_range=port_range, comment=comment)
	
      #get the UUID of the newly generated portlist
      portlist_uuid  = (item for item in cli.list_port_lists() if item["name"] == pname).next().get('@id')

      #get the UUID of Full and Fast
      config_uuid = (item for item in cli.list_configs() if item["name"] == "Full and fast").next().get('@id')

      #create a targetlist, based on the discovered hosts in the nmap scan
      print("[*] .... created target list")
      hosts_range=",".join(hosts)
      cli.create_target(name=pname, hosts=hosts_range, port_list=portlist_uuid , comment=comment)

      #get the UUID of the newly created target
      target_uuid = (item for item in cli.list_targets() if item["name"] == pname).next().get('@id')
      
      print("[*] .... created task")
      cli.create_task(name=pname, config_uuid=config_uuid, target_uuid=target_uuid, comment=comment)

      #get the UUID of the new task
      task_uuid = (item for item in cli.list_tasks() if item["name"] == pname).next().get('@id')
      #for task in cli.list_tasks():
         #print task #.get("progress")
         #print("###############################\n\n")
      #start the task?
      print("[*] Do you want to start this task?")
      menu = IdentifierMenu(options=['Yes', 'No'], sort=True)
      selection = menu.get_response()

      if selection == 'Yes':
        print("[*] .... starting task")
        cli.start_task(uuid=task_uuid)

xmlfiles = [name for name in os.listdir('.') if os.path.isfile(name) and 'xml' in name]

#default filename
selection='disco_tcp_top1000.xml'

if len(xmlfiles) == 0:
  print("[!] No XML files found.  Exiting")
  exit()



if len(xmlfiles) > 1:
  print("[*] Multiple XML files found, please select one:")
  menu = IdentifierMenu(options=xmlfiles, sort=True)
  selection = menu.get_response()

print("[*] Starting automated vuln scanner loading....")

hosts = get_hosts(selection)
ports = get_ports(selection)

do_vulnscan(pname +"."+selection, hosts, ports)
 
