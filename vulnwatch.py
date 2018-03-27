from pyvas import Client
import os, nmap, re
from collections import OrderedDict
from simplemenus import IdentifierMenu
from time import sleep
import progressbar

sensor = "localhost"
username = "admin"
password = ""

def check_vulnscan(task_uuid):
  
  try: 
    with Client(sensor, username=username, password=password) as cli:
      #get the UUID of the task
      #task_uuid = (item for item in cli.list_tasks() if item["name"] == pname).next().get('@id')
      
      if cli.get_task(task_uuid).get('progress') == -1:
        return 100
      else: 
        return cli.get_task(task_uuid).get('progress').get('#text')
  except Exception:
      print("wobbly")
      return 

def get_running_tasks():

    tasks = []

    with Client(sensor, username=username, password=password) as cli:
      for item in cli.list_tasks():
         if item["progress"] != "-1":
           tasks.append(item.get('name'))

      if len(tasks) == 0:
        print("[!] no running tasks... quitting")
        exit()
   
      print("[*] Pick a task to monitor.... ")
      menu = IdentifierMenu(options=tasks, sort=True)
      selection = menu.get_response()

      print(selection)
      
      #lookup the taskid by name
      task_uuid = (item for item in cli.list_tasks() if item["name"] == selection).next().get('@id')

    return task_uuid

pname = get_running_tasks()

progress=0
bar = progressbar.ProgressBar(term_width=90, widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])
bar.start()

while(progress < 100):
  progress = int(check_vulnscan(pname))
  if progress >0:
    bar.update(progress)
  sleep(60)

bar.finish()
 


#check_vulnscan(pname)
 
