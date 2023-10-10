import socket
import time
import threading
import sys
from queue import Queue
from datetime import datetime
import whois


def scanPorts(target1):
   discovered_ports = []
   socket.setdefaulttimeout(0.30)
   print_lock = threading.Lock()

   ####    whois   #####

   whoisinfo = whois.whois(target1)

   ####    whois   #####
    


   time.sleep(1)
   target = target1
   error = ("Invalid Input")
   try:
      t_ip = socket.gethostbyname(target)
   except (UnboundLocalError, socket.gaierror):

     sys.exit()

   t1 = datetime.now()

   def portscan(port):

      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       
      try:
         portx = s.connect((t_ip, port))
         with print_lock:

            discovered_ports.append(str(port))

         portx.close()

      except (ConnectionRefusedError, AttributeError, OSError):
         pass

   def threader():
      while True:
         worker = q.get()
         portscan(worker)
         q.task_done()
      
   q = Queue()
     

     
   for x in range(200):
      t = threading.Thread(target = threader)
      t.daemon = True
      t.start()

   for worker in range(1, 6000):     #65536
      q.put(worker)

   q.join()

   t2 = datetime.now()
   total = t2 - t1

   t3 = datetime.now()
   total1 = t3 - t1
   return discovered_ports, whoisinfo


# target = "google.com" 

# print(scanPorts(target))

