import socket
import time
import threading
import sys
from queue import Queue
from datetime import datetime
import whois
from nslookup import Nslookup


def scanPorts(target1):
   discovered_ports = []
   socket.setdefaulttimeout(0.30)
   print_lock = threading.Lock()

   ####    whois   #####

   whoisinfo = whois.whois(target1)

   ####    whois   #####

   ####    nslookup   ####


   dns_query = Nslookup()
   # Alternatively, the Nslookup constructor supports optional
   # arguments for setting custom dns servers (defaults to system DNS),
   # verbosity (default: True) and using TCP instead of UDP (default: False)
   dns_query = Nslookup(dns_servers=["1.1.1.1"], verbose=False, tcp=False)

   ips_record = dns_query.dns_lookup(target1)
   ns1 = [ips_record.response_full, ips_record.answer]

   soa_record = dns_query.soa_lookup(target1)
   ns2 = [soa_record.response_full, soa_record.answer]


   #### nslookup    ####
    


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
   return discovered_ports, whoisinfo, ns1, ns2


# target = "google.com" 

# print(scanPorts(target))

