import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, HTTPServer
from alive_progress import alive_bar; import time
import os
import json
import threading
import time
import re

def xml_to_json(xml_string):
    # Преобразование строки XML в объект ElementTree
    root = ET.fromstring(xml_string)
    
    # Рекурсивный обход дерева элементов XML и преобразование их в объекты JSON
    def element_to_json(element):
        json_obj = {}
        
        # Копирование атрибутов элемента в объект JSON
        for key, value in element.attrib.items():
            json_obj[key] = value
        
        # Обход всех дочерних элементов и преобразование их в объекты JSON
        for child in element:
            child_json = element_to_json(child)
            
            # Обработка случая, когда у элемента есть несколько дочерних элементов с одним и тем же тегом
            if child.tag in json_obj:
                if isinstance(json_obj[child.tag], list):
                    json_obj[child.tag].append(child_json)
                else:
                    json_obj[child.tag] = [json_obj[child.tag], child_json]
            else:
                json_obj[child.tag] = child_json
        
        # Обработка случая, когда у элемента есть только текстовое содержимое
        if not json_obj and element.text:
            return element.text
        
        return json_obj
    
    # Преобразование корневого элемента в объект JSON
    return json.dumps(element_to_json(root))


# HTTPRequestHandler class
class testHTTPServer_RequestHandler(BaseHTTPRequestHandler):

  # GET
  def do_HEAD(self):
    # Send response status code
    self.send_response(200)

    # Send message back to client
    index = open("index.html", "r")
    message = (index.read().encode())

    # Send headers
    self.send_header('Content-type','text/plain; charset=utf-8')
    self.send_header('Content-length', str(len(message)))
    self.end_headers()

    # Write content as utf-8 data
    self.wfile.write(message)
    return
    
  def do_AUTHHEAD(self):
    self.send_response(401)
    self.send_header('WWW-Authenticate', 'Basic realm=\"metrics\"')
    self.send_header('Content-type', 'text/html')
    self.end_headers()

  def do_GET(self):
    ''' Present frontpage with user authentication. '''
    if self.headers['Authorization'] == None:
        self.do_AUTHHEAD()
        self.wfile.write(bytes('no auth header received', 'UTF-8'))
        pass
    elif self.headers['Authorization'] == 'Basic XXXXXXXXXXXXXXXXX':
        self.do_HEAD()
        self.wfile.write(bytes(self.headers['Authorization'], 'UTF-8'))
        self.wfile.write(bytes(' authenticated!', 'UTF-8'))
        pass
    else:
        self.do_AUTHHEAD()
        self.wfile.write(bytes(self.headers['Authorization'], 'UTF-8'))
        self.wfile.write(bytes(' not authenticated', 'UTF-8'))
        pass

def webserver():
  print('### STARTING METRICS SERVER')
  # Server settings
  # Choose port 8080, for port 80, which is normally used for a http server, you need root access
  server_address = ('', 8080)
  httpd = HTTPServer(server_address, testHTTPServer_RequestHandler)
  print('### METRICS SERVER STARTED')
  thread = threading.Thread(target = httpd.serve_forever)
  thread.daemon = True
  thread.start()
#  httpd.serve_forever()

def scan():
    print('### SEARCHING OPEN PORTS')
    os.system('masscan -sS -c /opt/masscan/all-network.conf --excludefile /opt/masscan/whitelist.conf')
    print('### SEARCH COMPLETED')
    MASRESULT = open("/opt/masscan/all-network.json", "r")
    ARR = (MASRESULT.read())
    jsArr = json.loads(ARR)
    MASRESULT.close()
    print('### DISCOVERING SERVICES & VULNS')
    os.system('truncate -s 0 search.html')
    COUNT = len(jsArr)
    try:
       CACHEDFILE = open("index.html", "r")
       CACHE = (CACHEDFILE.read())
       CACHEDFILE.close()
       print('### CACHE FOUND')
    except:
       CACHE = "EMPTY"
       print('### CACHE NOT FOUND')
    with alive_bar(COUNT) as bar:
        for value in jsArr:
           IP = (str(value['ip']))
           PORT = (str(value['ports'][0]['port']))
           PROTO = (str(value['ports'][0]['proto']))
           os.environ["IP"] = IP
           os.environ["PORT"] = PORT
           if PROTO == "tcp":
              os.environ["PROTO"] = "T"
           if PROTO == "udp":
              os.environ["PROTO"] = "U"
           if IP in CACHE:
              CACHEARR = CACHE.split('\n')
              for i in range(len(CACHEARR)):
                 if IP in CACHEARR[i] and PORT in CACHEARR[i]:
                    os.environ["CACHED"] = CACHEARR[i]
                    os.system('echo "#TYPE netscan_host gauge" >> /srv/netscan/search.html')
                    os.system('echo \\"$CACHED\\" >> /srv/netscan/search.html')
                    print(f'### FOUND CACHED HOST {IP} {PORT}')
                    
           else:
              print(f'### FOUND NEW HOST {IP} {PORT}')
              os.system('nmap --script-updatedb')
              os.system('nmap --min-parallelism 100 --max-parallelism 100 -sV$PROTO --version-intensity 7 -Pn -oX /opt/nmap/nmap.xml --script vuln -p $PORT $IP')
              XMLSTR = open("/opt/nmap/nmap.xml", "r")
              XML = (XMLSTR.read())
              JSONSTRING = xml_to_json(XML)
              jsArr = json.loads(JSONSTRING)
   
              try:
                 netscan_host_service=(jsArr["host"]["ports"]["port"]["service"]["name"])
              except:
                 netscan_host_service=('unknown')
   
              try:
                 netscan_host_service_version_product = (jsArr["host"]["ports"]["port"]["service"]["product"])
              except:
                 netscan_host_service_version_product=('')
   
              try:
                 netscan_host_service_version_ver = (jsArr["host"]["ports"]["port"]["service"]["version"])
              except:
                 netscan_host_service_version_ver=('')
   
              try:
                 netscan_host_service_version_extrainfo = (jsArr["host"]["ports"]["port"]["service"]["extrainfo"])
              except:
                 netscan_host_service_version_extrainfo=('')
   
             
              netscan_host_service_version = netscan_host_service_version_product + netscan_host_service_version_ver + netscan_host_service_version_extrainfo
              if netscan_host_service_version == "":
                 netscan_host_service_version=('unknown')
   
              netscan_host_ip=(jsArr["host"]["address"]["addr"])
              netscan_host_port_id=(jsArr["host"]["ports"]["port"]["portid"])
              netscan_host_port_protocol=(jsArr["host"]["ports"]["port"]["protocol"])
              os.environ["netscan_host_ip"] = netscan_host_ip
              os.environ["netscan_host_port_id"] = netscan_host_port_id
   
              if "http" in netscan_host_service or "ssl" in netscan_host_service:
                  curl = os.system('curl -k https://$netscan_host_ip:$netscan_host_port_id --tlsv1.0 --tls-max 1.0')
                  if curl == 0:
                     netscan_host_service_min_ssl_version = "1.0"
                  else:
                    curl = os.system('curl -k https://$netscan_host_ip:$netscan_host_port_id --tlsv1.1 --tls-max 1.1')
                    if curl == 0:
                       netscan_host_service_min_ssl_version = "1.1"
                    else:
                       curl = os.system('curl -k https://$netscan_host_ip:$netscan_host_port_id --tlsv1.2 --tls-max 1.2')
                       if curl == 0:
                          netscan_host_service_min_ssl_version = "1.2"
                       else:
                          curl = os.system('curl -k https://$netscan_host_ip:$netscan_host_port_id --tlsv1.3 --tls-max 1.3')
                          if curl == 0:
                             netscan_host_service_min_ssl_version = "1.3"
                          else:
                             netscan_host_service_min_ssl_version = "unknown"
              else:
                 netscan_host_service_min_ssl_version = "unknown"
   
              try:
                 host_cidr = IP.split('.')
                 host_cidr[-1] = '0'
                 netscan_host_cidr = '.'.join(host_cidr)
              except:
                 netscan_host_cidr = "unknown"
   
              os.environ["netscan_host_cidr"] = netscan_host_cidr
              os.environ["netscan_host_vuln"] = "novuln"
              os.environ["netscan_host_port_protocol"] = netscan_host_port_protocol
              os.environ["netscan_host_service"] = netscan_host_service
              os.environ["netscan_host_service_version"] = netscan_host_service_version
              os.environ["netscan_host_service_min_ssl_version"] = netscan_host_service_min_ssl_version
                #find vulneravles in scripts
              try:
                  netscan_host_vuln_script=(jsArr["host"]["hostscript"]["script"])
                  host_vuln = [{netscan_host_vuln_script[i]['id']:netscan_host_vuln_script[i]['output']} for i in range(len(netscan_host_vuln_script))]
                  print(host_vuln)
                  netscan_host_vuln = re.sub('[^A-Za-z0-9-:.= ]+', '', str(host_vuln))
                  if ((netscan_host_vuln is not None) and (netscan_host_vuln.index("VULNERABLE"))):
                      os.environ["netscan_host_vuln"] = netscan_host_vuln
              except:
                  print('### PORTSCRIPT NOVULN')
                 # os.environ["netscan_host_vuln"] = "NONE"
              try:
                  netscan_host_port_vuln_script=(jsArr["host"]["ports"]["port"]["script"])
                  port_vuln = [{netscan_host_port_vuln_script[i]['id']:netscan_host_port_vuln_script[i]['output']} for i in range(len(netscan_host_port_vuln_script))]
                  print(port_vuln)
                  netscan_host_port_vuln = re.sub('[^A-Za-z0-9-:.= ]+', '', str(port_vuln))
                  if ((netscan_host_port_vuln is not None) and (netscan_host_port_vuln.index("VULNERABLE"))):
                      os.environ["netscan_host_vuln"] = netscan_host_port_vuln
              except:
                  print('### HOSTSCRIPT NOVULN')
                  #os.environ["netscan_host_vuln"] = "NONE"
      
              os.system('echo "#TYPE netscan_host gauge" >> /srv/netscan/search.html')
              os.system('echo "netscan_host {netscan_host_cidr=\\"$netscan_host_cidr\\", netscan_host_ip=\\"$netscan_host_ip\\", netscan_host_port_id=\\"$netscan_host_port_id\\", netscan_host_port_protocol=\\"$netscan_host_port_protocol\\", netscan_host_service=\\"$netscan_host_service\\", netscan_host_service_version=\\"$netscan_host_service_version\\", netscan_host_service_min_ssl_version=\\"$netscan_host_service_min_ssl_version\\", netscan_host_vuln=\\"$netscan_host_vuln\\"} 1" >> /srv/netscan/search.html')
   
              bar() 
    print('### DISCOVERING COMPLETED')
    os.system('truncate -s 0 index.html && cat search.html >> index.html && truncate -s 0 search.html')
    time.sleep(3600)

print(' ███╗░░██╗███████╗████████╗░██████╗░█████╗░░█████╗░███╗░░██╗ ')
print(' ████╗░██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔══██╗████╗░██║ ')
print(' ██╔██╗██║█████╗░░░░░██║░░░╚█████╗░██║░░╚═╝███████║██╔██╗██║ ')
print(' ██║╚████║██╔══╝░░░░░██║░░░░╚═══██╗██║░░██╗██╔══██║██║╚████║ ')
print(' ██║░╚███║███████╗░░░██║░░░██████╔╝╚█████╔╝██║░░██║██║░╚███║ ')
print(' ╚═╝░░╚══╝╚══════╝░░░╚═╝░░░╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝ ')
print('                        .7.:^~7?.             .              ')
print('                         :^^:.:@P         :7?PG5P57:         ')
print('                               &P      .!PBPYJJ5GPB#P^       ')
print('         @@@@@@@@@@@@@        .@B.   .^G&?..    .:5GY&G.     ')
print('       @@@@@@@@@@@@@@@@@:      ?#B5Y5G#G~          G&JB5     ')
print('     .Y#&@@@@@@@@@@@@@@@@&P:     :^~^:.             @B5&J    ')
print('     .@@@@@@@@@@@@@@@@@@@@@@~                       ?@!GG    ')
print('     .@@@@@@@@@@@@@@@@@@@@@@@5:                     :@JB#.   ')
print('      B@@@@@@@@@@@@@@@@@&&&#&@@#~                   ^@J#G.   ')
print('      .&@@@@@@@@@@@@&&&&Y   @ @@@&                   5@J&B   ')
print('        7#@@@@@@&&#B#&YBG5G@G@@@&~#                 !@#5@~   ')
print('    ..:^^^~75B&&&@@@@BBY@@@@@@@@@@&Y.            .Y@@Y#G     ')
print(' .!G##&@&&&#J. ......JY#@@@@@@@@@@@@&:         :Y&@@PBG~!~^:.')
print(':&@BY^:^:^Y@@#. .~?YPB&@@@@@@@@@@@@@@@J:...:~J#@@@&GGJ5@@&&&&')
print('&@G.       5&@!5@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#PGY#@~:^~7Y')
print('@@Y       .#&G&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#YY~P@@@#?.   ')
print('#@@?.....:?&#B@@@@GP@@@@@@@@@@@@@@@@@@#BB#BG5?7~.  .7B&@@@#?.')
print('.P@@@&&&@@5#G@#5~.~#@@@@@@@@@@@@@&@@@&B#GG&&&7        .!&@@@@')
print('  .7P#&&#BJ&Y.  .G@@@@@@@G&@@@@@@B@@@@P#&&&&@@&Y:       ~@@@@')
print('      ...^5G. ~G@@@@@@&P^ &@@@@@&B@@@@PG#&##&&&@@&PJ??7Y#@@@@')
print('Y:    .!7?~^JB&@@@&&&5^  J@@@@@#5@@@@@J&&GB&&##&&#&@@@@@@@@#5')
print('7B    .!P##&@&&&BP7!:   J@@@@@5 7@@@@&JYB&&G5G#BGBBBPPBBY7!. ')
print('.. :!P&&BP5Y5YJ#@&P:   J@@@@&~  J&@@@GB#P?YP##PB&BY7:        ')
print('~JY###B##G#Y^.  J@&P  !@@@@B.   P#@@@J#@^ ^~^..^!!G#BG.      ')
print('5PJ~~&@&##~     .&&G..@@@@P    :#&@@#Y@Y 5@^.      :B&?      ')
print('    ^@&BPG.     ~G#P 5@@@#     5B&@@YB@J :B&P7^:.   P&7      ')
print('    .&@@#BY^:::J##@~ &@@@:    .##&@&JG@&.  :?55P#B~ Y@!      ')
print('     :#@@&&&B#@@&B~  Y@@@Y    :##@@GY&#@&:      ^@@:.G&!.....')
print('       ^YGB##BG?^     Y@@@B.  .B#@@J.YB#&@Y.    .&@~  ^7?7~^:')
print('                       ~&@@&^ .GG@@?  ~PB#@@#GG#&@G          ')
print('                        .5@@@^ J&@@5   .:?5GB#BB5^           ')
print('                          !@@# .Y&@&        ..               ')
print('                           B@&. .5&@7                        ')
print('                           &@7    ~#@7                       ')
print('                          P@5      .!BG!.      ..            ')
print('                 ...   .^B&!          :7YJ~:..  Y~           ')
print('                  :!JY55Y!.              .:~!!7JJ.           ')
print('                    ...                                      ')
    

webserver()
while True:
    scan()