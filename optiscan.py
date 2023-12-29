
import argparse
from collections import OrderedDict as odict
from os import path,sep,system
from time import sleep as se
import socket,threading,signal,sys,random,struct
import argparse

# Create an ArgumentParser object
parser = argparse.ArgumentParser()

# Add command line arguments
parser.add_argument("-t", "--target", help="Specify target hostname or IP")
parser.add_argument("-P", "--protocol", help="Specify connection protocol")
parser.add_argument("-p", "--ports", help="Specify ports to scan")
parser.add_argument("-s", "--start", help="Specify ports to scan")

# Parse the command line arguments
args = parser.parse_args()

# Access the values assigned to the variables
target = args.target
protocol = args.protocol
ports = args.ports
start = args.start

# Use the values as needed
print("Target:", target)
print("Protocol:", protocol)
print("Ports:", ports)
import queue,http.client as httplib, urllib.request as urllib
qu = lambda : queue.Queue()
input = input

Services = {512: 'exec', 1: 'tcpmux', 2: 'nbp', 515: 'printer', 4: 'echo', 517: 'talk', 6: 'zip', 7: 'echo', 520: 'route', 9: 'discard', 11: 'systat', 13: 'daytime', 526: 'tempo', 15: 'netstat', 5308: 'cfengine', 17: 'qotd', 18: 'msp', 19: 'chargen', 20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 538: 'gdomap', 540: 'uucp', 7002: 'afs3-prserver', 543: 'klogin', 544: 'kshell', 546: 'dhcpv6-client', 547: 'dhcpv6-server', 548: 'afpovertcp', 37: 'time', 2086: 'gnunet', 39: 'rlp', 2600: 'zebrasrv', 2601: 'zebra', 42: 'nameserver', 43: 'whois', 556: 'remotefs', 2605: 'bgpd', 2606: 'ospf6d', 2607: 'ospfapi', 2608: 'isisd', 49: 'tacacs', 563: 'nntps', 513: 'login', 53: 'domain', 2102: 'zephyr-srv', 2103: 'zephyr-clt', 1080: 'socks', 2105: 'eklogin', 3130: 'icpv2', 6003: 'x11-3', 2111: 'kx', 10080: 'amanda', 67: 'bootps', 68: 'bootpc', 69: 'tftp', 70: 'gopher', 2119: 'gsigatekeeper', 2121: 'iprop', 587: 'submission', 24554: 'binkp', 79: 'finger', 80: 'http', 6007: 'x11-7', 514: 'shell', 4691: 'mtn', 3632: 'distcc', 1109: 'kpop', 87: 'link', 88: 'kerberos', 17500: 'db-lsp', 4190: 'sieve', 607: 'nqs', 11201: 'smsqp', 610: 'npmp-local', 611: 'npmp-gui', 612: 'hmmp-ind', 2150: 'ninstall', 102: 'iso-tsap', 1127: 'supfiledbg', 104: 'acr-nema', 3689: 'daap', 106: 'poppassd', 11371: 'hkp', 17004: 'sgi-cad', 530: 'courier', 110: 'pop3', 111: 'sunrpc', 22128: 'gsidcap', 113: 'auth', 115: 'sftp', 628: 'qmqp', 119: 'nntp', 532: 'netnews', 2135: 'gris', 123: 'ntp', 636: 'ldaps', 2101: 'rtcm-sc104', 533: 'netwall', 4224: 'xtell', 17003: 'sgi-gcd', 3205: 'isns', 135: 'epmap', 137: 'netbios-ns', 138: 'netbios-dgm', 139: 'netbios-ssn', 706: 'silc', 143: 'imap2', 30865: 'csync2', 9667: 'xmms2', 1646: 'sa-msg-port', 1812: 'radius', 1178: 'skkserv', 623: 'asf-rmcp', 6001: 'x11-1', 5222: 'xmpp-client', 5680: 'canna', 10081: 'kamanda', 161: 'snmp', 162: 'snmp-trap', 163: 'cmip-man', 164: 'cmip-agent', 1701: 'l2f', 5269: 'xmpp-server', 1649: 'kermit', 57000: 'dircproxy', 1194: 'openvpn', 5052: 'enbd-sstatd', 6002: 'x11-2', 174: 'mailq', 177: 'xdmcp', 178: 'nextstep', 179: 'bgp', 8081: 'tproxy', 9673: 'zope', 6004: 'x11-4', 1210: 'predict', 5151: 'pcrd', 3260: 'iscsi-target', 6346: 'gnutella-svc', 1214: 'kazaa', 194: 'irc', 6347: 'gnutella-rtr', 5051: 'enbd-cstatd', 199: 'smux', 201: 'at-rtmp', 202: 'at-nbp', 631: 'ipp', 204: 'at-echo', 5666: 'nrpe', 206: 'at-zis', 209: 'qmtp', 210: 'z3950', 5667: 'nsca', 1236: 'rmtcfg', 213: 'ipx', 9418: 'git', 1241: 'nessus', 655: 'tinc', 549: 'idfp', 2000: 'cisco-sccp', 3690: 'svn', 2792: 'f5-globalsite', 5353: 'mdns', 3306: 'mysql', 5355: 'hostmon', 20012: 'vboxd', 749: 'kerberos-adm', 750: 'kerberos4', 751: 'kerberos-master', 752: 'passwd-server', 5672: 'amqp', 754: 'krb-prop', 8021: 'zope-ftp', 6697: 'ircs-u', 760: 'krbupdate', 2811: 'gsiftp', 10050: 'zabbix-agent', 554: 'rtsp', 1645: 'datametrics', 4353: 'f5-iquery', 2603: 'ripngd', 4373: 'remctl', 775: 'moira-db', 2583: 'mon', 777: 'moira-update', 779: 'moira-ureg', 783: 'spamd', 10000: 'webmin', 4369: 'epmd', 60179: 'fido', 1300: 'wipld', 1813: 'radius-acct', 7003: 'afs3-vlserver', 10051: 'zabbix-trapper', 8990: 'clc-build-daemon', 901: 'swat', 1313: 'xtel', 1314: 'xtelw', 4899: 'radmin-port', 60177: 'tfido', 808: 'omirr', 6444: 'sge-qmaster', 6445: 'sge-execd', 6446: 'mysql-proxy', 22125: 'dcap', 5432: 'postgresql', 9098: 'xinetd', 319: 'ptp-event', 320: 'ptp-general', 7009: 'afs3-rmtsys', 2602: 'ripd', 6667: 'ircd', 7100: 'font-service', 1863: 'msnp', 1352: 'lotusnote', 5671: 'amqps', 7001: 'afs3-callback', 1677: 'groupwise', 2104: 'zephyr-hm', 17002: 'sgi-crsd', 853: 'domain-s', 10809: 'nbd', 7000: 'afs3-fileserver', 345: 'pawserv', 346: 'zserv', 347: 'fatserv', 7004: 'afs3-kaserver', 7005: 'afs3-volser', 7006: 'afs3-errors', 7007: 'afs3-bos', 7008: 'afs3-update', 2401: 'cvspserver', 10082: 'amandaidx', 10083: 'amidxtape', 5688: 'ggz', 871: 'supfilesrv', 11112: 'dicom', 873: 'rsync', 6514: 'syslog-tls', 6000: 'x11', 369: 'rpc2portmap', 370: 'codaauth2', 371: 'clearcase', 372: 'ulistserv', 6005: 'x11-5', 6006: 'x11-6', 2604: 'ospfd', 5354: 'noclog', 2430: 'venus', 2431: 'venus-se', 2432: 'codasrv', 2433: 'codasrv-se', 13720: 'bprd', 2947: 'gpsd', 389: 'ldap', 6696: 'babel', 5002: 'rfe', 2053: 'knetd', 9101: 'bacula-dir', 9102: 'bacula-fd', 9103: 'bacula-sd', 8080: 'http-alt', 531: 'conference', 2628: 'dict', 4500: 'ipsec-nat-t', 27374: 'asp', 406: 'imsp', 13721: 'bpdbm', 8088: 'omniorb', 1433: 'ms-sql-s', 1434: 'ms-sql-m', 5190: 'aol', 525: 'timed', 13722: 'bpjava-msvc', 1093: 'proofd', 5674: 'mrtd', 1094: 'rootd', 1958: 'log-server', 1959: 'remoteping', 13724: 'vnetd', 427: 'svrloc', 2988: 'afbackup', 2989: 'afmbackup', 5555: 'rplay', 5556: 'freeciv', 1524: 'ingreslock', 5050: 'mmcc', 443: 'https', 444: 'snpp', 445: 'microsoft-ds', 4031: 'suucp', 5675: 'bgpsim', 1099: 'rmiregistry', 5060: 'sip', 5061: 'sip-tls', 3493: 'nut', 8140: 'puppet', 4557: 'fax', 4559: 'hylafax', 464: 'kpasswd', 465: 'submissions', 2003: 'cfinger', 20011: 'isdnlog', 13782: 'bpcd', 13783: 'vopied', 4569: 'iax', 2010: 'search', 989: 'ftps-data', 990: 'ftps', 1957: 'unix-status', 992: 'telnets', 993: 'imaps', 995: 'pop3s', 6566: 'sane-port', 487: 'saft', 1001: 'customs', 3050: 'gds-db', 22273: 'wnn6', 9359: 'mandelspawn', 765: 'webster', 15345: 'xpilot', 518: 'ntalk', 500: 'isakmp', 2049: 'nfs', 4600: 'distmp3', 1529: 'support', 17001: 'sgi-cmsd', 4094: 'sysrqd', 4949: 'munin'}

import os,re,codecs,socket,contextlib,pickle,sys
#startvslib
parser = lambda data: [[key,"|".join(data['match']['versioninfo'][key])] for key in data['match']['versioninfo'].keys() if data['match']['versioninfo'][key]] if "match" in data.keys() and "versioninfo" in data['match'].keys() else None
def write(text):
    sys.stdout.write(text.replace("#r", "\033[1;31m").replace("#g","\033[1;32m").replace("#y", "\033[1;33m").replace("#w", "\033[1;37m") + '\033[1;37m')
    sys.stdout.flush()
class serviceScan(object):
    def __init__(main, socktimeout=10, socksize=1024, tryy=2,verbose=False):
        main.socktimeout = socktimeout
        main.socksize = socksize
        main.verbose = verbose
        main.tryy = tryy
        main.tryyb  =main.tryy
        probesFile = open(__file__.split("optiscan.py")[0]+"probes.pkl", "rb")
        main.allprobes =  pickle.load(probesFile) if sys.version_info.major <=2 else pickle.load(probesFile, encoding="utf8")
        probesFile.close()
    sort_probes_by_rarity = lambda main,probes:sorted(probes, key=lambda k: k['rarity']['rarity'])
    def scan(main, host, port, protocol):
        main.done = False
        main.tryy = main.tryyb
        fingerprint = {}
        in_probes, ex_probes = main.filter_probes_by_port(port, main.allprobes)
        if in_probes:
            probes = main.sort_probes_by_rarity(in_probes)
            fingerprint = main.scan_with_probes(host, port, protocol, probes)
        if fingerprint: return fingerprint
        if ex_probes:
            fingerprint = main.scan_with_probes(host, port, protocol, ex_probes)
        return fingerprint
    def scan_with_probes(main, host, port, protocol, probes):
        fingerprint = {}
        for probe in probes:
            record = main.send_probestring_request(host, port, protocol, probe, main.socktimeout)
            if bool(record["match"]["versioninfo"]):
                fingerprint = record
                break
            if main.done:break
        return fingerprint
    def send_probestring_request(main, host, port, protocol, probe, timeout):
        proto = probe['probe']['protocol']
        payload = probe['probe']['probestring']
        payload, _ = codecs.escape_decode(payload)
        response = ""
        if (proto.upper() == protocol.upper()):
            if (protocol.upper() == "TCP"):response = main.send_tcp_request(host, port, payload, timeout)
            elif (protocol.upper() == "UDP"):response = main.send_udp_request(host, port, payload, timeout)
        pattern, fingerprint = main.match_probe_pattern(response, probe)
        return {"probe": {
                     "probename": probe["probe"]["probename"],
                     "probestring": probe["probe"]["probestring"]
                      },
                  "match": {
                     "pattern": pattern,
                     "versioninfo": fingerprint
                  }}
    def send_tcp_request(main, host, port, payload, timeout):
        data = ''
        try:
            with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as client:
                client.settimeout(timeout)
                client.connect((host, int(port)))
                client.send(payload)
                while True:
                    if main.done:break
                    _ = client.recv(main.socksize)
                    if not _: break
                    data += _ if sys.version_info.major <=2 else _.decode("ISO-8859-1")
        except Exception as err:
           if main.verbose: write("Try[#{}] {} : {} - {}".format(main.tryy,host, port, err))
           if not main.tryy:main.done = True
           else:main.tryy-=1
        return data
    def send_udp_request(main, host, port, payload, timeout):
        data = ''
        try:
            with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as client:
                client.settimeout(timeout)
                client.sendto(payload, (host, port))
                while True:
                    if main.done:break
                    _, addr =client.recvfrom(main.socksize)
                    if not _: break
                    data += _ if sys.version_info.major <=2 else _.decode("ISO-8859-1")
        except Exception as err:
           if main.verbose: write("Try[#{}] {} : {} - {}\n".format(main.tryy,host, port, err))
           if not main.tryy:main.done = True
           else:main.tryy-=1
        return data
    def match_probe_pattern(main, data, probe):
        pattern, fingerprint = "", {}
        if not data:return pattern, fingerprint
        for match in probe['matches']:
            rfind = match['pattern_compiled'].findall(data)
            if rfind and ("versioninfo" in match):
                versioninfo = match['versioninfo']
                rfind = rfind[0]
                rfind = [rfind] if isinstance(rfind, str) else rfind
                for index, value in enumerate(rfind):
                    dollar_name = "${}".format(index + 1)
                    versioninfo = versioninfo.replace(dollar_name, value)
                pattern = match['pattern']
                fingerprint = main.match_versioninfo(match['service'],versioninfo)
                break
        return pattern, fingerprint
    def match_versioninfo(main, service,versioninfo):
        record = {"service":[service],
                  "vendorproductname": [],
                  "version": [],
                  "info": [],
                  "hostname": [],
                  "operatingsystem": [],
                  "cpename": []}
        if "p/" in versioninfo:
            regex = re.compile(r"p/([^/]*)/")
            vendorproductname = regex.findall(versioninfo)
            record["vendorproductname"] = vendorproductname
        if "v/" in versioninfo:
            regex = re.compile(r"v/([^/]*)/")
            version = regex.findall(versioninfo)
            record["version"] = version
        if "i/" in versioninfo:
            regex = re.compile(r"i/([^/]*)/")
            info = regex.findall(versioninfo)
            record["info"] = info
        if "h/" in versioninfo:
            regex = re.compile(r"h/([^/]*)/")
            hostname = regex.findall(versioninfo)
            record["hostname"] = hostname
        if "o/" in versioninfo:
            regex = re.compile(r"o/([^/]*)/")
            operatingsystem = regex.findall(versioninfo)
            record["operatingsystem"] = operatingsystem
        if "d/" in versioninfo:
            regex = re.compile(r"d/([^/]*)/")
            devicetype = regex.findall(versioninfo)
            record["devicetype"] = devicetype
        if "cpe:/" in versioninfo:
            regex = re.compile(r"cpe:/a:([^/]*)/")
            cpename = regex.findall(versioninfo)
            record["cpename"] = cpename
        return record
    def filter_probes_by_port(main, port, probes):
        included = []
        excluded = []
        for probe in probes:
            if "ports" in probe:
                ports = probe['ports']['ports']
                if main.is_port_in_range(port, ports):included.append(probe)
                else:excluded.append(probe)
            elif "sslports" in probe:
                sslports = probe['sslports']['sslports']
                if main.is_port_in_range(port, sslports):included.append(probe)
                else: excluded.append(probe)
            else:excluded.append(probe)
        return included, excluded
    def is_port_in_range(main, port, port_rule):
        bret = False
        ports = port_rule.split(',')
        if str(port) in ports:
            bret = True
        else:
            for nmap_port in ports:
                if "-" in nmap_port:
                    s, e = nmap_port.split('-')
                    if int(port) in range(int(s), int(e)):
                        bret = True
        return bret

#vslibend

errmsg = lambda msg: write("#y[#r-#y] Error: {}#r !!!#w\n".format(msg))


class anym(threading.Thread):
    def __init__(main,prompt):
        threading.Thread.__init__(main)
        main.prompt = prompt
        main.done = False
    def run(main):
        main.done = False
        anim = ('[=      ]', '[ =     ]', '[  =    ]', '[   =   ]',
         '[    =  ]', '[     = ]', '[      =]', '[      =]',
         '[     = ]', '[    =  ]', '[   =   ]', '[  =    ]',
      '[ =     ]', '[=      ]')
        i = 0
        dot = "."
        while not main.done:
                if len(dot) ==4:
                    dot = "."
                    write("\b\b\b\b")
                    write("     ")
                write("\r"+anim[i % len(anim)]+main.prompt+dot)
                se(1.0/5)
                i+=1
                dot+="."
                if main.done:break

def getPorts(ports):
    if not set(ports).issubset("1234567890,-"):return False
    PORTS = []
    ports = ports.strip()
    if "," in ports:
      ports = list(filter(lambda elem:elem if elem.strip() else None,ports.split(",")))
      for port in ports:
       if "-" not in port:
        if port.isdigit() and  0 <= int(port) <= 65535:PORTS.append(int(port))
       else:
        if port.count("-")==1:
         s,e= port.split("-")
         if s.strip() and e.strip():
          if s.isdigit() and e.isdigit():
           s,e=int(s),int(e)
           if s<e:
            if s >=0 and e <= 65535: PORTS+=range(s, e+1)
    elif "-" in ports:
     if ports.count("-")==1:
      s,e = ports.split("-")
      if s.strip() and e.strip():
       if s.isdigit() and e.isdigit():
         s,e=int(s),int(e)
         if s<e:
          if s >= 0 and e <= 65535:PORTS=range(s, e+1)
    else:
     if ports.isdigit() and 0 <= int(ports) <= 65535 :PORTS = [int(ports)]
    return PORTS

def getService(port, status="open",raw=False):
    if port in Services.keys():
       if status=="open":return  "/#g{}".format(Services[port]) if not raw else Services[port]
       else:return "/#r{}".format(Services[port])
    return ""

class PortScan(object):
    def __init__(main,sock,target,port,timeout):
        main.sock = sock
        main.target = target
        main.port=port
        main.timeout = timeout
    @property
    def tcpScan(main):
        main.sock.settimeout(main.timeout)
        try:
            main.sock.connect((main.target, main.port))
            main.sock.close()
            return True
        except socket.error:pass
        return False

    @property
    def udpScan(main):
            try:
                main.sendPkt()
                main.sock.close()
                return True
            except (socket.error,socket.timeout):pass
            return False

    def sendPkt(main):
        pkt=main._build_packet()
        main.sock.settimeout(main.timeout)
        main.sock.sendto(bytes(pkt), (main.target, main.port))
        data, addr = main.sock.recvfrom(1024)
        main.sock.close()

    def _build_packet(main):
        randint = random.randint(0, 65535)
        packet = struct.pack(">H", randint)
        packet += struct.pack(">H", 0x0100)
        packet += struct.pack(">H", 1)
        packet += struct.pack(">H", 0)
        packet += struct.pack(">H", 0)
        packet += struct.pack(">H", 0)
        packet += struct.pack("B", 0)
        packet += struct.pack(">H", 1)
        packet += struct.pack(">H", 1)
        return packet

class scanThread(threading.Thread):
    daemon = True
    def __init__(main):
        threading.Thread.__init__(main)
    createSocket = lambda main: socket.socket(socket.AF_INET, socket.SOCK_STREAM) if config['protocol'] == "tcp" else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    def run(main):
        while True:
            lock.acquire()
            if config['ports'].empty():
                lock.release()
                break
            port = config['ports'].get()
            lock.release()
            sock = main.createSocket()
            if config['protocol']=="tcp":result = PortScan(sock, config['target'], port, config['timeout']).tcpScan
            else:result = PortScan(sock, config['target'], port, config['timeout']).udpScan
            if result:
                config['result']['open'].append(port)
                if config['verbose']:write("#g[#w+#g] {}#w:#g{}#w{}/#g{}#w :#g OPEN\n".format(config['target'], port,getService(port), config['protocol']))
                if config['servScan']:
                    if config['verbose']:write("[~] Scanning for [{}] Service Info...\n".format(port))
                    info  =config['servScan'].scan(config['target'], port, config['protocol'])
                    if info:
                        config['result']['version'][port]=parser(info)
                        config['result']['open'].remove(port)
            else:
                config['result']['close']+=1
                if config['verbose']:write("#y[#r-#y] {}#w:#r{}#y{}#y/#r{}#y :#r CLOSED\n".format(config['target'], port, getService(port, status="close"), config['protocol']))
            if isKilled():break
            config['ports'].task_done()
        config['ret']+=1

class Optiscan:
    def __init__(main):
        

        # Use the values as needed
        print("Target:", target)
        print("Protocol:", protocol)
        print("Ports:", ports)
        
        
        
        main.runner = False
        main.autoclean = False
        main.cmdCtrlC = True
        main.target = target
        main.mports = {"tcp":"1,3,7,9,13,17,19,20-23,25,26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464,465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157,50000", "udp":"7,9,13,17,19,21-23,37,42,49,53,67-69,80,88,111,120,123,135-139,158,161-162,177,192,199,389,407,427,443,445,464,497,500,514-515,517-518,520,593,623,626,631,664,683,800,989-990,996-999,1001,1008,1019,1021-1034,1036,1038-1039,1041,1043-1045,1049,1068,1419,1433-1434,1645-1646,1701,1718-1719,1782,1812-1813,1885,1900,2000,2002,2048-2049,2148,2222-2223,2967,3052,3130,3283,3389,3456,3659,3703,4000,4045,4444,4500,4672,5000-5001,5060,5093,5351,5353,5355,5500,5632,6000-6001,6346,7938,9200,9876,10000,10080,11487,16680,17185,19283,19682,20031,22986,27892,30718,31337,32768-32773,32815,33281,33354,34555,34861-34862,37444,39213,41524,44968,49152-49154,49156,49158-49159,49162-49163,49165-49166,49168,49171-49172,49179-49182,49184-49196,49199-49202,49205,49208-49211,58002,65024"}
        main.protocol = protocol
        main.portsSet = False
        main.ports = ports  # main.mports[main.protocol.lower()]
        main.timeout = "5"
        main.version = "true"
        main.threads = "30"
        main.verbose = "true"
        main.options = ("target", "ports", "protocol", "timeout", "threads", "version", "verbose")
        main.defaultVal = {"target":main.target,"protocol": main.protocol, "timeout": main.timeout, "threads":main.threads, "version":main.version, "verbose":main.verbose}
        main.tarOpt = odict([("target",['yes',"Specify Target hostname or IP",main.target]),
                        ("ports",['optional',"Specify Ports To Scan",main.ports]),
                        ("protocol",['optional', "Specify Connection Protocol",main.protocol]),
                       ("timeout", ['optional',"Specify Connection Timeout",main.timeout])])
        main.modOpt = odict([
                       ("threads", ['optional', "Specify Number Of Threads",main.threads]),
                       ("version", ['optional', "Specify 'true' To Enable Service And Version Scan",main.version]),
                       ("verbose",['optional',"Specify 'true' To Show Output",main.verbose])])
        main.commands = odict([("help","show this help msg"),
                         ("start","start optiscan scan "),
                         ("options","show optiscan options"),
                         ("set", "set values of options"),
                         ("reset", "reset value of option to default"),
                         ("exec", "execute an external command"),
                         ("autoclean", "auto clean the screen"),
                         ("exit", "exit optiscan script")])
                         
        main.banner = """

Optiscan

"""
    def quit(main,sig,fream):
     if not main.cmdCtrlC:
      if not config['verbose']: an.done = True
      if config['servScan']:config['servScan'].done = True
      kill()
      write("\n#y[#r~#y]#r Aborting#y...\n")
      while config['ret'] != config['threads']: continue
      if config['verbose'] and main.printed <2:
          for t in main.THREADS:write("#y[#r!#y] Thread-{} :#y Aborted #r!\n".format(t.ident))
      write("\n#r[#y!#r]#y Scan Die#r:#y reason#r:#y Aborted by user #r!!!\n\n")
      if not main.printed:main.printPorts()
      main.abroFlag = True
     else:sys.exit("\n")
    def startThreads(main):
        if config['verbose']:write("#g[#w~#g]#w Scanning ...\n")
        else:
            global an
            an = anym("Scanning[{}]".format(config['target']))
            an.start()
        for _ in range(config["threads"]):
            thread = scanThread()
            thread.start()
            main.THREADS.append(thread)
        for t in main.THREADS:t.join()
        main.finFlag = True

    def printPorts(main):
        if config['servScan'] and config['result']['version']:
            print(f"\nServices Info of {config['target']}\n")
            for port, info in config['result']['version'].items():
                print(f"\nPort {port} Info:")
                for key, val in info:
                    if val:
                        print(f"  {key.strip()} : {val.strip()}")
                print("\n")

        if not config['verbose'] and config['result']['close']:
            print(f"\nNot shown: {config['result']['close']} closed ports.\n")

        if config['result']['open']:
            print(f"\nServices Info of {config['target']}\n")
            for port in config['result']['open']:
                print(f"\nPort {port} Info:")
                service = getService(port, raw=True)
                print(f"  protocol : {config['protocol']}")
                print(f"  state : OPEN")
                print(f"  service : {service}\n")


    def show_options(main):
        if main.autoclean:main.clean()
        LAYOUT ="  {!s:15} {!s:10} {!s:50} {!s:39}"
        main.tarOpt = odict([("target",['yes',"Specify Target hostname or IP",main.target]),
                        ("ports",['optional',"Specify Ports To Scan",main.ports]),
                        ("protocol",['optional', "Specify Connection Protocol",main.protocol]),
                       ("timeout", ['optional',"Specify Connection Timeout",main.timeout])])
        main.modOpt = odict([
                       ("threads", ['optional', "Specify Number Of Threads",main.threads]),
                       ("version", ['optional', "Specify 'true' To Enable Service And Version Scan",main.version]),
                       ("verbose",['optional',"Specify 'true' To Show Output",main.verbose])])
        write("\n#gTarget Options\n#w==============#g\n\n")
        print(LAYOUT.format("[option]","[RQ]","[Description]","[value]"))
        write("#w  --------        ----       -------------                                      -------\n")
        for opt in main.tarOpt.keys():
            val = main.tarOpt[opt]
            if opt == "ports":val[-1]="top-200-ports"
            print(LAYOUT.format(*[opt]+val))

        write("\n#wModule Options\n#g==============#w\n\n")
        print(LAYOUT.format("[option]","[RQ]","[Description]","[value]"))
        write("#g  --------        ----       -------------                                      -------\n")
        for opt in main.modOpt.keys():
            print(LAYOUT.format(*[opt]+main.modOpt[opt]))

    def show_help(main):
                if main.autoclean:main.clean()
                LAYOUT ="  {!s:16} {!s:10}"
                write("\n#goptiscan Commands\n#w================\n\n")
                write("  Command          Description\n  #g-------#w          #g-----------\n")
                for com,des in main.commands.items():
                    print(LAYOUT.format(*[com,des]))
    clean = staticmethod(lambda : system("cls||clear"))

    def resetPorts(main):
        main.portsSet = False
        return main.mports[main.protocol]

    def checkInternet(main):
       try:
         socket.create_connection((socket.gethostbyname("www.google.com"), 80), 2)
         return True
       except socket.error: pass
       return False

    def shell(main):
        signal.signal(signal.SIGINT, main.quit)
        signal.signal(signal.SIGTERM,main.quit)
        if (start == "start"):
            main.start()
            
        cmd.lower() == "exit"
                
                
        try:
         while True:
            cmd = str(input("optiscan> "))
            if not cmd:continue
            elif cmd.lower() == "exit":
                        print("[*] Exit optiscan script...bye :)")
                        break
            elif cmd.lower() == "autoclean":
                main.autoclean = True if not main.autoclean else False
                write("[+] autoclean ==> {}\n".format("#w[#gON#w]" if main.autoclean else "#y[#rOFF#y]"))
            elif cmd.lower() in ("cls", "clear"):main.clean()
            elif cmd.lower() == "help":main.show_help()
            elif cmd.lower() == "options":main.show_options()
            elif cmd.lower() == "start":
                   main.cmdCtrlC = False
                   main.start()
                   main.cmdCtrlC = True
            elif cmd.lower().startswith("set"):
                data = "".join(cmd.strip().split("set")).strip()
                if not data:write("Usage: set <Option> <Value>\n")
                elif not " " in data:
                    opt = data.strip()
                    if not opt in  main.options:write("[!] Unknown Option: '{}' !!!\n".format(opt))
                    elif opt == "target":write("Usage: set target <target hostname or ip> e.g: set target google.com\n")
                    elif opt == "ports":write("Usage: set ports <port1,port2,port-range> e.g: set ports 20-25,80,445,8080,200-1025\n")
                    elif opt == "protocol":write("Usage: set protocol <protocol(tcp,udp)> e.g: set protocol udp\n")
                    elif opt == "timeout":write("Usage: set timeout  e.g: set timeout 0.05\n")
                    elif opt == "threads":write("Usage: set threads <number_of_threads> e.g: set threads 200\n")
                    elif opt == "version":write("Usage: set version <true, false> e.g: set version true")
                    elif opt == "verbose":write("Usage: set verbose <true, false> e.g: set verbose true")
                elif data.count(" ") != 1:write("[!] Unknown Command: '{}' !!!\n".format(data))
                else:
                    opt,val = data.split(" ")
                    opt = opt.lower()
                    if opt not in main.options:
                        write("[!] Unknown Option: '{}' !!!\n".format(opt))
                        continue
                    for option in main.options:
                        if opt == option:
                            if option == "ports":main.portsSet = True
                            if option == "protocol":
                                if not val.lower() in ("tcp", "udp"):
                                      errmsg("Invalid Connection Protocol Must be 'tcp' or 'udp'")
                                      break
                                if not main.portsSet:main.ports = main.mports[val.lower()]
                            write("[+] {} ==> {}\n".format(option, val))
                            exec('main.{} = "{}"'.format(option,val))
                            break
            elif cmd.lower().startswith("exec"):
                execom = "".join(cmd.split("exec")[1]).strip()
                if not execom:
                    write("[!] exec <command <args>: eg: ls -alt>\n")
                    continue
                system(execom)
            elif cmd.lower() in main.options:write("[*] {} = {} ".format(cmd, eval("main.{}".format(cmd.lower()))))
            elif cmd.lower().startswith("reset"):
                opt = cmd.lower().strip().split(" ")
                if len(opt) == 2:
                  opt = opt[1].lower()
                  if opt == "all":
                    write("[~] Reset All Options...\n")
                    for option in main.options:
                        defval = main.defaultVal[option] if option != "ports" else main.resetPorts()
                        exec('main.{} = "{}"'.format(option, defval))
                        write("  [+] {} ==> {}\n".format(option, defval if option != "ports" else "top-200-ports"))
                    continue
                  if opt not in main.options:
                    write("[!] Unable to reset option : reason: Unknown option !!!\n")
                    continue
                  defaultValue = main.defaultVal[opt] if opt != "ports" else main.resetPorts()
                  exec('main.{} = "{}"'.format(opt,defaultValue))
                  write("[~] {} ==> {}\n".format(opt, defaultValue if opt != "ports" else "top-200-ports"))
                  continue
                write("[*] Usage:  reset <option, all> (e.g: reset target)")
            else:write("[!] Unknown Command: '{}' !!!\n".format(cmd))
            print(" ")
         sys.exit(1)
        except EOFError:pass
    def start(main):
        global event,kill,isKilled,lock
        event = threading.Event()
        kill = lambda :event.set()
        isKilled =lambda :event.isSet()
        lock = threading.Lock()
        main.THREADS = []
        main.finFlag = False
        main.abroFlag = False
        main.printed = 0
        target = main.target
        ports = main.ports
        protocol = main.protocol.lower()
        timeout = main.timeout
        versionScan = main.version
        threads = main.threads
        verbose = main.verbose
        if not target.strip():
            errmsg("Target is not selected")
            return False
        ports =  getPorts(ports)
        if not ports:
            errmsg("Invalid Ports Selected")
            return False
        try:timeout = float(timeout)
        except ValueError:
              if not timeout.strip() or not timeout.isdigit():
                errmsg("timeout must be an number")
                return False
              timeout = int(timeout)
        if not timeout:
            errmsg("timeout cannot be '{}'".format(timeout))
            return False
        if not threads.strip() or not threads.isdigit():
            errmsg("threads Must be an number")
            return False
        threads = int(threads)
        if not threads:
            errmsg("threads cannot be '{}'".format(threads))
            return False
        if not verbose.strip() or verbose.lower() not in {'true','false'}:
            errmsg("verbose: must be 'true' or 'false'")
            return False
        if not versionScan.strip() or versionScan.lower() not in {'true', 'false'}:
            errmsg("versionScan: must be 'true' or 'false'")
            return False
        verbose = True if verbose.lower() == "true" else False
        versionScan = True if versionScan.lower() == "true" else False
        if versionScan:
            if not main.runner:
              write("[~] Loading ....\n")
              servScan = serviceScan()
              servScan.verbose = verbose
              main.runner = servScan
            else:servScan = main.runner
        else:servScan = False
        if threads > len(ports):threads = len(ports)
        qus = qu()
        for port in ports:qus.put(port)
        global config
        config = {"target":target,
                  "ports":qus,
                  "protocol":protocol,
                  "timeout":timeout,
                  "threads":threads,
                  "servScan": servScan,
                  "verbose": verbose,
                  "ret":0,
                  "result":{
                    "open":[],
                    "close":0,
                    "version": {}}}
        if verbose: write("#w[#y~#w]#y Starting #g{}#y Threads#w....\n".format(threads))
        mainThread = threading.Thread(target=main.startThreads)
        mainThread.daemon = True
        mainThread.start()
        while not main.finFlag:
            if main.abroFlag:break
        if main.abroFlag:return
        if not verbose: an.done = True
        else:
            for thread in main.THREADS:write("#g[#w*#g]#w Thread-{} : has #gFinshied\n".format(thread.ident))
            main.printed+=1
        write("\n")
        main.printPorts()
        main.printed+=1
        mainThread.join()
        return
if __name__ =="__main__":
    optiscan = Optiscan()
    optiscan.clean()
    write(optiscan.banner + "\n")
    optiscan.shell()

