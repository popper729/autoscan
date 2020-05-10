import argparse
import nmap
import sys
import datetime
import os
import time

###############################################################
#
# Initial setup of a pen test
# 1. Find online hosts (ping sweep, TCP host discovery) (functionality added)
# 2. Nmap of top 1000 ports on active IPs (TCP and UDP) (functionality added)
# 3. Nmap of all ports on active IPs (TCP and UDP) (functionality added)
# 4. DNS/Reverse DNS lookup (if applicable)
# 5. gobuster against web apps (working on code to find web apps)
# 6. nikto against web apps
#
###############################################################


###############################################################
#
# Returns the hosts file as a list of hosts
#  - hosts_file is the name of the file that contains the
#    different hosts (1 per line)
#
###############################################################
def get_hosts(hosts_file):
    try:
        f = open(hosts_file, 'r')
        lines = f.readlines()
        lines = [x.rstrip() for x in lines]
        print('\033[1;36;40m[*] Hosts list generated\033[0;37;40m')
        return lines
    except exception as e:
        print(e)
        print("\033[1;31;40m[-] Host file does not exist\033[0;37;40m")
        sys.exit(1)


###############################################################
#
# Prints the hosts to be scanned
#  - hosts_list is the list of hosts
#
###############################################################
def show_hosts(hosts_list, message):
    print('\033[1;36;40m[*] %s\033[0;37;40m' %(message))
    for host in hosts_list:
        print('\033[1;35;40m [*] %s\033[0;37;40m' %(host))


###############################################################
#
# Does a ping sweep to find active hosts
#  - hosts_list is the list of hosts to be scanned
#  - returns a list of active hosts
#
###############################################################
def find_active_hosts(hosts_list):
    nm = []
    for num, host in enumerate(hosts_list):
        nm.append(nmap.PortScanner())
        nm[num].scan(hosts=host, arguments='-sn -PE -PP -PM -oN %s-pingsweep.nmap' %(host.replace('/','-')))
        #print(nm[num].csv())
    active_hosts = []
    inactive_hosts = []
    for scan in nm:
        scanned_hosts = [(x, scan[x]['status']['state']) for x in scan.all_hosts()]
        for host, status in scanned_hosts:
            if status == 'up':
                active_hosts.append(host)
            else:
                inactive_hosts.append(host)
        #print(scanned_hosts)
    return active_hosts, inactive_hosts


###############################################################
#
# Writes hosts to a file
#  - hosts is the list of hosts to write to a file
#  - filename is the name of the file to write the hosts to
#
###############################################################
def write_hosts(hosts, filename):
    f = open(filename, 'w+')
    for host in hosts:
        f.write('%s\n' %(host))


###############################################################
#
# Find the web apps amond the known hosts
#  - nm is the PortScanner object that has done the scan
#
###############################################################
def find_web_apps(nm):
    web_apps = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            if 80 in nm[host][proto].keys():
                print('\033[1;32;40m[+] Found web app on port 80 of %s\033[0;37;40m' % (host))
                web_apps.append([host, 'http'])
            if 443 in nm[host][proto].keys():
                print('\033[1;32;40m[+] Found web app on port 443 of %s\033[0;37;40m' % (host))
                web_apps.append([host, 'https'])
    return web_apps


###############################################################
#
# Runs gobuster against the hosts
#  - web_apps is the list of web apps to test against
#   - each element should have the form [host, 'http'/'https']
#
###############################################################
def gobuster_test(web_apps):
    wordlist = '/usr/share/wordlists/averroes/raft-small-directories-lowercase.txt' # eventually give the option to specify this
    gb_path = 'gobuster_results'
    if not os.path.exists(gb_path):
        os.system('mkdir %s' % (gb_path))
    try:
        f = open(wordlist, 'r')
    except:
        try:
            f.open('raft-small-directories-lowercase.txt', 'r')
            wordlist = 'raft-small-directories-lowercase.txt'
        except:
            os.system('wget raw.githubusercontent.com/Averroes/raft/master/data/wordlists/raft-small-files-lowercase.txt')
            wordlist = 'raft-small-directories-lowercase.txt'
            pass
        pass
    for host in web_apps:
        print('\033[1;36;40m[*] Running gobuster against %s://%s\033[0;37;40m' % (host[1], host[0]))
        os.system('gobuster dir -e -r -u %s://%s -w %s --wildcard -v -k > %s/gobuster-results-%s-%s.txt' % (host[1], host[0], wordlist, gb_path, host[0], host[1])) 
        print('\033[1;32;40m[+] Completed gobuster scan for %s://%s\033[0;37;40m' % (host[1], host[0]))


###############################################################
#
# Runs nikto against the hosts
#  - web_apps is the list of web apps to test against
#   - each element should have the form [host, 'http'/'https']
#
###############################################################
def nikto_test(web_apps):
    nikto_path = 'nikto_results'
    if not os.path.exists(nikto_path):
        os.system('mkdir %s' % nikto_path)
    for host in web_apps:
        print('\033[1;36;40m[*] Running nikto against %s://%s\033[0;37;40m' % (host[1], host[0]))
        os.system('nikto -host %s://%s > %s/nikto-results-%s-%s.txt' % (host[1], host[0], nikto_path, host[0], host[1]))
        print('\033[1;32;40m[+] Completed nikto scan for %s://%s\033[0;37;40m' % (host[1], host[0]))


###############################################################
#
# Performs an nmap scan on known available hosts
# Works best on available hosts, will take much longer
# if IPs are included that belong to unavailable/
# non-existant hosts
#  - host_list is the list of hosts
#  - top_ports is the number of top ports to scan
#  - tcp (bool) - do a TCP scan if true, UDP if false
#
###############################################################
#def nmap_scan(host_list, top_ports, tcp):
def nmap_scan(filename, top_ports, tcp):
    nm = nmap.PortScanner()
    args = '-Pn -sV --top-ports %d -oN %s%s-scan-top%d.nmap -i %s' % (top_ports, filename, '' if tcp else '-udp', top_ports, filename)
    #for num, host in enumerate(host_list):
    #    nm.append(nmap.PortScanner())
    print('\033[1;36;40m[*] Running nmap scan of the top %d ports\033[0;37;40m' % (top_ports))
    #if tcp:
    #    nm.scan(arguments='-Pn -sV --top-ports %d -oN %s-scan-top%d.nmap -i %s' %(top_ports, filename, top_ports, filename))
    #else:
    #    nm.scan(arguments='-Pn -sU -sV --top-ports %d -oN %s-udp-scan-top%d.nmap -i %s' %(top_ports, filename, top_ports, filename))
    try:
        nm.scan(arguments=args)
    except nmap.PortScannerError:
        print('\033[1;31;40m[-] Port scan failed, re-trying...\033[0;37;40m')
        time.sleep(2)
        try:
            nm.scan(arguments=args)
        except nmap.PortScannerError:
            print('\033[1;31;40m[-] Port scan failed again, quitting...\033[0;37;40m')
            sys.exit(1)
    print('\033[1;32;40m[+] Completed nmap scan\033[0;37;40m')
    return nm


###############################################################
#
# Main
#
###############################################################
def main():
    parser = argparse.ArgumentParser(prog='autoscan.py', usage='python3 %(prog)s [hostfile]', description='Automate pentest')
    parser.add_argument('hostfile', help='Host file - one host/CIDR per line')

    args = parser.parse_args()

    current_time = datetime.datetime.now()
    uniqueID = current_time.strftime('%Y-%m-%d-%H.%M.%S')
    outfile = uniqueID + '-active-hosts.txt'

    hosts = get_hosts(args.hostfile)
    active, inactive = find_active_hosts(hosts)
    show_hosts(active, "The following hosts are active:")
    #show_hosts(inactive, "The following hosts are either down or did not respond to pings:")
    if not active:
        active = hosts
        show_hosts(active, "Either all hosts are down or are not responding to pings. The following hosts will be tested:")
    write_hosts(active, outfile)
    #write_hosts(active, uniqueID, "inactive")
    nm_tcp_1000 = nmap_scan(outfile, 1000, True)
    webapps = find_web_apps(nm_tcp_1000)
    gobuster_test(webapps)
    nikto_test(webapps)
    #nm_tcp_all = nmap_scan(outfile, 65535, True)
    #nm_udp_1000 = nmap_scan(outfile, 1000, False)
    #nm_udp_all = nmap_scan(outfile, 65535, False)
    print('\033[2;32;40m[+] All tasks completed successfully\033[0;37;40m')

if __name__ == '__main__':
    main()
