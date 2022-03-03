import argparse
import sys
import datetime
import os
import time
try:
    import nmap
except:
    print("\033[1;31;40m[-] Error: python-nmap is not installed. You can install it now (must be sudo)\033[0;37;40m")
    choice_nmap = input("\033[1;35;40m[*] Install python-nmap? y/n [y]: \033[0;37;40m" or 'y')
    if(choice_nmap == 'y'):
        choice_pip = input("\033[1;35;40m[*] This operation requires pip3. Install python3-pip? (requires sudo) y/n [n]: \033[0;37;40m" or 'n')
        if(choice_pip == 'y'):
            os.system("%sapt install -y python3-pip" % ("sudo " if os.getuid() else ""))
        os.system("pip3 install python-nmap")
    else:
        print("\033[1;31;40m[-] Quitting...\033[0;37;40m")
        sys.exit(0)
import nmap

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
    if not os.path.isdir("./hosts"):
        os.system("mkdir hosts")
    for num, host in enumerate(hosts_list):
        if not os.path.isdir("./hosts/%s" % (host.replace('/','-'))):
            os.system("mkdir ./hosts/%s" % (host.replace('/','-')))
        nm.append(nmap.PortScanner())
        nm[num].scan(hosts=host, arguments='-sn -PE -PP -PM -oN hosts/%s/%s-pingsweep.nmap' %(host.replace('/','-'), host.replace('/','-')))
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
        os.system('gobuster dir -e -r -u %s://%s -w %s --wildcard -v -k > hosts/%s/gobuster-results-%s-%s.txt' % (host[1], host[0], wordlist, host[1], host[0], host[1])) 
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
        os.system('nikto -host %s://%s > hosts/%s/nikto-results-%s-%s.txt' % (host[1], host[0], host[1], host[0], host[1]))
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
def nmap_scan(filename, top_ports='-p1-65535', tcp=True, single_file=False):
    nm = nmap.PortScanner()
    if not os.path.isdir("./hosts"):
        os.system("mkdir ./hosts")
    if single_file:
        print('\033[1;36;40m[*] Outputting as a single file\033[0;37;40m')
        args = '-Pn -sV -O %s -oN hosts/%s%s-scan-%s.nmap -iL %s' % (top_ports, filename, '' if tcp else '-udp', top_ports.replace(',','_'), filename)
        print('\033[1;36;40m[*] Running nmap scan of ports %s\033[0;37;40m' % (top_ports))
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
        f= open('./hosts/%s-scan-%s%s.csv' % (filename, top_ports.replace(',','_'), '' if tcp else '-udp'), 'w')
        f.write(nm.csv())
        f.close()
    else:
        with open(filename) as fp:
            hosts = fp.readlines()
            for h in hosts:
                host = h.rstrip()
                if not os.path.isdir("./hosts/%s" % (host.replace('/','-'))):
                    os.system("mkdir ./hosts/%s" % (host.replace('/','-')))
                print('\033[1;36;40m[*] Running nmap scan of ports %s on %s\033[0;37;40m' % (top_ports, host))
                args = '-Pn -sV -O %s -oN hosts/%s/%s%s-scan-%s.nmap %s' % (top_ports, host.replace('/','-'), host.replace('/','-'), '' if tcp else '-udp', top_ports.replace(',','_'), host)
                try:
                    nm.scan(arguments=args)
                    f= open('%s-scan-%s%s.csv' % (host.replace('/','-'), top_ports.replace(',','_'), '' if tcp else '-udp'), 'w')
                    f.write(nm.csv())
                    f.close()
                    print('\033[1;36;40m[*] Success\033[0;37;40m')
                except nmap.PortScannerError as e:
                    print(e)
                    print('\033[1;31;40m[-] Port scan for %s failed, re-trying...\033[0;37;40m' % (host))
                    try:
                        nm.scan(arguments=args)
                        print('\033[1;36;40m[*] Success\033[0;37;40m')
                        f.write(nm.csv)
                        f.close()
                    except nmap.PortScannerError:
                        print('\033[1;31;40m[-] Port scan failed again, skipping...\033[0;37;40m')
                        pass 
                f= open('./hosts/%s/%s-scan-%s%s.csv' % (host.replace('/','-'), host.replace('/','-'), top_ports.replace(',','_'), '' if tcp else '-udp'), 'w')
    
    if not os.path.isdir("./csv_reports"):
        os.system("mkdir csv_reports")
    os.system("mv *.csv ./csv_reports/")

    print('\033[1;32;40m[+] Completed nmap scan\033[0;37;40m')
    return nm


###############################################################
#
# Main
#
###############################################################
def main():
    parser = argparse.ArgumentParser(prog='autoscan.py', usage='python3 %(prog)s {-i [host]|-I [hostfile]} {-g|-n|-p [top_ports]|-f|-d|-u}', description='Automate pentest')
    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument('-I', help='Host file - one host/CIDR per line')
    host_group.add_argument('-i', help='Single host')
    parser.add_argument('-g', help='Perform gobuster scan on all web hosts', required=False, action="store_true")
    parser.add_argument('-n', help='Perform nikto scan on all web hosts', required=False, action="store_true")
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('-p', help='Perform nmap scan of the specified ports', required=False)
    port_group.add_argument('-P', type=int, help='Perform nmap scan of the top [x] ports', required=False)
    port_group.add_argument('-f', help='Perform nmap scan of all ports', required=False, action="store_true")
    port_group.add_argument('-q', help='Perform nmap ping scan only', required=False, action="store_true")
    parser.add_argument('-d', help='Perform nmap scan of all hosts (no ping scan)', required=False, action="store_true")
    parser.add_argument('-u', help='Perform UDP scan', required=False, action="store_true")

    args = parser.parse_args()

    current_time = datetime.datetime.now()
    uniqueID = current_time.strftime('%Y-%m-%d-%H.%M.%S')
#    outfile = uniqueID + '-active-hosts.txt'
#    inactive_hosts = uniqueID + '-inactive-hosts.txt'
    outfile = 'active-hosts.txt'
    inactive_hosts = 'inactive-hosts.txt'
    active = []
    inactive = []

    hosts = []
    if args.i:
        temp_file = uniqueID + '-temp-hostfile.txt'
        f = open(temp_file, "w")
        f.write(args.i)
        f.close()
        hosts = get_hosts(temp_file)
        os.system('rm %s' % (temp_file))

    if args.I:
        hosts = get_hosts(args.I)

    if not args.d:
        active, inactive = find_active_hosts(hosts)     # ping scan (get a list of active and inactive hosts)
        show_hosts(active, "The following hosts are active:")
    elif args.d:
        active = hosts
        outfile = 'tmp_all_hosts.txt'

    if not active:      # if the active hosts array is empty, scan all hosts
        active = hosts
        show_hosts(active, "Either all hosts are down or are not responding to pings. The following hosts will be tested:")

    write_hosts(active, outfile)
    write_hosts(inactive, inactive_hosts)

    scan_file = outfile
    #if args.d:
    #    scan_file = inactive_hosts

    nm_tcp = []
    if args.f:
        nm_tcp = nmap_scan(scan_file, '-p1-65535', not args.u)
    elif args.p:
        nm_tcp = nmap_scan(scan_file, '-p' + args.p, not args.u)
    elif args.q:
        pass
    elif args.P:
        nm_tcp = nmap_scan(scan_file, '--top-ports %d' % (args.P), not args.u)
    else:
        nm_tcp = nmap_scan(scan_file, '-p1-65535', not args.u)
    
    if nm_tcp:
        webapps = find_web_apps(nm_tcp)

    if args.g:
        gobuster_test(webapps)

    if args.n:
        nikto_test(webapps)

    print('\033[2;32;40m[+] All tasks completed successfully\033[0;37;40m')

if __name__ == '__main__':
    main()
