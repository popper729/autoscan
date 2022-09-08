import argparse
import sys
import datetime
import os
import time
from shutil import which
try:
    import nmap
except:
    print("\033[1;31;40m[-] Error: python-nmap is not installed. You can install it now (must be sudo)\033[0;37;40m")
    choice_nmap = input("\033[1;35;40m[*] Install python-nmap? y/n [y]: \033[0;37;40m" or 'y')
    if(choice_nmap == 'y'):
        if not which('pip3'):
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
# Color setup for print statements
#
###############################################################
ENDC = '\033[0;37;40m'
TEAL = '\033[1;36;40m'
GREEN = '\033[1;32;40m'
RED = '\033[1;31;40m'
PURPLE = '\033[1;35;40m'
WHITE = '\033[1;37;40m'

def print_info(msg):
    print('%s[*] %s%s' % (TEAL, msg, ENDC))

def print_success(msg):
    print('%s[+] %s%s' % (GREEN, msg, ENDC))

def print_err(msg):
    print("%s[-] %s%s" % (RED, msg, ENDC))

def print_color(msg, color):
    print(color + msg + ENDC)

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
        print_info('Hosts list generated')
        return lines
    except Exception as e:
        print(e)
        print_err("Host file does not exist")
        sys.exit(1)


###############################################################
#
# Prints the hosts to be scanned
#  - hosts_list is the list of hosts
#
###############################################################
def show_hosts(hosts_list, message):
    print_info(message)
    for host in hosts_list:
        print_color(' [*] ' + host, WHITE)


###############################################################
#
# Does a ping sweep to find active hosts
#  - hosts_list is the list of hosts to be scanned
#  - returns a list of active hosts
#
###############################################################
def find_active_hosts(hosts_list):
    print_info("Finding active hosts")
    nm = []
    active_hosts = []
    inactive_hosts = []
    if not os.path.isdir("./hosts"):
        os.system("mkdir hosts")
    for num, host in enumerate(hosts_list):
        if not os.path.isdir("./hosts/%s" % (host.replace('/','-'))):
            os.system("mkdir ./hosts/%s" % (host.replace('/','-')))
        nm.append(nmap.PortScanner())
        nm[num].scan(hosts=host, arguments='-sn -PE -PP -PM -oN hosts/%s/%s-pingsweep.nmap' %(host.replace('/','-'), host.replace('/','-')))
        scanned_hosts = [(x, nm[num][x]['status']['state']) for x in nm[num].all_hosts()]
        #print(nm[num].csv())
    #for scan in nm:
        #scanned_hosts = [(x, scan[x]['status']['state']) for x in scan.all_hosts()]
        for host_name, status in scanned_hosts:
            if status == 'up':
                active_hosts.append(host)
            else:
                inactive_hosts.append(host)
        #print(scanned_hosts)
    return active_hosts, inactive_hosts

###############################################################
# 
# Remove inactive hosts
#
###############################################################
def rem_hosts(hosts):
    print_info("Removing inactive hosts")
    for host in hosts:
        os.system('rm -rf ./hosts/%s' % (host))

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
def find_web_apps(nms):
    web_apps = []
    print_info("Discovring web apps")
    for nm in nms:
        for host in nm.all_hosts():
            hn = nm[host].hostname() if nm[host].hostname() else host
            for proto in nm[host].all_protocols():
                if 80 in nm[host][proto].keys():
                    print_success('Found web app on port 80 of %s' % (hn))
                    web_apps.append([host, 'http', nm[host].hostname()])
                if 443 in nm[host][proto].keys():
                    print_success('Found web app on port 443 of %s' % (hn))
                    web_apps.append([host, 'https', nm[host].hostname()])
    return web_apps


###############################################################
#
# Runs gobuster against the hosts
#  - web_apps is the list of web apps to test against
#   - each element should have the form [host, 'http'/'https', hostname]
#
###############################################################
def gobuster_test(web_apps, proxy):
    if not which('gobuster'):
        print_err('Gobuster v3 is required for this operation.')
        print_err('It can be installed with the following command: sudo apt install -y snapd && sudo snap install go --classic && sudo ln -s /snap/bin/go /usr/bin/go && sudo go install github.com/OJ/gobuster/v3@latest && sudo cp /root/go/bin/gobuster /usr/bin/gobuster')
        a = input("\033[1;35;40m[*] Install now? [y/n] \033[0;37;40m")
        if(a == 'y' or a == 'Y'):
            os.system("%sapt install -y snapd && %ssnap install go --classic && %sln -s /snap/bin/go /usr/bin/go && %sgo install github.com/OJ/gobuster/v3@latest && %scp /root/go/bin/gobuster /usr/bin/gobuster" % ("sudo " if os.getuid() else "", "sudo " if os.getuid() else "", "sudo " if os.getuid() else "", "sudo " if os.getuid() else "", "sudo " if os.getuid() else ""))
            print_success("Gobuster was successfully installed.")
        else:
            print_err("Skipping the gobuster scan.")
            return
    print_info("Starting gobuster scans")
    wordlist = '/usr/share/wordlists/averroes/raft-small-directories-lowercase.txt' # eventually give the option to specify this
    gb_path = 'gobuster_results'
    if not os.path.exists(gb_path):
        os.system('mkdir %s' % (gb_path))
    try:
        f = open(wordlist, 'r')
    except:
        try:
            f = open('raft-small-directories-lowercase.txt', 'r')
            wordlist = 'raft-small-directories-lowercase.txt'
        except Exception as e:
            print(e)
            os.system('wget raw.githubusercontent.com/Averroes/raft/master/data/wordlists/raft-small-directories-lowercase.txt')
            wordlist = 'raft-small-directories-lowercase.txt'
            pass
        pass
    for host in web_apps:
        hostname = host[2] if host[2] else host[0]
        print_info('Running gobuster against %s://%s' % (host[1], hostname))
        print_info('gobuster dir -e -r -u \'%s://%s\' -w \'%s\' --wildcard -v -k%s > hosts/%s/gobuster-results-%s-%s.txt' % (host[1], hostname, wordlist, ' --proxy %s --timeout 2ms' % (proxy) if proxy else '', hostname, hostname, host[1])) 
        os.system('gobuster dir -e -r -u \'%s://%s\' -w \'%s\' --wildcard -v -k%s > hosts/%s/gobuster-results-%s-%s.txt' % (host[1], hostname, wordlist, ' --proxy %s --timeout 2ms' % (proxy) if proxy else '', hostname, hostname, host[1])) 
        print_success('Completed gobuster scan for %s://%s' % (host[1], hostname))


###############################################################
#
# Runs nikto against the hosts
#  - web_apps is the list of web apps to test against
#   - each element should have the form [host, 'http'/'https', hostname]
#
###############################################################
def nikto_test(web_apps, proxy):
    if not which('nikto'):
        print_err('Nikto is required for this operation. It can be installed with the following command: sudo apt install -y nikto')
        a = input("\033[1;35;40m[*] Install now? [y/n] \033[0;37;40m")
        if(a == 'y' or a == 'Y'):
            os.system("%sapt update && %sapt install -y nikto" % ("sudo " if os.getuid() else "", "sudo " if os.getuid() else ""))
            if not which('nikto'):
                print_err('The package wasn\'t installed. Please add the non-free repos to /etc/apt/sources-list')
                print_err('Skipping the nikto scan')
                return
            else:
                print_success("Nikto was successfully installed.")
        else:
            print_err("Skipping the nikto scan.")
            return
        print_err('If the package doesn\'t exist, add the non-free repos to /etc/apt/sources-list')
    nikto_path = 'nikto_results'
    print_info("Starting nikto scans")
    if not os.path.exists(nikto_path):
        os.system('mkdir %s' % nikto_path)
    for host in web_apps:
        hostname = host[2] if host[2] else host[0]
        print_info('Running nikto against %s://%s' % (host[1], hostname))
        print_info('nikto -host %s://%s%s > hosts/%s/nikto-results-%s-%s.txt' % (host[1], hostname, ' -useproxy %s' % (proxy) if proxy else '', hostname, hostname, host[1]))
        os.system('nikto -host %s://%s%s > hosts/%s/nikto-results-%s-%s.txt' % (host[1], hostname, ' -useproxy %s' % (proxy) if proxy else '', hostname, hostname, host[1]))
        print_success('Completed nikto scan for %s://%s' % (host[1], hostname))


###############################################################
#
# Runs amass enum
#  - hosts is the generated host list
#  - amass_file is the output file for the enum
#
###############################################################
def amass_enum(hosts, amass_file):
    if not which('amass'):
        print_err('Amass is required for this operation. It can be installed with the following command: sudo snap install amass')
        a = input("\033[1;35;40m[*] Install now? [y/n] \033[0;37;40m")
        if(a == 'y' or a == 'Y'):
            os.system("%ssnap install amass" % ("sudo " if os.getuid() else ""))
            if not which('amass'):
                os.system("%sapt update && %sapt install -y snapd && %ssnap install amass" % ("sudo " if os.getuid() else "", "sudo " if os.getuid() else "", "sudo " if os.getuid() else ""))
                if not which('amass')
                    print_err('The package was not installed. Please check for system-specific installation instructions.')
                    print_err('Skipping the amass scan')
                    return
                else:
                    print_success("Amass was successfully installed.")
        else:
            print_err("Skipping the amass scan.")
            return
    print_info("Starting amass enumeration")
    args = ''
    for host in hosts:
        args += ' -d %s' % (host)
    #print(args)
    os.system("amass enum -passive%s -o %s" % (args, amass_file))

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
    #nm = nmap.PortScanner()
    print_info("Starting nmap scans")
    nms = []
    if not os.path.isdir("./hosts"):
        os.system("mkdir ./hosts")
    if single_file:
        nm = nmap.PortScanner()
        print_info('Outputting as a single file')
        args = '-Pn -sV -O %s -oN hosts/%s%s-scan-%s.nmap -iL %s' % (top_ports, filename, '' if tcp else '-udp', top_ports.replace(',','_'), filename)
        print_info('Running nmap scan of ports %s' % (top_ports))
        try:
            nm.scan(arguments=args)
        except nmap.PortScannerError:
            print_err('Port scan failed, re-trying...')
            time.sleep(2)
            try:
                nm.scan(arguments=args)
            except nmap.PortScannerError:
                print_err('Port scan failed again, quitting...')
                sys.exit(1)
        f= open('./hosts/%s-scan-%s%s.csv' % (filename, top_ports.replace(',','_'), '' if tcp else '-udp'), 'w')
        f.write(nm.csv())
        f.close()
        nms.append(nm)
    else:
        with open(filename) as fp:
            hosts = fp.readlines()
            for h in hosts:
                nm = nmap.PortScanner()
                host = h.rstrip()
                if not os.path.isdir("./hosts/%s" % (host.replace('/','-'))):
                    os.system("mkdir ./hosts/%s" % (host.replace('/','-')))
                print_info('Running nmap scan of ports %s on %s' % (top_ports, host))
                args = '-Pn -sV -O %s -oN hosts/%s/%s%s-scan-%s.nmap' % (top_ports, host.replace('/','-'), host.replace('/','-'), '' if tcp else '-udp', top_ports.replace(',','_'))
                try:
                    nm.scan(host, arguments=args)
                    f= open('%s-scan-%s%s.csv' % (host.replace('/','-'), top_ports.replace(',','_'), '' if tcp else '-udp'), 'w')
                    f.write(nm.csv())
                    f.close()
                    print_success('Success')
                    #nms.append(nm)
                except nmap.PortScannerError as e:
                    #print(e)
                    print_err('Port scan for %s failed, re-trying...' % (host))
                    try:
                        nm.scan(host, arguments=args)
                        print_success('Success')
                        f.write(nm.csv())
                        f.close()
                        #nms.append(nm)
                    except nmap.PortScannerError:
                        print_err('Port scan failed again, skipping %s...' % (host))
                        pass 
                nms.append(nm)
                #f= open('./hosts/%s/%s-scan-%s%s.csv' % (host.replace('/','-'), host.replace('/','-'), top_ports.replace(',','_'), '' if tcp else '-udp'), 'w')
    
    if not os.path.isdir("./csv_reports"):
        os.system("mkdir csv_reports")
    os.system("mv *.csv ./csv_reports/")

    print_success('Completed nmap scan')
    return nms


###############################################################
#
# Main
#
###############################################################
def main():
    parser = argparse.ArgumentParser(prog='autoscan.py', usage='python3 %(prog)s {-i [host]|-I [hostfile]} {-g|-n|-p [ports]|-P [top_ports]|-f|-d|-u|-q} {--proxy [http(s)]://[host][port]}', description='Automate scanning for pentests')
    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument('-I', help='Host file - one host/CIDR per line')
    host_group.add_argument('-i', help='Single host')
    parser.add_argument('-g', help='Perform gobuster scan on all web hosts', required=False, action="store_true")
    parser.add_argument('-n', help='Perform nikto scan on all web hosts', required=False, action="store_true")
    parser.add_argument('-a', help='Perform amass enumeration (amass enum -passive)', required=False, action="store_true")
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('-p', help='Perform nmap scan of the specified ports', required=False)
    port_group.add_argument('-P', type=int, help='Perform nmap scan of the top [x] ports', required=False)
    port_group.add_argument('-f', help='Perform nmap scan of all ports', required=False, action="store_true")
    port_group.add_argument('-q', help='Perform nmap ping scan only', required=False, action="store_true")
    parser.add_argument('-d', help='Perform nmap scan of all hosts (no ping scan)', required=False, action="store_true")
    parser.add_argument('-u', help='Perform UDP scan', required=False, action="store_true")
    parser.add_argument('--proxy', help='Specify proxy for gobuster/nikto [http(s)]://[host]:[port]', required=False)

    args = parser.parse_args()

    current_time = datetime.datetime.now()
    uniqueID = current_time.strftime('%Y-%m-%d-%H.%M.%S')
#    outfile = uniqueID + '-active-hosts.txt'
#    inactive_hosts = uniqueID + '-inactive-hosts.txt'
    outfile = 'active-hosts.txt'
    inactive_hosts = 'inactive-hosts.txt'
    active = []
    inactive = []
    webapps = []

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

    if args.a:
        amass_file = "amass-enum-autoscan.txt"
        amass_enum(hosts, amass_file)
        tmp = hosts + get_hosts(amass_file)
        hosts = [*set(tmp)]
        #print(hosts)

    if not args.d:
        active, inactive = find_active_hosts(hosts)     # ping scan (get a list of active and inactive hosts)
        show_hosts(active, "The following hosts are active:")
        rem_hosts(inactive)
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
        gobuster_test(webapps, args.proxy)

    if args.n:
        nikto_test(webapps, args.proxy)

    print_color('[+] All tasks completed successfully', PURPLE)

if __name__ == '__main__':
    main()
