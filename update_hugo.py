import os
import argparse
import ipaddress
import operator
import re

#backups = 'ask'

#####################################################################################
#
# Format misc directories found
#
#####################################################################################
def format_misc(path):
    dnames = []
    ip_addr = []
    urls = []
    for(dirpath, dirnames, filenames) in os.walk(path):
        dnames.extend(dirnames)
        break
    for dr in dnames:
        try:
            ip_addr.append(ipaddress.ip_address(dr))
        except:
            urls.append(dr)
    ip_addr.sort()
    urls.sort()
    fmt = ''
    for url in urls:
        fmt += '[%s](%s)  \n' % (url, url)
    for ip in ip_addr:
        tmp = format(ip)
        fmt += '[%s](%s)  \n' % (tmp, tmp)
    return fmt

#####################################################################################
#
# Format hosts page with all hosts
#
#####################################################################################
def format_hosts(path):
    dnames = []
    ip_addr = []
    urls = []
    for(dirpath, dirnames, filenames) in os.walk(path):
        dnames.extend(dirnames)
        break
    for dr in dnames:
        try:
            ip_addr.append(ipaddress.ip_address(dr))
        except:
            urls.append(dr)
    ip_addr.sort()
    urls.sort()
    fmt = ''
    for url in urls:
        fmt += '[%s](%s)  \n' % (url, url)
    for ip in ip_addr:
        tmp = format(ip)
        fmt += '[%s](%s)  \n' % (tmp, tmp)
    return fmt

#####################################################################################
#
# Format individual host page with results nmap/gobuster/nikto
#
#####################################################################################
def format_stats(path):
    dnames = []
    fnames = []
    fmt = ''
    #print(path)
    for dirpath, dirnames, filenames in os.walk(path):
        dnames.extend(dirnames)
        fnames = [item for item in filenames if '.md' not in item]
        break
    #for name in dnames:
    #    fmt += '[%s](%s)\n' 
    if "nmaps" in dnames:
        temp = []
        fmt += '''
### [Nmap](nmaps)
| Port | State | Service | Info |
| :--- | :---- | :------ | :--- |
'''
        p = os.path.join(path, "nmaps")
        for dirpath, dirnames, filenames in os.walk(p):
            temp = [item for item in filenames if '.md' not in item]
            break
        for fn in temp:
            i = open(os.path.join(p, fn))
            lines = i.readlines()
            i.close()
            for line in lines:
                #port = re.split(r'\t+', line)
                #port = line.split()
                if 'tcp' in line or 'udp' in line:
                    port = line.split()
                    #print(port)
                    if len(port) == 3:
                        fmt += '| %s | %s | %s | |\n' % (port[0], port[1], port[2])
                        #print(port)
                    else:
                        fmt += '| %s | %s | %s | %s |\n' % (port[0], port[1], port[2], ' '.join(port[3:]))
    if "nikto" in dnames:
        temp = []
        fmt += '''
### [Nikto](nikto)
'''
        p = os.path.join(path, 'nikto')
        for dirpath, dirnames, filenames in os.walk(p):
            temp = [item for item in filenames if '.md' not in item]
            break
        for fn in temp:
            i = open(os.path.join(p, fn))
            lines = i.readlines()
            i.close()
            count = len(lines) - 10 # number of actual findings without header/footer info
            fmt += '\n---------\nNumber of findings in %s: %d' % (fn, count)
            if count < 50:
                for line in lines:
                    fmt += '  \n%s' % (line.rstrip())
    if "gobuster" in dnames:
        temp = []
        status = []
        p = os.path.join(path, 'gobuster')
        counts = dict()
        lines = []
        s200 = ''
        fmt += '''
### [Gobuster](gobuster)
| HTTP Response Status | Count |
| :----- | :---- |
'''
        for dirpath, dirnames, filenames in os.walk(p):
            temp = [item for item in filenames if '.md' not in item]
            #print(temp)
            break
        for fn in temp:
            i = open(os.path.join(p, fn))
            lines = i.readlines()
            i.close()
            for line in lines:
                if "Status:" in line:
                    status.append(re.search(r'\((.*?)\)',line).group(1))
                    if "Status: 200" in line:
                        s200 += '>' + line.rstrip() + '  \n'
            #counts = dict()
            for s in status:
                counts[s] = counts.get(s, 0) + 1
                #if s == "Status: 200":
                #    print(path + ' ' + s)
            #print(counts)
        for j in sorted(counts.keys()):
            #print(j)
            fmt += '| %s | %d |\n' % (j.split()[1], counts[j])
        if "Status: 200" in counts and counts["Status: 200"] < 50:
            #print("Status: 200")
            fmt += '\n**Paths found**\n\n' + s200
            #for line in lines:
            #    if "Status: 200" in line:
            #        fmt += '%s\n' % (line)
            #        print(line)
    return fmt
#    fmt = '''
#| Port | Info |
#| :----- | :---------- |
#'''

#####################################################################################
#
# Format main page with results from csv_reports directory
#
#####################################################################################
def format_content(path):
    fmt = '''
| Hostname | IP | Ports |
| :----- | :----- | :---------- |
'''
    fnames = []
    #title = ''
    dpath = os.path.join(path, "csv_reports")
    rows = []
    for(dirpath, dirnames, filenames) in os.walk(dpath):
        #fnames.extend(filenames)
        fnames = [item for item in filenames if '.md' not in item]
        #title = dirpath.split('/')[-1]
        break
    for name in fnames:
        ports = []
        ip = ''
        hostname = ''
        #print(os.path.join(path,"hosts/%s" % (name)))
        f = open(os.path.join(dpath,name), 'r')
        lines = f.readlines()[1:]
        #print(lines)
        for line in lines:
            tmp = line.rstrip().split(';')
            #print(tmp)
            if tmp[0] != "host" and tmp[0]:
                #print(line)
                try:
                    ip = tmp[0]
                    #ip = "[%s](%s)" % (tmp[0],tmp[0]) if os.path.exists(os.path.join(path, "hosts/%s" % (tmp[0]))) and tmp[0] else tmp[0]
                    #print(ip)
                    #print(os.path.join(path,"hosts/%s" % (ip)))
                    hostname = tmp[1]
                    #hostname = "[%s](%s)" % (tmp[1],tmp[1]) if os.path.exists(os.path.join(path, "hosts/%s" % (tmp[1]))) and tmp[1] else tmp[1]
                    #print(hostname)
                    ports.append(tmp[4])
                except Exception as e:
                    #print(e)
                    pass
        #fmt += "| %s | %s | %s |\n" % ("[%s](%s)" % (ip,ip) if os.path.exists(os.path.join(path,"hosts/%s" % (ip))) else ip, "[%s](%s)" % (hostname,hostname) if os.path.exists(os.path.join(path,"hosts/%s" % (hostname))) else hostname, ' '.join(ports))
        #fmt += "| %s | %s | %s |\n" % (ip, hostname, ' '.join(ports))
        try:
            rows.append([ipaddress.ip_address(ip), hostname if hostname else 'zzzz', ' '.join(ports)])
        except:
            pass
    table = []
    for col in reversed((0,1)):
        table = sorted(rows, key=operator.itemgetter(col))
    for col in reversed((1,0)):
        rows = sorted(table, key=operator.itemgetter(col))
    for row in rows:
        ip = "[%s](hosts/%s)" % (format(row[0]),format(row[0])) if os.path.join(path, "hosts/%s" % (format(row[0]))) and format(row[0]) else format(row[0])
        hostname = ''
        if row[1] != "zzzz":
            hostname = "[%s](hosts/%s)" % (row[1],row[1]) if os.path.exists(os.path.join(path, "hosts/%s" % (row[1]))) and row[1] else row[1]
        ports = row[2]
        fmt += "| %s | %s | %s |  \n" % (hostname, ip, ports)
    #print(fmt)
    return fmt

#####################################################################################
#
# All directories with subdirectories become branches
# - Branches have links to raw files (leaves)
# - Content branch (home page) has undecided information
# - Hosts branch displays all hosts as links (maybe some light information)
# - Individual hosts display curated information about the host + links to leaves
#
#####################################################################################
def write_branch(path):
    outfile = "%s/_index.md" % (path)
    fnames = []
    dnames = []
    dpath = ''
    title = ''
    for(dirpath, dirnames, filenames) in os.walk(path):
        fnames = [item for item in filenames if '.md' not in item]
        dnames.extend(dirnames)
        dpath = dirpath
        #print(dpath)
        title = dirpath.split('/')[-1]
        if title == "":
            title = "content"
        #print(title)
        break
    header = '''
---
title: %s
---

''' % (title)
    backup_file(outfile, fnames)
    f = open(outfile, 'w')
    f.write(header)
    #f.write(format_hosts(dpath))
    if title == "content":
        f.write(format_content(path))
    elif title == "hosts":
        f.write(format_hosts(dpath))
    elif "hosts" in path:
        f.write(format_stats(dpath))
    else:
        f.write(format_misc(dpath))
    # create functions for the different known directories (nikto, gobuster, nmap, hosts, etc.)

#####################################################################################
#
# Any directories without subdirectories just display raw files
#
#####################################################################################
def write_leaf(path):
    outfile = "%s/index.md" % (path)
    fnames = []
    title = ''
    for(dirpath, dirnames, filenames) in os.walk(path):
        fnames = [item for item in filenames if '.md' not in item and 'pingsweep' not in item]
        title = dirpath.split('/')[-1]
        break
    header = '''
---
title: %s
---

''' % (title)
    backup_file(outfile, fnames)
    f = open(outfile, 'w')
    f.write(header)
    for name in fnames:
        try:
            f.write("------------------------------")
            f.write("\n\n### %s\n\n" % (name))
            i = open(os.path.join(path,name), 'r')
            lines = i.readlines()
            #f.write('`\n')
            for line in lines:
                if not "Status: 404" in line and line.strip():
                    #f.write('> ' + line.replace('#','\#').replace('=','-') + '\n')
                    f.write('> ' + line.replace('#','\#').replace('=','').rstrip() + '  \n')
                    #if "[+]" in line:
                    #    print(line.rstrip())
            #f.write('`')
            i.close()
        except Exception as e:
            f.write("Unviewable file %s" % (name))
    f.close()

#####################################################################################
#
# Backup all index.md and _index.md files
#
#####################################################################################
def backup_file(filename, fnames):
    if filename in fnames:
        if '%s.bak' % (filename) in fnames:
            if backups == 'ask':
                choice = input("%s.bak already exists. Replace it? (I'm lazy, so 'y' or 'Y' replaces the file, any other option creates a unique filename for the backup) [y/n]: " % (filename))
                if choice != 'y' and choice != 'Y':
                    timestamp = time.strftime("%Y-%m-%d-%H:%M", time.localtime())
                    os.system('mv %s %s.%s.bak' % (filename, filename, timestamp))
            elif choice == 'replace':
                os.system('mv %s %s.bak' % (filename, filename))
            elif choice == 'unique':
                timestamp = time.strftime("%Y-%m-%d-%H:%M", time.localtime())
                os.system('mv %s %s.%s.bak' % (filename, filename, timestamp))
        else:
            os.system('mv %s %s.bak' % (filename, filename))

#####################################################################################
#
# List directories in path
# List files in path
# Go through directories recursively
# When there are no directories (only files)
#  - Go through each file
#  - Write to _index.md or index.md
#
#####################################################################################
def build_tree(path):
    fnames = []
    dnames = []
    dpath = ''
    for(dirpath, dirnames, filenames) in os.walk(path): #lists all directories files 
        #fnames.extend(filenames)
        fnames = [item for item in filenames if '.md' not in item]
        dnames.extend(dirnames)
        dpath = dirpath
        #print(dirpath)
        break # breaks before exploring sub-directories
    if len(dnames):
        for name in dnames:
            build_tree(os.path.join(dpath, name))
        write_branch(dpath)
    else:
        write_leaf(dpath)
    #print(fnames)
    #print(dnames)

def main():
    parser = argparse.ArgumentParser(prog='hugo_update.py', usage='python3 %(prog)s [-r/-u] /path/to/content (default: current directory)', description='Update branches and leaves for Hugo')
    parser.add_argument('path', metavar='P', default='./', nargs='?', help='Path to the content folder (default current folder)')
    backup_group = parser.add_mutually_exclusive_group(required=False)
    backup_group.add_argument('-r', action="store_true", required=False, help='Automatically replace backup')
    backup_group.add_argument('-u', action="store_true", required=False, help='Automatically create unique backup')
    
    args = parser.parse_args()

    path = args.path
    global backups
    if args.r:
        backups = 'replace'
    elif args.u:
        backups = 'unique'
    else:
        backups = 'ask'

    build_tree(path)

    #handle_hosts(path)
    #handle_gobuster(path)
    #handle_nikto(path)
    #handle_nmap(path)
    #handle_other(path)


if __name__ == '__main__':
    main()

