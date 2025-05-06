#!/usr/bin/env python3

import argparse
import datetime
import logging
import os
import pwd
import grp
import re
import subprocess
import sys
import time
import json
import tarfile
import configparser
from typing import List, Optional, Tuple, Dict, Generator, Any
from urllib.parse import urlparse
from shutil import which
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging.handlers import RotatingFileHandler
from tqdm import tqdm
import glob
from abc import ABC, abstractmethod

if os.geteuid() != 0:
    sys.exit("\033[1;31;40m[-] ERROR: Run as root for Nmap functionality.\033[0;37;40m")

try:
    import nmap
except ImportError:
    print("\033[1;31;40m[-] Error: python-nmap is not installed.\033[0;37;40m")
    choice = input("\033[1;35;40m[*] Install python-nmap? [y/n] \033[0;37;40m") or 'y'
    if choice.lower() == 'y':
        try:
            subprocess.run(["pip3", "install", "python-nmap"], check=True)
            import nmap
        except subprocess.CalledProcessError:
            sys.exit("\033[1;31;40m[-] Failed to install python-nmap. Install manually.\033[0;37;40m")
    else:
        sys.exit("\033[1;31;40m[-] Quitting...\033[0;37;40m")

try:
    from tqdm import tqdm
except ImportError:
    print("\033[1;31;40m[-] Error: tqdm is not installed.\033[0;37;40m")
    choice = input("\033[1;35;40m[*] Install tqdm? [y/n] \033[0;37;40m") or 'y'
    if choice.lower() == 'y':
        try:
            subprocess.run(["pip3", "install", "tqdm"], check=True)
            from tqdm import tqdm
        except subprocess.CalledProcessError:
            sys.exit("\033[1;31;40m[-] Failed to install tqdm. Install manually.\033[0;37;40m")
    else:
        sys.exit("\033[1;31;40m[-] Quitting...\033[0;37;40m")

ENDC = '\033[0;37;40m'
TEAL = '\033[1;36;40m'
GREEN = '\033[1;32;40m'
RED = '\033[1;31;40m'
PURPLE = '\033[1;35;40m'
WHITE = '\033[1;37;40m'

logger = logging.getLogger('autoscan')
logger.setLevel(logging.INFO)

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            if '[-]' in record.msg:
                msg = f"{RED}[-] {record.msg[len('[-] '):]}{ENDC}"
            elif '[+]' in record.msg:
                msg = f"{GREEN}[+] {record.msg[len('[+] '):]}{ENDC}"
            elif '[*]' in record.msg:
                msg = f"{TEAL}[*] {record.msg[len('[*] '):]}{ENDC}"
            else:
                msg = record.msg
        else:
            msg = f"{RED}{record.msg}{ENDC}"
        record.msg = msg
        return super().format(record)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(ColoredFormatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(console_handler)

log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'autoscan.log')
file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(file_handler)

def print_info(msg: str) -> None:
    logger.info(f"[*] {msg}")

def print_success(msg: str) -> None:
    logger.info(f"[+] {msg}")

def print_err(msg: str) -> None:
    logger.error(f"[-] {msg}")

def print_color(msg: str, color: str) -> None:
    if color == RED:
        logger.error(msg)
    else:
        logger.info(msg)

def ensure_directory(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
        os.chmod(path, 0o755)
    except OSError as e:
        print_err(f"Failed to create directory {path}: {e}")

def install_tool(tool_name: str, install_cmd: str, apt_package: Optional[str] = None, fallback_cmd: Optional[str] = None) -> bool:
    if which(tool_name):
        return True
    print_err(f"{tool_name.capitalize()} is required. Install with: {install_cmd}")
    if input(f"\033[1;35;40m[*] Install {tool_name} now? [y/n] \033[0;37;40m").lower() in ('y', ''):
        try:
            if apt_package:
                subprocess.run(["sudo", "apt", "update"], check=True)
                subprocess.run(["sudo", "apt", "install", "-y", apt_package], check=True)
            subprocess.run(install_cmd, shell=True, check=True)
            print_success(f"{tool_name.capitalize()} installed successfully.")
            return True
        except subprocess.CalledProcessError as e:
            print_err(f"Failed to install {tool_name} with primary method: {str(e)}")
            if fallback_cmd:
                print_info(f"Attempting fallback installation: {fallback_cmd}")
                try:
                    subprocess.run(fallback_cmd, shell=True, check=True)
                    print_success(f"{tool_name.capitalize()} installed successfully via fallback.")
                    return True
                except subprocess.CalledProcessError as e2:
                    print_err(f"Fallback installation failed: {str(e2)}")
            return False
    print_err(f"Skipping {tool_name} scan.")
    return False

def setup_hugo_environment(hugo_dir: str, theme_url: str, force: bool = False, non_interactive: bool = False) -> None:
    print_info(f"Attempting to set up Hugo environment in {hugo_dir}")
    if not which("hugo"):
        hugo_install_cmd = "sudo apt install -y snapd && sudo snap install hugo"
        hugo_fallback_cmd = "git clone https://github.com/gohugoio/hugo.git /tmp/hugo && cd /tmp/hugo && go build -tags extended && sudo mv hugo /usr/local/bin/ && sudo chmod +x /usr/local/bin/hugo && cd - && rm -rf /tmp/hugo"
        if not install_tool("hugo", hugo_install_cmd, apt_package="snapd", fallback_cmd=hugo_fallback_cmd):
            print_err("Hugo setup aborted due to installation failure.")
            return
    config_file = os.path.join(hugo_dir, "config.toml")
    themes_dir = os.path.join(hugo_dir, "themes")
    content_dir = os.path.join(hugo_dir, "content")
    if os.path.exists(config_file) or os.path.exists(themes_dir) or os.path.exists(content_dir):
        print_info(f"Hugo site detected at {hugo_dir}")
        if not force:
            if non_interactive:
                print_info("Non-interactive mode: Skipping Hugo setup to avoid overwriting existing site.")
                return
            choice = input(f"\033[1;35;40m[*] Hugo site exists at {hugo_dir}. Overwrite? [y/n] \033[0;37;40m") or 'n'
            if choice.lower() != 'y':
                print_info("Skipping Hugo setup to preserve existing site.")
                return
        print_info("Overwriting existing Hugo site.")
        try:
            subprocess.run(["rm", "-rf", hugo_dir], check=True)
            print_info(f"Removed existing Hugo site at {hugo_dir}")
        except subprocess.CalledProcessError as e:
            print_err(f"Failed to remove existing Hugo site: {str(e)}")
            return
    try:
        ensure_directory(hugo_dir)
        subprocess.run(["hugo", "new", "site", hugo_dir], check=True, capture_output=True)
        print_success(f"Created Hugo site in {hugo_dir}")
    except subprocess.CalledProcessError as e:
        print_err(f"Failed to create Hugo site: {str(e)}")
        return
    theme_name = theme_url.split('/')[-1].replace('.git', '')
    theme_dir = os.path.join(hugo_dir, "themes", theme_name)
    try:
        subprocess.run(["git", "clone", theme_url, theme_dir], check=True, capture_output=True)
        print_success(f"Cloned Hugo theme {theme_name} from {theme_url}")
    except subprocess.CalledProcessError as e:
        print_err(f"Failed to clone Hugo theme: {str(e)}")
        return
    config_file = os.path.join(hugo_dir, "config.toml")
    with open(config_file, 'w') as f:
        f.write(f"""
baseURL = "http://example.org/"
languageCode = "en-us"
title = "Autoscan Results"
theme = "{theme_name}"
""")
    print_success(f"Configured Hugo site with theme {theme_name}")

def validate_proxy(proxy: Optional[str]) -> Optional[str]:
    if not proxy:
        return None
    parsed = urlparse(proxy)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        print_err("Invalid proxy format. Use http(s)://host:port")
        return None
    return proxy

def sanitize_nmap_args(nmap_args: str) -> str:
    args_list = nmap_args.split()
    sanitized_args = [arg for arg in args_list if not arg.startswith('-p') and arg != '-sn']
    return ' '.join(sanitized_args)

def validate_ports(ports: str) -> bool:
    try:
        for part in ports.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                    return False
            else:
                port = int(part)
                if not (1 <= port <= 65535):
                    return False
        return True
    except ValueError:
        return False

def validate_input(line: str) -> bool:
    if '/' in line:
        try:
            ipaddress.ip_network(line, strict=False)
            return True
        except ValueError:
            return False
    elif '-' in line:
        try:
            start, end = line.split('-')
            ipaddress.ip_address(start.strip())
            ipaddress.ip_address(end.strip())
            return True
        except ValueError:
            return False
    else:
        try:
            ipaddress.ip_address(line)
            return True
        except ValueError:
            return urlparse(line).netloc != ''
    return False

def expand_cidr(cidr: str) -> Generator[Tuple[str, str], None, None]:
    print_info(f"Expanding CIDR: {cidr}")
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        for host in network.hosts():
            yield str(host), cidr
    except ValueError as e:
        print_err(f"Invalid CIDR format: {cidr}")

def expand_range(ran: str) -> List[Tuple[str, str]]:
    try:
        start, end = ran.split('-')
        start_ip = ipaddress.ip_address(start.strip())
        end_ip = ipaddress.ip_address(end.strip())
        ips = []
        current = start_ip
        while current <= end_ip:
            ips.append((str(current), ran))
            current = ipaddress.ip_address(int(current) + 1)
        print_info("Range expanded")
        return ips
    except ValueError:
        print_err(f"Invalid range format: {ran}")
        return [(ran, ran)]

def get_hosts(hosts_file: str, dirname: str = '.', single: bool = False) -> List[Tuple[str, str]]:
    try:
        lines = [hosts_file] if single else [x.rstrip() for x in open(os.path.join(dirname, hosts_file)).readlines()]
        hosts = set()
        for line in lines:
            if not validate_input(line):
                print_err(f"Skipping invalid input: {line}")
                continue
            print_info(f"Processing: {line}")
            if '/' in line:
                hosts.update(expand_cidr(line))
            elif '-' in line:
                hosts.update(expand_range(line))
            else:
                try:
                    url = urlparse(line)
                    hosts.add((url.netloc or line, line))
                except ValueError:
                    hosts.add((line, line))
        print_info("Hosts list generated")
        return list(hosts)
    except FileNotFoundError:
        print_err(f"Host file '{os.path.join(dirname, hosts_file)}' does not exist")
        return []

def show_hosts(hosts: List[Tuple[str, str]], message: str) -> None:
    print_info(message)
    for host, _ in hosts:
        print_color(f" [*] {host}", WHITE)

def create_host_directory(base_dir: str, dirname: str, host: str, hostname: Optional[str] = None) -> str:
    try:
        ipaddress.ip_address(host)
        host_dir = host.replace('/', '-').replace(':', '-')
    except ValueError:
        host_dir = (hostname or host).replace('/', '-').replace(':', '-').replace('.', '-')
    full_path = os.path.join(base_dir, dirname, host_dir)
    ensure_directory(full_path)
    return host_dir

def scan_host_status(nm: nmap.PortScanner, host: str, base_dir: str, dirname: str, hostname: Optional[str] = None, retries: int = 3) -> Tuple[List[Tuple[str, str]], Optional[str]]:
    host_dir = create_host_directory(base_dir, dirname, host, hostname)
    scan_args = f'{args.ping_args} -oN {base_dir}/{dirname}/{host_dir}/{host_dir}-pingsweep.nmap'
    print_info(f"Scanning {host} with arguments: {scan_args}")
    for attempt in range(retries):
        try:
            nm.scan(hosts=host, arguments=scan_args)
            scanned_hosts = nm.all_hosts()
            print_info(f"Scan results for {host}: {scanned_hosts}")
            if host not in scanned_hosts:
                print_err(f"Host {host} not found in scan results: {scanned_hosts}")
                return [], None
            hostname = nm[host].hostname() if nm[host].hostname() else None
            return [(x, nm[x]['status']['state']) for x in scanned_hosts], hostname
        except Exception as e:
            print_err(f"Scan failed for {host} (attempt {attempt+1}/{retries}): {str(e)}")
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
            else:
                print_err(f"Max retries reached for {host}, skipping")
                return [], None

def find_active_hosts(hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str) -> Tuple[List[Tuple[str, str, Optional[str]]], List[Tuple[str, str, Optional[str]]]]:
    print_info("Finding active hosts")
    active_hosts = []
    inactive_hosts = hosts.copy()
    max_workers = min(config.getint('Tools', 'nmap_threads', fallback=8), len(hosts))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(scan_host_status, nmap.PortScanner(), host, base_dir, dirname, hostname, config.getint('Nmap', 'retries', fallback=3)): (host, original, hostname) for host, original, hostname in hosts}

        for future in as_completed(future_to_host):
            host, original, hostname = future_to_host[future]
            try:
                scanned_hosts, resolved_hostname = future.result()
                if not scanned_hosts:
                    print_err(f"No scan results for {host}, marking as inactive")
                    continue
                for host_name, status in scanned_hosts:
                    if status == 'up':
                        active_hosts.append((host_name, original, resolved_hostname or hostname))
                        if (host_name, original, hostname) in inactive_hosts:
                            inactive_hosts.remove((host_name, original, hostname))
            except Exception as e:
                print_err(f"Scan failed for {host}: {str(e)}")

    return active_hosts, inactive_hosts

def remove_inactive_hosts(hosts: List[Tuple[str, str]], base_dir: str, dirname: str) -> None:
    print_info("Removing inactive hosts")
    for host, _ in hosts:
        host_dir = f"{base_dir}/{dirname}/{host.replace('/', '-')}"
        if os.path.exists(host_dir):
            subprocess.run(["rm", "-rf", host_dir], check=True)

def write_hosts(hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str, filename: str, checkpoint: bool = False) -> None:
    ensure_directory(os.path.join(base_dir, dirname))
    suffix = ".tmp" if checkpoint else ""
    with open(os.path.join(base_dir, dirname, f"{filename}{suffix}"), 'w') as f:
        for host, _, hostname in hosts:
            f.write(f"{hostname or host}\n")

def find_web_apps(nms: List[nmap.PortScanner]) -> List[List[str]]:
    web_apps = []
    print_info("Discovering web apps")
    for nm in nms:
        for host in nm.all_hosts():
            hn = nm[host].hostname() or host
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                if 80 in ports:
                    print_success(f"Found web app on port 80 of {hn}")
                    web_apps.append([host, 'http', nm[host].hostname()])
                if 443 in ports:
                    print_success(f"Found web app on port 443 of {hn}")
                    web_apps.append([host, 'https', nm[host].hostname()])
    return web_apps

def nuclei_test(web_apps: List[List[str]], base_dir: str, dirname: str, proxy: Optional[str], config: configparser.ConfigParser) -> None:
    snap_cmd = "sudo apt install -y snapd && sudo snap install nuclei"
    binary_cmd = "git clone https://github.com/projectdiscovery/nuclei.git /tmp/nuclei && cd /tmp/nuclei && go build -o nuclei ./cmd/nuclei && sudo mv nuclei /usr/local/bin/ && sudo chmod +x /usr/local/bin/nuclei && cd - && rm -rf /tmp/nuclei"
    if not install_tool("nuclei", snap_cmd, apt_package="snapd", fallback_cmd=binary_cmd):
        return
    print_info("Starting Nuclei scans")
    concurrency = config.get('Tools', 'nuclei_concurrency', fallback='50')
    max_workers = config.getint('Tools', 'nuclei_threads', fallback=4)

    def run_nuclei(host, protocol, hostname):
        target = hostname or host
        host_dir = create_host_directory(base_dir, dirname, host, hostname)
        ensure_directory(f"{base_dir}/{dirname}/{host_dir}/nuclei")
        output_file = f"{base_dir}/{dirname}/{host_dir}/nuclei/nuclei-results-{target}-{protocol}.txt"
        cmd = ["nuclei", "-u", f"{protocol}://{target}", "-o", output_file, "-silent", "-c", concurrency]
        if proxy:
            cmd.extend(["-proxy", proxy])
        print_info(f"Running Nuclei against {protocol}://{target}")
        try:
            subprocess.run(cmd, check=True)
            print_success(f"Completed Nuclei scan for {protocol}://{target}")
        except subprocess.CalledProcessError:
            print_err(f"Nuclei scan failed for {protocol}://{target}")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(run_nuclei, host, protocol, hostname) for host, protocol, hostname in web_apps]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print_err(f"Nuclei scan thread failed: {str(e)}")

def feroxbuster_test(web_apps: List[List[str]], base_dir: str, dirname: str, proxy: Optional[str], config: configparser.ConfigParser) -> None:
    snap_cmd = "sudo apt install -y snapd && sudo snap install feroxbuster --classic"
    binary_cmd = "git clone https://github.com/epi052/feroxbuster.git /tmp/feroxbuster && cd /tmp/feroxbuster && cargo build --release && sudo mv target/release/feroxbuster /usr/local/bin/ && sudo chmod +x /usr/local/bin/feroxbuster && cd - && rm -rf /tmp/feroxbuster"
    if not install_tool("feroxbuster", snap_cmd, apt_package="snapd", fallback_cmd=binary_cmd):
        return
    print_info("Starting Feroxbuster scans")
    wordlist = config.get('Tools', 'wordlist', fallback='~/snap/feroxbuster/common/raft-small-directories-lowercase.txt')
    if not os.path.exists(wordlist):
        try:
            subprocess.run(["wget", "https://raw.githubusercontent.com/Averroes/raft/master/data/wordlists/raft-small-directories-lowercase.txt", "-O", os.path.expanduser(wordlist)], check=True)
            print_success(f"Downloaded wordlist to {wordlist}")
        except subprocess.CalledProcessError:
            print_err("Failed to download wordlist. Skipping feroxbuster.")
            return
    threads = config.get('Tools', 'feroxbuster_threads', fallback='20')
    max_workers = config.getint('Tools', 'feroxbuster_parallel_threads', fallback=4)

    def run_feroxbuster(host, protocol, hostname):
        target = hostname or host
        host_dir = create_host_directory(base_dir, dirname, host, hostname)
        ensure_directory(f"{base_dir}/{dirname}/{host_dir}/feroxbuster")
        output_file = f"{base_dir}/{dirname}/{host_dir}/feroxbuster/feroxbuster-results-{target}-{protocol}.txt"
        cmd = ["feroxbuster", "-u", f"{protocol}://{target}", "-w", wordlist, "-o", output_file, "--silent", "-t", threads]
        if proxy:
            cmd.extend(["-proxy", proxy])
        print_info(f"Running Feroxbuster against {protocol}://{target}")
        try:
            subprocess.run(cmd, check=True)
            print_success(f"Completed Feroxbuster scan for {protocol}://{target}")
        except subprocess.CalledProcessError:
            print_err(f"Feroxbuster scan failed for {protocol}://{target}")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(run_feroxbuster, host, protocol, hostname) for host, protocol, hostname in web_apps]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print_err(f"Feroxbuster scan thread failed: {str(e)}")

def subfinder_enum(hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str, subfinder_file: str) -> None:
    if not install_tool("subfinder", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && sudo cp ~/go/bin/subfinder /usr/local/bin/"):
        return
    print_info("Starting Subfinder enumeration")
    output_file = f"{base_dir}/{dirname}/{subfinder_file}"
    max_workers = config.getint('Tools', 'subfinder_threads', fallback=4)

    def run_subfinder(domain, temp_output):
        cmd = ["subfinder", "-silent", "-o", temp_output, "-d", domain]
        try:
            subprocess.run(cmd, check=True, timeout=300)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print_err(f"Subfinder failed for {domain}: {str(e)}")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        temp_files = [f"{base_dir}/{dirname}/subfinder_temp_{i}.txt" for i in range(len(hosts))]
        futures = [executor.submit(run_subfinder, host[0], temp_files[i]) for i, host in enumerate(hosts)]
        for future in as_completed(futures):
            future.result()

    with open(output_file, 'w') as outfile:
        for temp_file in temp_files:
            if os.path.exists(temp_file):
                with open(temp_file, 'r') as infile:
                    outfile.write(infile.read())
                os.remove(temp_file)
    print_success("Completed Subfinder enumeration")

def nmap_scan(hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str, top_ports: str = '-p1-65535', tcp: bool = True, nmap_args: str = '-Pn -sV -O') -> List[nmap.PortScanner]:
    print_info("Starting nmap scans")
    nms = []
    ensure_directory(os.path.join(base_dir, dirname))
    max_workers = min(config.getint('Tools', 'nmap_threads', fallback=8), len(hosts))

    def scan_single_host(host, original, hostname, top_ports, tcp, nmap_args):
        nm = nmap.PortScanner()
        host_dir = create_host_directory(base_dir, dirname, host, hostname)
        ensure_directory(f"{base_dir}/{dirname}/{host_dir}/nmaps")
        scan_type = "" if tcp else "-udp"
        port_slug = top_ports.replace(',', '_').replace(' ', '').replace('-', '')
        target = host.replace('/', '-').replace(':', '-')
        output_base = f"{base_dir}/{dirname}/{host_dir}/nmaps/{target}{scan_type}-scan-{port_slug}"
        sanitized_nmap_args = sanitize_nmap_args(nmap_args)
        args = f"{sanitized_nmap_args} {top_ports} -oN {output_base}.nmap"

        for attempt in range(config.getint('Nmap', 'retries', fallback=3)):
            try:
                nm.scan(host, arguments=args)
                csv_data = nm.csv()
                print_info(f"Raw CSV for {host}: {csv_data[:200]}...")
                with open(f"{output_base}.csv", 'w') as f:
                    f.write(csv_data)
                print_success(f"Completed scan for {host}")
                return nm
            except nmap.PortScannerError as e:
                print_err(f"Port scan for {host} failed (attempt {attempt+1}/{retries}): {str(e)}")
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                else:
                    print_err(f"Max retries reached for {host}, skipping")
                    return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(scan_single_host, host, original, hostname, top_ports, tcp, nmap_args): host for host, original, hostname in hosts}
        for future in tqdm(as_completed(future_to_host), total=len(hosts), desc="Scanning hosts"):
            host = future_to_host[future]
            try:
                nm = future.result()
                if nm:
                    nms.append(nm)
            except Exception as e:
                print_err(f"Scan failed for {host}: {str(e)}")

    print_success("Completed nmap scans")
    return nms

def export_json_summary(hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str, output_file: str) -> None:
    ensure_directory(os.path.dirname(output_file) if os.path.dirname(output_file) else base_dir)
    summary = []
    for host, _, hostname in hosts:
        csv_path = os.path.join(base_dir, dirname, hostname or host)
        ports = []
        try:
            for fname in next(os.walk(csv_path))[2]:
                if fname.endswith('.csv'):
                    with open(os.path.join(csv_path, fname)) as f:
                        lines = f.readlines()[1:]
                        for line in lines:
                            parts = line.rstrip().split(';', maxsplit=5)
                            if len(parts) >= 5 and parts[0]:
                                ports.append(parts[4])
        except StopIteration:
            print_err(f"No CSV files found for {host}")
        summary.append({"host": host, "hostname": hostname, "ports": list(set(ports))})
    with open(output_file, 'w') as f:
        json.dump(summary, f, indent=2)
    print_success(f"Exported JSON summary to {output_file}")

def cleanup() -> None:
    print_info("Cleaning up...")
    stat_info = os.stat('.')
    uid = stat_info.st_uid
    gid = stat_info.st_gid
    user = pwd.getpwuid(uid)[0]
    group = grp.getgrgid(gid)[0]
    try:
        subprocess.run(["chown", "-R", f"{user}:{group}", "."], check=True)
        print_info("All clean!")
    except subprocess.CalledProcessError:
        print_err("Failed to change file ownership")

def format_hosts_hugo(path: str) -> str:
    try:
        dirs = next(os.walk(path))[1]
        ip_addrs = []
        urls = []
        for dr in dirs:
            try:
                ip_addrs.append(ipaddress.ip_address(dr))
            except ValueError:
                urls.append(dr)
        ip_addrs.sort()
        urls.sort()
        fmt = ''
        for url in urls:
            fmt += f'[{url}]({url})  \n'
        for ip in ip_addrs:
            fmt += f'[{str(ip)}]({str(ip)})  \n'
        return fmt
    except StopIteration:
        print_err(f"Failed to read directory: {path}")
        return ''

def format_stats_hugo(path: str) -> str:
    fmt = ''
    try:
        dirs, files = next(os.walk(path))[1:3]
        files = [f for f in files if not f.endswith('.md')]

        if 'nmaps' in dirs:
            nmap_path = os.path.join(path, 'nmaps')
            try:
                nmap_files = [f for f in next(os.walk(nmap_path))[2] if f.endswith('.csv')]
                print_info(f"Found CSV files in {nmap_path}: {nmap_files}")
                if nmap_files:
                    fmt += '''
### Nmap Summary
| Port | Protocol | Service |
|------|----------|---------|
'''
                    seen_ports = set()
                    for fname in nmap_files:
                        try:
                            with open(os.path.join(nmap_path, fname), 'r', encoding='utf-8') as f:
                                lines = f.readlines()
                            if not lines:
                                print_info(f"CSV file {fname} is empty")
                                continue
                            print_info(f"First 3 lines of {fname}: {lines[:3]}")
                            start_idx = 1 if lines and lines[0].startswith('host;') else 0
                            for line in lines[start_idx:]:
                                if not line.strip():
                                    continue
                                parts = line.rstrip().split(';')
                                if len(parts) >= 7 and parts[6].lower() == 'open':
                                    port_key = (parts[4], parts[3], parts[5] or "-")
                                    if port_key not in seen_ports:
                                        seen_ports.add(port_key)
                                        fmt += f'| {parts[4]} | {parts[3]} | {parts[5] or "-"} |\n'
                                else:
                                    print_info(f"Skipping line in {fname} (len={len(parts)}, state={parts[6] if len(parts) > 6 else 'N/A'}): {line.rstrip()}")
                        except (IOError, UnicodeDecodeError) as e:
                            print_err(f"Error reading {fname} in {nmap_path}: {e}")
                    fmt += '\n[Full Nmap Results](nmaps)\n'
                else:
                    print_info(f"No CSV files found in {nmap_path}")
            except StopIteration:
                print_err(f"Failed to access nmaps directory: {nmap_path}")
        else:
            print_info(f"No nmaps directory found in {path}")

        if 'nuclei' in dirs:
            fmt += '''
### Nuclei Summary
'''
            nuclei_path = os.path.join(path, 'nuclei')
            findings = []
            total_findings = 0
            try:
                for fname in next(os.walk(nuclei_path))[2]:
                    if fname.endswith('.txt'):
                        try:
                            with open(os.path.join(nuclei_path, fname), 'r', encoding='utf-8') as f:
                                lines = [l.rstrip() for l in f if l.strip()]
                            total_findings += len(lines)
                            for line in lines:
                                if any(sev in line for sev in ['[critical]', '[high]', '[moderate]']):
                                    findings.append(line)
                        except (IOError, UnicodeDecodeError) as e:
                            print_err(f"Error reading {fname} in {nuclei_path}: {e}")
                fmt += f'Found {total_findings} total findings.\n'
                if findings:
                    fmt += '\n**Critical/High/Moderate Findings:**\n'
                    fmt += '\n'.join(f'- {l}' for l in findings[:5]) + '\n'
                fmt += '\n[Full Nuclei Results](nuclei)\n'
            except StopIteration:
                print_err(f"Failed to access nuclei directory: {nuclei_path}")

        if 'feroxbuster' in dirs:
            fmt += '''
### Feroxbuster Summary
| Path | Status | Size |
|---------------|--------|------|
'''
            feroxbuster_path = os.path.join(path, 'feroxbuster')
            try:
                for fname in next(os.walk(feroxbuster_path))[2]:
                    if fname.endswith('.txt'):
                        try:
                            with open(os.path.join(feroxbuster_path, fname), 'r', encoding='utf-8') as f:
                                for line in f:
                                    if line.strip() and ('200' in line or '301' in line):
                                        parts = line.strip().split()
                                        if len(parts) >= 3:
                                            status, path, size = parts[0], parts[1], parts[2]
                                            fmt += f'| {path} | {status} | {size} |\n'
                        except (IOError, UnicodeDecodeError) as e:
                            print_err(f"Error reading {fname} in {feroxbuster_path}: {e}")
                fmt += '\n[Full Feroxbuster Results](feroxbuster)\n'
            except StopIteration:
                print_err(f"Failed to access feroxbuster directory: {feroxbuster_path}")

        if not fmt.strip():
            print_info(f"No scan results found for {path}")
        return fmt
    except StopIteration:
        print_err(f"Failed to process stats for {path}")
        return ''

def format_content_hugo(hugo_dir: str, dirname: str) -> str:
    fmt = f'## Hosts in {dirname}\n\n'
    fmt += '''
| Hostname | IP | Ports |
|----------|----------|----------|
'''
    rows = []
    scan_dir = os.path.join(hugo_dir, dirname)
    print_info(f"Processing scan directory: {scan_dir}")
    try:
        host_dirs = next(os.walk(scan_dir))[1]
        print_info(f"Found host directories: {host_dirs}")
        if not host_dirs:
            print_err(f"No host directories found in {scan_dir}. Check scan output.")
            return fmt + '| No hosts scanned | - | - |\n\n'

        for hdir in host_dirs:
            print_info(f"Processing directory: {hdir}")
            csv_path = os.path.join(scan_dir, hdir, 'nmaps')
            print_info(f"Checking CSV path: {csv_path}")
            try:
                csv_files = [f for f in next(os.walk(csv_path))[2] if f.endswith('.csv')]
                print_info(f"Found CSV files in {csv_path}: {csv_files}")
                if not csv_files:
                    print_err(f"No CSV files found in {csv_path}. Check Nmap output.")
                    continue

                seen_ports = set()
                ip = hostname = ''
                for fname in csv_files:
                    print_info(f"Processing CSV file: {os.path.join(csv_path, fname)}")
                    try:
                        with open(os.path.join(csv_path, fname)) as f:
                            lines = f.readlines()
                        if not lines:
                            print_err(f"CSV file {fname} is empty.")
                            continue
                        print_info(f"CSV contents (first 5 lines): {lines[:5]}")
                        if lines and lines[0].startswith('host;'):
                            print_info(f"Header detected and skipped: {lines[0].rstrip()}")
                            lines = lines[1:]
                        else:
                            print_info(f"No standard header detected in {fname}. Processing all lines.")
                        if not lines:
                            print_err(f"No data lines in {fname} after skipping header.")
                            continue
                        for line in lines:
                            line = line.rstrip()
                            if not line:
                                print_info(f"Skipping empty line in {fname}")
                                continue
                            parts = line.split(';')
                            if len(parts) < 5 or not parts[0]:
                                print_info(f"Skipping invalid CSV line (insufficient fields): {line}")
                                continue
                            if not parts[4] or not parts[4].isdigit():
                                print_info(f"Skipping non-port line (invalid port '{parts[4]}'): {line}")
                                continue
                            ip = parts[0]
                            hostname = parts[1] or ip
                            port = parts[4]
                            print_info(f"Extracted: IP={ip}, Hostname={hostname}, Port={port}")
                            seen_ports.add(port)
                    except (IOError, UnicodeDecodeError) as e:
                        print_err(f"Error reading {fname} in {csv_path}: {e}")
                if ip and seen_ports:
                    rows.append([ip, hostname, ' '.join(sorted(seen_ports))])
                elif ip:
                    print_info(f"No ports for {ip}, adding with 'none'")
                    rows.append([ip, hostname, 'none'])
                else:
                    print_err(f"No valid port data for {hdir}.")
            except StopIteration:
                print_err(f"Failed to access nmaps directory: {csv_path}")
                continue

        if not rows:
            print_err(f"No valid scan data found for hosts in {scan_dir}.")
            return fmt + '| No valid scan data | - | - |\n\n'

        def ip_key(row):
            try:
                return int(ipaddress.ip_address(row[0]))
            except ValueError:
                return row[0]

        rows.sort(key=lambda x: (x[1], ip_key(x)))

        for ip, hostname, ports in rows:
            ip_link = f'[{ip}]({dirname}/{ip})' if os.path.exists(os.path.join(hugo_dir, dirname, ip)) else ip
            hn_link = f'[{hostname}]({dirname}/{ip})' if os.path.exists(os.path.join(hugo_dir, dirname, ip)) else hostname
            fmt += f'| {hn_link} | {ip_link} | {ports} |  \n'

        return fmt + '\n'
    except StopIteration:
        print_err(f"Failed to access scan directory: {scan_dir}")
        return fmt + '| No scan directories found | - | - |\n\n'

def write_branch_hugo(path: str, dirname: str, backup_mode: str, all_dir_content: Optional[Dict[str, str]] = None) -> None:
    title = os.path.basename(path) or 'content'
    index_filename = '_index.md' if title != 'content' else 'index.md'
    outfile = os.path.join(path, index_filename)
    backup_file_hugo(outfile, backup_mode)
    # Add weight and chapter for hugo-theme-learn navigation
    weight = len(os.listdir(path)) + 1 if os.path.isdir(path) else 1
    header = f'---\ntitle: {title}\ndraft: false\nweight: {weight}\nchapter: {str(title != "content").lower()}\n---\n'
    
    if title == 'content' and all_dir_content:
        content = '\n'.join(all_dir_content.values())
        if not content.strip():
            content = '\nNo scan results available across all directories.\n'
    else:
        content = format_stats_hugo(path) if title != 'content' and title != dirname else format_content_hugo(path, dirname) if title == 'content' else format_hosts_hugo(path)
        if not content.strip() or content == header.strip():
            content += '\nNo scan results available.\n'

    # Validate Markdown table syntax
    if '|' in content:
        lines = content.split('\n')
        table_lines = [l for l in lines if l.strip().startswith('|')]
        if table_lines:
            header_row = table_lines[0]
            separator_row = table_lines[1] if len(table_lines) > 1 else ''
            if not separator_row or not all(c in '-| ' for c in separator_row.replace('|', '')):
                print_err(f"Invalid table in {outfile}. Adding separator row.")
                lines.insert(lines.index(header_row) + 1, '| ' + '--- |' * (header_row.count('|') - 1))
                content = '\n'.join(lines)

    with open(outfile, 'w') as f:
        f.write(header + content)
    print_success(f"Generated {outfile}")

def write_leaf_hugo(path: str, backup_mode: str) -> None:
    title = os.path.basename(path)
    outfile = os.path.join(path, 'index.md')
    backup_file_hugo(outfile, backup_mode)
    header = f'---\ntitle: {title}\ndraft: false\nweight: 1\n---\n'
    with open(outfile, 'w') as f:
        f.write(header)
        files = next(os.walk(path))[2]
        non_md_files = [fname for fname in files if not fname.endswith('.md') and 'pingsweep' not in fname]
        if non_md_files:
            for fname in non_md_files:
                try:
                    f.write('------------------------------\n')
                    f.write(f'### {fname}\n\n')
                    with open(os.path.join(path, fname)) as i:
                        for line in i:
                            if not ('Status: 404' in line) and line.strip():
                                processed_line = line.rstrip().replace("#", "\\#").replace("=", "")
                                f.write(f'> {processed_line}  \n')
                except (IOError, UnicodeDecodeError):
                    f.write(f'Unviewable file {fname}\n')
        else:
            f.write('No results available for this tool.\n')
    print_success(f"Generated {outfile}")

def backup_file_hugo(filename: str, backup_mode: str) -> None:
    if os.path.exists(filename):
        if backup_mode == 'replace':
            subprocess.run(['mv', filename, f'{filename}.bak'], check=True)
        elif backup_mode == 'unique':
            timestamp = time.strftime('%Y-%m-%d-%H:%M', time.localtime())
            subprocess.run(['mv', filename, f'{filename}.{timestamp}.bak'], check=True)
        else:
            bak_file = f'{filename}.bak'
            if os.path.exists(bak_file):
                choice = input(f"{bak_file} exists. Replace? [y/n]: ") or 'n'
                if choice.lower() == 'y':
                    subprocess.run(['mv', filename, bak_file], check=True)
                else:
                    timestamp = time.strftime('%Y-%m-%d-%H:%M', time.localtime())
                    subprocess.run(['mv', filename, f'{filename}.{timestamp}.bak'], check=True)
            else:
                subprocess.run(['mv', filename, bak_file], check=True)
    alt_filename = filename.replace('_index.md', 'index.md') if '_index.md' in filename else filename.replace('index.md', '_index.md')
    if os.path.exists(alt_filename):
        bak_file = f'{alt_filename}.bak'
        subprocess.run(['mv', alt_filename, bak_file], check=True)

def update_hugo_structure(base_dir: str, dirname: str, backup_mode: str, hosts: Optional[List[Tuple[str, str, Optional[str]]]] = None) -> None:
    print_info("Starting Hugo structure update")
    hugo_dir = os.path.join(base_dir, dirname)
    ensure_directory(hugo_dir)
    
    try:
        for host, _, hostname in (hosts or []):
            host_dir = os.path.join(hugo_dir, hostname or host)
            if os.path.exists(host_dir) and any(os.path.getsize(f) > 0 for f in glob.glob(f"{host_dir}/**/*", recursive=True)):
                for subdir in ['nmaps', 'nuclei', 'feroxbuster']:
                    subdir_path = os.path.join(host_dir, subdir)
                    if os.path.exists(subdir_path) and glob.glob(f"{subdir_path}/*"):
                        write_leaf_hugo(subdir_path, backup_mode)
                write_branch_hugo(host_dir, dirname, backup_mode)
        write_branch_hugo(hugo_dir, dirname, backup_mode)
        print_success(f"Hugo structure updated in {hugo_dir}")
    except Exception as e:
        print_err(f"Failed to update Hugo structure for {dirname}: {str(e)}")

def process_hosts(args: argparse.Namespace, config: configparser.ConfigParser) -> Dict[str, List[Tuple[str, str, Optional[str]]]]:
    hosts_list = {}
    input_file = args.input_file or config.get('Input', 'input_file', fallback=None)
    input_host = args.input_host or config.get('Input', 'input_host', fallback=None)
    folder = args.folder or config.get('Input', 'folder', fallback=None)

    if input_host:
        hosts_list['hosts'] = [(h, o, None) for h, o in get_hosts(input_host, '.', True)]
    elif input_file:
        fname = os.path.splitext(os.path.basename(input_file))[0]
        hosts_list[fname] = [(h, o, None) for h, o in get_hosts(input_file)]
    elif folder:
        if not os.path.isdir(folder):
            print_err(f"Folder not found: {folder}")
            return {}
        for f in os.listdir(folder):
            if os.path.isfile(os.path.join(folder, f)):
                fname = os.path.splitext(f)[0]
                hosts_list[fname] = [(h, o, None) for h, o in get_hosts(f, folder)]
    else:
        print_err("No input source specified in command-line or autoscan.conf")
        sys.exit(1)

    return hosts_list

# New Modular Tool Classes
class Tool(ABC):
    name: str
    enabled_by_default: bool = False

    def __init__(self, config: configparser.ConfigParser):
        self.config = config
        self.enabled = self.enabled_by_default or config.getboolean('Scans', self.name.lower(), fallback=False)

    @abstractmethod
    def run(self, hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str, args: argparse.Namespace) -> Dict[str, Any]:
        """Run the tool and return results."""
        pass

    def is_enabled(self, args: argparse.Namespace) -> bool:
        """Check if the tool is enabled via args or config."""
        arg_value = getattr(args, self.name.lower(), False)
        no_arg = getattr(args, f"no_{self.name.lower()}", False)
        return (arg_value and not no_arg) or (not no_arg and self.enabled)

class NmapTool(Tool):
    name = "nmap"
    enabled_by_default = True

    def run(self, hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str, args: argparse.Namespace) -> Dict[str, Any]:
        print_info(f"Running {self.name} scan")
        ports = '-p1-65535' if args.full_scan else f'-p{args.ports}' if args.ports else f'--top-ports {args.top_ports}' if args.top_ports else '-p1-65535'
        if args.ping_only:
            print_info("Running ping-only scan")
            active, inactive = find_active_hosts(hosts, base_dir, dirname)
            write_hosts(active, base_dir, dirname, f"active-hosts-{dirname}.txt")
            write_hosts(active, base_dir, dirname, f"active-hosts-{dirname}.txt", checkpoint=True)
            return {"active_hosts": active, "inactive_hosts": inactive, "scanners": [], "webapps": []}
        scanners = nmap_scan(hosts, base_dir, dirname, ports, not args.udp, args.nmap_args)
        live_hosts = [(h, o, hn) for h, o, hn in hosts if any(h in nm.all_hosts() for nm in scanners)]
        write_hosts(live_hosts, base_dir, dirname, f"live-hosts-{dirname}.txt")
        webapps = find_web_apps(scanners)
        return {"active_hosts": live_hosts, "scanners": scanners, "webapps": webapps}

class SubfinderTool(Tool):
    name = "subfinder"
    enabled_by_default = False

    def run(self, hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str, args: argparse.Namespace) -> Dict[str, Any]:
        print_info(f"Running {self.name} scan")
        subfinder_file = f"subfinder-enum-{dirname}.txt"
        subfinder_enum(hosts, base_dir, dirname, subfinder_file)
        new_hosts = []
        if os.path.isfile(f"{base_dir}/{dirname}/{subfinder_file}"):
            new_hosts = [(h, o, None) for h, o in get_hosts(subfinder_file, f"{base_dir}/{dirname}")]
        return {"new_hosts": new_hosts}

class NucleiTool(Tool):
    name = "nuclei"
    enabled_by_default = False

    def run(self, hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str, args: argparse.Namespace) -> Dict[str, Any]:
        print_info(f"Running {self.name} scan")
        webapps = getattr(args, 'webapps', []) or [
            [host, 'http', hostname] for host, _, hostname in hosts if validate_input(host)
        ]
        if not webapps:
            print_info("No webapps to scan with Nuclei")
            return {"webapps": []}
        nuclei_test(webapps, base_dir, dirname, args.proxy, self.config)
        return {"webapps": webapps}

class FeroxbusterTool(Tool):
    name = "feroxbuster"
    enabled_by_default = False

    def run(self, hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str, args: argparse.Namespace) -> Dict[str, Any]:
        print_info(f"Running {self.name} scan")
        webapps = getattr(args, 'webapps', []) or [
            [host, 'http', hostname] for host, _, hostname in hosts if validate_input(host)
        ]
        if not webapps:
            print_info("No webapps to scan with Feroxbuster")
            return {"webapps": []}
        feroxbuster_test(webapps, base_dir, dirname, args.proxy, self.config)
        return {"webapps": webapps}

class HugoTool(Tool):
    name = "hugo"
    enabled_by_default = True

    def run(self, hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str, args: argparse.Namespace) -> Dict[str, Any]:
        print_info(f"Running {self.name} structure update")
        content = format_content_hugo(base_dir, dirname)
        update_hugo_structure(base_dir, dirname, args.hugo_backup, hosts)
        return {"content": content}

class ToolRegistry:
    def __init__(self, config: configparser.ConfigParser):
        self.tools = {
            'nmap': NmapTool(config),
            'subfinder': SubfinderTool(config),
            'nuclei': NucleiTool(config),
            'feroxbuster': FeroxbusterTool(config),
            'hugo': HugoTool(config),
        }

    def get_enabled_tools(self, args: argparse.Namespace) -> List[Tool]:
        return [tool for tool in self.tools.values() if tool.is_enabled(args)]

    def run_tools(self, hosts_list: Dict[str, List[Tuple[str, str, Optional[str]]]], base_dir: str, args: argparse.Namespace) -> Dict[str, Dict[str, Any]]:
        all_results = {}
        all_dir_content = {}
        for fname, hosts in hosts_list.items():
            results = {}
            current_hosts = hosts.copy()
            for tool in self.get_enabled_tools(args):
                print_info(f"Executing {tool.name} for {fname}")
                results[tool.name] = tool.run(current_hosts, base_dir, fname, args)
                # Chain outputs
                if tool.name == 'subfinder':
                    current_hosts.extend(results[tool.name].get('new_hosts', []))
                if tool.name == 'nmap':
                    args.webapps = results[tool.name].get('webapps', [])
                    if not args.no_ping and not args.ping_only:
                        current_hosts = results[tool.name].get('active_hosts', current_hosts)
                if tool.name == 'hugo':
                    all_dir_content[fname] = results[tool.name].get('content', '')
            all_results[fname] = results
            # Export JSON if requested
            if args.export_json:
                export_json_summary(current_hosts, base_dir, fname, args.export_json)
        # Write aggregated Hugo content
        if self.tools['hugo'].is_enabled(args) and all_dir_content:
            write_branch_hugo(base_dir, None, args.hugo_backup, all_dir_content)
            print_success("Aggregated all directory content into ./content/index.md")
        return all_results

def run_scans(args: argparse.Namespace, hosts_list: Dict[str, List[Tuple[str, str, Optional[str]]]], config: configparser.ConfigParser) -> None:
    unique_id = datetime.datetime.now().strftime('%Y-%m-%d-%H.%M.%S')
    base_dir = args.output_dir
    registry = ToolRegistry(config)
    registry.run_tools(hosts_list, base_dir, args)
    if args.compress:
        archive_name = f"{base_dir}/scan_results_{unique_id}.tar.gz"
        with tarfile.open(archive_name, "w:gz") as tar:
            for fname in hosts_list:
                tar.add(f"{base_dir}/{fname}", arcname=fname)
        print_success(f"Compressed output to {archive_name}")
    cleanup()

def main() -> None:
    global args, config
    config = configparser.ConfigParser()
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'autoscan.conf')
    if not os.path.exists(config_path):
        print_err("Configuration file 'autoscan.conf' not found")
        sys.exit(1)
    config.read(config_path)

    parser = argparse.ArgumentParser(
        prog='autoscan.py',
        description='Automate network scanning with modular tool execution',
        epilog='Example: python3 autoscan.py --input-host 192.168.1.1 --nmap --nuclei'
    )
    host_group = parser.add_mutually_exclusive_group()
    host_group.add_argument('-I', '--input-file', help='File with one host/CIDR per line')
    host_group.add_argument('-i', '--input-host', help='Single host or IP')
    host_group.add_argument('--folder', help='Directory containing multiple host files')

    # Tool flags
    for tool in ['nmap', 'subfinder', 'nuclei', 'feroxbuster', 'hugo']:
        parser.add_argument(f'--{tool}', action='store_true', help=f'Run {tool} tool')
        parser.add_argument(f'--no-{tool}', action='store_true', help=f'Disable {tool} tool')

    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('-p', '--ports', help='Nmap scan specific ports (e.g., 80,443,1000-2000)')
    port_group.add_argument('-P', '--top-ports', type=int, help='Nmap scan top X ports')
    port_group.add_argument('-f', '--full-scan', action='store_true', help='Nmap scan all ports')
    port_group.add_argument('-q', '--ping-only', action='store_true', help='Nmap ping scan only')

    parser.add_argument('-d', '--no-ping', action='store_true', help='Skip ping scan')
    parser.add_argument('-u', '--udp', action='store_true', help='Perform UDP scan')
    parser.add_argument('--proxy', help='Proxy for nuclei/feroxbuster (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--nmap-args', default=config.get('Nmap', 'nmap_args', fallback='-Pn -sV -O'), help='Custom Nmap arguments')
    parser.add_argument('--ping-args', default=config.get('Nmap', 'ping_args', fallback='-sn -PE -PP -PM'), help='Custom Nmap ping arguments')
    parser.add_argument('--compress', action='store_true', help='Compress output files')
    parser.add_argument('--export-json', help='Export scan summary to JSON file')
    parser.add_argument('--setup-hugo', action='store_true', help='Set up Hugo environment')
    parser.add_argument('--force-hugo', action='store_true', help='Force overwrite Hugo site')
    parser.add_argument('--output-dir', default=config.get('Output', 'output_dir', fallback='./content'), help='Output directory')
    parser.add_argument('--hugo-backup', choices=['ask', 'replace', 'unique'], default='ask', help='Backup mode for Hugo')

    args = parser.parse_args()

    # Validate ports
    if args.ports and not validate_ports(args.ports):
        parser.error("Invalid port format. Use comma-separated ports or ranges (e.g., 80,443,1000-2000)")

    # Validate proxy
    args.proxy = validate_proxy(args.proxy)

    # Setup Hugo if requested
    if args.setup_hugo or (args.hugo and not args.no_hugo):
        hugo_dir = config.get('Hugo', 'hugo_dir', fallback='./hugo_site')
        hugo_theme = config.get('Hugo', 'hugo_theme', fallback='https://github.com/matcornic/hugo-theme-learn.git')
        config_file = os.path.join(hugo_dir, "config.toml")
        themes_dir = os.path.join(hugo_dir, "themes")
        content_dir = os.path.join(hugo_dir, "content")
        if not (os.path.exists(config_file) or os.path.exists(themes_dir) or os.path.exists(content_dir)):
            print_info(f"No Hugo site found at {hugo_dir}. Setting up new Hugo environment...")
            setup_hugo_environment(hugo_dir, hugo_theme, force=args.force_hugo, non_interactive='--non-interactive' in sys.argv)
        else:
            print_info(f"Hugo site exists at {hugo_dir}. Skipping setup unless --force-hugo is used.")

    # Process hosts
    hosts_list = process_hosts(args, config)
    if not hosts_list:
        sys.exit(1)

    # Run scans
    run_scans(args, hosts_list, config)
    print_color("[+] All tasks completed successfully", PURPLE)

if __name__ == '__main__':
    main()
