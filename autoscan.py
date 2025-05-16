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
import socket
from typing import List, Optional, Tuple, Dict, Any
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

# Constants
ENDC = '\033[0;37;40m'
TEAL = '\033[1;36;40m'
GREEN = '\033[1;32;40m'
RED = '\033[1;31;40m'
PURPLE = '\033[1;35;40m'
NMAP_DEFAULT_ARGS = '-Pn -sV -O'
PING_DEFAULT_ARGS = '-sn -PE -PP -PM'
OUTPUT_DIR_DEFAULT = './content'
HUGO_DIR_DEFAULT = './hugo_site'
HUGO_THEME_DEFAULT = 'https://github.com/matcornic/hugo-theme-learn.git'

# Logging Setup
logger = logging.getLogger('autoscan')
logger.setLevel(logging.INFO)

class ColoredFormatter(logging.Formatter):
    """Formats log messages with colors based on level or success attribute."""
    def format(self, record):
        if record.levelno == logging.ERROR:
            msg = f"{RED}[-] {record.msg}{ENDC}"
        elif getattr(record, 'success', False):
            msg = f"{GREEN}[+] {record.msg}{ENDC}"
        else:
            msg = f"{TEAL}[*] {record.msg}{ENDC}"
        record.msg = msg
        return super().format(record)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(ColoredFormatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(console_handler)

log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'autoscan.log')
file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(file_handler)

def log_message(msg: str, level: str = 'info') -> None:
    """Logs a message with the specified level (info, success, error)."""
    if level == 'success':
        logger.info(msg, extra={'success': True})
    elif level == 'error':
        logger.error(msg)
    else:
        logger.info(msg)

# Utility Class
class ScanUtils:
    """Utility methods for scanning and file operations."""
    @staticmethod
    def ensure_directory(path: str) -> None:
        """Creates a directory with permissions if it doesn't exist."""
        try:
            os.makedirs(path, exist_ok=True)
            os.chmod(path, 0o755)
            log_message(f"Ensured directory exists: {path}", "info")
        except OSError as e:
            log_message(f"Failed to create directory {path}: {e}", "error")
            raise

    @staticmethod
    def install_tool(tool_name: str, install_cmd: str, apt_package: Optional[str] = None, fallback_cmd: Optional[str] = None) -> bool:
        """Installs a tool if not present, with fallback option."""
        if which(tool_name):
            return True
        log_message(f"{tool_name.capitalize()} is required. Install with: {install_cmd}", "error")
        if input(f"\033[1;35;40m[*] Install {tool_name} now? [y/n] \033[0;37;40m").lower() in ('y', ''):
            try:
                if apt_package:
                    subprocess.run(["sudo", "apt", "update"], check=True)
                    subprocess.run(["sudo", "apt", "install", "-y", apt_package], check=True)
                subprocess.run(install_cmd, shell=True, check=True)
                log_message(f"{tool_name.capitalize()} installed successfully.", "success")
                return True
            except subprocess.CalledProcessError as e:
                log_message(f"Failed to install {tool_name}: {str(e)}", "error")
                if fallback_cmd:
                    log_message(f"Attempting fallback: {fallback_cmd}", "info")
                    try:
                        subprocess.run(fallback_cmd, shell=True, check=True)
                        log_message(f"{tool_name.capitalize()} installed via fallback.", "success")
                        return True
                    except subprocess.CalledProcessError as e2:
                        log_message(f"Fallback failed: {str(e2)}", "error")
                return False
        log_message(f"Skipping {tool_name} scan.", "error")
        return False

    @staticmethod
    def validate_proxy(proxy: Optional[str]) -> Optional[str]:
        """Validates proxy format (http(s)://host:port)."""
        if not proxy:
            return None
        parsed = urlparse(proxy)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc:
            log_message("Invalid proxy format. Use http(s)://host:port", "error")
            return None
        return proxy

    @staticmethod
    def validate_ports(ports: str) -> bool:
        """Validates port specifications (e.g., 80,443,1000-2000)."""
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

    @staticmethod
    def validate_input(line: str) -> Tuple[str, str]:
        """Validates input as CIDR, range, IP, domain, or invalid."""
        line = line.strip()
        if '/' in line:
            try:
                ipaddress.ip_network(line, strict=False)
                return 'cidr', line
            except ValueError:
                pass
        elif '-' in line:
            try:
                start, end = line.split('-')
                ipaddress.ip_address(start.strip())
                ipaddress.ip_address(end.strip())
                return 'range', line
            except ValueError:
                pass
        try:
            ipaddress.ip_address(line)
            return 'ip', line
        except ValueError:
            pass
        parsed = urlparse(line if line.startswith(('http://', 'https://')) else f'http://{line}')
        domain = parsed.hostname
        if domain:
            domain_regex = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            if re.match(domain_regex, domain):
                return 'domain', domain
        return 'invalid', line

    @staticmethod
    def expand_network(input_str: str, input_type: str) -> List[Tuple[str, str]]:
        """Expands CIDR or IP range into individual IPs."""
        try:
            if input_type == 'cidr':
                network = ipaddress.ip_network(input_str, strict=False)
                log_message(f"Expanding CIDR: {input_str}", "info")
                return [(str(host), input_str) for host in network.hosts()]
            elif input_type == 'range':
                start, end = input_str.split('-')
                start_ip = ipaddress.ip_address(start.strip())
                end_ip = ipaddress.ip_address(end.strip())
                ips = []
                current = start_ip
                while current <= end_ip:
                    ips.append((str(current), input_str))
                    current = ipaddress.ip_address(int(current) + 1)
                log_message("Range expanded", "info")
                return ips
            return []
        except ValueError as e:
            log_message(f"Invalid {input_type} format: {input_str}", "error")
            return [(input_str, input_str)]

    @staticmethod
    def get_hosts(hosts_file: str, dirname: str = '.', single: bool = False) -> List[Tuple[str, str]]:
        """Parses host input file or single host, expanding CIDR/ranges."""
        try:
            lines = [hosts_file] if single else [x.rstrip() for x in open(os.path.join(dirname, hosts_file)).readlines()]
            hosts = set()
            for line in lines:
                input_type, value = ScanUtils.validate_input(line)
                if input_type == 'invalid':
                    log_message(f"Skipping invalid input: {line}", "error")
                    continue
                log_message(f"Processing {input_type}: {value}", "info")
                if input_type in ('cidr', 'range'):
                    hosts.update(ScanUtils.expand_network(value, input_type))
                elif input_type in ('ip', 'domain'):
                    hosts.add((value, line))
            log_message("Hosts list generated", "info")
            return list(hosts)
        except FileNotFoundError:
            log_message(f"Host file '{os.path.join(dirname, hosts_file)}' not found", "error")
            return []

    @staticmethod
    def write_hosts(hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str, filename: str, checkpoint: bool = False) -> None:
        """Writes host list to a file."""
        ScanUtils.ensure_directory(os.path.join(base_dir, dirname))
        suffix = ".tmp" if checkpoint else ""
        with open(os.path.join(base_dir, dirname, f"{filename}{suffix}"), 'w') as f:
            for host, _, hostname in hosts:
                f.write(f"{hostname or host}\n")

    @staticmethod
    def export_json_summary(hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str, output_file: str) -> None:
        """Exports scan summary to JSON."""
        ScanUtils.ensure_directory(os.path.dirname(output_file) if os.path.dirname(output_file) else base_dir)
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
                log_message(f"No CSV files found for {host}", "error")
            summary.append({"host": host, "hostname": hostname, "ports": list(set(ports))})
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
        log_message(f"Exported JSON summary to {output_file}", "success")

    @staticmethod
    def cleanup() -> None:
        """Restores file ownership after scanning."""
        log_message("Cleaning up...", "info")
        stat_info = os.stat('.')
        uid = stat_info.st_uid
        gid = stat_info.st_gid
        user = pwd.getpwuid(uid)[0]
        group = grp.getgrgid(gid)[0]
        try:
            subprocess.run(["chown", "-R", f"{user}:{group}", "."], check=True)
            log_message("All clean!", "info")
        except subprocess.CalledProcessError:
            log_message("Failed to change file ownership", "error")

    @staticmethod
    def run_threaded(tasks: List[Tuple[callable, Any]], max_workers: int, desc: str = "Processing") -> List[Any]:
        """Runs tasks concurrently with ThreadPoolExecutor."""
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_task = {executor.submit(task[0], *task[1]): task for task in tasks}
            for future in tqdm(as_completed(future_to_task), total=len(tasks), desc=desc):
                try:
                    results.append(future.result())
                except Exception as e:
                    task = future_to_task[future]
                    log_message(f"Task {task[0].__name__} failed: {str(e)}", "error")
        return results

# Tool Classes
class Tool(ABC):
    """Base class for scanning tools."""
    name: str
    enabled_by_default: bool = False

    def __init__(self, config: configparser.ConfigParser, args: argparse.Namespace):
        self.config = config
        self.args = args
        self.enabled = self.enabled_by_default or config.getboolean('Scans', self.name.lower(), fallback=False)

    @abstractmethod
    def run(self, hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str) -> Dict[str, Any]:
        """Runs the tool and returns results."""
        pass

    def is_enabled(self) -> bool:
        """Checks if the tool is enabled via args or config."""
        arg_value = getattr(self.args, self.name.lower(), False)
        no_arg = getattr(self.args, f"no_{self.name.lower()}", False)
        enabled = (arg_value and not no_arg) or (not no_arg and self.enabled)
        log_message(f"Tool {self.name} enabled: {enabled}", "info")
        return enabled

class NmapTool(Tool):
    name = "nmap"
    enabled_by_default = True

    def create_host_directory(self, base_dir: str, dirname: str, host: str, hostname: Optional[str] = None) -> str:
        """Creates a directory for a host, prioritizing hostname, keeping dots."""
        host_dir = (hostname or host).replace('/', '-').replace(':', '-')
        if not hostname and ScanUtils.validate_input(host)[0] == 'ip':
            log_message(f"Using IP {host} for directory; expected hostname, check input", "error")
        full_path = os.path.join(base_dir, dirname, host_dir)
        ScanUtils.ensure_directory(full_path)
        log_message(f"Created host directory: {full_path}", "info")
        return host_dir

    def scan_host_status(self, host: str, base_dir: str, dirname: str, hostname: Optional[str] = None, retries: int = 3) -> Tuple[List[Tuple[str, str]], Optional[str]]:
        """Performs a ping scan to check host status."""
        host_dir = self.create_host_directory(base_dir, dirname, host, hostname)
        scan_args = f'{self.args.ping_args} -oN {base_dir}/{dirname}/{host_dir}/{host_dir}-pingsweep.nmap'
        log_message(f"Scanning {host} with arguments: {scan_args} (dir: {host_dir})", "info")
        
        nm = nmap.PortScanner()
        scan_host = host
        for attempt in range(retries):
            try:
                nm.scan(hosts=scan_host, arguments=scan_args)
                scanned_hosts = nm.all_hosts()
                log_message(f"Scan results for {host}: {scanned_hosts}", "info")
                resolved_hostname = None
                for scanned_host in scanned_hosts:
                    if scanned_host == scan_host or nm[scanned_host].hostname() == scan_host:
                        resolved_hostname = nm[scanned_host].hostname() or hostname or scan_host
                        return [(scan_host, nm[scanned_host]['status']['state'])], resolved_hostname
                log_message(f"Host {scan_host} not found in scan results: {scanned_hosts}", "error")
                return [], None
            except Exception as e:
                log_message(f"Scan failed for {host} (attempt {attempt+1}/{retries}): {str(e)}", "error")
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                else:
                    log_message(f"Max retries reached for {host}, skipping", "error")
                    return [], None

    def find_active_hosts(self, hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str) -> Tuple[List[Tuple[str, str, Optional[str]]], List[Tuple[str, str, Optional[str]]]]:
        """Identifies active hosts via ping scans."""
        log_message("Finding active hosts", "info")
        active_hosts = []
        inactive_hosts = hosts.copy()
        max_workers = min(self.config.getint('Tools', 'nmap_threads', fallback=8), len(hosts))

        tasks = [(self.scan_host_status, (host, base_dir, dirname, hostname, self.config.getint('Nmap', 'retries', fallback=3))) for host, _, hostname in hosts]
        results = ScanUtils.run_threaded(tasks, max_workers, "Scanning hosts")

        for (host, original, hostname), (scanned_hosts, resolved_hostname) in zip(hosts, results):
            if not scanned_hosts:
                log_message(f"No scan results for {host}, marking as inactive", "error")
                continue
            for host_name, status in scanned_hosts:
                if status == 'up':
                    active_hosts.append((host_name, original, resolved_hostname or hostname))
                    if (host_name, original, hostname) in inactive_hosts:
                        inactive_hosts.remove((host_name, original, hostname))

        return active_hosts, inactive_hosts

    def scan_ports(self, hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str, top_ports: str, tcp: bool) -> List[nmap.PortScanner]:
        """Performs Nmap port scans on active hosts."""
        log_message("Starting nmap scans", "info")
        nms = []
        ScanUtils.ensure_directory(os.path.join(base_dir, dirname))
        max_workers = min(self.config.getint('Tools', 'nmap_threads', fallback=8), len(hosts))

        def scan_single_host(host, original, hostname):
            nm = nmap.PortScanner()
            host_dir = self.create_host_directory(base_dir, dirname, host, hostname)
            nmaps_dir = os.path.join(base_dir, dirname, host_dir, 'nmaps')
            ScanUtils.ensure_directory(nmaps_dir)
            log_message(f"Ensured nmaps directory: {nmaps_dir}", "info")
            scan_type = "" if tcp else "-udp"
            port_slug = top_ports.replace(',', '_').replace(' ', '').replace('-', '')
            target = (hostname or host).replace('/', '-').replace(':', '-')
            output_base = f"{base_dir}/{dirname}/{host_dir}/nmaps/{target}{scan_type}-scan-{port_slug}"
            args_list = self.args.nmap_args.split()
            sanitized_args = [arg for arg in args_list if not arg.startswith('-p') and arg != '-sn']
            args = f"{' '.join(sanitized_args)} {top_ports} -oN {output_base}.nmap"

            for attempt in range(self.config.getint('Nmap', 'retries', fallback=3)):
                try:
                    nm.scan(host, arguments=args)
                    csv_data = nm.csv()
                    log_message(f"Raw CSV for {host}: {csv_data[:200]}...", "info")
                    with open(f"{output_base}.csv", 'w') as f:
                        f.write(csv_data)
                    log_message(f"Completed scan for {host}", "success")
                    return nm
                except nmap.PortScannerError as e:
                    log_message(f"Port scan for {host} failed (attempt {attempt+1}/{retries}): {str(e)}", "error")
                    if attempt < retries - 1:
                        time.sleep(2 ** attempt)
                    else:
                        log_message(f"Max retries reached for {host}, skipping", "error")
                        return None

        tasks = [(scan_single_host, (host, original, hostname)) for host, original, hostname in hosts]
        nms = [result for result in ScanUtils.run_threaded(tasks, max_workers, "Scanning hosts") if result]
        log_message("Completed nmap scans", "success")
        return nms

    def find_web_apps(self, nms: List[nmap.PortScanner]) -> List[List[str]]:
        """Identifies web applications from Nmap scan results, using hostname as host."""
        web_apps = []
        log_message("Discovering web apps", "info")
        for nm in nms:
            for host in nm.all_hosts():
                hostname = nm[host].hostname() or host
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    if 80 in ports:
                        log_message(f"Found web app on port 80 of {hostname}", "success")
                        web_apps.append([hostname, 'http', hostname])
                    if 443 in ports:
                        log_message(f"Found web app on port 443 of {hostname}", "success")
                        web_apps.append([hostname, 'https', hostname])
        return web_apps

    def run(self, hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str) -> Dict[str, Any]:
        """Runs Nmap scans, filtering active hosts and identifying web apps."""
        log_message("Running nmap scan", "info")
        ports = '-p1-65535' if self.args.full_scan else f'-p{self.args.ports}' if self.args.ports else f'--top-ports {self.args.top_ports}' if self.args.top_ports else '-p1-65535'
        if self.args.ping_only:
            log_message("Running ping-only scan", "info")
            active_hosts, inactive_hosts = self.find_active_hosts(hosts, base_dir, dirname)
            ScanUtils.write_hosts(active_hosts, base_dir, dirname, f"active-hosts-{dirname}.txt")
            ScanUtils.write_hosts(active_hosts, base_dir, dirname, f"active-hosts-{dirname}.txt", checkpoint=True)
            return {"active_hosts": active_hosts, "inactive_hosts": inactive_hosts, "scanners": [], "webapps": []}
        
        active_hosts, _ = self.find_active_hosts(hosts, base_dir, dirname) if not self.args.no_ping else (hosts, [])
        scanners = self.scan_ports(active_hosts, base_dir, dirname, ports, not self.args.udp)
        live_hosts = []
        for h, o, hn in active_hosts:
            found = False
            for nm in scanners:
                if h in nm.all_hosts():
                    found = True
                    break
                for scanned_host in nm.all_hosts():
                    if nm[scanned_host].hostname() == h:
                        found = True
                        break
                if found:
                    break
            if found:
                live_hosts.append((h, o, hn or h))
            else:
                log_message(f"Host {h} not found in port scan results, skipping", "info")
        ScanUtils.write_hosts(live_hosts, base_dir, dirname, f"live-hosts-{dirname}.txt")
        webapps = self.find_web_apps(scanners)
        log_message(f"Web apps detected: {webapps}", "info")
        return {"active_hosts": live_hosts, "scanners": scanners, "webapps": webapps}

class SubfinderTool(Tool):
    name = "subfinder"
    enabled_by_default = False

    def enumerate(self, hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str, subfinder_file: str) -> None:
        """Performs Subfinder enumeration for domains."""
        if not ScanUtils.install_tool("subfinder", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && sudo cp ~/go/bin/subfinder /usr/local/bin/"):
            return
        log_message("Starting Subfinder enumeration", "info")
        output_file = f"{base_dir}/{dirname}/{subfinder_file}"
        max_workers = self.config.getint('Tools', 'subfinder_threads', fallback=4)

        def run_subfinder(domain, temp_output):
            cmd = ["subfinder", "-silent", "-o", temp_output, "-d", domain]
            try:
                subprocess.run(cmd, check=True, timeout=300)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                log_message(f"Subfinder failed for {domain}: {str(e)}", "error")

        tasks = [(run_subfinder, (host[0], f"{base_dir}/{dirname}/subfinder_temp_{i}.txt")) for i, host in enumerate(hosts) if ScanUtils.validate_input(host[0])[0] == 'domain']
        ScanUtils.run_threaded(tasks, max_workers, "Enumerating domains")

        with open(output_file, 'w') as outfile:
            for i in range(len(hosts)):
                temp_file = f"{base_dir}/{dirname}/subfinder_temp_{i}.txt"
                if os.path.exists(temp_file):
                    with open(temp_file, 'r') as infile:
                        outfile.write(infile.read())
                    os.remove(temp_file)
        log_message("Completed Subfinder enumeration", "success")

    def run(self, hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str) -> Dict[str, Any]:
        """Runs Subfinder to enumerate subdomains."""
        log_message("Running subfinder scan", "info")
        subfinder_file = f"subfinder-enum-{dirname}.txt"
        self.enumerate(hosts, base_dir, dirname, subfinder_file)
        new_hosts = []
        if os.path.isfile(f"{base_dir}/{dirname}/{subfinder_file}"):
            new_hosts = [(h, o, None) for h, o in ScanUtils.get_hosts(subfinder_file, f"{base_dir}/{dirname}")]
        return {"new_hosts": new_hosts}

class NucleiTool(Tool):
    name = "nuclei"
    enabled_by_default = False

    def scan(self, web_apps: List[List[str]], base_dir: str, dirname: str) -> None:
        """Performs Nuclei scans on web applications."""
        snap_cmd = "sudo apt install -y snapd && sudo snap install nuclei"
        binary_cmd = "git clone https://github.com/projectdiscovery/nuclei.git /tmp/nuclei && cd /tmp/nuclei && go build -o nuclei ./cmd/nuclei && sudo mv nuclei /usr/local/bin/ && sudo chmod +x /usr/local/bin/nuclei && cd - && rm -rf /tmp/nuclei"
        if not ScanUtils.install_tool("nuclei", snap_cmd, apt_package="snapd", fallback_cmd=binary_cmd):
            return
        log_message("Starting Nuclei scans", "info")
        concurrency = self.config.get('Tools', 'nuclei_concurrency', fallback='50')
        max_workers = self.config.getint('Tools', 'nuclei_threads', fallback=4)

        def run_nuclei(host, protocol, hostname):
            target = hostname or host
            if ScanUtils.validate_input(target)[0] == 'ip':
                log_message(f"IP {target} used as target for Nuclei; expected hostname", "error")
            host_dir = NmapTool(self.config, self.args).create_host_directory(base_dir, dirname, target, hostname=hostname)
            nuclei_dir = os.path.join(base_dir, dirname, host_dir, 'nuclei')
            ScanUtils.ensure_directory(nuclei_dir)
            output_file = f"{nuclei_dir}/nuclei-results-{target.replace('/', '-').replace(':', '-')}-{protocol}.txt"
            cmd = ["nuclei", "-u", f"{protocol}://{target}", "-o", output_file, "-silent", "-c", concurrency]
            if self.args.proxy:
                cmd.extend(["-proxy", self.args.proxy])
            log_message(f"Running Nuclei against {protocol}://{target} (dir: {host_dir})", "info")
            try:
                subprocess.run(cmd, check=True)
                log_message(f"Completed Nuclei scan for {protocol}://{target}", "success")
            except subprocess.CalledProcessError:
                log_message(f"Nuclei scan failed for {protocol}://{target}", "error")

        tasks = [(run_nuclei, (host, protocol, hostname)) for host, protocol, hostname in web_apps]
        ScanUtils.run_threaded(tasks, max_workers, "Scanning web apps")

    def run(self, hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str) -> Dict[str, Any]:
        """Runs Nuclei scans on detected web applications."""
        log_message("Running nuclei scan", "info")
        webapps = getattr(self.args, 'webapps', [])
        if not webapps:
            log_message("No webapps provided by Nmap; skipping fallback", "info")
            return {"webapps": []}
        log_message(f"Nuclei web apps: {webapps}", "info")
        self.scan(webapps, base_dir, dirname)
        return {"webapps": webapps}

class FeroxbusterTool(Tool):
    name = "feroxbuster"
    enabled_by_default = False

    def scan(self, web_apps: List[List[str]], base_dir: str, dirname: str) -> None:
        """Performs Feroxbuster scans on web applications."""
        snap_cmd = "sudo apt install -y snapd && sudo snap install feroxbuster --classic"
        binary_cmd = "git clone https://github.com/epi052/feroxbuster.git /tmp/feroxbuster && cd /tmp/feroxbuster && cargo build --release && sudo mv target/release/feroxbuster /usr/local/bin/ && sudo chmod +x /usr/local/bin/feroxbuster && cd - && rm -rf /tmp/feroxbuster"
        if not ScanUtils.install_tool("feroxbuster", snap_cmd, apt_package="snapd", fallback_cmd=binary_cmd):
            return
        log_message("Starting Feroxbuster scans", "info")
        wordlist = self.config.get('Tools', 'wordlist', fallback='~/snap/feroxbuster/common/raft-small-directories-lowercase.txt')
        if not os.path.exists(wordlist):
            try:
                subprocess.run(["wget", "https://raw.githubusercontent.com/Averroes/raft/master/data/wordlists/raft-small-directories-lowercase.txt", "-O", os.path.expanduser(wordlist)], check=True)
                log_message(f"Downloaded wordlist to {wordlist}", "success")
            except subprocess.CalledProcessError:
                log_message("Failed to download wordlist. Skipping feroxbuster.", "error")
            return
        threads = self.config.get('Tools', 'feroxbuster_threads', fallback='20')
        max_workers = self.config.getint('Tools', 'feroxbuster_parallel_threads', fallback=4)

        def run_feroxbuster(host, protocol, hostname):
            target = hostname or host
            if ScanUtils.validate_input(target)[0] == 'ip':
                log_message(f"IP {target} used as target for Feroxbuster; expected hostname", "error")
            host_dir = NmapTool(self.config, self.args).create_host_directory(base_dir, dirname, target, hostname=hostname)
            feroxbuster_dir = os.path.join(base_dir, dirname, host_dir, 'feroxbuster')
            ScanUtils.ensure_directory(feroxbuster_dir)
            output_file = f"{feroxbuster_dir}/feroxbuster-results-{target.replace('/', '-').replace(':', '-')}-{protocol}.txt"
            cmd = ["feroxbuster", "-u", f"{protocol}://{target}", "-w", wordlist, "-o", output_file, "--silent", "-t", threads]
            if self.args.proxy:
                cmd.extend(["-proxy", self.args.proxy])
            log_message(f"Running Feroxbuster against {protocol}://{target} (dir: {host_dir})", "info")
            try:
                subprocess.run(cmd, check=True)
                log_message(f"Completed Feroxbuster scan for {protocol}://{target}", "success")
            except subprocess.CalledProcessError:
                log_message(f"Feroxbuster scan failed for {protocol}://{target}", "error")

        tasks = [(run_feroxbuster, (host, protocol, hostname)) for host, protocol, hostname in web_apps]
        ScanUtils.run_threaded(tasks, max_workers, "Scanning web apps")

    def run(self, hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str) -> Dict[str, Any]:
        """Runs Feroxbuster scans on detected web applications."""
        log_message("Running feroxbuster scan", "info")
        webapps = getattr(self.args, 'webapps', [])
        if not webapps:
            log_message("No webapps provided by Nmap; skipping fallback", "info")
            return {"webapps": []}
        log_message(f"Feroxbuster web apps: {webapps}", "info")
        self.scan(webapps, base_dir, dirname)
        return {"webapps": webapps}

class HugoTool(Tool):
    name = "hugo"
    enabled_by_default = True

    def setup_environment(self, hugo_dir: str, theme_url: str, force: bool = False, non_interactive: bool = False) -> None:
        """Sets up a Hugo environment for scan results."""
        log_message(f"Setting up Hugo environment in {hugo_dir}", "info")
        ScanUtils.ensure_directory(hugo_dir)
        if not ScanUtils.install_tool("hugo", "sudo apt install -y snapd && sudo snap install hugo", apt_package="snapd", 
                                     fallback_cmd="git clone https://github.com/gohugoio/hugo.git /tmp/hugo && cd /tmp/hugo && go build -tags extended && sudo mv hugo /usr/local/bin/ && sudo chmod +x /usr/local/bin/hugo && cd - && rm -rf /tmp/hugo"):
            log_message("Hugo setup aborted due to installation failure.", "error")
            return
        if os.path.exists(os.path.join(hugo_dir, "config.toml")) and not force:
            if non_interactive:
                log_message("Non-interactive mode: Skipping Hugo setup.", "info")
                return
            if input(f"\033[1;35;40m[*] Hugo site exists at {hugo_dir}. Overwrite? [y/n] \033[0;37;40m").lower() != 'y':
                log_message("Skipping Hugo setup to preserve existing site.", "info")
                return
        try:
            subprocess.run(["hugo", "new", "site", hugo_dir], check=True, capture_output=True)
            theme_name = theme_url.split('/')[-1].replace('.git', '')
            subprocess.run(["git", "clone", theme_url, os.path.join(hugo_dir, "themes", theme_name)], check=True, capture_output=True)
            with open(os.path.join(hugo_dir, "config.toml"), 'w') as f:
                f.write(f"baseURL = 'http://example.org/'\nlanguageCode = 'en-us'\ntitle = 'Autoscan Results'\ntheme = '{theme_name}'")
            log_message(f"Configured Hugo site with theme {theme_name}", "success")
        except subprocess.CalledProcessError as e:
            log_message(f"Failed to set up Hugo: {str(e)}", "error")

    def format_hosts(self, path: str) -> str:
        """Formats host directories as Hugo Markdown links."""
        log_message(f"Formatting hosts for path: {path}", "info")
        try:
            dirs = next(os.walk(path))[1]
            log_message(f"Host directories found: {dirs}", "info")
            domains = sorted(dirs)
            return ''.join(f'[{domain}]({domain})  \n' for domain in domains)
        except StopIteration:
            log_message(f"Failed to read directory: {path}", "error")
            return ''

    def format_stats(self, path: str) -> str:
        """Formats scan statistics for Hugo Markdown."""
        log_message(f"Formatting stats for path: {path}", "info")
        fmt = ''
        try:
            dirs, files = next(os.walk(path))[1:3]
            files = [f for f in files if not f.endswith('.md')]
            log_message(f"Found directories: {dirs}, files: {files}", "info")

            if 'nmaps' in dirs:
                nmap_path = os.path.join(path, 'nmaps')
                try:
                    nmap_files = [f for f in next(os.walk(nmap_path))[2] if f.endswith('.csv')]
                    log_message(f"Nmap files found: {nmap_files}", "info")
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
                            except (IOError, UnicodeDecodeError) as e:
                                log_message(f"Error reading {fname}: {e}", "error")
                        fmt += '\n[Full Nmap Results](nmaps)\n'
                except StopIteration:
                    log_message(f"Failed to access nmaps directory: {nmap_path}", "error")

            if 'nuclei' in dirs:
                fmt += '''
### Nuclei Summary
'''
                nuclei_path = os.path.join(path, 'nuclei')
                findings = []
                total_findings = 0
                try:
                    nuclei_files = [f for f in next(os.walk(nuclei_path))[2] if f.endswith('.txt')]
                    log_message(f"Nuclei files found: {nuclei_files}", "info")
                    for fname in nuclei_files:
                        try:
                            with open(os.path.join(nuclei_path, fname), 'r', encoding='utf-8') as f:
                                lines = [l.rstrip() for l in f if l.strip()]
                            total_findings += len(lines)
                            for line in lines:
                                if any(sev in line for sev in ['[critical]', '[high]', '[moderate]']):
                                    findings.append(line)
                        except (IOError, UnicodeDecodeError) as e:
                            log_message(f"Error reading {fname}: {e}", "error")
                    fmt += f'Found {total_findings} total findings.\n'
                    if findings:
                        fmt += '\n**Critical/High/Moderate Findings:**\n'
                        fmt += '\n'.join(f'- {l}' for l in findings[:5]) + '\n'
                    fmt += '\n[Full Nuclei Results](nuclei)\n'
                except StopIteration:
                    log_message(f"Failed to access nuclei directory: {nuclei_path}", "error")

            if 'feroxbuster' in dirs:
                fmt += '''
### Feroxbuster Summary
| Path | Status | Size |
|---------------|--------|------|
'''
                feroxbuster_path = os.path.join(path, 'feroxbuster')
                try:
                    feroxbuster_files = [f for f in next(os.walk(feroxbuster_path))[2] if f.endswith('.txt')]
                    log_message(f"Feroxbuster files found: {feroxbuster_files}", "info")
                    for fname in feroxbuster_files:
                        try:
                            with open(os.path.join(feroxbuster_path, fname), 'r', encoding='utf-8') as f:
                                for line in f:
                                    if line.strip() and ('200' in line or '301' in line):
                                        parts = line.strip().split()
                                        if len(parts) >= 3:
                                            status, path, size = parts[0], parts[1], parts[2]
                                            fmt += f'| {path} | {status} | {size} |\n'
                        except (IOError, UnicodeDecodeError) as e:
                            log_message(f"Error reading {fname}: {e}", "error")
                    fmt += '\n[Full Feroxbuster Results](feroxbuster)\n'
                except StopIteration:
                    log_message(f"Failed to access feroxbuster directory: {feroxbuster_path}", "error")

            return fmt if fmt.strip() else '\nNo scan results available.\n'
        except StopIteration:
            log_message(f"Failed to process stats for {path}", "error")
            return '\nNo scan results available.\n'

    def format_content(self, hugo_dir: str, dirname: str) -> str:
        """Formats host scan results as a Hugo Markdown table."""
        log_message(f"Formatting content for directory: {hugo_dir}, dirname: {dirname}", "info")
        fmt = f'## Hosts in {dirname}\n\n'
        fmt += '''
| Hostname | IP | Ports |
|----------|----------|----------|
'''
        rows = []
        scan_dir = os.path.join(hugo_dir, dirname)
        log_message(f"Processing scan directory: {scan_dir}", "info")
        try:
            host_dirs = next(os.walk(scan_dir))[1]
            log_message(f"Host directories found: {host_dirs}", "info")
            if not host_dirs:
                log_message(f"No host directories found in {scan_dir}.", "error")
                return fmt + '| No hosts scanned | - | - |\n\n'

            for hdir in host_dirs:
                log_message(f"Processing host directory: {hdir}", "info")
                csv_path = os.path.join(scan_dir, hdir, 'nmaps')
                try:
                    csv_files = [f for f in next(os.walk(csv_path))[2] if f.endswith('.csv')]
                    log_message(f"CSV files in {csv_path}: {csv_files}", "info")
                    if not csv_files:
                        log_message(f"No CSV files found in {csv_path}.", "error")
                        continue

                    seen_ports = set()
                    ip = hostname = ''
                    for fname in csv_files:
                        try:
                            with open(os.path.join(csv_path, fname)) as f:
                                lines = f.readlines()
                            if not lines:
                                log_message(f"CSV file {fname} is empty.", "error")
                                continue
                            if lines[0].startswith('host;'):
                                lines = lines[1:]
                            for line in lines:
                                line = line.rstrip()
                                if not line:
                                    continue
                                parts = line.split(';')
                                if len(parts) < 5 or not parts[0]:
                                    continue
                                if not parts[4] or not parts[4].isdigit():
                                    continue
                                ip = parts[0]
                                hostname = parts[1] or hdir
                                port = parts[4]
                                seen_ports.add(port)
                        except (IOError, UnicodeDecodeError) as e:
                            log_message(f"Error reading {fname}: {e}", "error")
                    if hostname and seen_ports:
                        rows.append([hostname, ip or 'N/A', ' '.join(sorted(seen_ports))])
                    elif hostname:
                        rows.append([hostname, ip or 'N/A', 'none'])
                except StopIteration:
                    log_message(f"Failed to access nmaps directory: {csv_path}", "error")
                    continue

            if not rows:
                log_message(f"No valid scan data found in {scan_dir}.", "error")
                return fmt + '| No valid scan data | - | - |\n\n'

            rows.sort(key=lambda x: x[0])
            for hostname, ip, ports in rows:
                dir_name = hostname
                hn_link = f'[{hostname}]({dirname}/{dir_name})' if os.path.exists(os.path.join(hugo_dir, dirname, dir_name)) else hostname
                ip_display = ip if ip != 'N/A' else '-'
                fmt += f'| {hn_link} | {ip_display} | {ports} |  \n'
            return fmt + '\n'
        except StopIteration:
            log_message(f"Failed to access scan directory: {scan_dir}", "error")
            return fmt + '| No scan directories found | - | - |\n\n'

    def backup_file(self, filename: str, backup_mode: str) -> None:
        """Backs up a Hugo file based on the specified mode."""
        log_message(f"Backing up file: {filename} with mode: {backup_mode}", "info")
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
            subprocess.run(['mv', alt_filename, f'{alt_filename}.bak'], check=True)
        log_message(f"Backup completed for {filename}", "info")

    def write_branch(self, path: str, dirname: str, backup_mode: str, all_dir_content: Optional[Dict[str, str]] = None) -> None:
        """Writes a Hugo branch page (index or _index.md)."""
        log_message(f"Writing branch page for path: {path}, dirname: {dirname}", "info")
        title = os.path.basename(path) or 'content'
        index_filename = '_index.md' if title != 'content' else 'index.md'
        outfile = os.path.join(path, index_filename)
        self.backup_file(outfile, backup_mode)
        header = f'---\ntitle: {title}\ndraft: false\n'
        if title == 'content':
            header += 'chapter: true\n'
        header += '---\n'

        if title == 'content' and all_dir_content:
            content = '\n'.join(all_dir_content.values()) or '\nNo scan results available across all directories.\n'
        elif os.path.basename(path) not in ['content', dirname]:
            content = self.format_stats(path)
            if not content.strip():
                content = '\nNo scan results available.\n'
        else:
            content = self.format_stats(path) if title != 'content' and title != dirname else self.format_content(path, dirname) if title == 'content' else self.format_hosts(path)
            if not content.strip():
                content += '\nNo scan results available.\n'

        if '|' in content:
            lines = content.split('\n')
            table_lines = [l for l in lines if l.strip().startswith('|')]
            if table_lines:
                header_row = table_lines[0]
                separator_row = table_lines[1] if len(table_lines) > 1 else ''
                if not separator_row or not all(c in '-| ' for c in separator_row.replace('|', '')):
                    log_message(f"Invalid table in {outfile}. Adding separator row.", "error")
                    lines.insert(lines.index(header_row) + 1, '| ' + '--- |' * (header_row.count('|') - 1))
                    content = '\n'.join(lines)

        try:
            with open(outfile, 'w') as f:
                f.write(header + content)
            log_message(f"Generated branch page: {outfile}", "success")
        except Exception as e:
            log_message(f"Failed to write branch page {outfile}: {str(e)}", "error")
            raise

    def write_leaf(self, path: str, backup_mode: str) -> None:
        """Writes a Hugo leaf page (index.md) for tool results."""
        log_message(f"Writing leaf page for path: {path}", "info")
        title = os.path.basename(path)
        outfile = os.path.join(path, 'index.md')
        self.backup_file(outfile, backup_mode)
        header = f'---\ntitle: {title}\ndraft: false\n---\n'
        content = ''
        try:
            files = next(os.walk(path))[2]
            log_message(f"Files found in {path}: {files}", "info")
            non_md_files = [fname for fname in files if not fname.endswith('.md') and 'pingsweep' not in fname]
            if non_md_files:
                for fname in non_md_files:
                    try:
                        content += '------------------------------\n'
                        content += f'### {fname}\n\n'
                        with open(os.path.join(path, fname)) as i:
                            for line in i:
                                if not ('Status: 404' in line) and line.strip():
                                    processed_line = line.rstrip().replace("#", "\\#").replace("=", "")
                                    content += f'> {processed_line}  \n'
                    except (IOError, UnicodeDecodeError) as e:
                        content += f'Unviewable file {fname}\n'
                        log_message(f"Error reading {fname}: {e}", "error")
            else:
                content += f'No results available for {title}.\n'
            with open(outfile, 'w') as f:
                f.write(header + content)
            log_message(f"Generated leaf page: {outfile}", "success")
        except Exception as e:
            log_message(f"Failed to write leaf page {outfile}: {str(e)}", "error")
            raise

    def update_structure(self, base_dir: str, dirname: str, backup_mode: str, hosts: Optional[List[Tuple[str, str, Optional[str]]]] = None) -> None:
        """Updates Hugo site structure with scan results."""
        log_message(f"Starting Hugo structure update for base_dir: {base_dir}, dirname: {dirname}, hosts: {hosts}", "info")
        hugo_dir = os.path.join(base_dir, dirname)
        ScanUtils.ensure_directory(hugo_dir)
        try:
            host_dirs = [d for d in next(os.walk(hugo_dir))[1] if d not in ['nmaps', 'nuclei', 'feroxbuster']]
            log_message(f"Found host directories: {host_dirs}", "info")
            
            if not hosts:
                hosts = [(d, d, d) for d in host_dirs]
            else:
                hosts = [(host, original, hostname or host) for host, original, hostname in hosts]

            for host, _, hostname in hosts:
                host_dir = os.path.join(hugo_dir, hostname)
                log_message(f"Checking host directory: {host_dir} (exists: {os.path.exists(host_dir)})", "info")
                if not os.path.exists(host_dir):
                    log_message(f"Host directory {host_dir} does not exist, creating", "info")
                    ScanUtils.ensure_directory(host_dir)

                subdirs = ['nmaps', 'nuclei', 'feroxbuster']
                log_message(f"Processing subdirectories: {subdirs}", "info")
                for subdir in subdirs:
                    subdir_path = os.path.join(host_dir, subdir)
                    log_message(f"Checking subdirectory: {subdir_path} (exists: {os.path.exists(subdir_path)})", "info")
                    ScanUtils.ensure_directory(subdir_path)
                    self.write_leaf(subdir_path, backup_mode)

                self.write_branch(host_dir, dirname, backup_mode)

            self.write_branch(hugo_dir, dirname, backup_mode)
            log_message(f"Hugo structure updated in {hugo_dir}", "success")
        except Exception as e:
            log_message(f"Failed to update Hugo structure for {dirname}: {str(e)}", "error")
            raise

    def run(self, hosts: List[Tuple[str, str, Optional[str]]], base_dir: str, dirname: str) -> Dict[str, Any]:
        """Generates Hugo site with scan results."""
        log_message(f"Running Hugo structure update for base_dir: {base_dir}, dirname: {dirname}, hosts: {hosts}", "info")
        content = self.format_content(base_dir, dirname)
        self.update_structure(base_dir, dirname, self.args.hugo_backup, hosts)
        return {"content": content}

class ToolRegistry:
    """Manages scanning tools and their execution."""
    def __init__(self, config: configparser.ConfigParser, args: argparse.Namespace):
        self.tools = {
            'nmap': NmapTool(config, args),
            'subfinder': SubfinderTool(config, args),
            'nuclei': NucleiTool(config, args),
            'feroxbuster': FeroxbusterTool(config, args),
            'hugo': HugoTool(config, args),
        }

    def get_enabled_tools(self) -> List[Tool]:
        """Returns enabled tools based on args and config."""
        enabled_tools = [tool for tool in self.tools.values() if tool.is_enabled()]
        log_message(f"Enabled tools: {[tool.name for tool in enabled_tools]}", "info")
        return enabled_tools

    def run_tools(self, hosts_list: Dict[str, List[Tuple[str, str, Optional[str]]]], base_dir: str) -> Dict[str, Dict[str, Any]]:
        """Executes enabled tools for each host list."""
        log_message(f"Running tools for hosts_list: {list(hosts_list.keys())}", "info")
        all_results = {}
        all_dir_content = {}
        for fname, hosts in hosts_list.items():
            results = {}
            current_hosts = hosts.copy()
            for tool in self.get_enabled_tools():
                log_message(f"Executing {tool.name} for {fname} with hosts: {current_hosts}", "info")
                results[tool.name] = tool.run(current_hosts, base_dir, fname)
                if tool.name == 'subfinder':
                    current_hosts.extend(results[tool.name].get('new_hosts', []))
                if tool.name == 'nmap':
                    self.tools['nuclei'].args.webapps = results[tool.name].get('webapps', [])
                    self.tools['feroxbuster'].args.webapps = results[tool.name].get('webapps', [])
                    if not self.tools['nmap'].args.no_ping and not self.tools['nmap'].args.ping_only:
                        current_hosts = results[tool.name].get('active_hosts', current_hosts)
                if tool.name == 'hugo':
                    all_dir_content[fname] = results[tool.name].get('content', '')
            all_results[fname] = results
            if self.tools['nmap'].args.export_json:
                ScanUtils.export_json_summary(current_hosts, base_dir, fname, self.tools['nmap'].args.export_json)
        if self.tools['hugo'].is_enabled() and all_dir_content:
            log_message("Writing root index with aggregated content", "info")
            self.tools['hugo'].write_branch(base_dir, None, self.tools['hugo'].args.hugo_backup, all_dir_content)
            log_message("Aggregated all directory content into ./content/index.md", "success")
        else:
            log_message("Hugo disabled or no content to aggregate, skipping root index", "info")
        return all_results

def debug_config(config: configparser.ConfigParser) -> None:
    """Logs the contents of the config for debugging."""
    log_message("Reading autoscan.conf contents:", "info")
    for section in config.sections():
        log_message(f"Section: {section}", "info")
        for key, value in config.items(section):
            log_message(f"  {key} = {value}", "info")

def run_scans(args: argparse.Namespace, hosts_list: Dict[str, List[Tuple[str, str, Optional[str]]]], config: configparser.ConfigParser) -> None:
    """Runs all scans and processes results."""
    unique_id = datetime.datetime.now().strftime('%Y-%m-%d-%H.%M.%S')
    base_dir = args.output_dir
    log_message(f"Starting scans with base_dir: {base_dir}, hosts_list: {list(hosts_list.keys())}", "info")
    registry = ToolRegistry(config, args)
    registry.run_tools(hosts_list, base_dir)
    if args.compress:
        archive_name = f"{base_dir}/scan_results_{unique_id}.tar.gz"
        with tarfile.open(archive_name, "w:gz") as tar:
            for fname in hosts_list:
                tar.add(f"{base_dir}/{fname}", arcname=fname)
        log_message(f"Compressed output to {archive_name}", "success")
    ScanUtils.cleanup()

def main() -> None:
    """Main function to parse arguments and run scans."""
    config = configparser.ConfigParser()
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'autoscan.conf')
    if not os.path.exists(config_path):
        log_message("Configuration file 'autoscan.conf' not found", "error")
        sys.exit(1)
    config.read(config_path)
    debug_config(config)

    parser = argparse.ArgumentParser(
        prog='autoscan.py',
        description='Automate network scanning with modular tool execution',
        epilog='Example: python3 autoscan.py --input-host 192.168.1.1 --nmap --nuclei'
    )
    host_group = parser.add_mutually_exclusive_group()
    host_group.add_argument('-I', '--input-file', help='File with one host/CIDR per line')
    host_group.add_argument('-i', '--input-host', help='Single host, IP, or URL')
    host_group.add_argument('--folder', help='Directory containing multiple host files')

    for tool in ['nmap', 'subfinder', 'nuclei', 'feroxbuster', 'hugo']:
        parser.add_argument(f'--{tool}', action='store_true', help=f'Run {tool} tool')
        parser.add_argument(f'--no-{tool}', action='store_true', help=f'Disable {tool} tool')

    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('-p', '--ports', help='Nmap specific ports (e.g., 80,443,1000-2000)')
    port_group.add_argument('-P', '--top-ports', type=int, help='Nmap scan top X ports')
    port_group.add_argument('-f', '--full-scan', action='store_true', help='Nmap scan all ports')
    port_group.add_argument('-q', '--ping-only', action='store_true', help='Nmap ping scan only')

    parser.add_argument('-d', '--no-ping', action='store_true', help='Skip ping scan')
    parser.add_argument('-u', '--udp', action='store_true', help='Perform UDP scan')
    parser.add_argument('--proxy', help='Proxy for nuclei/feroxbuster (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--nmap-args', default=config.get('Nmap', 'nmap_args', fallback=NMAP_DEFAULT_ARGS), help='Custom Nmap arguments')
    parser.add_argument('--ping-args', default=config.get('Nmap', 'ping_args', fallback=PING_DEFAULT_ARGS), help='Custom Nmap ping arguments')
    parser.add_argument('--compress', action='store_true', help='Compress output files')
    parser.add_argument('--export-json', help='Export scan summary to JSON file')
    parser.add_argument('--setup-hugo', action='store_true', help='Set up Hugo environment')
    parser.add_argument('--force-hugo', action='store_true', help='Force overwrite Hugo site')
    parser.add_argument('--output-dir', default=config.get('Output', 'output_dir', fallback=OUTPUT_DIR_DEFAULT), help='Output directory')
    parser.add_argument('--hugo-backup', choices=['ask', 'replace', 'unique'], default='ask', help='Backup mode for Hugo')

    args = parser.parse_args()

    if args.ports and not ScanUtils.validate_ports(args.ports):
        parser.error("Invalid port format. Use comma-separated ports or ranges (e.g., 80,443,1000-2000)")
    args.proxy = ScanUtils.validate_proxy(args.proxy)

    if args.setup_hugo or (args.hugo and not args.no_hugo):
        hugo_dir = config.get('Hugo', 'hugo_dir', fallback=HUGO_DIR_DEFAULT)
        hugo_theme = config.get('Hugo', 'hugo_theme', fallback=HUGO_THEME_DEFAULT)
        HugoTool(config, args).setup_environment(hugo_dir, hugo_theme, args.force_hugo, '--non-interactive' in sys.argv)

    hosts_list = {}
    if args.input_host:
        log_message(f"Using input-host from command line: {args.input_host}", "info")
        hosts_list['hosts'] = [(h, o, None) for h, o in ScanUtils.get_hosts(args.input_host, '.', True)]
    elif args.input_file:
        log_message(f"Using input-file from command line: {args.input_file}", "info")
        fname = os.path.splitext(os.path.basename(args.input_file))[0]
        hosts_list[fname] = [(h, o, None) for h, o in ScanUtils.get_hosts(args.input_file)]
    elif args.folder:
        log_message(f"Using folder from command line: {args.folder}", "info")
        if not os.path.isdir(args.folder):
            log_message(f"Folder not found: {args.folder}", "error")
            sys.exit(1)
        for f in os.listdir(args.folder):
            if os.path.isfile(os.path.join(args.folder, f)):
                fname = os.path.splitext(f)[0]
                hosts_list[fname] = [(h, o, None) for h, o in ScanUtils.get_hosts(f, args.folder)]
    else:
        input_host = config.get('Input', 'input_host', fallback=None)
        input_file = config.get('Input', 'input_file', fallback=None)
        folder = config.get('Input', 'folder', fallback=None)
        if input_host:
            log_message(f"Using input_host from config: {input_host}", "info")
            hosts_list['hosts'] = [(h, o, None) for h, o in ScanUtils.get_hosts(input_host, '.', True)]
        elif input_file:
            log_message(f"Using input_file from config: {input_file}", "info")
            fname = os.path.splitext(os.path.basename(input_file))[0]
            hosts_list[fname] = [(h, o, None) for h, o in ScanUtils.get_hosts(input_file)]
        elif folder:
            log_message(f"Using folder from config: {folder}", "info")
            if not os.path.isdir(folder):
                log_message(f"Folder not found: {folder}", "error")
                sys.exit(1)
            for f in os.listdir(folder):
                if os.path.isfile(os.path.join(folder, f)):
                    fname = os.path.splitext(f)[0]
                    hosts_list[fname] = [(h, o, None) for h, o in ScanUtils.get_hosts(f, folder)]
        else:
            log_message("No input source specified in command-line or autoscan.conf", "error")
            sys.exit(1)

    if not hosts_list:
        log_message("No valid hosts found from input source", "error")
        sys.exit(1)

    run_scans(args, hosts_list, config)
    log_message("All tasks completed successfully", "success")

if __name__ == '__main__':
    main()