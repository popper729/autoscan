# Autoscan

> Run with ./autoscan.sh with no arguments as long as autoscan.conf is properly defined.

## How to use
> Install the required tools (manually or using setup.sh)  
> Configure autoscan.conf (example found below or in the repo)  
> Run with autoscan.sh (a wrapper for autoscan.py that sets up a venv and runs the script) or directly with autoscan.py  

## Running with autoscan.py
### To run without autoscan.conf, the following command-line arguments can be used:
```
-I, --input-file <file>        File with one host/CIDR per line (e.g., hosts.txt)
-i, --input-host <host>        Single host or IP (e.g., 192.168.1.1 or example.com)
--folder <directory>           Directory containing multiple host files (e.g., inputs/)
--nmap                         Run Nmap scan
--no-nmap                      Disable Nmap scan
--subfinder                    Run Subfinder for subdomain enumeration
--no-subfinder                 Disable Subfinder
--nuclei                       Run Nuclei for web vulnerability scanning
--no-nuclei                    Disable Nuclei
--feroxbuster                  Run Feroxbuster for directory brute-forcing
--no-feroxbuster               Disable Feroxbuster
--hugo                         Generate Hugo static site (default: true)
--no-hugo                      Disable Hugo output
-p, --ports <ports>            Nmap specific ports (e.g., 80,443,1000-2000)
-P, --top-ports <number>       Nmap scan top X ports (e.g., 1000)
-f, --full-scan                Nmap scan all ports (1-65535)
-q, --ping-only                Nmap ping scan only
-d, --no-ping                  Skip Nmap ping scan
-u, --udp                      Perform UDP scan instead of TCP
--proxy <url>                  Proxy for Nuclei/Feroxbuster (e.g., http://127.0.0.1:8080)
--nmap-args <args>             Custom Nmap arguments (default: -Pn -sV -O)
--ping-args <args>             Custom Nmap ping arguments (default: -sn -PE -PP -PM)
--compress                     Compress output files into a .tar.gz archive
--export-json <file>           Export scan summary to JSON file (e.g., summary.json)
--setup-hugo                   Set up Hugo environment
--force-hugo                   Force overwrite of existing Hugo site
--output-dir <directory>       Output directory (default: ./content)
--hugo-backup <mode>           Hugo backup mode: ask, replace, or unique (default: ask)
```

## Autoscan.conf
### The following options can be used within autoscan.conf:
```
[Input]
input_file          File with one host/CIDR per line (string, e.g., "hosts.txt", default: None)
input_host          Single host or IP (string, e.g., "192.168.1.1", default: None)
folder              Directory containing multiple host files (string, e.g., "inputs/", default: None)
output_dir          Output directory for scan results (string, e.g., "./content", default: "./content")
[Nmap]
nmap_args           Custom Nmap arguments (string, e.g., "-Pn -sV -O", default: "-Pn -sV -O")
ping_args           Custom Nmap ping arguments (string, e.g., "-sn -PE -PP -PM", default: "-sn -PE -PP -PM")
retries             Number of retries for Nmap scans (integer, e.g., "3", default: "3")
ports               Specific ports for Nmap scan (string, e.g., "80,443", default: None)
top_ports           Number of top ports for Nmap scan (integer, e.g., "1000", default: None)
full_scan           Enable full port scan (1-65535) (boolean, e.g., "false", default: "false")
ping_only           Enable ping-only scan (boolean, e.g., "false", default: "false")
[Tools]
nmap_threads        Number of threads for Nmap scans (integer, e.g., "8", default: "8")
nuclei_concurrency  Concurrency level for Nuclei scans (string, e.g., "50", default: "50")
nuclei_threads      Number of threads for Nuclei scans (integer, e.g., "4", default: "4")
feroxbuster_threads 	Number of threads for Feroxbuster scans (string, e.g., "20", default: "20")
feroxbuster_parallel_threads 	Number of parallel threads for Feroxbuster (integer, e.g., "4", default: "4")
subfinder_threads   Number of threads for Subfinder scans (integer, e.g., "4", default: "4")
wordlist            Path to wordlist for Feroxbuster (string, e.g., "/snap/feroxbuster/common/raft-small-directories-lowercase.txt", default: "/snap/feroxbuster/common/raft-small-directories-lowercase.txt")
[Scans]
nmap                Enable Nmap scan (boolean, e.g., "true", default: "true")
subfinder           Enable Subfinder scan (boolean, e.g., "false", default: "false")
nuclei              Enable Nuclei scan (boolean, e.g., "false", default: "false")
feroxbuster         Enable Feroxbuster scan (boolean, e.g., "false", default: "false")
hugo                Enable Hugo output (boolean, e.g., "true", default: "true")
compress            Enable compression of output files (boolean, e.g., "false", default: "false")
export_json         Path to JSON summary file (string, e.g., "scan_summary.json", default: None)
hugo_backup         Hugo backup mode (string: "ask", "replace", or "unique", default: "ask")
[Hugo]
hugo_dir            Directory for Hugo site (string, e.g., "./hugo_site", default: "./hugo_site")
hugo_theme          URL of Hugo theme repository (string, e.g., "https://github.com/matcornic/hugo-theme-learn.git", default: "https://github.com/matcornic/hugo-theme-learn.git")
```

### Example autoscan.conf file:

```
[Input]
input_file = hosts.txt
output_dir = ./content

[Nmap]
nmap_args = -Pn -sV -O
ping_args = -sn -PE -PP -PM
retries = 3
ports = 80,443
full_scan = false
ping_only = false

[Tools]
nmap_threads = 8
nuclei_concurrency = 50
nuclei_threads = 4
feroxbuster_threads = 20
feroxbuster_parallel_threads = 4
subfinder_threads = 4
wordlist = ~/snap/feroxbuster/common/raft-small-directories-lowercase.txt

[Scans]
nmap = true
subfinder = false
nuclei = false
feroxbuster = false
hugo = true
compress = false
export_json = scan_summary.json
hugo_backup = ask

[Hugo]
hugo_dir = ./hugo_site
hugo_theme = https://github.com/matcornic/hugo-theme-learn.git
```
