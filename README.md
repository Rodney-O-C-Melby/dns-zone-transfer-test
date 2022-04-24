# DNS Zone Transfer Test
Automates Domain Name System (DNS) zone transfer testing. 

Automatically finds a given domains nameservers, and 
tests for zone transfers, if successfully, identified A records are printed to standard output.

# Requirements
```
python >= 3.9
pip >= 20.3.4
```

# Installation
Download the repository change to the relevant directory, and install the PIP package.
```
git clone https://github.com/Rodney-O-C-Melby/zone-transfer-tester.git  
cd dns-zone-transfer-test
pip install .
```  
  
# Usage  
sudo/root is required, or SETCAP permissions for the user to make a new network connection is required. 
Also, python greater than or equal to version 3.9 is required and python sitepackages should be included in 
the PATH environment variable.  
```
usage: dztt [-h] [-f FILE] [-n NAMESERVER] [target]

DNS Zone Transfer Test: dztt tests IP's or domains for zone transfers. (XFR)

positional arguments:
  target                Target IP or Domain name to test

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  file of domain names to test, one per line
  -n NAMESERVER, --nameserver NAMESERVER
                        DNS IP for target DNS query, defaults to local DNS

### EXAMPLES ###
dztt  
sudo dztt zonetransfer.me
sudo dztt -f domains.txt  
sudo dztt -n 8.8.8.8 zonetransfer.me  
sudo dztt -f domains.txt -n 8.8.8.8
```  
# Output
A domain that is vulnerable to zone transfers will print the following message to standard out, and print each 
identified A record.
``` 
zonetransfer.me is VULNERABLE to DNS Zone Transfers!!!  
Found 34 subdomains at zonetransfer.me  
``` 
A domain that is not vulnerable to zone transfers will print the following message to standard out.
``` 
nmap.org is SECURE against DNS Zone Transfers :-)  
```

# Input
Accepts a file containing domain names to test, one per line.

# PIP Requirements
```
dnspython >= 2.2.1
```