# Zone Transfer Tester
Domain DNS zone transfer tester.

# Get Zone Transfer Tester
Download the repository change to the relevant directory, install the PIP requirements and give the file execute permissions
```
git clone https://github.com/Rodney-O-C-Melby/zone-transfer-tester.git  
cd zone-transfer-tester
sudo pip install -r requirements
sudo chmod +x ztt.py
```  
  
# Use Zone Transfer Tester  
sudo or root is required to make a new network connection, python indicates python v3.9 is used to interpret, and ztt.py is the program to interpret or run.  
```
sudo python ztt.py  
sudo python ztt.py zonetransfer.me
sudo python ztt.py -f domains.txt  
sudo python ztt.py -n 8.8.8.8 zonetransfer.me  
sudo python ztt.py -f domains.txt -n 8.8.8.8
```  
# Zone Transfer Tester Responses  
A domain that is vulnerable to zone transfers
``` 
zonetransfer.me is VULNERABLE to DNS Zone Transfers!!!  
Found 34 subdomains at zonetransfer.me  
``` 
A domain that is not vulnerable to zone transfers
``` 
google.co.uk is SECURE against DNS Zone Transfers :-)  
```
