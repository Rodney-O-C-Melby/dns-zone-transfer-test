#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Zone Transfer Tester - Tests if zone transfers are possible for a given domain name.

    GNU LGPL v3
    Copyright (C) 2021 Rodney Olav Christopher Melby

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software Foundation,
    Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

# Imports
from argparse import ArgumentParser
from re import match
from os import geteuid
from sys import exit
from sys import argv
from dns.query import xfr
from dns.zone import from_xfr
from dns.query import TransferError
from dns.exception import FormError
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1

__author__ = "Rodney Olav Christopher Melby"
__copyright__ = "Copyright 2021, pearcom.co.uk"
__credits__ = ["Rodney Olav Christopher Melby"]
__license__ = "LGPL v3"
__version__ = "1.0.0"
__maintainer__ = "Rodney Olav Christopher Melby"
__status__ = "Production"


def get_local_name_server():
    """ Returns the local machines nameserver IP or googles dns """
    nameserver = "1.1.1.1"
    with open("/etc/resolv.conf") as fh:
        for line in fh.readlines():
            groups = match("nameserver (.*)", line)
            if groups:
                nameserver = groups.groups()[0]
                break
    return nameserver


def get_target_nameservers(target, ns="1.1.1.1"):
    """ Returns a domain names name servers """
    dns_req = IP(dst=ns)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=target, qtype="NS", qclass="IN"))
    answer = sr1(dns_req, verbose=0)  # scapy python library
    # dns_req.show()  # debugging
    # answer.show()
    servers = []
    for x in range(answer[DNS].ancount):
        servers.append(answer[DNSRR][x].rdata.decode("utf-8"))
    return servers


def get_target_subdomains_from_auth_ns(target, auth_ns):
    """ Checks domains nameserver for zone transfers, if allowed returns a list of enumerated subdomain DNS records"""
    try:
        z = from_xfr(xfr(auth_ns, target))  # zone transfer dig request using auth ns
        subdomains = []
        names = z.nodes.keys()  # node key values
        for n in names:
            at = match("@", str(n))  # removes dns self (@) symbol
            if not at:
                subdomain = str(n) + "." + target
                subdomains.append(subdomain)
                # print(subdomain)
        print(target, "is VULNERABLE to DNS Zone Transfers!!!")
        return subdomains
    except TransferError:  # most domains
        print(target, "is SECURE against DNS Zone Transfers :-)")
        exit(1)
    except FormError:  # google.co.uk
        print(target, "is SECURE against DNS Zone Transfers :-)")
        exit(1)
    except TimeoutError:  # rhul.ac.uk
        print(target, "is VERY SECURE against DNS Zone Transfers :-)")
        exit(1)
    except OSError:  # the next router
        print("[No route to host] Lookup Failure!")
        print("Domain name reverse fqdn lookup error - Check your on the domains internal network, or setup dnscrypt "
              "for the domain as all european ISPs high-jack all dns traffic to censor the internet!")
        exit(2)


def ztt(domain, nameserver="1.1.1.1"):
    """ Zone Transfer Test for a Given Domain Name and/or nameserver """
    # handle if user domain set
    if "1.1.1.1" in nameserver:
        nameserver = get_local_name_server()  # get local nameservers
    else:
        print("Using given nameserver ", nameserver)  # use user given nameserver
    # get target nameservers
    target_nameserver = get_target_nameservers(domain, nameserver)

    # # For Users and Debugging
    # print("Using Nameserver: \t", local_nameserver)
    # print("Target Domain Name: \t", domain)
    # print("Target Nameserver 1: \t", target_nameserver[0])
    # print("Target Nameserver 2: \t", target_nameserver[1], "\n")

    # test if nameserver lookup was ok
    try:
        # attempt zone transfer to enumerate all subdomains
        subdomains = get_target_subdomains_from_auth_ns(domain, target_nameserver[0])
        if len(subdomains) > 0:
            print("Found", len(subdomains), "subdomains at", domain)
            return True
        else:  # no subdomains found
            print("No subdomains found at", domain)
            return False
    except IndexError:
        print("Domain NS lookup failed. Check domain name is correct and network connection is active!")
        exit(3)


def ztt_file(filepath, nameserver="1.1.1.1"):
    """ Reads a file of domains and uses ztt to check each domain and/or with optionally given nameserver """
    # handle if user domain set
    if "1.1.1.1" in nameserver:  # no given nameserver, use local
        with open(filepath) as fh:
            for line in fh.read().splitlines():
                print("Trying domain", line)
                ztt(line)
    else:  # use user given nameserver
        with open(filepath) as fh:
            for line in fh.read().splitlines():
                print("Trying domain", line)
                ztt(line, nameserver)


def main():
    """ Main program - handle user input, usage etc """

    # handle optional positional arguments
    if not geteuid() == 0:  # check root permissions
        exit("\nOnly root can run this script. Try using sudo!\n")
    if len(argv) < 2:  # accept no arguments
        ztt("zonetransfer.me")
    if len(argv) == 2:  # accept one positional argument
        domain = argv[1]  # get domain
        ztt(domain)
    if len(argv) > 5:
        print("Too many arguments. One domain name only!")
        exit(4)

    # handle help and usage
    parser = ArgumentParser(description="Zone Transfer Tester ztt tests domain zone transfers to enumerate subdomains.")
    parser.add_argument("-d", "--domain", action="store", help="The target domain name")
    parser.add_argument("-f", "--file", action="store", help="input file of domain names, one per line.")
    parser.add_argument("-n", "--nameserver", action="store", help="Nameserver IP to use for target NS query.")
    args = parser.parse_args()

    # handle optional arguments
    if args.domain and args.nameserver:
        # print(args.domain)
        ztt(args.domain, args.nameserver)
    if args.file and args.nameserver:
        ztt_file(args.file, args.nameserver)
    if args.domain and not args.nameserver:
        ztt(args.domain)
    if args.file and not args.nameserver:
        ztt_file(args.file)


if __name__ == '__main__':
    main()
