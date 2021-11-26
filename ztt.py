#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# REQUIREMENTS: dnspython
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
from re import match
from os import geteuid
from sys import exit
from sys import argv
from dns import resolver
from dns.query import xfr
from dns.zone import from_xfr
from dns.query import TransferError
from dns.exception import FormError
from argparse import ArgumentParser
from socket import gethostbyaddr, gethostbyname, herror

__author__ = "Rodney Olav Christopher Melby"
__copyright__ = "Copyright 2022, Rodney Olav Christopher Melby"
__credits__ = ["Rodney Olav Christopher Melby"]
__license__ = "LGPL v3"
__version__ = "1.0.1"
__maintainer__ = "Rodney Olav Christopher Melby"
__status__ = "Production"

GREEN = '\033[92m'
RED = '\033[91m'
END = '\033[0m'


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


def ipv4(s):
    return str(int(s)) == s and 0 <= int(s) <= 255


def ipv6(s):
    if len(s) > 4:
        return False
    return int(s, 16) >= 0 and s[0] != '-'


def valid_ip(address):
    """ Validates an IP address, return true or false. """
    try:
        if address.count(".") == 3 and all(ipv4(i) for i in address.split(".")):
            return True
        if address.count(":") == 7 and all(ipv6(i) for i in address.split(":")):
            return True
        return False
    except ValueError:
        return False


def get_target_nameservers(target, ns="1.1.1.1"):
    """ Returns a domain names name servers IP. """
    servers = []
    if valid_ip(target):  # handle IPs
        servers.append(target)
    else:  # handle domain names
        my_resolver = resolver.Resolver()
        my_resolver.nameservers = [ns]
        try:
            nameservers = my_resolver.resolve(target, 'NS')  # NS lookup
            for server in nameservers:
                # print(server)
                ip = gethostbyname(str(server))  # get NS ip
                servers.append(ip)
        except resolver.NoNameservers:
            print(RED + "No DNS servers at " + target + END)
            exit(-1)
        except resolver.NXDOMAIN:
            print(RED + "The DNS query name does not exist: " + target + END)
            exit(-1)
    return servers


def get_target_subdomains_from_auth_ns(target, auth_ns):
    """ Checks domains nameserver for zone transfers, if allowed returns a list of enumerated subdomain DNS records"""
    if valid_ip(target):  # handle IPs
        try:
            gethostbyaddr(str(target))
        except herror:
            print(RED + "Could not get hostname from " + str(target) + ", check target is live/up." + END)
            exit(-1)
    try:
        z = from_xfr(xfr(str(auth_ns), target))  # zone transfer dig request using auth ns
        subdomains = []
        names = z.nodes.keys()  # node key values
        for n in names:
            at = match("@", str(n))  # removes dns self (@) symbol
            if not at:
                subdomain = str(n) + "." + target
                subdomains.append(subdomain)
                # print(subdomain)
        print(RED + target, "is VULNERABLE to DNS Zone Transfers!!!" + END)
        return subdomains
    except TransferError:  # most domains
        print(GREEN + target, "is SECURE against DNS Zone Transfers :-)" + END)
        exit(1)
    except FormError:  # google.co.uk
        print(GREEN + target, "is SECURE against DNS Zone Transfers :-)" + END)
        exit(1)
    except TimeoutError:  # rhul.ac.uk
        print(GREEN + target, "is VERY SECURE against DNS Zone Transfers :-)" + END)
        exit(1)
    except OSError:  # the next router
        print(RED + "[No route to host] Lookup Failure!" + END)
        print("Domain name reverse fqdn lookup error - Check your on the domains internal network, or setup dnscrypt "
              "for the domain as all european ISPs high-jack all dns traffic to censor the internet!")
        exit(1)


def ztt(domain, nameserver=""):
    """ Zone Transfer Test for a Given Domain Name and/or nameserver """
    # handle if user domain set
    if nameserver == "":
        nameserver = get_local_name_server()  # get local nameservers
    target_nameserver = get_target_nameservers(domain, nameserver)  # get target nameservers

    # For Users and Debugging
    print("DNS Server: \t", nameserver)
    print("Target: \t", domain)
    count = 1
    for server in target_nameserver:
        print("Target DNS " + str(count) + ": \t", server)
        count += 1

    # test if nameserver lookup was ok
    try:
        subdomains = []
        for server in target_nameserver:
            # attempt zone transfer to enumerate all subdomains
            subdomains = get_target_subdomains_from_auth_ns(domain, server)
            if len(subdomains) > 0:
                print(GREEN + "Found", len(subdomains), "subdomains at", domain, "from nameserver", server + END)
                # print(subdomains)

        if len(subdomains) > 0:
            exit(1)
        else:  # no subdomains found
            print(RED + "No subdomains found at", domain + END)
            exit(1)
    except IndexError:
        print(RED + "Domain NS lookup failed. Check domain name is correct and network connection is active!" + END)
        exit(1)


def ztt_file(filepath, nameserver=""):
    """ Reads a file of domains and uses ztt to check each domain and/or with optionally given nameserver """
    # handle if nameserver set
    if nameserver == "":
        nameserver = get_local_name_server()  # get local nameservers
    with open(filepath) as fh:
        for target in fh.read().splitlines():
            ztt(target, nameserver)


def main():
    """ Main program - handle user input, usage etc """
    # handle optional positional arguments
    if not geteuid() == 0:  # check root permissions
        print(RED + "Only root can run this script. Try using sudo!" + END)
        exit(1)
    if len(argv) > 5:
        print("Too many arguments. One domain name only!")
        exit(1)

    # handle help and usage
    parser = ArgumentParser(description="Zone Transfer Tester: ztt tests IP's or domains for zone transfers. (XFR)")
    parser.add_argument('target', action="store", nargs="?", help="Target IP or Domain name to test")
    parser.add_argument('-f', "--file", action='store', dest="file", default=False,
                        help='file of domain names to test, one per line')
    parser.add_argument('-n', "--nameserver", action='store', dest="nameserver", default=False,
                        help='DNS IP for target DNS query, defaults to local DNS')
    args = parser.parse_args()

    target, filename, nameserver = "", "", ""
    bad_chars = [';', ':', '!', "*", '"', "'", '#', '$', '|', '%', '^', '&', '*', '(', ')', '<', '>', ',', '/', '?',
                 '\\', '[', ']', '{', '}', '-', '_', '+', '=']  # illegal chars (special except dot)
    # strip bad characters from user input
    if args.target:
        target = str(args.target)
        for i in bad_chars:
            target = target.replace(i, '')
    if args.file:
        filename = str(args.file)
        for i in bad_chars:
            filename = filename.replace(i, '')
    if args.nameserver:
        nameserver = str(args.nameserver)
        for i in bad_chars:
            nameserver = nameserver.replace(i, '')
    # handle optional arguments
    if args.target and args.nameserver:
        ztt(target, nameserver)
    if args.file and args.nameserver:
        ztt_file(filename, nameserver)
    if args.target and not args.nameserver:
        ztt(target)
    if args.file and not args.nameserver:
        ztt_file(filename)
    if args.nameserver and not args.file and not args.target:
        ztt("zonetransfer.me", nameserver)


if __name__ == '__main__':
    main()
