#!/usr/bin/env python3
#
# -------------------------------------------------------------------------------
#
# This helper script supports auditors in finding orphanded DNS
# references like CNAMES or MX records pointing to third-party
# domains that have been forgotten and are not registered anymore.
#
# Written by Martin Schobert <martin@weltregierung.de>
#
# -------------------------------------------------------------------------------
#
# Copyright (c) 2017, Martin Schobert
#
# All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
#  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#  The views and conclusions contained in the software and documentation are those
#  of the authors and should not be interpreted as representing official policies,
#  either expressed or implied, of the project.

#  NON-MILITARY-USAGE CLAUSE
#  Redistribution and use in source and binary form for military use and
#  military research is not permitted. Infringement of these clauses may
#  result in publishing the source code of the utilizing applications and
#  libraries to the public. As this software is developed, tested and
#  reviewed by *international* volunteers, this clause shall not be refused
#  due to the matter of *national* security concerns.

import dns.resolver # dnspython
import lxml.etree as ET
import argparse
import sys
import concurrent.futures 
import threading

interesting_types = ["CNAME", "MX", "SRV", "DNAME"]

log_fh = None
log_lock = threading.Lock()

def my_dns_query(host, r_type):
    answers = []
    
    myresolver = dns.resolver.Resolver()
    myresolver.timeout = 5
    myresolver.lifetime = 5
    answers = myresolver.query(host, r_type)
    return answers
    
def log_print(str):
    """ Log a sring to STDOUT and a logfile."""
    print(str)
    if log_fh:
        log_lock.acquire()
        log_fh.write(str + "\n")
        log_lock.release()
    
def print_issue(r_name, r_type):
    str = "+ Possible ISSUE: Error resolving entry for %s (%s)" % (r_name, r_type)
    log_print(str)

def print_no(r_name, r_type):
    str = "+ NO entry found: %s (%s)" % (r_name, r_type)
    log_print(str)    

def print_ok(r_name, r_type, resolved_addresses):    
    str = "+ OK %s (%s) -> %s" % (r_name, r_type, resolved_addresses)
    log_print(str)

def lookup_a_and_aaaa(host):
    ''' Returns either a list of IP adresses or an empty list
    when records do not exists or None in case of an error. '''
    results = []
    answers_a = []
    answers_aaaa = []
    
    try:
        
        answers_a = my_dns_query(host, "A")
        
    except dns.resolver.NoAnswer:
        log_print("+ No answer for %s (A)" % host)
        pass
    except dns.resolver.NXDOMAIN:
        log_print("+ NXDOMAIN for %s (A)" % host)
        return None

    try:
        answers_aaaa = my_dns_query(host, "AAAA")
        
    except dns.resolver.NoAnswer:
        log_print("+ No answer for %s (AAAA)" % host)
        pass
    except dns.resolver.NXDOMAIN:
        log_print("+ NXDOMAIN for %s (AAAA)" % host)
        return None

    for rdata_a in answers_a:
        results.append(rdata_a.address)

    for rdata_a in answers_aaaa:
        results.append(rdata_a.address)
        
    return results

    
def lookup_names(host, r_type):
    ''' Returns either a dict of NAME -> IP-addresses or an
    empty dict when records do not exists or None in case of an error. '''
    results = {}

    answers = None

    try:
        answers = my_dns_query(host, r_type)
        
    # catch exceptions for lookups of type CNAME, MX, ...
    except dns.resolver.NoAnswer:
        # indicates an error
        log_print("+ No answer for %s (%s)" % (host, r_type))
        return {}
    except dns.resolver.NXDOMAIN:
        # Why have we requested it than?
        log_print("+ NXDOMAIN for %s (%s)" % (host, r_type))
        return None
    
    for rdata in answers:

        if r_type == 'MX':
            target = rdata.exchange
            log_print("+ MX %s -> %s" % (host, target))                
        else:
            target = rdata.target

        results[target] = lookup_a_and_aaaa(target)
            
        if results[target] is None:
            log_print("+ Hit! No answer for %s -> %s (%s)" % (host, target, r_type))
            
    return results

  
    
def lookup_names_worker(hostname):

    
    for r_type in interesting_types:
        #print("%s - %d" % (r_type, len(interesting_types)))
        ip_addresses = lookup_names(hostname, r_type)

        if ip_addresses is None:
            print_issue(hostname, r_type)
            #print_no(hostname, r_type) XXX
            
        elif not ip_addresses:
            print_no(hostname, r_type)

        else:
            print_ok(hostname, r_type, ip_addresses)


def wait_check_results(futures):
    log_print("+ Wait for threads to finish")
    concurrent.futures.wait(futures)
    print("+ Check results")
    for future in futures:
        try:
            data = future.result()
        except Exception as exc:
            print('exception: %s' % (exc))
            raise exc
        else:
            print("+ done")

    
def check_targets_from_stdin(num_threads):
    ''' Read line by line from STDIN and resolve CNAMEs etc. if possible.'''

    futures = []
    print("+ Using %d thread(s)." % num_threads)
    #pool = concurrent.futures.ThreadPoolExecutor(num_threads)
    pool = concurrent.futures.ProcessPoolExecutor(num_threads)

    for line in sys.stdin:
        hostname = line.rstrip()
        log_print("+ Submitting job for " + hostname)
        futures.append(pool.submit(lookup_names_worker, hostname))

    wait_check_results(futures)
                                        


def check_targets_from_dnsrecon_xml(filename, num_threads):
    
    futures = []
    pool = concurrent.futures.ThreadPoolExecutor(num_threads)

    xml_root = ET.parse(filename)
    for t in xml_root.findall("./record"):

        r_type = t.attrib['type']
        if r_type.upper() in interesting_types:

            # simplify via dict!
            if r_type.upper() == 'MX':
                r_name = t.attrib['exchange']
            elif r_type.upper() == 'CNAME':
                r_name = t.attrib['target']
            else:
                r_name = t.attrib['name']

            log_print("+ Submitting job for " + r_name)
            futures.append(pool.submit(lookup_names_worker, r_name))

    wait_check_results(futures)
    
def main():

    # process command line arguments
    parser = argparse.ArgumentParser(description='Find orphaned CNAMEs and other records')

    parser.add_argument('--dnsrecon', help="Process XML files generated by 'dnsrecon'.",
                        metavar='FILE', nargs='?', const='')

    parser.add_argument('--stdin', help='Read hostnames from STDIN line by line.', action='store_true')

    parser.add_argument('--threads', help="Number of threads for DNS requests.' (default: 50).",
                        metavar='N', default=50, type=int)

    parser.add_argument('--log', help="Write results to this log file.",
                        metavar='FILE', nargs='?', const='')
    
    (options, args) = parser.parse_known_args()

    if options.log:
        global log_fh
        log_fh = open(options.log, "w")
        print("+ Logging to file " + options.log)
        
    if options.dnsrecon:
        check_targets_from_dnsrecon_xml(options.dnsrecon, options.threads)
    elif options.stdin:
        check_targets_from_stdin(options.threads)
    else:
        parser.print_help()
        
    if log_fh:
        log_fh.close()
        
if __name__ == "__main__":
    main()
        
