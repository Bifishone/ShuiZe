#!/usr/bin/env python
#
# SubBrute v1.2
# A (very) fast subdomain enumeration tool.
#
# Maintained by rook
# Contributors:
# JordanMilne, KxCode, rc0r, memoryprint, ppaulojr
#
import re
import optparse
import os
import signal
import sys
import uuid
import random
import ctypes
import dns.resolver
import dns.rdatatype
import json

# Python 2.x and 3.x compatiablity
try:
    import queue as Queue
except ImportError:
    import Queue

import multiprocessing

# Microsoft compatiablity
if sys.platform.startswith('win'):
    import threading

    multiprocessing.Process = threading.Thread


class verify_nameservers(multiprocessing.Process):

    def __init__(self, target, record_type, resolver_q, resolver_list, wildcards):
        multiprocessing.Process.__init__(self, target=self.run)
        self.daemon = True
        signal_init()

        self.time_to_die = False
        self.resolver_q = resolver_q
        self.wildcards = wildcards
        self.record_type = "A"
        if record_type == "AAAA":
            self.record_type = record_type
        self.resolver_list = resolver_list
        resolver = dns.resolver.Resolver()
        self.target = target
        self.most_popular_website = "www.google.com"
        self.backup_resolver = resolver.nameservers + ['127.0.0.1', '8.8.8.8', '8.8.4.4']
        resolver.timeout = 1
        resolver.lifetime = 1
        try:
            resolver.nameservers = ['8.8.8.8']
            resolver.query(self.most_popular_website, self.record_type)
        except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoAnswer):
            resolver = dns.resolver.Resolver()
        self.resolver = resolver

    def end(self):
        self.time_to_die = True

    def add_nameserver(self, nameserver):
        keep_trying = True
        while not self.time_to_die and keep_trying:
            try:
                self.resolver_q.put(nameserver, timeout=1)
                trace("Added nameserver:", nameserver)
                keep_trying = False
            except Queue.Full:
                keep_trying = True
            except Exception as e:
                trace(f"Error adding nameserver {nameserver}: {e}")
                keep_trying = False

    def verify(self, nameserver_list):
        added_resolver = False
        for server in nameserver_list:
            if self.time_to_die:
                break
            server = server.strip()
            if not server:
                continue
            self.resolver.nameservers = [server]
            try:
                if self.find_wildcards(self.target):
                    self.add_nameserver(server)
                    added_resolver = True
                else:
                    trace("Rejected nameserver - wildcard:", server)
            except Exception as e:
                trace(f"Rejected nameserver - unreliable: {server} ({type(e).__name__})")
        return added_resolver

    def run(self):
        random.shuffle(self.resolver_list)
        if not self.verify(self.resolver_list):
            sys.stderr.write('Warning: No nameservers found, trying fallback list.\n')
            self.verify(self.backup_resolver)
        try:
            self.resolver_q.put(False, timeout=1)
        except Queue.Full:
            pass

    def find_wildcards(self, host):
        try:
            wildtest = self.resolver.query(uuid.uuid4().hex + ".com", "A")
            if len(wildtest):
                trace("Spam DNS detected:", host)
                return False
        except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoAnswer):
            pass
        except Exception as e:
            trace(f"Error in spam DNS check: {e}")
            return False

        test_counter = 8
        looking_for_wildcards = True
        while looking_for_wildcards and test_counter >= 0:
            looking_for_wildcards = False
            test_counter -= 1
            try:
                testdomain = f"{uuid.uuid4().hex}.{host}"
                wildtest = self.resolver.query(testdomain, self.record_type)
                if wildtest:
                    for w in wildtest:
                        w_str = str(w)
                        if w_str not in self.wildcards:
                            self.wildcards[w_str] = None
                            looking_for_wildcards = True
            except dns.resolver.NXDOMAIN:
                return True
            except dns.name.EmptyLabel:
                return True
            except Exception as e:
                trace(f"wildcard exception: {self.resolver.nameservers} ({type(e).__name__})")
                return False
        return test_counter >= 0


class lookup(multiprocessing.Process):

    def __init__(self, in_q, out_q, resolver_q, domain, wildcards, spider_blacklist):
        multiprocessing.Process.__init__(self, target=self.run)
        signal_init()
        self.required_nameservers = 16
        self.in_q = in_q
        self.out_q = out_q
        self.resolver_q = resolver_q
        self.domain = domain
        self.wildcards = wildcards
        self.spider_blacklist = spider_blacklist
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = []

    def get_ns(self):
        ret = []
        try:
            ns = self.resolver_q.get_nowait()
            if ns is False:
                self.resolver_q.put(False)
                ret = []
            else:
                ret = [ns]
        except Queue.Empty:
            pass
        except Exception as e:
            trace(f"Error getting nameserver: {e}")
        return ret

    def get_ns_blocking(self):
        ret = []
        try:
            ns = self.resolver_q.get()
            if ns is False:
                trace("get_ns_blocking - Resolver list is empty.")
                self.resolver_q.put(False)
                ret = []
            else:
                ret = [ns]
        except Exception as e:
            trace(f"Error in blocking nameserver get: {e}")
        return ret

    def check(self, host, record_type="A", retries=0):
        trace("Checking:", host)
        cname_record = []
        retries_count = retries
        if len(self.resolver.nameservers) <= self.required_nameservers:
            self.resolver.nameservers += self.get_ns()

        while True:
            try:
                if not record_type or record_type == "A":
                    resp = self.resolver.query(host)
                    hosts = extract_hosts(str(resp.response), self.domain)
                    for h in hosts:
                        if h not in self.spider_blacklist:
                            self.spider_blacklist[h] = None
                            trace("Found host with spider:", h)
                            self.in_q.put((h, record_type, 0))
                    return resp
                elif record_type == "CNAME":
                    for x in range(20):
                        try:
                            resp = self.resolver.query(host, record_type)
                        except dns.resolver.NoAnswer:
                            resp = None
                            break
                        if resp and resp[0]:
                            host = str(resp[0]).rstrip(".")
                            cname_record.append(host)
                        else:
                            break
                    return cname_record
                else:
                    return self.resolver.query(host, record_type)

            except dns.resolver.NoNameservers:
                self.in_q.put((host, record_type, 0))
                self.resolver.nameservers += self.get_ns_blocking()
                return False
            except dns.resolver.NXDOMAIN:
                return False
            except dns.resolver.NoAnswer:
                if retries_count >= 1:
                    trace("NoAnswer retry exhausted")
                    return False
                retries_count += 1
            except dns.resolver.Timeout:
                trace(f"lookup timeout: {host} (retries: {retries_count})")
                if retries_count >= 3:
                    if retries_count > 3:
                        return ['Multiple Query Timeout - External address resolution was restricted']
                    else:
                        self.in_q.put((host, record_type, retries_count + 1))
                    return False
                retries_count += 1
            except IndexError:
                pass
            except TypeError:
                self.in_q.put((host, record_type, 0))
                return False
            except dns.rdatatype.UnknownRdatatype:
                error(f"DNS record type not supported: {record_type}")
            except Exception as e:
                trace(f"Unexpected error processing {host}: {e}")
                return False

    def run(self):
        self.resolver.nameservers += self.get_ns_blocking()
        while True:
            found_addresses = []
            work = self.in_q.get()
            while not work:
                try:
                    work = self.in_q.get(blocking=False)
                    if work:
                        self.in_q.put(False)
                except Queue.Empty:
                    trace('End of work queue')
                    work = False
                    break
            if not work:
                self.in_q.put(False)
                self.out_q.put(False)
                break
            else:
                if len(work) == 3:
                    (hostname, record_type, timeout_retries) = work
                    response = self.check(hostname, record_type, timeout_retries)
                else:
                    (hostname, record_type) = work
                    response = self.check(hostname, record_type)
                sys.stdout.flush()
                trace(response)
                reject = False
                if response:
                    for a in response:
                        a_str = str(a)
                        if a_str in self.wildcards:
                            trace("resolved wildcard:", hostname)
                            reject = True
                            break
                        else:
                            found_addresses.append(a_str)
                    if not reject:
                        result = (hostname, record_type, found_addresses)
                        self.out_q.put(result)


host_match = re.compile(r"((?<=[\s])[a-zA-Z0-9_-]+\.(?:[a-zA-Z0-9_-]+\.?)+(?=[\s]))")


def extract_hosts(data, hostname):
    ret = []
    hosts = re.findall(host_match, data)
    for fh in hosts:
        host = fh.rstrip(".")
        if host.endswith(hostname):
            ret.append(host)
    return ret


domain_match = re.compile("([a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)+")


def extract_subdomains(file_name):
    subs = {}
    try:
        with open(file_name, 'r') as f:
            sub_file = f.read()
    except Exception as e:
        error(f"Failed to read subdomains file: {e}")

    f_all = re.findall(domain_match, sub_file)
    for i in f_all:
        if "." in i:
            p = i.split(".")[0:-1]
            while p and len(p[-1]) <= 3:
                p = p[0:-1]
            p = p[0:-1]
            if len(p) >= 1:
                for q in p:
                    if q:
                        q = q.lower()
                        subs[q] = subs.get(q, 0) + 1
    del f_all
    return sorted(subs.keys(), key=lambda x: subs[x], reverse=True)


def print_target(target, record_type=None, subdomains="names.txt", resolve_list="resolvers.txt",
                 process_count=16, output=False, json_output=False, found_subdomains=[], verbose=False):
    subdomains_list = []
    # 修复重复执行run()的问题
    run_results = run(target, record_type, subdomains, resolve_list, process_count)
    for result in run_results:
        (hostname, record_type, response) = result
        if not record_type:
            result_str = hostname
        else:
            result_str = f"{hostname},{','.join(response).strip(',')}"
        if result_str not in found_subdomains:
            if verbose:
                print(result_str)
            subdomains_list.append(result_str)
    return set(subdomains_list)


def run(target, record_type=None, subdomains="names.txt", resolve_list="resolvers.txt", process_count=16):
    subdomains = check_open(subdomains)
    resolve_list = check_open(resolve_list)
    # 修复拼写错误 resovlers -> resolvers
    if (len(resolve_list) / 16) < process_count:
        sys.stderr.write(
            'Warning: Fewer than 16 resolvers per thread, consider adding more nameservers to resolvers.txt.\n')

    if os.name == 'nt':
        wildcards = {}
        spider_blacklist = {}
    else:
        wildcards = multiprocessing.Manager().dict()
        spider_blacklist = multiprocessing.Manager().dict()

    in_q = multiprocessing.Queue()
    out_q = multiprocessing.Queue()
    resolve_q = multiprocessing.Queue(maxsize=2)

    verify_nameservers_proc = verify_nameservers(target, record_type, resolve_q, resolve_list, wildcards)
    verify_nameservers_proc.start()

    in_q.put((target, record_type))
    spider_blacklist[target] = None

    for s in subdomains:
        s = str(s).strip()
        if not s:
            continue
        if ',' in s:
            s = s.split(",")[0]
        if not s.endswith(target):
            hostname = f"{s}.{target}"
        else:
            hostname = s
        if hostname not in spider_blacklist:
            spider_blacklist[hostname] = None
            in_q.put((hostname, record_type))

    in_q.put(False)

    for _ in range(process_count):
        worker = lookup(in_q, out_q, resolve_q, target, wildcards, spider_blacklist)
        worker.start()

    threads_remaining = process_count
    while True:
        try:
            result = out_q.get(True, 10)
            if not result:
                threads_remaining -= 1
            else:
                yield result
        except Queue.Empty:
            pass
        except Exception as e:
            trace(f"Error in result queue: {e}")
        if threads_remaining <= 0:
            break

    trace("killing nameserver process")
    try:
        killproc(pid=verify_nameservers_proc.pid)
    except:
        verify_nameservers_proc.end()
    trace("End")


def killproc(signum=0, frame=0, pid=False):
    if not pid:
        pid = os.getpid()
    if sys.platform.startswith('win'):
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(1, 0, pid)
            kernel32.TerminateProcess(handle, 0)
        except Exception as e:
            trace(f"Error terminating process on Windows: {e}")
    else:
        try:
            os.kill(pid, 9)
        except Exception as e:
            trace(f"Error killing process: {e}")


verbose = False


def trace(*args, **kwargs):
    if verbose:
        sys.stderr.write(" ".join(map(str, args)) + "\n")


def error(*args, **kwargs):
    sys.stderr.write(" ".join(map(str, args)) + "\n")
    sys.exit(1)


def check_open(input_file):
    ret = []
    try:
        with open(input_file, 'r') as f:
            ret = f.readlines()
    except Exception as e:
        error(f"File error: {input_file} - {e}")
    if not ret:
        error(f"File is empty: {input_file}")
    return ret


def signal_init():
    signal.signal(signal.SIGINT, killproc)
    try:
        signal.signal(signal.SIGTSTP, killproc)
        signal.signal(signal.SIGQUIT, killproc)
    except AttributeError:
        pass


if __name__ == "__main__":
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
        multiprocessing.freeze_support()
    else:
        base_path = os.path.dirname(os.path.realpath(__file__))

    parser = optparse.OptionParser("usage: %prog [options] target")
    parser.add_option("-s", "--subs", dest="subs",
                      default=os.path.join(base_path, "names.txt"),
                      help="(optional) list of subdomains, default = 'names.txt'")
    parser.add_option("-r", "--resolvers", dest="resolvers",
                      default=os.path.join(base_path, "resolvers.txt"),
                      help="(optional) list of DNS resolvers, default = 'resolvers.txt'")
    parser.add_option("-t", "--targets_file", dest="targets", default="",
                      help="(optional) file with newline-delimited domains to brute force")
    parser.add_option("-o", "--output", dest="output", default=False,
                      help="(optional) output to file (Greppable Format)")
    parser.add_option("-j", "--json", dest="json", default=False,
                      help="(optional) output to file (JSON Format)")
    parser.add_option("-a", "-A", action='store_true', dest="ipv4", default=False,
                      help="(optional) print all IPv4 addresses (default=off)")
    parser.add_option("--type", dest="type", default=False,
                      help="(optional) DNS record type (CNAME, AAAA, TXT, etc)")
    parser.add_option("-c", "--process_count", dest="process_count",
                      default=16, type="int",
                      help="(optional) number of lookup threads (default=16)")
    parser.add_option("-f", "--filter_subs", dest="filter", default="",
                      help="(optional) filter unorganized domains into subdomains list")
    parser.add_option("-v", "--verbose", action='store_true', dest="verbose", default=False,
                      help="(optional) print debug information")

    (options, args) = parser.parse_args()
    verbose = options.verbose

    if len(args) < 1 and options.filter == "" and options.targets == "":
        parser.error("You must provide a target. Use -h for help.")

    if options.filter != "":
        for d in extract_subdomains(options.filter):
            print(d)
        sys.exit()

    targets = check_open(options.targets) if options.targets else args

    output_file = None
    if options.output:
        try:
            output_file = open(options.output, "w")
        except Exception as e:
            error(f"Failed to write to output file: {e}")

    json_file = None
    if options.json:
        try:
            json_file = open(options.json, "w")
        except Exception as e:
            error(f"Failed to write to JSON file: {e}")

    record_type = False
    if options.ipv4:
        record_type = "A"
    if options.type:
        record_type = str(options.type).upper()

    for target in targets:
        target = target.strip()
        if target:
            print_target(target, record_type, options.subs, options.resolvers,
                         options.process_count, output_file, json_file)

    if output_file:
        output_file.close()
    if json_file:
        json_file.close()