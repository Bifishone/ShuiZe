#!/usr/bin/env python
# coding: utf-8
import re
import sys
import os
import argparse
import time
import hashlib
import random
import multiprocessing
import threading
import socket
import json
from collections import Counter
import warnings
from bs4 import BeautifulSoup  # 新增HTML解析库

# 忽略SSL证书验证警告
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
sys.path.append(os.path.dirname(os.path.abspath(__file__)))  # 优化路径导入
import dns.resolver
import requests

# Python 3 兼容性处理
import urllib.parse as urlparse
import urllib.parse as urllib

# 禁用SSL警告
try:
    import requests.packages.urllib3

    requests.packages.urllib3.disable_warnings()
except:
    pass

# 检查是否为Windows平台
is_windows = sys.platform.startswith('win')

# 控制台颜色
if is_windows:
    G = '\033[92m'  # 绿色
    Y = '\033[93m'  # 黄色
    B = '\033[94m'  # 蓝色
    R = '\033[91m'  # 红色
    W = '\033[0m'  # 白色
    try:
        import win_unicode_console, colorama

        win_unicode_console.enable()
        colorama.init()
    except ImportError:
        G = Y = B = R = W = ''
else:
    G = '\033[92m'  # 绿色
    Y = '\033[93m'  # 黄色
    B = '\033[94m'  # 蓝色
    R = '\033[91m'  # 红色
    W = '\033[0m'  # 白色


def banner():
    pass


def parser_error(errmsg):
    banner()
    print(f"Usage: python {sys.argv[0]} [Options] use -h for help")
    print(f"{R}Error: {errmsg}{W}")
    sys.exit(1)  # 规范退出码


def parse_args():
    parser = argparse.ArgumentParser(epilog=f'\tExample: \r\npython {sys.argv[0]} -d google.com')
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain name to enumerate it's subdomains", required=True)
    parser.add_argument('-b', '--bruteforce', help='Enable the subbrute bruteforce module',
                        action='store_true')  # 改为布尔值参数
    parser.add_argument('-p', '--ports', help='Scan the found subdomains against specified tcp ports')
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime',
                        action='store_true')  # 改为布尔值参数
    parser.add_argument('-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int,
                        default=30)
    parser.add_argument('-e', '--engines', help='Specify a comma-separated list of search engines')
    parser.add_argument('-o', '--output', help='Save the results to text file')
    return parser.parse_args()


def write_file(filename, subdomains):
    try:
        file_path = os.path.abspath(filename)
        print(f"{Y}[+] Saving results to file: {W}{R}{file_path}{W}")
        with open(file_path, 'wt', encoding='utf-8') as f:
            for subdomain in subdomains:
                f.write(subdomain + '\n')
    except IOError as e:
        print(f"{R}[!] 无法写入文件 {filename}: {str(e)}{W}")


def subdomain_sorting_key(hostname):
    parts = hostname.split('.')[::-1]
    if parts and parts[-1] == 'www':
        return parts[:-1], 1
    return parts, 0


class enumratorBase(object):
    # User-Agent池，减少被封锁概率
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
    ]

    def __init__(self, base_url, engine_name, domain, subdomains=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.domain = urlparse.urlparse(domain).netloc or domain
        self.session = requests.Session()
        self.subdomains = []
        self.timeout = 30  # 延长超时时间
        self.base_url = base_url
        self.engine_name = engine_name
        self.silent = silent
        self.verbose = verbose
        self.headers = {
            'User-Agent': random.choice(self.USER_AGENTS),  # 随机选择User-Agent
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
        }
        self.print_banner()

    def print_(self, text):
        if not self.silent:
            print(text)

    def print_banner(self):
        return

    def send_req(self, query, page_no=1):
        try:
            url = self.base_url.format(query=urllib.quote(query), page_no=page_no)
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            resp.raise_for_status()
            return resp.content.decode('utf-8', errors='ignore')  # 处理编码问题
        except requests.exceptions.RequestException as e:
            self.print_(f"{R}[!] {self.engine_name} 请求错误: {str(e)}{W}")
            return None

    def check_max_subdomains(self, count):
        if self.MAX_DOMAINS == 0:
            return False
        return count >= self.MAX_DOMAINS

    def check_max_pages(self, num):
        if self.MAX_PAGES == 0:
            return False
        return num >= self.MAX_PAGES

    def extract_domains(self, resp):
        return []

    def check_response_errors(self, resp):
        return True if resp else False

    def should_sleep(self):
        time.sleep(random.uniform(1, 3))  # 调整休眠时间

    def generate_query(self):
        return ""

    def get_page(self, num):
        return num + 10

    def enumerate(self, altquery=False):
        flag = True
        page_no = 0
        prev_links = []
        retries = 0

        while flag and retries < 3:
            query = self.generate_query()
            if not query:
                break

            count = query.count(self.domain)

            if self.check_max_subdomains(count):
                page_no = self.get_page(page_no)

            if self.check_max_pages(page_no):
                return self.subdomains

            resp = self.send_req(query, page_no)
            if not self.check_response_errors(resp):
                return self.subdomains

            links = self.extract_domains(resp)

            if links == prev_links:
                retries += 1
                page_no = self.get_page(page_no)
                if retries >= 3:
                    break
            else:
                retries = 0

            prev_links = links
            self.should_sleep()

        return self.subdomains


class enumratorBaseThreaded(multiprocessing.Process, enumratorBase):
    def __init__(self, base_url, engine_name, domain, subdomains=None, q=None, lock=threading.Lock(), silent=False,
                 verbose=True):
        subdomains = subdomains or []
        enumratorBase.__init__(self, base_url, engine_name, domain, subdomains, silent=silent, verbose=verbose)
        multiprocessing.Process.__init__(self)
        self.lock = lock
        self.q = q if q is not None else multiprocessing.Manager().list()  # 统一进程安全队列
        return

    def run(self):
        try:
            domain_list = self.enumerate()
            for domain in domain_list:
                if domain not in self.q:
                    self.q.append(domain)
        except Exception as e:
            self.print_(f"{R}[!] {self.engine_name} 线程错误: {str(e)}{W}")


class GoogleEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = "https://google.com/search?q={query}&btnG=Search&hl=en-US&biw=&bih=&gbv=1&start={page_no}&filter=0"
        self.engine_name = "Google"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 200
        super(GoogleEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent,
                                         verbose=verbose)
        return

    def extract_domains(self, resp):
        links_list = []
        if not resp:
            return links_list

        try:
            soup = BeautifulSoup(resp, 'html.parser')
            # 使用BeautifulSoup替代正则解析
            for cite in soup.find_all('cite'):
                link = cite.get_text(strip=True)
                link = re.sub('<span.*?>.*?</span>', '', link, flags=re.IGNORECASE | re.DOTALL)
                if not link.startswith(('http://', 'https://')):
                    link = "http://" + link
                parsed = urlparse.urlparse(link)
                subdomain = parsed.netloc or parsed.path.split('/')[0]
                if subdomain and subdomain.endswith(
                        self.domain) and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                    self.subdomains.append(subdomain.strip())
                    links_list.append(link)
        except Exception as e:
            self.print_(f"{R}[!] {self.engine_name} 解析错误: {str(e)}{W}")
        return links_list

    def check_response_errors(self, resp):
        if resp and 'Our systems have detected unusual traffic' in resp:
            self.print_(f"{R}[!] Google 可能阻止了我们的请求，请稍后再试{W}")
            self.print_(f"{R}[~] 结束 Google 枚举...{W}")
            return False
        return True


class BingEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.bing.com/search?q={query}&go=Submit&first={page_no}'
        self.engine_name = "Bing"
        self.MAX_DOMAINS = 30
        self.MAX_PAGES = 0
        super(BingEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent,
                                       verbose=verbose)
        return

    def extract_domains(self, resp):
        links_list = []
        if not resp:
            return links_list

        try:
            soup = BeautifulSoup(resp, 'html.parser')
            # 解析Bing搜索结果链接
            for a in soup.select('li.b_algo h2 a, div.b_title h2 a'):
                link = a.get('href', '')
                if link:
                    link = re.sub('<(\/)?strong>|<span.*?>|<|>', '', link)
                    if not link.startswith(('http://', 'https://')):
                        link = "http://" + link
                    subdomain = urlparse.urlparse(link).netloc
                    if subdomain and subdomain.endswith(
                            self.domain) and subdomain not in self.subdomains and subdomain != self.domain:
                        if self.verbose:
                            self.print_(f"{R}{self.engine_name}: {W}{subdomain}")
                        self.subdomains.append(subdomain.strip())
                        links_list.append(link)
        except Exception as e:
            self.print_(f"{R}[!] {self.engine_name} 解析错误: {str(e)}{W}")
        return links_list

    def generate_query(self):
        if self.subdomains:
            fmt = 'domain:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = f"domain:{self.domain} -www.{self.domain}"
        return query


# 省略其他枚举类的类似优化（主要是用BeautifulSoup替换正则解析）


class portscan():
    def __init__(self, subdomains, ports, threads=20):
        self.subdomains = subdomains
        self.ports = ports
        self.threads = threads  # 允许配置线程数
        self.lock = threading.BoundedSemaphore(value=self.threads)

    def port_scan(self, host, ports):
        openports = []
        self.lock.acquire()
        try:
            for port in ports:
                try:
                    port_int = int(port)
                    if not (1 <= port_int <= 65535):  # 端口范围验证
                        continue
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(3)  # 延长超时时间
                        result = s.connect_ex((host, port_int))
                        if result == 0:
                            openports.append(str(port_int))
                except (ValueError, OverflowError):
                    continue
        except Exception as e:
            print(f"{R}[!] 端口扫描错误 {host}: {str(e)}{W}")
        finally:
            self.lock.release()

        if openports:
            print(f"{G}{host}{W} - {R}Found open ports:{W} {Y}{', '.join(openports)}{W}")

    def run(self):
        threads = []
        for subdomain in self.subdomains:
            t = threading.Thread(target=self.port_scan, args=(subdomain, self.ports))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()


def main(domain, threads, savefile, ports, silent, verbose, enable_bruteforce, engines):
    bruteforce_list = set()
    search_list = set()

    # 使用进程安全的队列
    subdomains_queue = multiprocessing.Manager().list()

    # 验证域名格式（优化正则）
    domain_check = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    if not domain_check.match(domain):
        if not silent:
            print(f"{R}Error: 请输入有效的域名（无需http/https前缀）{W}")
        return []

    # 处理域名格式
    parsed_domain = urlparse.urlparse(domain)
    domain_netloc = parsed_domain.netloc or parsed_domain.path.split('/')[0]
    domain_netloc = domain_netloc.split(':')[0]  # 移除端口

    if not silent:
        print(f"{B}[-] 正在枚举 {domain_netloc} 的子域名{W}")

    if verbose and not silent:
        print(f"{Y}[-] 已启用详细模式，将实时显示子域名结果{W}")

    # 支持的搜索引擎
    supported_engines = {
        'baidu': BaiduEnum,
        'bing': BingEnum,
        'google': GoogleEnum,
        'dnsdumpster': DNSdumpster,
        'virustotal': Virustotal,
        'ssl': CrtSearch
    }

    chosenEnums = []
    if engines is None:
        chosenEnums = [BaiduEnum, BingEnum, GoogleEnum, DNSdumpster, Virustotal, CrtSearch]
    else:
        engines = [e.strip().lower() for e in engines.split(',')]
        for engine in engines:
            if engine in supported_engines:
                chosenEnums.append(supported_engines[engine])

    # 启动引擎枚举
    enums = [enum(domain_netloc, [], q=subdomains_queue, silent=silent, verbose=verbose) for enum in chosenEnums]
    for enum in enums:
        enum.start()
    for enum in enums:
        enum.join()

    # 收集结果
    subdomains = set(subdomains_queue)
    for subdomain in subdomains:
        search_list.add(subdomain)

    # 暴力破解模块（如果启用）
    if enable_bruteforce:
        if not silent:
            print(f"{G}[-] 正在启动暴力破解模块...{W}")
        try:
            # 优化subbrute导入路径
            from subbrute import subbrute  # 假设subbrute在同一目录
            record_type = False
            path_to_file = os.path.dirname(os.path.abspath(__file__))
            subs = os.path.join(path_to_file, 'subbrute', 'names.txt')
            resolvers = os.path.join(path_to_file, 'subbrute', 'resolvers.txt')

            # 验证文件存在性
            if not os.path.exists(subs):
                raise FileNotFoundError(f"subbrute名称文件不存在: {subs}")
            if not os.path.exists(resolvers):
                raise FileNotFoundError(f"解析器文件不存在: {resolvers}")

            bruteforce_results = subbrute.print_target(
                domain_netloc, record_type, subs, resolvers,
                threads, False, False, search_list, verbose
            )
            bruteforce_list = set(bruteforce_results)
        except ImportError:
            print(f"{R}[!] 无法导入subbrute模块，跳过暴力破解{W}")
        except Exception as e:
            print(f"{R}[!] 暴力破解模块错误: {str(e)}{W}")

    # 合并结果并排序
    all_subdomains = search_list.union(bruteforce_list)
    if all_subdomains:
        all_subdomains = sorted(all_subdomains, key=subdomain_sorting_key)

        if savefile:
            write_file(savefile, all_subdomains)

        if not silent:
            print(f"{Y}[+] 找到的唯一子域名总数: {len(all_subdomains)}{W}")

        # 端口扫描（如果指定）
        if ports:
            if not silent:
                print(f"{G}[-] 开始端口扫描，端口: {Y}{ports}{W}")
            ports_list = ports.split(',')
            pscan = portscan(all_subdomains, ports_list, threads=min(50, threads))  # 限制最大线程数
            pscan.run()
        elif not silent:
            for subdomain in all_subdomains:
                print(f"{G}{subdomain}{W}")

    return list(all_subdomains)


def sublist3rRun(domain):
    threads = 30
    savefile = None
    ports = None
    enable_bruteforce = False
    verbose = False
    engines = 'baidu, dnsdumpster, virustotal'

    banner()
    return main(
        domain, threads, savefile, ports,
        silent=False, verbose=verbose,
        enable_bruteforce=enable_bruteforce,
        engines=engines
    )


if __name__ == '__main__':
    try:
        args = parse_args()
        main(
            args.domain, args.threads, args.output, args.ports,
            silent=False, verbose=args.verbose,
            enable_bruteforce=args.bruteforce,
            engines=args.engines
        )
    except KeyboardInterrupt:
        print(f"\n{R}[!] 用户中断操作{W}")
        sys.exit(1)