# discovery/bufferoverun.py
from Plugins.infoGather.subdomain.theHarvester.runTheHarvester.lib.core import *
import re


class SearchBufferover:
    def __init__(self, word):
        self.word = word
        self.totalhosts = set()
        self.totalips = set()
        self.proxy = False

    async def do_search(self):
        url = f'https://dns.bufferover.run/dns?q=.{self.word}'
        responses = await AsyncFetcher.fetch_all(urls=[url], json=True, proxy=self.proxy)
        responses = responses[0] if responses else {}
        dct = responses

        fdns_a = dct.get('FDNS_A', [])
        self.totalhosts = set()
        for host in fdns_a:
            if ',' in host:
                parts = host.split(',')
                part0 = parts[0].replace('www.', '')
                if self.word.replace('www.', '') in part0:
                    self.totalhosts.add(part0)
                else:
                    if len(parts) > 1:
                        self.totalhosts.add(parts[1].replace('www.', ''))
            else:
                self.totalhosts.add(host.replace('www.', ''))

        self.totalips = {
            ip.split(',')[0] for ip in fdns_a
            if ',' in ip and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip.split(',')[0])
        }

    async def get_hostnames(self) -> set:
        return self.totalhosts

    async def get_ips(self) -> set:
        return self.totalips

    async def process(self, proxy=False):
        self.proxy = proxy
        await self.do_search()