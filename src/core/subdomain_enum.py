import dns.asyncresolver
import aiohttp
import asyncio
from typing import List, Set

class SubdomainEnumerator:
    def __init__(self, wordlist: List[str] = None):
        if wordlist is None:
            # Minimal default wordlist; in production, load from file or config
            self.wordlist = ["www", "mail", "dev", "test", "api", "staging", "admin"]
        else:
            self.wordlist = wordlist

    async def dns_brute_force(self, domain: str) -> Set[str]:
        found = set()
        resolver = dns.asyncresolver.Resolver()
        tasks = []
        for sub in self.wordlist:
            fqdn = f"{sub}.{domain}"
            tasks.append(self._resolve(resolver, fqdn, found))
        await asyncio.gather(*tasks)
        return found

    async def _resolve(self, resolver, fqdn, found):
        try:
            await resolver.resolve(fqdn, "A")
            found.add(fqdn)
        except Exception:
            pass

    async def crtsh_enum(self, domain: str) -> Set[str]:
        found = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data:
                            name = entry.get("name_value", "")
                            for sub in name.split("\n"):
                                if sub.endswith(domain):
                                    found.add(sub.strip())
        except Exception:
            pass
        return found

    async def public_api_enum(self, domain: str) -> Set[str]:
        found = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        lines = text.splitlines()
                        for line in lines:
                            sub = line.split(",")[0]
                            if sub.endswith(domain):
                                found.add(sub.strip())
        except Exception:
            pass
        return found

    async def enumerate(self, domain: str) -> List[str]:
        results = set()
        dns_task = self.dns_brute_force(domain)
        crtsh_task = self.crtsh_enum(domain)
        api_task = self.public_api_enum(domain)
        dns_res, crtsh_res, api_res = await asyncio.gather(dns_task, crtsh_task, api_task)
        results.update(dns_res)
        results.update(crtsh_res)
        results.update(api_res)
        return sorted(results) 