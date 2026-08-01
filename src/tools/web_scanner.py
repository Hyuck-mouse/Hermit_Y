import asyncio
import aiohttp
import dns.resolver
from typing import List, Dict, Any, Optional


class WebScanner:
    def __init__(self):
        self.session = None

    async def _get_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
        return self.session

    async def directory_brute(self, base_url: str, wordlist: List[str]) -> Dict[str, Any]:
        results = []
        session = await self._get_session()
        
        async def check_path(path):
            url = f"{base_url}/{path}" if not base_url.endswith("/") else f"{base_url}{path}"
            try:
                async with session.get(url) as response:
                    if response.status in [200, 401, 403]:
                        return {"path": path, "status": response.status, "url": url}
            except:
                pass
            return None

        tasks = [check_path(path) for path in wordlist]
        responses = await asyncio.gather(*tasks)
        
        results = [r for r in responses if r]
        return {"base_url": base_url, "found": results}

    async def subdomain_enum(self, domain: str, wordlist: List[str]) -> Dict[str, Any]:
        results = []
        
        async def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                if answers:
                    ips = [str(rdata.address) for rdata in answers]
                    return {"subdomain": full_domain, "ips": ips}
            except:
                pass
            return None

        tasks = [check_subdomain(sub) for sub in wordlist]
        responses = await asyncio.gather(*tasks)
        
        results = [r for r in responses if r]
        return {"domain": domain, "subdomains": results}

    async def fuzz_params(self, url: str, param_name: str, wordlist: List[str]) -> Dict[str, Any]:
        results = []
        session = await self._get_session()
        
        async def test_param(value):
            test_url = url.replace(f"{{{param_name}}}", value)
            try:
                async with session.get(test_url) as response:
                    return {
                        "value": value,
                        "status": response.status,
                        "url": test_url,
                        "length": len(await response.text())
                    }
            except:
                return None

        tasks = [test_param(val) for val in wordlist]
        responses = await asyncio.gather(*tasks)
        
        results = [r for r in responses if r]
        return {"url": url, "param": param_name, "results": results}

    async def detect_waf(self, url: str) -> Dict[str, Any]:
        session = await self._get_session()
        
        test_payloads = [
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "' UNION SELECT 1,2,3--"
        ]
        
        waf_signatures = {
            "Cloudflare": ["cloudflare", "cf-ray"],
            "Akamai": ["akamai"],
            "AWS WAF": ["x-amzn-trace-id"],
            "ModSecurity": ["mod-security", "modsecurity"]
        }
        
        results = {"detected": None, "evidence": []}
        
        try:
            for payload in test_payloads:
                test_url = f"{url}?test={payload}"
                async with session.get(test_url) as response:
                    headers = dict(response.headers)
                    
                    for waf_name, signatures in waf_signatures.items():
                        for signature in signatures:
                            if any(signature.lower() in str(v).lower() for v in headers.values()):
                                results["detected"] = waf_name
                                results["evidence"].append(f"Header contains {signature}")
                                return results
                            
                            if signature.lower() in (await response.text()).lower():
                                results["detected"] = waf_name
                                results["evidence"].append(f"Response contains {signature}")
                                return results
        except Exception as e:
            results["error"] = str(e)
        
        return results

    async def check_headers(self, url: str) -> Dict[str, Any]:
        session = await self._get_session()
        
        security_headers = {
            "X-Content-Type-Options": "Expected: nosniff",
            "X-Frame-Options": "Expected: DENY or SAMEORIGIN",
            "Content-Security-Policy": "Should be set",
            "X-XSS-Protection": "Expected: 1; mode=block",
            "Strict-Transport-Security": "Should be set",
            "Referrer-Policy": "Should be set"
        }
        
        results = {"missing": [], "present": [], "url": url}
        
        try:
            async with session.get(url) as response:
                headers = dict(response.headers)
                
                for header, expected in security_headers.items():
                    if header in headers:
                        results["present"].append(f"{header}: {headers[header]}")
                    else:
                        results["missing"].append(f"{header}: {expected}")
        except Exception as e:
            results["error"] = str(e)
        
        return results

    async def close(self):
        if self.session:
            await self.session.close()
