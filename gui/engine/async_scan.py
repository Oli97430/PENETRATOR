from gui.engine._core import *
from gui.engine.recon import get_service, find_subdomains
from gui.engine.web import buster, sqli_detect, xss_reflected
from gui.engine.advanced import cors_test, open_redirect_test

# ---------------------------------------------------------------------------
# Async helper — safe coroutine execution (handles nested event loops)
# ---------------------------------------------------------------------------
def _run_async(coro_fn):
    """Run an async coroutine safely, even if called from inside an event loop.

    Prefers asyncio.run(); falls back to a new event loop only when the specific
    'cannot be called from a running event loop' error is detected.
    """
    import asyncio
    try:
        asyncio.run(coro_fn())
    except RuntimeError as exc:
        if "running event loop" not in str(exc) and "cannot" not in str(exc):
            raise  # Re-raise unrelated RuntimeErrors
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(coro_fn())
        finally:
            loop.close()


# ---------------------------------------------------------------------------
# Async port scanner — asyncio replaces the thread pool for ~5x speed
# ---------------------------------------------------------------------------
def scan_ports_async(target: str, start: int, end: int, concurrency: int,
                     timeout: float, log: Logger) -> list[int]:
    """Asyncio-based TCP scan. Massive speedup vs scan_ports() on big ranges."""
    import asyncio
    import socket as _socket

    try:
        ip = _socket.gethostbyname(target)
    except _socket.gaierror as exc:
        log(f"[-] Cannot resolve {target}: {exc}", "err")
        return []

    log(f"[*] Async scan {target} ({ip})  ports {start}-{end}  "
        f"concurrency={concurrency}", "cyan")

    open_ports: list[int] = []
    sem = None  # set inside the coroutine

    async def probe(port: int) -> None:
        """Attempt a TCP connection to a single port."""
        async with sem:
            if _should_stop():
                return
            try:
                fut = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception as exc:
                    log(f"  [-] {port}/tcp writer close: {exc}", "muted")
                open_ports.append(port)
                log(f"[+] {port:>5}/tcp   {get_service(port)}", "ok")
            except (asyncio.TimeoutError, OSError, ConnectionError):
                pass
            except Exception as exc:
                log(f"  [-] {port}/tcp: {exc}", "muted")

    async def runner() -> None:
        """Launch all port probes with a concurrency semaphore."""
        nonlocal sem
        sem = asyncio.Semaphore(concurrency)
        await asyncio.gather(*(probe(p) for p in range(start, end + 1)),
                             return_exceptions=True)

    t0 = time.time()
    _run_async(runner)
    log(f"[*] Found {len(open_ports)} open port(s) in {time.time() - t0:.2f}s "
        "(async)", "cyan")
    sorted_ports = sorted(open_ports)
    session_set("last_target", target)
    session_set("last_open_ports", sorted_ports)
    return sorted_ports


# ---------------------------------------------------------------------------
# Async directory buster
# ---------------------------------------------------------------------------
def buster_async(url: str, paths: list[str], concurrency: int,
                 log: Logger) -> list[tuple[int, str]]:
    """Asyncio-based directory buster — far faster on big wordlists."""
    import asyncio
    try:
        import aiohttp  # type: ignore
    except ImportError:
        log("[!] aiohttp not installed — falling back to threaded buster", "warn")
        import gui.engine as _eng
        return _eng.buster(url, paths, max(concurrency // 5, 10), log)

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    url = url.rstrip("/") + "/"

    found: list[tuple[int, str]] = []
    log(f"[*] Async-busting {url} with {len(paths)} paths "
        f"concurrency={concurrency}", "cyan")

    async def runner() -> None:
        """Run all directory probes concurrently via aiohttp."""
        sem = asyncio.Semaphore(concurrency)
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": random_ua()},
        ) as session:
            async def probe(path: str) -> None:
                """Probe a single path via HEAD/GET."""
                async with sem:
                    if _should_stop():
                        return
                    target = url + path.lstrip("/")
                    try:
                        async with session.head(target,
                                                allow_redirects=False) as r:
                            status = r.status
                        if status == 405:
                            async with session.get(target,
                                                   allow_redirects=False) as r:
                                status = r.status
                    except Exception as exc:
                        log(f"  [-] {exc}", "muted")
                        return
                    if status in (200, 201, 202, 204, 301, 302, 307, 401, 403):
                        found.append((status, target))
                        log(f"[+] {status}  {target}", "ok")

            await asyncio.gather(*(probe(p) for p in paths),
                                 return_exceptions=True)

    t0 = time.time()
    _run_async(runner)
    log(f"[*] Discovered {len(found)} endpoint(s) in {time.time()-t0:.2f}s "
        "(async)", "cyan")
    return sorted(found)


# ---------------------------------------------------------------------------
# Async subdomain finder
# ---------------------------------------------------------------------------
def find_subdomains_async(domain: str, concurrency: int,
                          log: Logger) -> list[tuple[str, str]]:
    """Asyncio DNS resolution of common subdomains."""
    import asyncio
    import socket as _socket

    found: list[tuple[str, str]] = []
    log(f"[*] Async subdomain enum for {domain} ({len(COMMON_SUBDOMAINS)} probes)",
        "cyan")

    loop = None  # set in runner

    async def probe(sub: str) -> None:
        """Resolve a single subdomain asynchronously."""
        if _should_stop():
            return
        host = f"{sub}.{domain}"
        try:
            ip = await loop.getaddrinfo(host, None,
                                        family=_socket.AF_INET,
                                        type=_socket.SOCK_STREAM)
            ip_str = ip[0][4][0]
            found.append((sub, ip_str))
            log(f"[+] {host} -> {ip_str}", "ok")
        except (_socket.gaierror, OSError):
            pass

    async def runner() -> None:
        """Launch all subdomain probes with a concurrency semaphore."""
        nonlocal loop
        loop = asyncio.get_running_loop()
        sem = asyncio.Semaphore(concurrency)

        async def bounded(sub):
            """Wrap probe() with a semaphore for concurrency control."""
            async with sem:
                await probe(sub)

        await asyncio.gather(*(bounded(s) for s in COMMON_SUBDOMAINS),
                             return_exceptions=True)

    t0 = time.time()
    _run_async(runner)
    log(f"[*] {len(found)} subdomain(s) in {time.time()-t0:.2f}s (async)",
        "cyan")
    return sorted(found)


# ---------------------------------------------------------------------------
# Async SQLi detection
# ---------------------------------------------------------------------------
def sqli_detect_async(url: str, concurrency: int,
                      log: Logger) -> list[tuple[str, str, str]]:
    """Async SQL injection scanner — tests all params × payloads concurrently."""
    import asyncio
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
    try:
        import aiohttp
    except ImportError:
        log("[!] aiohttp not installed — falling back to threaded sqli_detect", "warn")
        import gui.engine as _eng
        return _eng.sqli_detect(url, log)

    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    if not params:
        log("[-] URL has no query parameters to test.", "err")
        return []

    findings: list[tuple[str, str, str]] = []
    log(f"[*] Async SQLi scan on {len(params)} param(s) × {len(SQL_PAYLOADS)} payloads "
        f"concurrency={concurrency}", "cyan")

    async def runner() -> None:
        """Run all SQLi probes concurrently via aiohttp."""
        sem = asyncio.Semaphore(concurrency)
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": random_ua()},
        ) as session:
            async def probe(param: str, payload: str) -> None:
                """Test one parameter with one payload."""
                async with sem:
                    if _should_stop():
                        return
                    mutated = dict(params)
                    mutated[param] = params[param] + payload
                    test_url = urlunparse(
                        parsed._replace(query=urlencode(mutated)))
                    try:
                        async with session.get(test_url,
                                               allow_redirects=False) as r:
                            body = (await r.text()).lower()
                    except Exception as exc:
                        log(f"  [-] {exc}", "muted")
                        return
                    for sig in SQL_ERROR_SIGNATURES:
                        if sig in body:
                            findings.append((param, payload, sig))
                            log(f"[+] {param}  payload={payload}  indicator={sig}",
                                "ok")
                            break

            tasks = [probe(p, pl) for p in params for pl in SQL_PAYLOADS]
            await asyncio.gather(*tasks, return_exceptions=True)

    t0 = time.time()
    _run_async(runner)
    log(f"[*] SQLi scan done in {time.time() - t0:.2f}s (async)", "cyan")
    if not findings:
        log("[!] No obvious SQL injection indicator found", "warn")
    session_set("last_sqli_result", findings)
    return findings


# ---------------------------------------------------------------------------
# Async XSS reflected scanner
# ---------------------------------------------------------------------------
def xss_reflected_async(url: str, concurrency: int,
                        log: Logger) -> list[tuple[str, str]]:
    """Async reflected XSS scanner — tests all params × payloads concurrently."""
    import asyncio
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
    try:
        import aiohttp
    except ImportError:
        log("[!] aiohttp not installed — falling back to threaded xss_reflected", "warn")
        import gui.engine as _eng
        return _eng.xss_reflected(url, log)

    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    if not params:
        log("[-] URL has no query parameters to test.", "err")
        return []

    findings: list[tuple[str, str]] = []
    marker = "penetx1337"
    log(f"[*] Async XSS scan on {len(params)} param(s) × {len(XSS_PAYLOADS_BASIC)} payloads "
        f"concurrency={concurrency}", "cyan")

    async def runner() -> None:
        """Run all XSS probes concurrently via aiohttp."""
        sem = asyncio.Semaphore(concurrency)
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": random_ua()},
        ) as session:
            async def probe(param: str, payload: str) -> None:
                """Test one parameter with one payload for reflection."""
                async with sem:
                    if _should_stop():
                        return
                    marked = payload.replace("alert(1)", f"alert('{marker}')")
                    mutated = dict(params)
                    mutated[param] = marked
                    test_url = urlunparse(
                        parsed._replace(
                            query=urlencode(mutated, safe="<>\"'/=()")))
                    try:
                        async with session.get(test_url,
                                               allow_redirects=False) as r:
                            body = await r.text()
                    except Exception as exc:
                        log(f"  [-] {exc}", "muted")
                        return
                    if marked in body:
                        findings.append((param, marked))
                        log(f"[+] Reflected: {marked}", "ok")

            tasks = [probe(p, pl) for p in params for pl in XSS_PAYLOADS_BASIC]
            await asyncio.gather(*tasks, return_exceptions=True)

    t0 = time.time()
    _run_async(runner)
    log(f"[*] XSS scan done in {time.time() - t0:.2f}s (async)", "cyan")
    if not findings:
        log("[!] No reflected payloads detected", "warn")
    session_set("last_xss_result", findings)
    return findings


# ---------------------------------------------------------------------------
# Async CORS misconfiguration tester
# ---------------------------------------------------------------------------
def cors_test_async(url: str, concurrency: int,
                    log: Logger) -> dict:
    """Async CORS misconfiguration tester — probes origins concurrently."""
    import asyncio
    from urllib.parse import urlparse
    try:
        import aiohttp
    except ImportError:
        log("[!] aiohttp not installed — falling back to threaded cors_test", "warn")
        import gui.engine as _eng
        return _eng.cors_test(url, log)

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    origins = [
        "https://evil.com",
        f"https://{parsed.hostname}.evil.com",
        "null",
        f"http://attacker.{parsed.hostname}",
        "https://" + (parsed.hostname or "") + ".attacker.io",
    ]
    findings: list[dict] = []
    log(f"[*] Async CORS test {url}  ({len(origins)} origins)", "cyan")

    async def runner() -> None:
        """Probe all origins concurrently."""
        sem = asyncio.Semaphore(concurrency)
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": random_ua()},
        ) as session:
            async def probe(origin: str) -> None:
                """Test one origin header for CORS misconfiguration."""
                async with sem:
                    if _should_stop():
                        return
                    try:
                        async with session.get(
                            url,
                            headers={"Origin": origin},
                            allow_redirects=True,
                        ) as r:
                            acao = r.headers.get("Access-Control-Allow-Origin")
                            acac = r.headers.get("Access-Control-Allow-Credentials")
                    except Exception as exc:
                        log(f"  [-] {origin}: {exc}", "muted")
                        return
                    risky = False
                    notes: list[str] = []
                    if acao == origin:
                        risky = True
                        notes.append("reflected origin")
                    if acao == "*":
                        notes.append("wildcard")
                    if acac and acac.lower() == "true" and acao and acao != "*":
                        notes.append("creds=true with non-wildcard ACAO")
                        risky = True
                    tag = "err" if risky else "info"
                    log(f"  Origin={origin}  ACAO={acao}  ACAC={acac}  "
                        f"{' / '.join(notes)}", tag)
                    findings.append({"origin": origin, "acao": acao,
                                     "acac": acac, "risky": risky,
                                     "notes": notes})

            await asyncio.gather(*(probe(o) for o in origins),
                                 return_exceptions=True)

    t0 = time.time()
    _run_async(runner)
    risky_n = sum(1 for f in findings if f.get("risky"))
    log(f"[*] {risky_n} risky CORS config(s) in {time.time() - t0:.2f}s (async)",
        "warn" if risky_n else "ok")
    result = {"findings": findings}
    session_set("last_cors_result", result)
    return result


# ---------------------------------------------------------------------------
# Async open-redirect tester
# ---------------------------------------------------------------------------
def open_redirect_test_async(url: str, concurrency: int,
                             log: Logger) -> list[tuple[str, str]]:
    """Async open-redirect scanner — tests params × payloads concurrently."""
    import asyncio
    from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
    try:
        import aiohttp
    except ImportError:
        log("[!] aiohttp not installed — falling back to threaded open_redirect_test",
            "warn")
        import gui.engine as _eng
        return _eng.open_redirect_test(url, log)

    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    if not params:
        log("[-] URL has no query parameters to test.", "err")
        return []

    redirect_payloads = [
        "https://evil.example.com",
        "//evil.example.com",
        "/\\evil.example.com",
        "https:%2f%2fevil.example.com",
        "https://example.com@evil.example.com",
    ]
    findings: list[tuple[str, str]] = []
    log(f"[*] Async redirect test on {len(params)} param(s) × "
        f"{len(redirect_payloads)} payloads  concurrency={concurrency}", "cyan")

    async def runner() -> None:
        """Run all redirect probes concurrently."""
        sem = asyncio.Semaphore(concurrency)
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": random_ua()},
        ) as session:
            async def probe(param: str, payload: str) -> None:
                """Test one param+payload combo for open redirect."""
                async with sem:
                    if _should_stop():
                        return
                    mut = dict(params)
                    mut[param] = payload
                    test_url = urlunparse(
                        parsed._replace(query=urlencode(mut)))
                    try:
                        async with session.get(
                            test_url,
                            allow_redirects=False,
                        ) as r:
                            loc = r.headers.get("Location", "")
                    except Exception as exc:
                        log(f"  [-] {exc}", "muted")
                        return
                    if loc and "evil.example.com" in loc:
                        findings.append((param, payload))
                        log(f"[+] Redirect via {param}={payload}  "
                            f"Location={loc}", "err")

            tasks = [probe(p, pl) for p in params for pl in redirect_payloads]
            await asyncio.gather(*tasks, return_exceptions=True)

    t0 = time.time()
    _run_async(runner)
    log(f"[*] Redirect test done in {time.time() - t0:.2f}s (async)", "cyan")
    if not findings:
        log("[+] No open-redirect indicator found", "ok")
    session_set("last_open_redirect", findings)
    return findings

