"""OSINT tools: email checks, IP geolocation, username search, reverse DNS."""
from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table

from core.i18n import t
from core.menu import Menu, MenuItem
from core.utils import (
    ask_input,
    pause,
    print_error,
    print_info,
    print_success,
    print_warning,
)

console = Console()

EMAIL_REGEX = re.compile(
    r"^[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$"
)

USERNAME_SITES: dict[str, str] = {
    "GitHub":     "https://github.com/{u}",
    "GitLab":     "https://gitlab.com/{u}",
    "Twitter/X":  "https://x.com/{u}",
    "Instagram":  "https://www.instagram.com/{u}/",
    "Reddit":     "https://www.reddit.com/user/{u}",
    "Medium":     "https://medium.com/@{u}",
    "DevTo":      "https://dev.to/{u}",
    "Hashnode":   "https://hashnode.com/@{u}",
    "HackerNews": "https://news.ycombinator.com/user?id={u}",
    "HackerOne":  "https://hackerone.com/{u}",
    "Bugcrowd":   "https://bugcrowd.com/{u}",
    "Pinterest":  "https://www.pinterest.com/{u}/",
    "Twitch":     "https://www.twitch.tv/{u}",
    "YouTube":    "https://www.youtube.com/@{u}",
    "TikTok":     "https://www.tiktok.com/@{u}",
    "Keybase":    "https://keybase.io/{u}",
    "Steam":      "https://steamcommunity.com/id/{u}",
    "Vimeo":      "https://vimeo.com/{u}",
    "StackOverflow": "https://stackoverflow.com/users/{u}",
    "SoundCloud": "https://soundcloud.com/{u}",
}


def email_verify() -> None:
    email = ask_input(t("ui.email"))
    if not email:
        return
    match = EMAIL_REGEX.match(email.strip())
    if not match:
        print_error(t("modules.osint.invalid_syntax"))
        pause()
        return
    print_success(t("modules.osint.valid_syntax"))
    domain = match.group(1)

    try:
        import dns.resolver  # type: ignore
    except ImportError:
        print_warning("dnspython not installed; skipping MX lookup.")
        pause()
        return
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        for rdata in answers:
            print_info(t("modules.osint.mx_found", mx=str(rdata)))
    except Exception:
        print_warning(t("modules.osint.no_mx"))
    pause()


def ip_geolocate() -> None:
    try:
        import requests
    except ImportError:
        print_error("requests not installed. Run: pip install requests")
        pause()
        return
    target = ask_input(t("ui.ip"))
    if not target:
        return
    try:
        resp = requests.get(f"http://ip-api.com/json/{target}", timeout=8)
        data = resp.json()
    except Exception as exc:
        print_error(str(exc))
        pause()
        return
    if data.get("status") != "success":
        print_error(data.get("message", "lookup failed"))
        pause()
        return
    table = Table(title=f"Geolocation: {target}", border_style="green")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    for key in ("query", "country", "regionName", "city", "zip",
                "lat", "lon", "timezone", "isp", "org", "as"):
        if data.get(key):
            table.add_row(key, str(data[key]))
    console.print(table)
    pause()


def username_search() -> None:
    try:
        import requests
    except ImportError:
        print_error("requests not installed. Run: pip install requests")
        pause()
        return
    username = ask_input("Username").strip()
    if not username:
        return

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (PENETRATOR/1.0)",
        "Accept-Language": "en-US,en;q=0.9",
    })

    def check(site: str, tmpl: str) -> tuple[str, str, int]:
        url = tmpl.format(u=username)
        try:
            resp = session.get(url, timeout=8, allow_redirects=True)
            return site, url, resp.status_code
        except requests.RequestException:
            return site, url, 0

    table = Table(title=f"Username: {username}", border_style="green")
    table.add_column("Site", style="cyan")
    table.add_column("Status", justify="right")
    table.add_column("URL", style="dim", overflow="fold")

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(check, site, url) for site, url in USERNAME_SITES.items()]
        for fut in as_completed(futures):
            site, url, code = fut.result()
            if code == 200:
                table.add_row(site, f"[green]200[/]", url)
            elif code == 404:
                table.add_row(site, f"[dim]404[/]", url)
            elif code == 0:
                table.add_row(site, "[red]ERR[/]", url)
            else:
                table.add_row(site, str(code), url)
    console.print(table)
    print_warning("200 does not always mean 'exists' - some sites return 200 for any path.")
    pause()


def phone_info() -> None:
    try:
        import phonenumbers  # type: ignore
        from phonenumbers import carrier, geocoder, timezone  # type: ignore
    except ImportError:
        print_error("phonenumbers not installed. Run: pip install phonenumbers")
        pause()
        return
    number = ask_input("Phone number (with country code, e.g. +33...)")
    if not number:
        return
    try:
        parsed = phonenumbers.parse(number, None)
    except Exception as exc:
        print_error(str(exc))
        pause()
        return
    table = Table(border_style="green")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Valid", str(phonenumbers.is_valid_number(parsed)))
    table.add_row("Possible", str(phonenumbers.is_possible_number(parsed)))
    table.add_row("Country code", str(parsed.country_code))
    table.add_row("National number", str(parsed.national_number))
    table.add_row("Region", geocoder.description_for_number(parsed, "en"))
    table.add_row("Carrier", carrier.name_for_number(parsed, "en"))
    table.add_row("Timezones", ", ".join(timezone.time_zones_for_number(parsed)))
    table.add_row("E.164", phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164))
    table.add_row("International", phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
    console.print(table)
    pause()


def reverse_dns() -> None:
    ip = ask_input(t("ui.ip"))
    if not ip:
        return
    try:
        name, aliases, addrs = socket.gethostbyaddr(ip)
    except socket.herror as exc:
        print_error(str(exc))
        pause()
        return
    table = Table(border_style="green")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Hostname", name)
    table.add_row("Aliases", ", ".join(aliases) or "(none)")
    table.add_row("Addresses", ", ".join(addrs))
    console.print(table)
    pause()


def build_menu(parent: Menu | None = None) -> Menu:
    menu = Menu(title_key="modules.osint.title", parent=parent)
    menu.add(MenuItem("modules.osint.email_verify", email_verify,
                      "modules.osint.email_verify_desc"))
    menu.add(MenuItem("modules.osint.ip_geolocate", ip_geolocate,
                      "modules.osint.ip_geolocate_desc"))
    menu.add(MenuItem("modules.osint.username_search", username_search,
                      "modules.osint.username_search_desc"))
    menu.add(MenuItem("modules.osint.phone_info", phone_info,
                      "modules.osint.phone_info_desc"))
    menu.add(MenuItem("modules.osint.reverse_dns", reverse_dns,
                      "modules.osint.reverse_dns_desc"))
    return menu
