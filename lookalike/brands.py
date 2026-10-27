import os
import re
from pathlib import Path

DEFAULT_BRANDS = """
google.com gmail.com youtube.com facebook.com instagram.com whatsapp.com microsoft.com
live.com outlook.com office.com apple.com icloud.com amazon.com paypal.com netflix.com
ebay.com linkedin.com twitter.com github.com dropbox.com adobe.com spotify.com
steampowered.com discord.com telegram.org binance.com coinbase.com chase.com
wellsfargo.com bankofamerica.com americanexpress.com dhl.com fedex.com usps.com
yahoo.com reddit.com twitch.tv tiktok.com cloudflare.com docusign.com zoom.us
stripe.com wetransfer.com
""".split()

_DOMAIN = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


def config_dir():
    home = os.environ.get("LOOKALIKE_HOME")
    if home:
        return Path(home)
    base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "lookalike"


def user_file():
    return config_dir() / "brands.txt"


def parse_list(text):
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line and _DOMAIN.match(line):
            out.append(line)
    return out


def load_brands(extra_file=None, use_user_file=True):
    seen = dict.fromkeys(DEFAULT_BRANDS)
    if use_user_file:
        try:
            seen.update(dict.fromkeys(parse_list(user_file().read_text(encoding="utf-8"))))
        except FileNotFoundError:
            pass
    if extra_file:
        seen.update(dict.fromkeys(parse_list(Path(extra_file).read_text(encoding="utf-8"))))
    return list(seen)


def add_brand(domain):
    domain = domain.strip().lower()
    if not _DOMAIN.match(domain):
        raise ValueError("not a plain ascii domain: %r" % domain)
    path = user_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = parse_list(path.read_text(encoding="utf-8")) if path.exists() else []
    if domain in existing:
        return path, False
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(domain + "\n")
    return path, True
