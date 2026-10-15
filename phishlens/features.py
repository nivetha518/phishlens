"""URL feature extraction. Every feature is scaled to roughly 0..1 so that
(coefficient x value) is a directly readable contribution to the risk score."""
import math
import re
from collections import Counter
from urllib.parse import urlparse

BRANDS = ["paypal", "google", "apple", "microsoft", "amazon", "netflix", "facebook",
          "instagram", "whatsapp", "paytm", "irctc", "linkedin", "dropbox", "binance",
          "coinbase", "wellsfargo", "outlook", "office365", "hdfcbank", "icicibank"]
KW = ["login", "signin", "verify", "secure", "account", "update", "confirm", "password",
      "wallet", "bonus", "billing", "suspend", "unlock", "banking", "validate", "recover",
      "authenticate", "giveaway", "claim", "invoice"]
TRUST = ["google.com", "github.com", "wikipedia.org", "microsoft.com", "apple.com",
         "amazon.com", "amazon.in", "youtube.com", "linkedin.com", "paypal.com",
         "netflix.com", "openai.com", "anthropic.com", "claude.ai", "stackoverflow.com",
         "irctc.co.in", "sbi.co.in", "paytm.com", "facebook.com", "instagram.com",
         "whatsapp.com", "reddit.com", "mozilla.org"]
BADTLD = ["zip", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
          "work", "icu", "buzz", "monster", "rest", "support"]
SHORT = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly",
         "rebrand.ly", "shorturl.at"]
SLD = {"co", "com", "org", "net", "gov", "ac", "edu"}

LABELS = {
    "ip": "IP address as host", "at": "'@' in URL", "len": "Long URL",
    "sub": "Many subdomains", "hy": "Hyphens in host", "dg": "Digits in domain",
    "kw": "Phishing keywords", "imp": "Brand impersonation", "look": "Look-alike domain",
    "pun": "Punycode (xn--)", "tld": "High-abuse TLD", "sh": "URL shortener",
    "http": "Not using HTTPS", "en": "Random-looking domain",
    "sp": "Special characters", "pc": "Percent-encoding", "port": "Non-standard port",
    "emb": "Embedded URL / redirect", "exe": "Executable download",
    "tr": "Known reputable domain",
}
FEATURES = list(LABELS)


def _norm(s):
    s = s.lower().replace("rn", "m").replace("vv", "w").replace("0", "o")
    s = re.sub(r"[1!|]", "l", s).replace("3", "e").replace("5", "s")
    return re.sub(r"[^a-z]", "", s)


def _lev(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _entropy(s):
    if not s:
        return 0.0
    return -sum(c / len(s) * math.log2(c / len(s)) for c in Counter(s).values())


def _clip(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))


def extract(url):
    """Return (features, parts). features: name -> (value, human_note)."""
    s = url.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I):
        s = "https://" + s
    u = urlparse(s)
    host = (u.hostname or "").lower()
    if not host:
        raise ValueError("Invalid URL")
    L = host.split(".")
    n = len(L)
    rn = 3 if n >= 3 and len(L[-1]) == 2 and L[-2] in SLD else 2
    reg = ".".join(L[-rn:])
    label = L[max(0, n - rn)]
    sub = ".".join(L[: max(0, n - rn)])
    tld = L[-1]
    path_q = u.path + ("?" + u.query if u.query else "")
    full = (host + path_q).lower()
    trusted = reg in TRUST
    ip = bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host)) or ":" in host
    kws = [k for k in KW if k in full]

    imp, look = None, None
    nh = _norm(host.replace(".", "") + u.path)
    rl = _norm(label)
    for b in BRANDS:
        if ip:
            break
        if rl == b and label != b:
            look = f"'{label}' imitates {b}"
            break
        if len(b) >= 5 and label != b and not trusted and rl != b and (b in nh or b in host):
            imp = b
        if not look and not trusted and len(label) >= 5 and label != b \
                and abs(len(label) - len(b)) <= 2 and _lev(label, b) <= 2:
            look = f"'{label}' is {_lev(label, b)} edit(s) from {b}"

    try:
        port = u.port
    except ValueError:
        port = None
    pc = len(re.findall(r"%[0-9a-f]{2}", s, re.I))
    sp = len(re.sub(r"[\w\-./=&?]", "", path_q))
    ent = _entropy(label.replace("-", ""))
    hy = host.count("-")
    dg = sum(c.isdigit() for c in label) / max(1, len(label))

    f = {
        "ip": (float(ip), f"Host is a raw IP ({host}) instead of a domain name."),
        "at": (float("@" in u.netloc), "Text before '@' is ignored by browsers and hides the real host."),
        "len": (_clip((len(s) - 40) / 80), f"{len(s)} characters; long URLs hide the real domain."),
        "sub": (_clip((n - rn - 1) / 3), f"{n - rn} subdomain level(s): '{sub}'."),
        "hy": (_clip(hy / 4), f"{hy} hyphen(s) in host (brand-stuffing style)."),
        "dg": (_clip(dg * 4), "Unusually many digits in the domain name."),
        "kw": (_clip(len(kws) / 3), "Found keywords: " + ", ".join(kws) + "."),
        "imp": (float(bool(imp)), f"Mentions '{imp}' but is hosted on {reg}."),
        "look": (float(bool(look)), f"{look} (typosquat / homoglyph)."),
        "pun": (float("xn--" in host), "Punycode domain can render with look-alike Unicode letters."),
        "tld": (float(tld in BADTLD), f".{tld} is heavily abused by throw-away domains."),
        "sh": (float(reg in SHORT), "Shortener hides the final destination."),
        "http": (float(u.scheme != "https"), "No HTTPS encryption."),
        "en": (_clip((ent - 2.8) / 1.2), f"Domain entropy {ent:.2f} bits looks auto-generated."),
        "sp": (_clip(sp / 8), f"{sp} unusual characters in path/query."),
        "pc": (_clip(pc / 4), f"{pc} percent-encoded sequences can mask keywords."),
        "port": (float(port not in (None, 80, 443)), f"Non-standard port {port}."),
        "emb": (float(bool(re.search(r"https?://", path_q + u.fragment, re.I)) or "//" in u.path),
                "Another URL is nested inside this one."),
        "exe": (float(bool(re.search(r"\.(exe|scr|apk|msi|bat|js|jar|zip|rar|iso)$", u.path, re.I))),
                "Link points straight to a downloadable program/archive."),
        "tr": (float(trusted), f"{reg} is on the reputable-domain list."),
    }
    parts = {"scheme": u.scheme, "subdomain": sub or "-", "domain": reg,
             "path": u.path or "/", "query": u.query or "-", "keywords": kws}
    return f, parts


def vectorize(url):
    f, parts = extract(url)
    return [f[k][0] for k in FEATURES], f, parts
