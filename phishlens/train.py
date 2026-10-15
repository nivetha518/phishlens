"""Train the URL classifier.
  python train.py                      -> trains on built-in synthetic data (demo)
  python train.py --csv urls.csv       -> trains on a real dataset (columns: url,label)
Label may be 1/0 or bad/good/malicious/benign/phishing."""
import argparse, csv, random, string
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from features import BADTLD, BRANDS, FEATURES, KW, SHORT, TRUST, vectorize

R = random.Random(42)
WORDS = ["blue", "cafe", "daily", "news", "garden", "tech", "learn", "shop", "travel", "photo",
         "music", "health", "sports", "books", "food", "city", "cloud", "design", "studio", "labs"]
PATHS = ["", "/", "/about", "/products/%d", "/search?q=weather", "/blog/2025/post-%d",
         "/login", "/account/settings", "/docs/getting-started", "/watch?v=abc123"]


def rs(k=8):
    return "".join(R.choice(string.ascii_lowercase + string.digits) for _ in range(k))


def legit():
    d = R.choice(TRUST) if R.random() < .6 else R.choice(WORDS) + R.choice(WORDS) + R.choice([".com", ".org", ".in", ".io", ".co.uk"])
    sub = R.choice(["", "www.", "mail.", "docs.", "accounts.", "blog."])
    p = R.choice(PATHS)
    p = p % R.randint(1, 999) if "%d" in p else p
    return f"{'https' if R.random() < .96 else 'http'}://{sub}{d}{p}"


def typo(b):
    c = R.choice(["sub", "add", "drop"])
    i = R.randrange(len(b))
    if c == "sub":
        return b[:i] + {"o": "0", "l": "1", "a": "4", "e": "3"}.get(b[i], b[i] + b[i]) + b[i + 1:]
    return b[:i] + b[i] + b[i:] if c == "add" else b[:i] + b[i + 1:]


def malicious():
    k = R.randrange(7)
    tld = R.choice(BADTLD + ["com", "net"])
    kws = "-".join(R.sample(KW, R.randint(1, 3)))
    b = R.choice(BRANDS)
    if k == 0:
        u = f"{typo(b)}-{R.choice(KW)}.{tld}/{R.choice(KW)}/{rs(6)}"
    elif k == 1:
        u = f"{b}.com.{rs(6)}-{R.choice(KW)}.{tld}/{R.choice(KW)}"
    elif k == 2:
        u = f"{'.'.join(str(R.randint(1, 254)) for _ in range(4))}{R.choice(['', ':8080', ':8888'])}/{R.choice(KW)}/{rs(5)}{R.choice(['', '.exe', '.apk'])}"
    elif k == 3:
        u = f"{kws}.{rs(9)}.{tld}/index.php?id={rs(12)}"
    elif k == 4:
        u = f"{R.choice(SHORT)}/{rs(7)}"
    elif k == 5:
        u = f"xn--{rs(7)}-{rs(3)}.com/{R.choice(KW)}"
    else:
        u = f"{R.choice(KW)}.{b}.{rs(5)}.{rs(6)}.{tld}/r?url=http://{rs(8)}.com/%2e%2e/{rs(20)}"
    return f"{'http' if R.random() < .7 else 'https'}://{u}"


def load_csv(path):
    pos = {"1", "bad", "malicious", "phishing", "malware", "defacement"}
    with open(path, newline="", encoding="utf-8", errors="ignore") as fh:
        return [(r["url"], int(r["label"].strip().lower() in pos)) for r in csv.DictReader(fh)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv")
    ap.add_argument("--n", type=int, default=4000)
    a = ap.parse_args()
    rows = load_csv(a.csv) if a.csv else [(legit(), 0) for _ in range(a.n)] + [(malicious(), 1) for _ in range(a.n)]
    X, y = [], []
    for url, lab in rows:
        try:
            X.append(vectorize(url)[0]); y.append(lab)
        except Exception:
            pass
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=.2, random_state=1, stratify=y)
    m = LogisticRegression(C=2.0, max_iter=2000).fit(Xtr, ytr)
    print(classification_report(yte, m.predict(Xte), target_names=["legit", "malicious"]))
    joblib.dump({"coef": m.coef_[0].tolist(), "intercept": float(m.intercept_[0]), "features": FEATURES}, "model.joblib")
    print("Saved model.joblib")
    for f, c in sorted(zip(FEATURES, m.coef_[0]), key=lambda t: -abs(t[1])):
        print(f"{f:6s} {c:+.2f}")


if __name__ == "__main__":
    main()
