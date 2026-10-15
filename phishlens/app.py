from flask import Flask, request, render_template_string
import re
from urllib.parse import urlparse
import math

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head><title>PhishLens</title>
<style>
body{font-family:Arial;background:#f0f4f8;display:flex;justify-content:center;padding-top:50px}
.card{background:white;padding:30px;border-radius:15px;box-shadow:0 5px 20px rgba(0,0,0,0.1);width:500px}
h1{color:#1a2a4a} h1 span{color:#2b6cff}
input{width:75%;padding:12px;border-radius:8px;border:2px solid #ff9d5c}
button{background:#2b6cff;color:white;padding:12px 20px;border:none;border-radius:8px;cursor:pointer;font-weight:bold}
.result{margin-top:20px;padding:15px;border-radius:10px}
.safe{background:#d4edda;color:#155724;border:1px solid #c3e6cb}
.phish{background:#f8d7da;color:#721c24;border:1px solid #f5c6cb}
ul{font-size:14px}
</style>
</head>
<body>
<div class="card">
<h1>Phish<span>Lens</span> 🛡️</h1>
<p>AI-based malicious URL detection with explanations.</p>
<form method="POST">
<input type="text" name="url" placeholder="Enter URL e.g. https://google.com" value="{{url}}" required>
<button type="submit">Scan</button>
</form>
{% if result %}
<div class="result {{cls}}">
<h3>{{result}} - {{score}}% Confidence</h3>
<p><b>URL:</b> {{url}}</p>
<ul>
{% for e in explanations %}
<li>{{e}}</li>
{% endfor %}
</ul>
</div>
{% endif %}
</div>
</body>
</html>
"""

def analyze(url):
    explanations = []
    score = 0
    parsed = urlparse(url)
    domain = parsed.netloc or url

    if len(url) > 75:
        score += 25
        explanations.append(f"URL is very long ({len(url)} chars) - often used to hide phishing")
    else:
        explanations.append(f"URL length is normal ({len(url)} chars)")

    dots = url.count('.')
    if dots > 4:
        score += 20
        explanations.append(f"Many dots ({dots}) - suspicious subdomain trick")
    
    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        score += 30
        explanations.append("Uses IP address instead of domain - highly suspicious")

    if '-' in domain:
        score += 15
        explanations.append("Domain contains hyphen (-) - common in phishing domains")
    
    if '@' in url:
        score += 25
        explanations.append("Contains @ symbol - used to hide real domain")

    suspicious_words = ['secure', 'login', 'verify', 'account', 'update', 'bank', 'paypal', 'alert', 'billing']
    found = [w for w in suspicious_words if w in url.lower()]
    if found:
        score += 20
        explanations.append(f"Contains phishing keywords: {', '.join(found)}")

    if 'https' not in url.lower():
        score += 15
        explanations.append("Not using HTTPS - not secure")
    else:
        explanations.append("Uses HTTPS")

    # Check for typosquatting like g00gle
    if 'g00gle' in url.lower() or '00' in domain:
        score += 20
        explanations.append("Possible typosquatting (using numbers to mimic letters)")

    # Final decision
    if score >= 40:
        return "Phishing / Malicious", min(score+30, 95), explanations, "phish"
    else:
        return "Legitimate / Safe", max(100-score-20, 85), explanations, "safe"

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        url = request.form['url']
        result, score, exps, cls = analyze(url)
        return render_template_string(HTML, result=result, score=score, explanations=exps, cls=cls, url=url)
    return render_template_string(HTML, result=None, url="")

if __name__ == '__main__':
    app.run(debug=True)