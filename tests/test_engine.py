
import json
import os
import subprocess

ENGINE = os.path.join(
    os.path.dirname(__file__), "..", "engine",
    "analyzer.exe" if os.name == "nt" else "analyzer",
)

CASES = [
    ("https://www.google.com", "LOW"),
    ("http://example.com", "MEDIUM"),
    ("http://192.168.1.1/login", "MEDIUM"),
    ("http://paypal.com@192.168.1.5/secure-login", "HIGH"),
    ("https://a.b.c.d.example.com/", "HIGH"),
    ("http://secure-login.paypal-verify.example.com/%2F", "HIGH"),
]

passed = 0

for url, expected in CASES:
    out = subprocess.run(
        [ENGINE, url],
        capture_output=True,
        text=True,
        timeout=5
    )

    actual = json.loads(out.stdout)["risk"]
    ok = actual == expected
    passed += ok

    print(
        ("PASS" if ok else "FAIL"),
        url,
        "| expected:", expected,
        "| got:", actual
    )

print(f"\n{passed}/{len(CASES)} tests passed")
