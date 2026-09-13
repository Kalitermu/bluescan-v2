cat > scanner.py <<'PY'
from scanner_http import scan_http
from scanner_tls import scan_tls
from scanner_dns import scan_dns
from scanner_tech import scan_technology
from scanner_whatweb import scan_whatweb
from correlator import correlate


def _extract_host(url):
    host = url.split("://", 1)[-1]
    host = host.split("/", 1)[0]
    host = host.split(":", 1)[0]
    return host


def scan_target(url):
    result = {
        "target": url,
        "http": None,
        "tls": None,
        "dns": None,
        "technology": None,
        "whatweb": None,
        "correlation": None,
    }

    # HTTP
    http_result = scan_http(url)
    result["http"] = http_result

    # Fingerprinting básico
    result["technology"] = scan_technology(
        http_result
    )

    # WhatWeb
    result["whatweb"] = scan_whatweb(url)

    # TLS
    if url.lower().startswith("https://"):
        tls_result = scan_tls(url)
        result["tls"] = tls_result
    else:
        tls_result = None

    # DNS
    host = _extract_host(url)
    result["dns"] = scan_dns(host)

    # Correlação
    result["correlation"] = correlate(
        http_result=http_result,
        tls_result=tls_result,
    )

    return result
PY
