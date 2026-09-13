import re


PATTERNS = {
    "WordPress": [
        r"wp-content",
        r"wp-includes",
        r"wordpress"
    ],
    "Joomla": [
        r"joomla"
    ],
    "Drupal": [
        r"drupal"
    ],
    "React": [
        r"react"
    ],
    "Vue.js": [
        r"vue"
    ],
    "Angular": [
        r"angular"
    ],
}


def scan_technology(http_result):
    technologies = []

    headers = http_result.get("headers", {})
    body = http_result.get("body", "")

    combined = (
        str(headers) + "\n" + body[:200000]
    ).lower()

    server = headers.get("Server")

    if server:
        technologies.append({
            "name": "Web Server",
            "evidence": server
        })

    powered_by = headers.get("X-Powered-By")

    if powered_by:
        technologies.append({
            "name": "X-Powered-By",
            "evidence": powered_by
        })

    for technology, patterns in PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, combined):
                technologies.append({
                    "name": technology,
                    "evidence": pattern
                })
                break

    return {
        "technologies": technologies,
        "count": len(technologies)
    }
