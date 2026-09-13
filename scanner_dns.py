import dns.resolver


RECORD_TYPES = [
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
]


def scan_dns(hostname, timeout=3):
    result = {
        "target": hostname,
        "records": {},
        "findings": []
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(
                hostname,
                record_type
            )

            values = []

            for answer in answers:
                values.append(answer.to_text())

            result["records"][record_type] = values

        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout
        ):
            result["records"][record_type] = []

        except Exception as exc:
            result["records"][record_type] = []
            result["findings"].append({
                "title": "Erro durante consulta DNS",
                "severity": "INFO",
                "category": "DNS",
                "evidence": f"{record_type}: {exc}"
            })

    if not any(result["records"].values()):
        result["findings"].append({
            "title": "Nenhum registro DNS encontrado",
            "severity": "INFO",
            "category": "DNS",
            "evidence": hostname
        })

    return result
