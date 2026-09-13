import socket
import ssl
from datetime import datetime, timezone
from cryptography import x509


def scan_tls(url, timeout=5):
    if not url.startswith("https://"):
        return {
            "target": url,
            "error": "O alvo precisa usar HTTPS."
        }

    host_port = url.split("://", 1)[1].split("/", 1)[0]

    if ":" in host_port:
        host, port_text = host_port.rsplit(":", 1)
        port = int(port_text)
    else:
        host = host_port
        port = 443

    result = {
        "target": url,
        "host": host,
        "port": port,
        "tls_version": None,
        "cipher": None,
        "certificate": {},
        "findings": []
    }

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # O laboratório usa certificado autoassinado.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(
            (host, port),
            timeout=timeout
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=host
            ) as tls_sock:

                result["tls_version"] = tls_sock.version()
                result["cipher"] = tls_sock.cipher()

                cert_der = tls_sock.getpeercert(binary_form=True)

                if cert_der:
                    cert = x509.load_der_x509_certificate(cert_der)

                    subject = cert.subject.rfc4514_string()
                    issuer = cert.issuer.rfc4514_string()

                    not_before = cert.not_valid_before_utc
                    not_after = cert.not_valid_after_utc

                    now = datetime.now(timezone.utc)

                    san = []

                    try:
                        san_extension = cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName
                        )
                        san = san_extension.value.get_values_for_type(
                            x509.DNSName
                        )
                    except x509.ExtensionNotFound:
                        pass

                    result["certificate"] = {
                        "subject": subject,
                        "issuer": issuer,
                        "serial_number": str(cert.serial_number),
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "days_remaining": (not_after - now).days,
                        "san": san
                    }

                    if now > not_after:
                        result["findings"].append({
                            "title": "Certificado TLS expirado",
                            "severity": "HIGH",
                            "category": "TLS",
                            "evidence": not_after.isoformat()
                        })

                    elif (not_after - now).days <= 7:
                        result["findings"].append({
                            "title": "Certificado TLS próximo do vencimento",
                            "severity": "LOW",
                            "category": "TLS",
                            "evidence": f"{(not_after - now).days} dias restantes"
                        })

                    if not san:
                        result["findings"].append({
                            "title": "Certificado sem SAN",
                            "severity": "LOW",
                            "category": "TLS",
                            "evidence": "Subject Alternative Name ausente"
                        })

                if result["tls_version"] in ("TLSv1", "TLSv1.1"):
                    result["findings"].append({
                        "title": "Versão TLS antiga",
                        "severity": "MEDIUM",
                        "category": "TLS",
                        "evidence": result["tls_version"]
                    })

                if result["tls_version"] in ("TLSv1.2", "TLSv1.3"):
                    result["findings"].append({
                        "title": "Versão TLS moderna negociada",
                        "severity": "INFO",
                        "category": "TLS",
                        "evidence": result["tls_version"]
                    })

    except Exception as exc:
        result["error"] = str(exc)

    return result
