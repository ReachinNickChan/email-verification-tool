import re
import dns.resolver
import smtplib
import socket
from typing import List, Optional


def check_syntax(email: str) -> bool:
    """
    Check if the email address conforms to a typical user@domain.tld format.

    Notes:
    - This uses a pragmatic regex suitable for most real-world addresses.
    - It does not attempt to fully implement RFC 5322 (which is intentionally very permissive).
    """
    regex = r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
    return re.match(regex, email) is not None


def _normalize_domain(domain: str) -> str:
    """Return the ASCII (IDNA/Punycode) representation of a domain if needed."""
    try:
        return domain.encode("idna").decode("ascii")
    except Exception:
        return domain


def check_mx_records(domain: str) -> Optional[List[str]]:
    """
    Confirm that the domain has valid Mail Exchange (MX) records.

    Returns a list of MX hostnames sorted by priority (lowest first), or None if:
    - The domain has no MX records,
    - The domain publishes a "Null MX" (exchange='.' per RFC 7505), or
    - DNS lookup fails/times out.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 10.0
        ascii_domain = _normalize_domain(domain)

        answers = resolver.resolve(ascii_domain, 'MX')
        mx_entries = []
        for rdata in answers:
            # rdata.exchange is a dns.name.Name; convert to str and strip the trailing dot
            exchange = str(rdata.exchange).rstrip('.')
            preference = int(rdata.preference)
            # Null MX (RFC 7505) indicates the domain does not accept email
            if exchange == '' or exchange == '.':
                continue
            mx_entries.append((preference, exchange))

        if not mx_entries:
            return None

        # Sort by MX preference (lower value = higher priority)
        mx_entries.sort(key=lambda x: x[0])
        return [host for _, host in mx_entries]

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return None
    except Exception as e:
        print(f"Error checking MX records for {domain}: {e}")
        return None


def check_smtp(email: str, mx_servers: List[str]) -> str:
    """
    Perform a lightweight SMTP dialogue to test if a mailbox exists without sending an email.

    Steps (per RFC 5321):
    1) Connect to the MX server on port 25.
    2) EHLO/HELO to introduce the client.
    3) If the server advertises STARTTLS, attempt to upgrade the connection (optional but improves acceptance).
    4) MAIL FROM uses a benign, syntactically valid sender.
    5) RCPT TO for the target mailbox. Interpret common response codes:
       - 250 (OK) or 251 (User not local, will forward): treat as Exists.
       - 550/551/553: treat as DoesNotExist.
       - 450/451/452 or other 4xx: temporary failure -> Unverifiable.
       - Anything else unexpected: Unverifiable.
    6) QUIT to close the connection cleanly.

    Returns one of: "Exists", "DoesNotExist", "Unverifiable".

    Implementation notes:
    - Many modern providers use anti-harvesting protections (catch-all, tarpits, or always-accept).
      Therefore, even a 250 may not guarantee deliverability, but it's the best heuristic available
      via SMTP without sending email.
    - Some providers close connections early or after banner; handled as Unverifiable.
    """
    if not mx_servers:
        return "Unverifiable"

    try:
        local_helo = socket.getfqdn() or 'localhost'
    except Exception:
        local_helo = 'localhost'

    for mx_host in mx_servers:
        try:
            # Establish SMTP connection with a timeout
            server = smtplib.SMTP(mx_host, 25, timeout=10)
            try:
                code, _ = server.ehlo()
                if 200 <= code < 300 and server.has_extn('starttls'):
                    # Attempt to upgrade to TLS when available
                    try:
                        server.starttls()
                        server.ehlo()
                    except smtplib.SMTPException:
                        # If STARTTLS fails, continue without TLS
                        pass
                else:
                    # Fallback to HELO if EHLO not accepted
                    server.helo(local_helo)

                # Use a neutral sender. Some servers validate the sender domain too.
                sender = f"no-reply@{local_helo.split('.', 1)[-1] or 'localhost'}"
                server.mail(sender)

                code, message = server.rcpt(email)

                # Always try to quit cleanly; ignore errors on QUIT
                try:
                    server.quit()
                except Exception:
                    pass

                # Interpret response codes
                if code in (250, 251):
                    return "Exists"
                elif code in (550, 551, 553):
                    return "DoesNotExist"
                elif 400 <= code < 500:
                    return "Unverifiable"
                else:
                    return "Unverifiable"

            except (smtplib.SMTPServerDisconnected, smtplib.SMTPResponseException, smtplib.SMTPHeloError) as e:
                print(f"SMTP protocol error with {mx_host}: {e}")
                try:
                    server.quit()
                except Exception:
                    pass
                continue
            except (socket.timeout, socket.error) as e:
                print(f"Socket error with {mx_host}: {e}")
                try:
                    server.quit()
                except Exception:
                    pass
                continue
            except Exception as e:
                print(f"Unexpected SMTP error with {mx_host}: {e}")
                try:
                    server.quit()
                except Exception:
                    pass
                continue

        except (smtplib.SMTPConnectError, smtplib.SMTPException, socket.error) as e:
            print(f"SMTP connection error to {mx_host}: {e}")
            continue

    return "Unverifiable"


if __name__ == '__main__':
    # Library module; main CLI is implemented in main.py
    pass


