import socket
import OpenSSL
import ssl
from datetime import datetime, timedelta

def ssl_expiry_datetime(hostname: str):
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    # 3 second timeout because Lambda has runtime limitations
    conn.settimeout(3.0)

    try:
        conn.connect((hostname, 443))
    except socket.timeout:
        return None
    except socket.gaierror:
        return None

    ssl_info = conn.getpeercert()
    # parse the string from the certificate into a Python datetime object
    return datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)

def ssl_valid_time_remaining(hostname: str):
    """Get the number of days left in a cert's lifetime."""
    expires = ssl_expiry_datetime(hostname)
    if expires is None:
        return None
    return expires - datetime.utcnow()

def check_ssl_expiry(hostname: str):
    """Check if `hostname` SSL cert is expired or going to expire in next 7 days."""
    remaining = ssl_valid_time_remaining(hostname)
    
    # if the cert is expired
    if remaining < timedelta(0):
        return f"Cert expired {remaining} days ago"

    # if the cert will be expired in next 7 days
    elif remaining < timedelta(days=7):
        return f"Cert will be expired in {remaining} days"

    # otherwise, it's okay
    else:
        return f"Cert is okay, it will be expired in {remaining} days"


if __name__ == "__main__":
    domain = 'www.google.com' # Replace with your domain
    print(check_ssl_expiry(domain))
