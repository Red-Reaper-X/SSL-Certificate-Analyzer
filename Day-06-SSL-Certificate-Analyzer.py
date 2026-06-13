
import ssl, socket
from datetime import datetime, UTC
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import io

def analyze_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert["issuer"])
                expiry_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
                days_left = (expiry_date - datetime.now(UTC)).days
                score = 100 - (50 if days_left <= 0 else (20 if days_left < 30 else 0))
                return {
                    "domain": domain, "issuer": issuer.get("organizationName", "Unknown"),
                    "expiry": cert["notAfter"], "days_left": days_left, "score": score, "expired": days_left <= 0
                }
    except Exception as e:
        return {"domain": domain, "error": str(e)}

def generate_pdf(results):
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    y = 750
    p.drawString(100, y, "SSL Certificate Report")
    y -= 20
    for r in results:
        if "error" not in r:
            for k, v in r.items():
                if k != "domain":
                    p.drawString(100, y, f"{k}: {v}")
                    y -= 20
            if r["expired"]:
                p.drawString(100, y, "WARNING: Certificate Expired!")
            y -= 20
    p.save()
    buffer.seek(0)
    return buffer

if __name__ == "__main__":
    domains = input("Enter domains (comma-separated): ").split(',')
    results = [analyze_ssl(d.strip()) for d in domains]
    for r in results:
        if "error" not in r:
            print(f"\nDomain: {r['domain']}\nIssuer: {r['issuer']}\nExpiry: {r['expiry']}\nDays Left: {r['days_left']}\nScore: {r['score']}/100")
            if r["expired"]:
                print("WARNING: Certificate Expired!")
        else:
            print(f"Error for {r['domain']}: {r['error']}")
    with open("ssl_report.pdf", "wb") as f:
        f.write(generate_pdf(results).getvalue())
    print("\nPDF report generated as 'ssl_report.pdf'!")
