from pathlib import Path

whois_samples_dir = Path(__file__).parent


def whois_sample(domain):
    """Load a captured raw WHOIS response, e.g. whois_sample("github.com")"""
    return (whois_samples_dir / f"{domain}.txt").read_text()


def whois_samples():
    """Every captured response, keyed by domain"""
    return {p.stem: p.read_text() for p in whois_samples_dir.glob("*.txt")}
