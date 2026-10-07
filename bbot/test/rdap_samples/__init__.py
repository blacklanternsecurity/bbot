"""
Real RDAP responses (trimmed) used by the RDAP helper and module tests.
"""

import json
from pathlib import Path

rdap_samples_dir = Path(__file__).parent


def rdap_sample(name):
    """Load a sample RDAP response by name, e.g. rdap_sample("verisign_com_github")"""
    return json.loads((rdap_samples_dir / f"{name}.json").read_text())
