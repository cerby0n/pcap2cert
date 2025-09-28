import subprocess
import pathlib
import os
import json

# Mapping basic TLS version and cipher suites
TLS_VERSIONS = {
    "0x0300": "SSL 3.0",
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
}

CIPHERS_PATH = pathlib.Path(__file__).parent / "ciphers.json"

with open(CIPHERS_PATH, "r", encoding="utf-8") as f:
    CIPHERS = {int(k, 16): v for k, v in json.load(f).items()}

def decode_cipher(hex_str: str) -> str:
    try:
        return CIPHERS[int(hex_str, 16)]
    except Exception:
        return f"Unknown({hex_str})"


def extract_tls_info(pcap: str, ip: str = None, outdir: str = "certs_out"):
    """
    Extract TLS session info (version, cipher suites proposed, chosen) using tshark.
    Writes a txt file summarizing the negotiation.
    """
    pcap = os.path.expanduser(pcap)
    outdir_path = pathlib.Path(outdir)
    outdir_path.mkdir(parents=True, exist_ok=True)
    
    ip_filter = f" && ip.addr=={ip}" if ip else ""

    # Proposed ciphers (Client Hello)
    cmd_prop = [
        "tshark", "-r", pcap,
        "-Y", f"tls.handshake.type==1{ip_filter}",
        "-T", "fields", "-e", "tls.handshake.ciphersuite"
    ]
    prop_raw = subprocess.run(cmd_prop, stdout=subprocess.PIPE, text=True).stdout.strip().split("\n")

    proposed = set()
    for line in prop_raw:
        if line.strip():
            for x in line.split(","):
                proposed.add(decode_cipher(x.strip()))
    proposed = sorted(proposed)

    # Chosen cipher + version (Server Hello)
    cmd_serv = [
        "tshark", "-r", pcap,
        "-Y", f"tls.handshake.type==2{ip_filter}",
        "-T", "fields",
        "-e", "tls.handshake.ciphersuite",
        "-e", "tls.handshake.version",
        "-e", "tls.handshake.extensions.supported_version"
    ]
    serv_raw = subprocess.run(cmd_serv, stdout=subprocess.PIPE, text=True).stdout.strip().split("\n")

    chosen = None
    version = None
    ext_version = None
    std_version = None
    for line in serv_raw:
        parts = line.split()
        if len(parts) >= 1 and parts[0] and not chosen:
            chosen = decode_cipher(parts[0])
        # Save first non-empty supported_version extension
        if len(parts) >= 3 and parts[2] and not ext_version:
            ext_version = TLS_VERSIONS.get(parts[2], f"Unknown({parts[2]})")
        # Save first non-empty handshake.version
        if len(parts) >= 2 and parts[1] and not std_version:
            std_version = TLS_VERSIONS.get(parts[1], f"Unknown({parts[1]})")
    version = ext_version or std_version

    # Write summary
    report_path = outdir_path / "tls_session.txt"
    with open(report_path, "w") as f:
        f.write("# TLS Session Information\n")
        f.write(f"TLS version negotiated: {version or 'N/A'}\n")
        f.write("\n")
        if proposed:
            f.write(f"Cipher suites proposed ({len(proposed)}):\n")
            for cs in proposed:
                f.write(f"  - {cs}\n")
        else:
            f.write("Cipher suites proposed: N/A\n")
        f.write("\n")
        f.write(f"Cipher suite chosen: {chosen or 'N/A'}\n")
    
    return report_path
