import subprocess
import pathlib
import os
import base64


def write_pem(der_bytes, f):
    """Write one DER cert as PEM inside an already opened file."""
    f.write(b"-----BEGIN CERTIFICATE-----\n")
    f.write(base64.encodebytes(der_bytes))
    f.write(b"-----END CERTIFICATE-----\n")


def extract_pems(pcap: str, ip: str = None, outdir: str = "certs_out",
                 combine_chain: bool = False, split: bool = False, desegment: bool = False):
    """
    Extract PEM certificates from PCAP/PCAPNG using tshark.
    Files are named with ipSrc-ipDst_streamID.pem
    """
    pcap = os.path.expanduser(pcap)
    outdir_path = pathlib.Path(outdir)
    outdir_path.mkdir(parents=True, exist_ok=True)

    display_filter = "ssl.handshake.certificate or tls.handshake.certificate"
    if ip:
        display_filter += f" && ip.addr=={ip}"

    extra_args = []
    if desegment:
        extra_args.extend(["-o", "tls.desegment_ssl_records:TRUE"])

    cmd = [
        "tshark", "-r", pcap,
        "-Y", display_filter,
        "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.stream", "-e", "tls.handshake.certificate"
    ] + extra_args

    raw_output = subprocess.run(cmd, stdout=subprocess.PIPE, text=True).stdout.strip().split("\n")

    pem_files = []
    for line in raw_output:
        if not line.strip():
            continue

        try:
            ip_src, ip_dst, stream_id, certs_hex = line.split("\t")
        except ValueError:
            continue

        if ip and not (ip_src == ip or ip_dst == ip):
            continue
        
        certs = []
        for cert_hex in certs_hex.split(","):
            hex_clean = cert_hex.strip().replace(":", "").replace("\n", "")
            if not hex_clean:
                continue
            try:
                certs.append(bytes.fromhex(hex_clean))
            except Exception:
                continue

        if not certs:
            continue

        base_name = f"{ip_src}-{ip_dst}_stream{stream_id}"

        if combine_chain and not split:
            pem_path = outdir_path / f"{base_name}.pem"
            with open(pem_path, "wb") as f:
                for der in certs:
                    write_pem(der, f)
            pem_files.append(pem_path)

        elif split:
            for idx, der in enumerate(certs):
                pem_path = outdir_path / f"{base_name}_{idx}.pem"
                with open(pem_path, "wb") as f:
                    write_pem(der, f)
                pem_files.append(pem_path)

        else:
            # Default: same as combine_chain (chain in one file)
            pem_path = outdir_path / f"{base_name}.pem"
            with open(pem_path, "wb") as f:
                for der in certs:
                    write_pem(der, f)
            pem_files.append(pem_path)

    return pem_files
