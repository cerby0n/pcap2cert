#!/usr/bin/env python3
import argparse
import pathlib

from . import extractor
from . import analyzer
from . import tlsinfo
from . import checker


def main():
    parser = argparse.ArgumentParser(
        description="pcap2cert - Extract and analyze TLS certificates from PCAP/PCAPNG files",
        epilog="""
Examples:
  Extract all certificates chain from a PCAP:
    pcap2cert capture.pcap

  Extract certificates for a specific IP:
    pcap2cert capture.pcap --ip 8.8.8.8

  Extract and analyze with details (TLS session info & Certificate details):
    pcap2cert capture.pcap --details

  Extract and analyze with details decompose cert chain:
    pcap2cert capture.pcap --details --split

  Extract and analyze certificate with details and perform minimal check on certs
    pcap2cert capture.pcap --details --check

  Run checks only on existing certificates:
    pcap2cert --outdir certs_out --check

  You can combine differents options to get the result you want
S
Output:
  default : certs_out
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("pcap", nargs="?", help="PCAP/PCAPNG file to analyze")
    parser.add_argument("-i", "--ip", help="Filter by source IP")
    parser.add_argument("-o", "--outdir", default="certs_out", help="Output directory")
    parser.add_argument("-s", "--split", action="store_true", help="Extract and separate certificate in multiple files")
    parser.add_argument("-cC", "--combine-chain", action="store_true",
                        help="Combine chain into a single PEM per stream")
    parser.add_argument("-d", "--details", action="store_true",
                        help="Write extra details about certs and TLS session")
    parser.add_argument("-k", "--check", action="store_true", help="Check PEM certificates for common issues")
    parser.add_argument("--desegment", action="store_true",
                        help="Enable TLS record reassembly")
    args = parser.parse_args()

    outdir = pathlib.Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    if args.check and not args.pcap:
        print(f"[+] Checking certificates in {args.outdir}")
        checker.check_all_certs(args.outdir)
        return
    
    # 1. Extraction PEM
    pem_files = extractor.extract_pems(
        pcap=args.pcap,
        ip=args.ip,
        outdir=args.outdir,
        split=args.split,
        combine_chain=args.combine_chain,
        desegment=args.desegment,
    )
    print(f"[+] Extracted {len(pem_files)} PEM certificates")

    # 2. Détails supplémentaires (--details)
    if args.details:
        # Analyse statique par certificat
        for pem in pem_files:
            txt_path = analyzer.analyze_pem(pem)
            print(f"[+] Wrote details for {pem} -> {txt_path}")

        # Analyse dynamique de la session TLS
        report = tlsinfo.extract_tls_info(args.pcap, ip=args.ip, outdir=args.outdir)
        print(f"[+] TLS session details written to {report}")

    if args.check:
        print("[+] Running certificate checks...")
        checker.check_all_certs(args.outdir)

if __name__ == "__main__":
    main()
