# pcap2cert — TLS Certificate Extraction from PCAP

A small CLI tool to automatically extract TLS/SSL certificates from PCAP/PCAPNG captures.

> Goal: provide a simple, robust, and auditable way to extract server certificates, full chains,
> and generate usable PEM files.
> Features: extract and analyze TLS/SSL certificates, full chains, and session details from PCAP/PCAPNG files. Supports filtering by IP, chain combination, splitting, certificate checks, and output analysis files.

---

## 1. Synopsis

`pcap2cert [-h] [-i IP] [-o OUTDIR] [-s] [-cC] [-d] [-k] [--desegment] [pcap]`



* `PCAP` : `.pcap` or `.pcapng` file to analyze.
* `-i, --ip IP` : only keep certificates where `ip.src == IP`.
* `-o, --outdir DIR` : output directory (default: `certs_out`).
* `-s, --split` : extract and separate each certificate into individual PEM files per stream.
* `-cC, --combine-chain` : write the full chain into a **single PEM file** per stream (implies `--chain`).
* `-k, --check` : Check PEM certificates for common issues.
* `--desegment` : enable TLS record reassembly (useful when certificates are fragmented).

---

## 2. Dependencies

**System** (Kali / Debian):

```bash
sudo apt update && sudo apt install -y tshark openssl vim-common
```

* `tshark`: extract TLS fields.
* `openssl`: convert DER -> PEM.
* `xxd` (provided by `vim-common`): convert hex -> binary when needed.

---

## 3. Installation

1. Install the tool in Production mode:
   - Using pip:
     ```sh
     pip install .
     ```
   - Using uv:
     ```sh
     uv tool install .
     ```
2. Install the tool in editable / development mode:
   - Using pip:
     ```sh
     pip install -e .
     ```
   - Using uv:
     ```sh
     uv tool install --editable .
     ```
---

## 4. Usage examples

1. Extract all certificates chain from a PCAP:

```bash
pcap2cert capture.pcap
```

2. Extract certificates for a specific IP:

```bash
pcap2cert capture.pcap --ip 8.8.8.8
```

3. Extract and analyze with details (TLS session info & Certificate details):

```bash
pcap2cert capture.pcap --details
```

4. Extract and analyze with details decompose cert chain:

```bash
pcap2cert capture.pcap --details --split
```

5. Extract and analyze certificate with details and perform minimal check on certs:

```bash
pcap2cert capture.pcap --details --check
``` 

6. Run checks only on existing certificates:

```bash
pcap2cert --outdir certs_out --check
``` 

---

## 5. Output

* By default, the folder `certs_out/` (or `--outdir`) will contain PEM files.

To inspect a PEM:

```bash
openssl x509 -in certs/<file>.pem -noout -subject -issuer -dates -fingerprint -sha256
```

---

## 6. Tips & Troubleshooting

* If no result: try `--desegment` to see the raw `tshark` output.
* Check that `tshark` exposes `tls.handshake.certificate`:

  ```bash
  tshark -G fields | egrep 'tls\.handshake\.certificate|ssl\.handshake\.certificate'
  ```
* If you need to filter by domain (SNI), you can extend the script with `--domain example.com` using `tls.handshake.extensions_server_name`.
* Warning: multiple certificates may come from the same IP. If you force a filename like `IP.pem`, later ones will overwrite previous ones. Using stream numbers or SHA256 in filenames is safer.

---

## 7. License

MIT — free to use, modify and distribute (add a LICENSE file if needed).

---