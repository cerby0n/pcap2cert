# pcap2cert — TLS Certificate Extraction from PCAP

A small CLI tool to automatically extract TLS/SSL certificates from PCAP/PCAPNG captures.

> Goal: provide a simple, robust, and auditable way to extract server certificates, full chains,
> and generate usable PEM files.

---

## 1. Synopsis

`pcap2cert [PCAP] [--ip IP] [--chain] [--combine-chain] [--outdir DIR] [--desegment] [--keep-intermediate] [--verbose]`

* `PCAP` : `.pcap` or `.pcapng` file to analyze.
* `--ip IP` : only keep certificates where `ip.src == IP`.
* `--chain` : extract the full chain (intermediate certificates included).
* `--combine-chain` : write the full chain into a **single PEM file** per stream (implies `--chain`).
* `--outdir DIR` : output directory (default: `certs_out`).
* `--desegment` : enable TLS record reassembly (useful when certificates are fragmented).
* `--keep-intermediate` : keep `.hex` / `.der` temporary files (otherwise only `.pem` remain).
* `--verbose` : detailed logs for debugging.

---

## 2. Dependencies

**System** (Kali / Debian):

```bash
sudo apt update && sudo apt install -y tshark openssl vim-common
```

* `tshark`: extract TLS fields.
* `openssl`: convert DER -> PEM.
* `xxd` (provided by `vim-common`): convert hex -> binary when needed.

**Python (optional)**: if you want to use the extended Python version:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Recommended `requirements.txt`:

```text
pyshark>=0.4.2
cryptography>=3.4
tqdm>=4.60.0
```

> Note: the main script works without `pyshark`; it relies on `tshark` via `subprocess`.

---

## 3. Quick install (optional)

Make the script executable and install it globally as `pcap2cert`:

```bash
chmod +x extract_certs_chain.py
sudo mv extract_certs_chain.py /usr/local/bin/pcap2cert
# now: pcap2cert --help
```

---

## 4. Usage examples

1. Extract the server certificate (default):

```bash
pcap2cert ~/pcaps/session.pcap --outdir certs
```

2. Extract only from a given source IP:

```bash
pcap2cert ~/pcaps/session.pcap --ip 178.249.97.99 --outdir certs
```

3. Extract the full chain and write a single PEM per stream:

```bash
pcap2cert ~/pcaps/session.pcap --ip 178.249.97.99 --chain --combine-chain --outdir certs
```

4. Force TLS reassembly (if fields are empty or fragmented):

```bash
pcap2cert ~/pcaps/session.pcap --desegment --chain --combine-chain --verbose --outdir certs
```

---

## 5. Output

* By default, the folder `certs_out/` (or `--outdir`) will contain PEM files.
* With `--combine-chain`, you get `IP_streamNN.chain.pem` containing multiple `-----BEGIN CERTIFICATE-----` blocks concatenated.
* With `--keep-intermediate`, you also keep `.hex` and `.der` files for debugging.

To inspect a PEM:

```bash
openssl x509 -in certs/<file>.pem -noout -subject -issuer -dates -fingerprint -sha256
```

---

## 6. Tips & Troubleshooting

* If no result: try `--desegment` and `--verbose` to see the raw `tshark` output.
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