from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import pathlib
from datetime import datetime, timezone


def check_certificate(path: pathlib.Path):
    """Return a list of errors for a given PEM certificate."""
    errors = []
    with open(path, "rb") as f:
        data = f.read()

    certs = data.split(b"-----END CERTIFICATE-----")
    certs = [c + b"-----END CERTIFICATE-----\n" for c in certs if b"BEGIN CERTIFICATE" in c]

    for idx, pem in enumerate(certs):
        cert = x509.load_pem_x509_certificate(pem, default_backend())
        now = datetime.now(timezone.utc)

        # 1. Validity period
        if cert.not_valid_after_utc < now:
            errors.append(f"{path.name} [cert {idx}]: expired on {cert.not_valid_after_utc}")
        if cert.not_valid_before_utc > now:
            errors.append(f"{path.name} [cert {idx}]: not valid before {cert.not_valid_before_utc}")

        # 3. Weak key sizes
        pubkey = cert.public_key()
        if isinstance(pubkey, rsa.RSAPublicKey) and pubkey.key_size < 2048:
            errors.append(f"{path.name} [cert {idx}]: weak RSA key ({pubkey.key_size} bits)")
        if isinstance(pubkey, ec.EllipticCurvePublicKey) and pubkey.key_size < 256:
            errors.append(f"{path.name} [cert {idx}]: weak EC key ({pubkey.key_size} bits)")

        # 4. Weak signature algorithm
        sig_algo = cert.signature_hash_algorithm
        if sig_algo is not None and sig_algo.name.lower() in ["md5", "sha1"]:
            errors.append(f"{path.name} [cert {idx}]: weak signature algorithm ({sig_algo.name})")

        # 5. Self-signed
        if cert.issuer == cert.subject:
            errors.append(f"{path.name} [cert {idx}]: self-signed certificate")

    return errors


def check_all_certs(cert_dir="certs_out"):
    """Check all PEM certs in directory and print errors."""
    certs_path = pathlib.Path(cert_dir)
    for pem in certs_path.glob("*.pem"):
        errors = check_certificate(pem)
        for e in errors:
            print(f"[!] {e}")
