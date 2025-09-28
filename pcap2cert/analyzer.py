from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone


def analyze_pem(pem_path):
    """
    Analyze a PEM or chain of PEMs.
    For each cert: write validity, issuer, key type, key size.
    """
    with open(pem_path, "rb") as f:
        pem_data = f.read()

    # Découper la chaîne en certificats individuels
    certs = pem_data.split(b"-----END CERTIFICATE-----")
    certs = [c + b"-----END CERTIFICATE-----\n" for c in certs if b"BEGIN CERTIFICATE" in c]

    txt_path = pem_path.with_suffix(".txt")
    with open(txt_path, "w") as f:
        f.write(f"# Certificate Chain Information for {pem_path.name}\n\n")
        for idx, cert_bytes in enumerate(certs):
            cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
            f.write(f"## Certificate {idx}\n")
            cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if cn_attrs:
                f.write(f"Common Name: {cn_attrs[0].value}\n")
            else:
                f.write("Common Name: N/A\n")
            f.write(f"Valid from: {cert.not_valid_before_utc}\n")
            f.write(f"Valid until: {cert.not_valid_after_utc}\n")
            now = datetime.now(timezone.utc)
            valid = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
            f.write(f"Currently valid: {valid}\n")
            f.write(f"Issuer: {cert.issuer.rfc4514_string()}\n")

            pubkey = cert.public_key()
            f.write(f"Public key type: {pubkey.__class__.__name__}\n")
            try:
                f.write(f"Key size: {pubkey.key_size}\n")
            except AttributeError:
                f.write("Key size: N/A\n")
            f.write("\n")

    return txt_path
