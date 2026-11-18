#!/usr/bin/env python3
"""Patch impacket's ADCS attack modules for Python 3.14 + pyOpenSSL >= 26.

pyOpenSSL 26+ removed crypto.X509Req(). impacket's adcsattack.py and
rpcattack.py use it for CSR generation in ADCS relay attacks (ESC1/ESC11).
This patch replaces the broken code with pure `cryptography` equivalents.

Applied at image build time via Dockerfile. Idempotent — safe to re-run.
"""
import re
import sys
from pathlib import Path

IMPACKET_DIRS = [
    Path("/usr/lib/python3/dist-packages/impacket"),
    Path("/usr/local/lib").glob("python3.*/dist-packages/impacket"),
]

def find_impacket_roots():
    roots = []
    for p in IMPACKET_DIRS:
        if isinstance(p, Path):
            if p.is_dir():
                roots.append(p)
        else:
            roots.extend(x for x in p if x.is_dir())
    return roots


ADCSATTACK_GENERATE_CSR_OLD = re.compile(
    r'(    @staticmethod\s+def generate_csr\(key, CN.*?\n)'
    r'(.*?)'
    r'(\n    @staticmethod\s+def generate_pfx)',
    re.DOTALL,
)

GENERATE_CSR_NEW = '''    @staticmethod
    def generate_csr(key, CN, altName, csr_type=None):
        """Generate CSR using cryptography (pyOpenSSL 26+ compat)."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.x509 import (
            CertificateSigningRequestBuilder, Name, NameAttribute,
            SubjectAlternativeName, OtherName,
        )
        from cryptography.x509.oid import NameOID, ObjectIdentifier

        LOG.info("Generating CSR...")
        builder = CertificateSigningRequestBuilder()
        if CN:
            builder = builder.subject_name(Name([
                NameAttribute(NameOID.COMMON_NAME, CN),
            ]))
        if altName:
            upn_oid = ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
            raw = altName.encode("utf-8")
            # DER-encode as UTF8String: tag 0x0c + length + content
            if len(raw) < 128:
                upn_der = bytes([0x0c, len(raw)]) + raw
            else:
                # long-form length (2-byte)
                upn_der = bytes([0x0c, 0x81, len(raw)]) + raw
            builder = builder.add_extension(
                SubjectAlternativeName([OtherName(upn_oid, upn_der)]),
                critical=False,
            )
        # Accept both pyOpenSSL PKey and cryptography key objects
        if hasattr(key, "to_cryptography_key"):
            key_crypto = key.to_cryptography_key()
        elif hasattr(key, "private_bytes"):
            key_crypto = key
        else:
            raise TypeError("Unsupported key type: %s" % type(key))

        csr = builder.sign(key_crypto, hashes.SHA256())

        # Return DER for ICPR (RPC), PEM for HTTP
        try:
            from OpenSSL.crypto import FILETYPE_ASN1
            want_der = (csr_type == FILETYPE_ASN1)
        except (ImportError, AttributeError):
            want_der = (csr_type == 2)  # FILETYPE_ASN1 = 2

        if want_der:
            return csr.public_bytes(Encoding.DER)
        return csr.public_bytes(Encoding.PEM)

'''


RPCATTACK_KEY_OLD = re.compile(
    r'(class ICPRRPCAttack:\s+def _run\(self\):\s+)'
    r'key = crypto\.PKey\(\)\s+'
    r'key\.generate_key\(crypto\.TYPE_RSA, 4096\)',
)

RPCATTACK_KEY_NEW = (
    r'\g<1>'
    r'from cryptography.hazmat.primitives.asymmetric import rsa\n'
    r'        key = rsa.generate_private_key(65537, 4096)'
)

RPCATTACK_PFX_OLD = 'certificate_store = ADCSAttack.generate_pfx(key.to_cryptography_key(), cert_obj)'
RPCATTACK_PFX_NEW = (
    'key_for_pfx = key.to_cryptography_key() if hasattr(key, "to_cryptography_key") else key\n'
    '        certificate_store = ADCSAttack.generate_pfx(key_for_pfx, cert_obj)'
)

RPCATTACK_CSR_OLD = 'csr = ADCSAttack.generate_csr(key, self.username, self.config.altName, crypto.FILETYPE_ASN1)'
RPCATTACK_CSR_NEW = 'csr = ADCSAttack.generate_csr(key, self.username, self.config.altName, 2)  # 2 = DER/ASN1'


def patch_adcsattack(root):
    path = root / "examples/ntlmrelayx/attacks/httpattacks/adcsattack.py"
    if not path.exists():
        return False
    src = path.read_text()
    if "pyOpenSSL 26+ compat" in src:
        print(f"  [skip] {path} already patched")
        return True
    m = ADCSATTACK_GENERATE_CSR_OLD.search(src)
    if not m:
        print(f"  [warn] {path}: generate_csr pattern not found — manual check needed")
        return False
    new_src = src[:m.start()] + GENERATE_CSR_NEW + m.group(3) + src[m.end():]
    path.write_text(new_src)
    print(f"  [OK] {path}: generate_csr patched")
    return True


def patch_rpcattack(root):
    path = root / "examples/ntlmrelayx/attacks/rpcattack.py"
    if not path.exists():
        return False
    src = path.read_text()
    if "rsa.generate_private_key" in src:
        print(f"  [skip] {path} already patched")
        return True

    patched = False

    # 1) key generation
    new_src, n = RPCATTACK_KEY_OLD.subn(RPCATTACK_KEY_NEW, src)
    if n:
        src = new_src
        patched = True
        print(f"  [OK] {path}: key generation patched")

    # 2) CSR call — use integer 2 instead of crypto.FILETYPE_ASN1
    if RPCATTACK_CSR_OLD in src:
        src = src.replace(RPCATTACK_CSR_OLD, RPCATTACK_CSR_NEW)
        patched = True
        print(f"  [OK] {path}: CSR call patched")

    # 3) PFX generation — handle both key types
    if RPCATTACK_PFX_OLD in src:
        src = src.replace(RPCATTACK_PFX_OLD, RPCATTACK_PFX_NEW)
        patched = True
        print(f"  [OK] {path}: PFX generation patched")

    if patched:
        path.write_text(src)
    else:
        print(f"  [warn] {path}: no patterns matched — manual check needed")
    return patched


def main():
    roots = find_impacket_roots()
    if not roots:
        print("[!] No impacket installation found")
        sys.exit(1)

    ok = True
    for root in roots:
        print(f"Patching {root}...")
        ok &= patch_adcsattack(root)
        ok &= patch_rpcattack(root)
        # clear pycache so Python picks up the changes
        for pyc in root.rglob("__pycache__"):
            for f in pyc.iterdir():
                f.unlink()

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
