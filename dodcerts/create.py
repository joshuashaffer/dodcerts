import base64
import binascii
import logging
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import warnings
import zipfile

from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit
from urllib.request import urlopen

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509 import (
    Certificate,
    load_der_x509_certificate,
    load_pem_x509_certificate,
)
from cryptography.x509.name import NameOID


log = logging.getLogger("dod-certs")
if not log.handlers:
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )
    log.addHandler(ch)

CERT_SUFFIXES = {".cer", ".crt", ".pem"}
PEM_CERTIFICATE_HEADER = b"-----BEGIN CERTIFICATE-----"


def describe_cert(cert):
    """Extract and format certificate information as comments."""
    if not isinstance(cert, Certificate):
        raise TypeError("cert must be a cryptography.x509.Certificate")

    def first_name_value(name, oid, default="Unknown"):
        values = name.get_attributes_for_oid(oid)
        return values[0].value if values else default

    expires = getattr(cert, "not_valid_after_utc", None)
    if expires is None:
        expires = cert.not_valid_after.replace(tzinfo=timezone.utc)

    return (
        "\n# Subject: {}\n# Issued by: {} {}\n# Signed with: {}\n# Expires: {}\n"
    ).format(
        first_name_value(cert.subject, NameOID.COMMON_NAME),
        first_name_value(cert.issuer, NameOID.ORGANIZATION_NAME),
        first_name_value(cert.issuer, NameOID.ORGANIZATIONAL_UNIT_NAME),
        first_name_value(cert.issuer, NameOID.COMMON_NAME),
        expires,
    )


def _is_certificate_path(path):
    return path.suffix.lower() in CERT_SUFFIXES


def _archive_target(destination, member_name):
    """Return a safe extraction target or raise for an unsafe archive member."""
    member = PurePosixPath(member_name.replace("\\", "/"))
    if member.is_absolute() or ".." in member.parts:
        raise ValueError(f"unsafe archive member path: {member_name!r}")

    target = destination.joinpath(*member.parts).resolve()
    destination = destination.resolve()
    if target != destination and destination not in target.parents:
        raise ValueError(f"archive member escapes destination: {member_name!r}")
    return target


def _write_archive_member(source, destination, member_name):
    target = _archive_target(destination, member_name)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as output:
        shutil.copyfileobj(source, output)


def _extract_certificate_archive(archive_path, destination):
    """Safely extract certificate files and return whether this was an archive."""
    if tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path, mode="r:*") as archive:
            members = [
                member
                for member in archive
                if member.isfile() and _is_certificate_path(Path(member.name))
            ]
            for member in members:
                _archive_target(destination, member.name)
            for member in members:
                source = archive.extractfile(member)
                if source is None:
                    continue
                with source:
                    _write_archive_member(source, destination, member.name)
        return True

    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as archive:
            members = [
                member
                for member in archive.infolist()
                if not member.is_dir() and _is_certificate_path(Path(member.filename))
            ]
            for member in members:
                _archive_target(destination, member.filename)
            for member in members:
                with archive.open(member) as source:
                    _write_archive_member(source, destination, member.filename)
        return True

    return False


def download_resources(urls, destination=None):
    """Download certificate resources and safely extract supported archives."""
    if destination is None:
        destination_path = Path(tempfile.mkdtemp(prefix="certs_"))
        log.info("Created temporary directory: %s", destination_path)
    else:
        destination_path = Path(destination)
        destination_path.mkdir(parents=True, exist_ok=True)

    if not destination_path.is_dir():
        raise NotADirectoryError(destination_path)

    if isinstance(urls, str):
        urls = [urls]

    for url in urls:
        if not isinstance(url, str):
            raise TypeError("resource URLs must be strings")
        if not url:
            continue

        filename = Path(unquote(urlsplit(url).path)).name
        if not filename:
            raise ValueError(f"resource URL has no filename: {url!r}")

        resource_path = destination_path / filename
        log.info("Downloading resource: %s", url)
        with urlopen(url) as response, resource_path.open("wb") as output:
            shutil.copyfileobj(response, output)
        log.info("Resource written to: %s", resource_path)

        try:
            extracted = _extract_certificate_archive(resource_path, destination_path)
        except (OSError, tarfile.TarError, zipfile.BadZipFile, ValueError) as exc:
            log.warning("Unable to extract resource %s: %s", resource_path, exc)
            continue

        if extracted:
            resource_path.unlink()
            log.info("Extracted archive and removed: %s", resource_path)

    return str(destination_path)


def _openssl_pem_compatibility(contents, encoding):
    """Ask OpenSSL to validate and PEM-armor a certificate cryptography rejects."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-inform", encoding, "-outform", "PEM"],
            input=contents,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"OpenSSL compatibility parser unavailable: {exc}") from exc

    if result.returncode != 0 or not result.stdout.startswith(PEM_CERTIFICATE_HEADER):
        detail = result.stderr.decode(errors="replace").strip()
        raise ValueError(detail or "OpenSSL rejected the certificate")

    if encoding == "DER":
        try:
            payload = result.stdout.split(PEM_CERTIFICATE_HEADER, 1)[1]
            payload = payload.split(b"-----END CERTIFICATE-----", 1)[0]
            converted_der = base64.b64decode(b"".join(payload.split()), validate=True)
        except (IndexError, binascii.Error) as exc:
            raise ValueError("OpenSSL returned malformed PEM") from exc
        if converted_der != contents:
            raise ValueError("OpenSSL compatibility conversion changed the DER bytes")

    return result.stdout


def _load_certificate(contents, source):
    """Return descriptive comments and PEM bytes for one certificate."""
    is_pem = contents.lstrip().startswith(PEM_CERTIFICATE_HEADER)
    loader = load_pem_x509_certificate if is_pem else load_der_x509_certificate
    encoding = "PEM" if is_pem else "DER"

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", CryptographyDeprecationWarning)
            cert = loader(contents)
    except (ValueError, CryptographyDeprecationWarning) as strict_error:
        try:
            pem = _openssl_pem_compatibility(contents, encoding)
        except ValueError as compatibility_error:
            raise ValueError(
                f"strict parser: {strict_error}; "
                f"compatibility parser: {compatibility_error}"
            ) from strict_error

        log.info(
            "Using OpenSSL compatibility parsing for %s after the strict "
            "parser rejected its encoding",
            source,
        )
        log.debug("Strict parser rejection for %s: %s", source, strict_error)
        comments = (
            f"\n# Source: {source}\n"
            "# Note: preserved by the OpenSSL compatibility parser\n"
        ).encode()
        return comments, pem

    return describe_cert(cert).encode(), cert.public_bytes(Encoding.PEM)


def _certificate_sort_key(path):
    name = path.name.lower()
    if "ca" in name and "root" not in name:
        return 0, name, str(path)
    if "root" in name:
        return 1, name, str(path)
    return 2, name, str(path)


def create_pem_bundle(destination, urls=None, resource_dir=None, set_env_var=True):
    """Create a PEM certificate bundle from downloaded or local resources."""
    if resource_dir is None and urls is None:
        raise ValueError("urls and/or resource_dir must be specified")

    if resource_dir is None:
        resource_path = None
    else:
        resource_path = Path(resource_dir)
        if not resource_path.is_dir():
            raise NotADirectoryError(resource_path)

    if urls is not None:
        resource_path = Path(download_resources(urls, resource_path))

    certificate_paths = sorted(
        (
            path
            for path in resource_path.rglob("*")
            if path.is_file()
            and _is_certificate_path(path)
            and ("ca" in path.name.lower() or "root" in path.name.lower())
        ),
        key=_certificate_sort_key,
    )

    bundle = bytearray(f"# Bundle Created: {datetime.now()} \n".encode())
    loaded = 0
    for path in certificate_paths:
        try:
            comments, pem = _load_certificate(
                path.read_bytes(), path.relative_to(resource_path)
            )
        except (OSError, ValueError) as exc:
            log.warning("Unable to load certificate %s: %s", path, exc)
            continue
        bundle.extend(comments)
        bundle.extend(pem)
        loaded += 1

    if not loaded:
        raise ValueError(f"no valid CA or root certificates found in {resource_path}")

    destination_path = Path(destination).absolute()
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination_path.parent,
            prefix=f".{destination_path.name}.",
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            output.write(bundle)
        os.replace(temporary_path, destination_path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

    if set_env_var:
        os.environ["DOD_CA_CERTS_PEM_PATH"] = str(destination_path)
        log.info("Set DOD_CA_CERTS_PEM_PATH environment variable")

    return str(destination_path)
