import base64
import os
import shutil

import tarfile
import tempfile
import zipfile

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_der_x509_certificate
from datetime import datetime
from pathlib import Path


def test_where():
    try:
        from dodcerts import where
    except ImportError:
        assert False
    filepath = where()
    assert filepath is not None
    filepath = Path(filepath)
    assert filepath.name == "dod-ca-certs.pem"
    assert filepath.exists()
    with open(filepath) as f:
        assert f.readline().find("# Bundle Created: ") == 0
        assert f.readline().find("\n") == 0
        assert f.readline().find("# Subject: ") == 0
        assert f.readline().find("# Issued by: ") == 0
        assert f.readline().find("# Signed with: ") == 0
        assert f.readline().find("# Expires: ") == 0
        assert f.readline().find("-----BEGIN CERTIFICATE-----\n") == 0
        for line in f.readlines():
            last = line
        assert last.find("-----END CERTIFICATE-----\n") == 0

    env = os.getenv("DOD_CA_CERTS_PATH", None)
    os.environ["DOD_CA_CERTS_PEM_PATH"] = "TEST"
    filepath = where()
    assert filepath == "TEST"
    if env is not None:
        os.environ["DOD_CA_CERTS_PEM_PATH"] = env
    else:
        os.environ.pop("DOD_CA_CERTS_PEM_PATH")


def test_describe_cert():
    try:
        from dodcerts.create import describe_cert
    except ImportError:
        assert False
    fpath = Path(__file__).parent / "input" / "DoDRoot5.cer"
    with open(fpath, "rb") as f:
        cert = load_der_x509_certificate(f.read(), backend=default_backend())
        res = describe_cert(cert)
        assert (
            res == "\n"
            "# Subject: DoD Root CA 5\n"
            "# Issued by: U.S. Government DoD\n"
            "# Signed with: DoD Root CA 5\n"
            "# Expires: 2041-06-14 17:17:27+00:00\n"
        )


def test_download_resources():
    try:
        from dodcerts.create import download_resources
    except ImportError:
        assert False
    fpath = Path(__file__).parent / "input" / "DoDRoot5.cer"

    with tempfile.TemporaryDirectory() as resource_dir:
        # verify string input and single file with specified destination
        assert len(os.listdir(resource_dir)) == 0
        assert (
            download_resources(urls=fpath.resolve().as_uri(), destination=resource_dir)
            == resource_dir
        )
        assert len(os.listdir(resource_dir)) == 1

    # verify iterable input
    resource_dir = download_resources(
        urls=[
            fpath.as_uri(),
        ]
    )
    assert len(os.listdir(resource_dir)) == 1
    shutil.rmtree(resource_dir)

    with tempfile.TemporaryDirectory() as archive_dir:
        # verify zip file
        zippath = Path(archive_dir) / "certs.zip"
        with zipfile.ZipFile(zippath, "w") as zip:
            zip.write(fpath)
        resource_dir = download_resources(
            [
                zippath.as_uri(),
            ]
        )
        assert len(os.listdir(resource_dir)) == 1
        shutil.rmtree(resource_dir)

        # verify tar file
        tarpath = Path(archive_dir) / "certs.tar"
        with tarfile.TarFile(tarpath, "w") as tar:
            tar.add(fpath)
        resource_dir = download_resources([tarpath.as_uri()])
        assert len(os.listdir(resource_dir)) == 1
        shutil.rmtree(resource_dir)


def test_create_pem_bundle():
    try:
        from dodcerts.create import create_pem_bundle
    except ImportError:
        assert False

    with tempfile.TemporaryDirectory() as tmpdir:
        # make bundle from test cert
        fpath = Path(os.path.dirname(__file__)) / "input" / "DoDRoot5.cer"
        bundlepath = Path(tmpdir) / "dod-ca-certs.pem"

        env = os.environ.get("DOD_CA_CERTS_PEM_PATH", None)
        if env is not None:
            os.environ.pop("DOD_CA_CERTS_PEM_PATH")

        create_pem_bundle(
            destination=bundlepath.as_posix(),
            urls=[
                fpath.as_uri(),
            ],
            set_env_var=False,
        )
        assert bundlepath.exists()
        with open(bundlepath) as f:
            bundle_dt = datetime.strptime(
                f.readline(), "# Bundle Created: %Y-%m-%d %H:%M:%S.%f\n"
            )
            span = datetime.now() - bundle_dt
            assert span.total_seconds() < 10.0
        assert os.environ.get("DOD_CA_CERTS_PEM_PATH", None) is None

        res = create_pem_bundle(
            destination=bundlepath.as_posix(),
            urls=[
                fpath.as_uri(),
            ],
            set_env_var=True,
        )
        assert os.environ.get("DOD_CA_CERTS_PEM_PATH", None) == res

        if env is not None:
            os.environ["DOD_CA_CERTS_PEM_PATH"] = env


def test_create_pem_bundle_preserves_nonconforming_dod_root_4():
    from dodcerts.create import create_pem_bundle

    fixture = Path(__file__).parent / "input" / "DoDRoot4.der.b64"
    original_der = base64.b64decode(fixture.read_bytes())

    with tempfile.TemporaryDirectory() as tmpdir:
        resource_dir = Path(tmpdir) / "certs"
        resource_dir.mkdir()
        (resource_dir / "DoDRoot4.cer").write_bytes(original_der)
        bundle_path = Path(tmpdir) / "bundle.pem"

        create_pem_bundle(bundle_path, resource_dir=resource_dir, set_env_var=False)

        bundle = bundle_path.read_bytes()
        pem_body = bundle.split(b"-----BEGIN CERTIFICATE-----", 1)[1]
        pem_body = pem_body.split(b"-----END CERTIFICATE-----", 1)[0]
        assert base64.b64decode(pem_body) == original_der
        assert b"OpenSSL compatibility parser" in bundle


def test_create_pem_bundle_detects_pem_by_content_not_extension():
    from dodcerts.create import create_pem_bundle

    fixture = Path(__file__).parent / "input" / "DoDRoot5.cer"
    cert = load_der_x509_certificate(fixture.read_bytes())

    with tempfile.TemporaryDirectory() as tmpdir:
        resource_dir = Path(tmpdir) / "nested"
        resource_dir.mkdir()
        (resource_dir / "DoDRoot5.cer").write_bytes(cert.public_bytes(Encoding.PEM))
        bundle_path = Path(tmpdir) / "bundle.pem"

        create_pem_bundle(bundle_path, resource_dir=resource_dir, set_env_var=False)

        assert bundle_path.read_bytes().count(b"-----BEGIN CERTIFICATE-----") == 1


def test_download_resources_rejects_archive_path_traversal():
    from dodcerts.create import download_resources

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        archive_path = tmp_path / "unsafe.zip"
        destination = tmp_path / "destination"
        destination.mkdir()
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("../escaped.cer", b"not a certificate")

        download_resources(archive_path.as_uri(), destination)

        assert not (tmp_path / "escaped.cer").exists()
