"""binary_cache hardening: zip-bomb caps (#19) + safe staging/idempotency (#14)."""
import zipfile

import tools._vl_core.binary_cache as bc


def _make_zip(path, files):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return path


def test_zip_within_caps_extracts(tmp_path):
    archive = _make_zip(tmp_path / "ok.zip", {"a.txt": b"hello", "b.txt": b"world"})
    out = tmp_path / "out"
    out.mkdir()
    assert bc._unpack_zipfile(archive, out) is True
    assert (out / "a.txt").read_bytes() == b"hello"


def test_zip_rejected_when_total_size_exceeds_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(bc, "_MAX_UNZIP_BYTES", 4)        # tiny cap
    archive = _make_zip(tmp_path / "big.zip", {"a.txt": b"way more than four bytes"})
    out = tmp_path / "out"
    out.mkdir()
    assert bc._unpack_zipfile(archive, out) is False
    assert not any(out.iterdir())                          # nothing written


def test_zip_rejected_when_too_many_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(bc, "_MAX_UNZIP_ENTRIES", 1)
    archive = _make_zip(tmp_path / "many.zip", {"a": b"x", "b": b"y"})
    out = tmp_path / "out"
    out.mkdir()
    assert bc._unpack_zipfile(archive, out) is False


def test_get_unpacked_is_idempotent(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x7fELF" + b"\x00" * 32)
    d1 = bc.get_unpacked(f)
    d2 = bc.get_unpacked(f)            # cache hit -> same dir, no crash/race
    assert d1 == d2
    assert d1.is_dir()
