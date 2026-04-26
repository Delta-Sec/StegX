
import json

from stegx.audit_log import append_record, summarise, verify_chain

def test_empty_file_verifies_clean(tmp_path):
    path = str(tmp_path / "audit.log")
    ok, count, bad = verify_chain(path)
    assert ok is True
    assert count == 0
    assert bad is None

def test_append_and_verify(tmp_path):
    path = str(tmp_path / "audit.log")
    assert append_record(path, "encode", ok=True) is True
    assert append_record(path, "decode", ok=True, note="smoke-test") is True
    assert append_record(path, "encode", ok=False, note="ValueError") is True

    ok, count, bad = verify_chain(path)
    assert ok is True
    assert count == 3
    assert bad is None

def test_chain_links_each_record_to_previous(tmp_path):
    path = str(tmp_path / "audit.log")
    append_record(path, "a", ok=True)
    append_record(path, "b", ok=True)
    append_record(path, "c", ok=True)

    records = summarise(path)
    assert len(records) == 3
    assert records[0]["prev"] == ""
    assert records[1]["prev"] == records[0]["chain"]
    assert records[2]["prev"] == records[1]["chain"]

def test_tampered_record_breaks_chain(tmp_path):
    path = str(tmp_path / "audit.log")
    append_record(path, "a", ok=True)
    append_record(path, "b", ok=True)

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()


    record0 = json.loads(lines[0])
    record0["op"] = "tampered"
    lines[0] = json.dumps(record0, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False) + "\n"
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    ok, _count, bad = verify_chain(path)
    assert ok is False
    assert bad == 1

def test_content_hashes_when_given_a_file(tmp_path):
    path = str(tmp_path / "audit.log")
    data_file = tmp_path / "data.bin"
    data_file.write_bytes(b"sensitive bytes that should not leak")

    append_record(path, "encode", ok=True, cover_path=str(data_file))
    records = summarise(path)
    assert records[0]["cover"]

    log_bytes = open(path, "rb").read()
    assert b"sensitive bytes" not in log_bytes

def test_flags_are_sorted(tmp_path):
    path = str(tmp_path / "audit.log")
    append_record(path, "encode", ok=True,
                  flags=["--z", "--a", "--m"])
    rec = summarise(path)[0]
    assert rec["flags"] == ["--a", "--m", "--z"]

def test_missing_file_summarise_returns_empty(tmp_path):
    assert summarise(str(tmp_path / "nope.log")) == []


def test_hmac_signed_records_roundtrip(tmp_path):
    path = str(tmp_path / "audit.log")
    key = b"secret-audit-key-16bytes+"
    append_record(path, "encode", ok=True, hmac_key=key)
    append_record(path, "decode", ok=True, hmac_key=key)
    ok, count, bad = verify_chain(path, hmac_key=key)
    assert ok is True
    assert count == 2
    assert bad is None

def test_hmac_missing_from_existing_record_is_flagged(tmp_path):
    path = str(tmp_path / "audit.log")
    append_record(path, "encode", ok=True)
    ok, _count, bad = verify_chain(path, hmac_key=b"any")
    assert ok is False
    assert bad == 1

def test_hmac_tamper_detected(tmp_path):
    import json as _json
    path = str(tmp_path / "audit.log")
    key = b"k" * 32
    append_record(path, "encode", ok=True, hmac_key=key)
    append_record(path, "decode", ok=True, hmac_key=key)

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    rec0 = _json.loads(lines[0])
    rec0["note"] = "tampered after-the-fact"


    import hashlib as _h
    claimed_hmac = rec0.pop("hmac")
    rec0.pop("chain")
    new_chain = _h.sha256(
        _json.dumps(rec0, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=False).encode()
    ).hexdigest()
    rec0["chain"] = new_chain
    rec0["hmac"] = claimed_hmac
    lines[0] = _json.dumps(
        rec0, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ) + "\n"
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    ok, _count, bad = verify_chain(path, hmac_key=key)
    assert ok is False
    assert bad == 1
