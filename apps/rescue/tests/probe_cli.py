"""Synthetic fixtures only; no passwords or encrypted contents are opened."""
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
worker = root / "target" / "release" / ("kryptocore-rescue.exe" if os.name == "nt" else "kryptocore-rescue")

def frame(payload):
    return struct.pack("<I", len(payload)) + payload

with tempfile.TemporaryDirectory() as directory:
    source = Path(directory) / "misleading.exe"
    original = b"KCV2\0" + bytes(216)
    source.write_bytes(original)
    result = subprocess.run([str(worker), "inspect", str(source)], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    reply = json.loads(result.stdout)
    data = json.loads(reply["text"])
    assert reply["ok"] and data["format"] == "vault_v2"
    assert data["authenticity"] == "not_verified" and data["data_access_available"] is False
    assert set(data) == {"schema_version", "format", "label", "file_bytes", "payload_offset", "payload_bytes", "credential_routes", "authenticity", "data_access_available"}
    assert source.read_bytes() == original
    assert list(Path(directory).iterdir()) == [source]
    source.write_bytes(b"not a supported file")
    failed = subprocess.run([str(worker), "inspect", str(source)], capture_output=True, timeout=10)
    assert failed.returncode == 2 and not json.loads(failed.stdout)["ok"]
    metadata = json.dumps({"action": "inspect", "input": str(source)}).encode()
    credentials = b"must-not-be-accepted-or-echoed"
    request = frame(metadata) + frame(credentials) + frame(b"")
    rejected = subprocess.run([str(worker)], input=request, capture_output=True, timeout=10)
    assert rejected.returncode == 0 and not json.loads(rejected.stdout)["ok"]
    assert credentials not in rejected.stdout and credentials not in rejected.stderr
    assert str(source).encode() not in rejected.stdout
    assert source.read_bytes() == b"not a supported file"
    assert list(Path(directory).iterdir()) == [source]

print("Rescue CLI passed: marker-only result, no authentication claim, source preservation, CLI failure status and credential rejection.")
