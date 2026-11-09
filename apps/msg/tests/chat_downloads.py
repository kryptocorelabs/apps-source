import json, pathlib, queue, socket, struct, subprocess, tempfile, threading
from contextlib import ExitStack

exe = pathlib.Path("target/release/kryptocore-desktop-engine.exe").resolve()
secret = b"only synthetic messenger test phrase"

def frame(data):
    if not isinstance(data, bytes):
        data = json.dumps(data).encode()
    return struct.pack("<I", len(data)) + data

def initial(request, second=b""):
    return frame(request) + frame(secret) + frame(second)

def new_identity(path):
    reply = subprocess.run([exe], input=initial({"action": "new_identity", "path": str(path)}, secret), capture_output=True, timeout=15, check=True)
    data = json.loads(reply.stdout)
    assert data["ok"], data
    return data["text"]

def endpoints():
    with socket.socket() as alice, socket.socket() as bob:
        alice.bind(("127.0.0.1", 0)); bob.bind(("127.0.0.1", 0))
        return [f"127.0.0.1:{s.getsockname()[1]}" for s in (alice, bob)]

class Peer:
    def __init__(self, stack, path, key, local, remote):
        self.worker = stack.enter_context(subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE))
        stack.callback(self.stop)
        self.events = queue.Queue()
        self.saved = []
        def collect():
            for line in self.worker.stdout:
                self.events.put(json.loads(line))
        threading.Thread(target=collect, daemon=True).start()
        self.worker.stdin.write(initial(dict(action="chat", path=str(path), peer=key, local=local, address=remote, tor=False)))
        self.worker.stdin.flush()
    def stop(self):
        if self.worker.poll() is None:
            self.worker.kill()
    def send(self, kind, **fields):
        self.worker.stdin.write(frame(dict(kind=kind, **fields)))
        self.worker.stdin.flush()
    def event(self, event_name, **expected):
        for index, event in enumerate(self.saved):
            if event.get("event") == event_name:
                del self.saved[index]
                assert all(event[k] == v for k,v in expected.items()), event
                return event
        while True:
            event = self.events.get(timeout=15)
            if event.get("event") == event_name:
                assert all(event[k] == v for k,v in expected.items()), event
                return event
            if "event" not in event:
                raise AssertionError(event)
            self.saved.append(event)

with tempfile.TemporaryDirectory() as scratch, ExitStack() as stack:
    root = pathlib.Path(scratch)
    a, b = root / "a.kcmi", root / "b.kcmi"
    a_key, b_key = new_identity(a), new_identity(b)
    a_addr, b_addr = endpoints()
    left = Peer(stack, a, b_key, a_addr, b_addr)
    right = Peer(stack, b, a_key, b_addr, a_addr)
    left.event("chat_connected"); right.event("chat_connected")
    left.send("text", text="Ping")
    right.send("text", text="Pong")
    left.event("chat_text", text="Pong")
    right.event("chat_text", text="Ping")
    left.event("chat_receipt", ok=True)
    right.event("chat_receipt", ok=True)
    source = root / "attachment.dat"
    payload = bytes(range(251)) * 400
    source.write_bytes(payload)
    left.send("file", path=str(source))
    offer = right.event("chat_download")
    ident = offer["id"]
    assert offer["name"] == source.name and offer["size"] == len(payload)
    assert not offer["confirm"] and not offer["has_folder"]
    assert not (root / "MSG-attachment.dat").exists()
    right.send("text", text="Can still reply during the save prompt")
    left.event("chat_text", text="Can still reply during the save prompt")
    right.event("chat_receipt", ok=True)
    right.send("save_download", id=ident + 1, path=str(root/"wrong.bin"))
    right.event("chat_download_expired", id=ident + 1)
    assert not (root / "wrong.bin").exists()
    existing = root / "existing.bin"
    existing.write_bytes(b"keep me")
    right.send("save_download", id=ident, path=str(existing))
    right.event("chat_download_error", id=ident)
    assert existing.read_bytes() == b"keep me"
    saved = root / "selected-name.bin"
    right.send("save_download", id=ident, path=str(saved))
    right.event("chat_file")
    left.event("chat_receipt", ok=True)
    assert saved.read_bytes() == payload
    left.send("file", path=str(source))
    offer = right.event("chat_download")
    right.send("reject_download", id=offer["id"])
    right.event("chat_download_closed")
    left.event("chat_receipt", ok=False)
    left.send("file", path=str(source))
    offer = right.event("chat_download")
    right.send("download_folder", id=offer["id"], path=scratch)
    right.event("chat_folder")
    right.event("chat_file")
    left.event("chat_receipt", ok=True)
    assert (root/"MSG-attachment.dat").read_bytes() == payload
    risky_names = [
        "release.txt.EXE", ".ps1", "report.docm", "letter.dotm", "records.XLSM",
        "model.xltm", "formula.xlam", "book.xlsb", "slides.pptm", "style.potm",
        "show.ppsm", "extension.ppam", "image.ISO", "machine.vhd", "machine.vhdx",
    ]
    fixtures = [(name, b"test fixture") for name in risky_names]
    fixtures.append(("renamed.txt", b"MZ fixture"))
    for name, contents in fixtures:
        attachment = root / name
        attachment.write_bytes(contents)
        destination = root / f"MSG-{name}"
        left.send("file", path=str(attachment))
        offer = right.event("chat_download", name=name, confirm=True, has_folder=True)
        assert not destination.exists()
        right.send("reject_download", id=offer["id"])
        right.event("chat_download_closed", id=offer["id"])
        left.event("chat_receipt", ok=False)
        assert not destination.exists()
    attachment = root / "records.XLSM"
    destination = root / f"MSG-{attachment.name}"
    left.send("file", path=str(attachment))
    offer = right.event("chat_download", name=attachment.name, confirm=True, has_folder=True)
    right.send("save_in_folder", id=offer["id"])
    right.event("chat_file", id=offer["id"])
    left.event("chat_receipt", ok=True)
    assert destination.read_bytes() == attachment.read_bytes()
    empty = root / "empty.bin"
    empty.write_bytes(b"")
    left.send("file", path=str(empty))
    right.event("chat_file")
    left.event("chat_receipt", ok=True)
    assert (root/"MSG-empty.bin").read_bytes() == b""
    left.worker.stdin.close()
    assert left.worker.wait(5) == 0
    assert right.worker.wait(5) == 0
    print("Preview worker passed: download offers, replies, stale decisions, collision protection, risky attachment confirmation, remembered folder, empty file and shutdown.")

