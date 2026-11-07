"""Refresh the companion's locked, all-target dependency snapshot and license copies.

Run from any directory with Cargo on PATH. Uses only cached, locked dependencies.
The resolution reflects workspace feature unification, including build/dev edges.
"""
import csv
import json
from pathlib import Path
import re
import subprocess


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main():
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--offline", "--locked", "--format-version", "1"],
        cwd=ROOT, text=True, encoding="utf-8"))
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    root = next(p["id"] for p in metadata["packages"]
                if p["name"] == "kryptocore-signatures")
    reached, pending = set(), [root]
    while pending:
        current = pending.pop()
        if current in reached:
            continue
        reached.add(current)
        pending.extend(d["pkg"] for d in nodes[current]["deps"])
    checksums = {}
    for block in (ROOT / "Cargo.lock").read_text(encoding="utf-8").split("[[package]]")[1:]:
        fields = dict(re.findall(r'^([a-z]+) = "([^"\n]*)"$', block, re.M))
        checksums[(fields["name"], fields["version"])] = fields.get("checksum", "")
    direct = {d["pkg"]: ",".join(sorted({k["kind"] or "normal" for k in d["dep_kinds"]}))
              for d in nodes[root]["deps"]}
    rows = []
    for package_id in sorted(reached - {root}, key=lambda k: (packages[k]["name"], packages[k]["version"])):
        package = packages[package_id]
        name, version = package["name"], package["version"]
        source = Path(package["manifest_path"]).parent
        slug = name + "-" + version
        target = HERE / "third-party" / "licenses" / slug
        notices = []
        for entry in sorted(source.iterdir()):
            if not entry.name.upper().startswith(("LICENSE", "COPYING", "COPYRIGHT", "NOTICE", "AUTHORS")):
                continue
            paths = [entry] if entry.is_file() else sorted(p for p in entry.rglob("*") if p.is_file())
            for path in paths:
                destination = target / path.relative_to(source)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(path.read_bytes())
                notices.append(destination.relative_to(HERE).as_posix())
        if not notices:
            raise RuntimeError("Missing upstream notices for " + slug)
        rows.append([name, version, "direct/" + direct[package_id] if package_id in direct else "transitive",
                     package["license"], checksums[(name, version)],
                     package.get("repository") or "", "; ".join(notices)])
    inventory = HERE / "third-party" / "DEPENDENCIES.tsv"
    inventory.parent.mkdir(parents=True, exist_ok=True)
    with inventory.open("w", encoding="utf-8", newline="") as output:
        writer = csv.writer(output, delimiter="\t", lineterminator="\n")
        writer.writerow(["component", "version", "relation", "license", "registry_sha256", "upstream", "notice_files"])
        writer.writerows(rows)
    print("Recorded {} locked dependencies and their upstream notices.".format(len(rows)))


if __name__ == "__main__":
    main()
