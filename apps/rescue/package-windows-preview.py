"""Package an existing Rescue executable with its versioned upstream notices."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile


ROOT = Path(__file__).resolve().parents[2]
WINDOWS = "x86_64-pc-windows-msvc"
EXE = "KryptoCore-Rescue.exe"
NOTICE_PREFIXES = ("LICENSE", "COPYING", "COPYRIGHT", "NOTICE", "AUTHORS", "THIRD-PARTY")


def output(*command):
    return subprocess.check_output(command, cwd=ROOT, encoding="utf-8").strip()


def notice_files(directory):
    for entry in sorted(directory.iterdir()):
        if entry.name.upper().startswith(NOTICE_PREFIXES):
            if entry.is_file():
                yield entry
            elif entry.is_dir():
                yield from sorted(file for file in entry.rglob("*") if file.is_file())


def read_notice(file):
    data = file.read_bytes()
    if not data.strip():
        raise ValueError(f"Empty upstream notice: {file.name}")
    return data


def rust_notices():
    metadata = json.loads(output(
        "cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", WINDOWS,
    ))
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    rescue = next(package for package in packages.values()
                  if package["id"] in metadata["workspace_members"]
                  and package["name"] == "kryptocore-rescue")
    pending, visited = [rescue["id"]], set()
    while pending:
        package_id = pending.pop()
        if package_id in visited:
            continue
        visited.add(package_id)
        pending.extend(dep["pkg"] for dep in nodes[package_id]["deps"]
                       if any(kind["kind"] != "dev" for kind in dep["dep_kinds"]))

    files, rows = {}, []
    for package in sorted((packages[item] for item in visited),
                          key=lambda item: (item["name"], item["version"])):
        directory = Path(package["manifest_path"]).parent
        slug = f"{package['name']}-{package['version']}"
        notices = {file.relative_to(directory).as_posix(): file for file in notice_files(directory)}
        if package["license_file"]:
            license_file = directory / package["license_file"]
            notices[license_file.name] = license_file
        if not notices and package["source"] is None:
            notices["LICENSE"] = ROOT / "LICENSE"
        if not notices and (package["source"] or "").startswith("git+"):
            checkout = next(parent for parent in directory.parents if (parent / ".git").exists())
            notices["LICENSE"] = checkout / "LICENSE"
        if not notices or not (package["license"] or package["license_file"]):
            raise ValueError(f"Missing license information for {slug}")
        prefix = f"third-party/rust/{slug}"
        for name, file in notices.items():
            files[f"{prefix}/{name}"] = read_notice(file)
        rows.append("\t".join((package["name"], package["version"],
                              package["license"] or package["license_file"], prefix)))
    files["RUST-DEPENDENCIES.tsv"] = (
        "component\tversion\tlicense\tnotices\n" + "\n".join(rows) + "\n"
    ).encode()

    runtime = Path(output("rustc", "--print", "sysroot")) / "share/doc/rust"
    for file in [runtime / "COPYRIGHT-library.html", *sorted((runtime / "licenses").glob("*.txt"))]:
        files[f"third-party/rust-runtime/{file.relative_to(runtime).as_posix()}"] = read_notice(file)
    return rescue["version"], files


def dotnet_notices(version):
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Expected an exact .NET runtime version.")
    cache = Path(os.environ.get("NUGET_PACKAGES", Path.home() / ".nuget/packages"))
    files = {}
    for package in ("microsoft.netcore.app.runtime.win-x64",
                    "microsoft.windowsdesktop.app.runtime.win-x64"):
        directory = cache / package / version
        if not directory.is_dir():
            raise ValueError(f"Restore {package} {version} before packaging.")
        notices = list(notice_files(directory))
        if not any(file.name.upper().startswith("LICENSE") for file in notices):
            raise ValueError(f"Missing license for {package} {version}.")
        if package.startswith("microsoft.netcore.") and not any(
                file.name.upper().startswith("THIRD-PARTY") for file in notices):
            raise ValueError(f"Missing third-party notices for {package} {version}.")
        for file in notices:
            files[f"third-party/dotnet/{package}/{file.relative_to(directory).as_posix()}"] = (
                read_notice(file)
            )
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--dotnet-runtime", required=True)
    args = parser.parse_args()
    if args.executable.name != EXE:
        parser.error(f"Expected {EXE}.")
    binary = args.executable.read_bytes()
    if not binary.startswith(b"MZ"):
        parser.error("Expected a Windows executable.")

    version, files = rust_notices()
    if not re.fullmatch(r"\d+\.\d+\.\d+-preview\.\d+", version):
        parser.error(f"Expected a Rescue preview version, got {version}.")
    files.update(dotnet_notices(args.dotnet_runtime))
    files[EXE] = binary
    files["LICENSE"] = read_notice(ROOT / "LICENSE")
    files["START.txt"] = (
        f"KryptoCore Rescue {version} for Windows x64\n\n"
        "Extract the complete archive, then open KryptoCore-Rescue.exe.\n"
        "Work on a copy. Select a supported Vault or Container and supply its matching credential.\n"
        "Rescue preserves the original. Treat exported data as plaintext.\n"
        "Verify downloads and read the supported formats at https://github.com/kryptocorelabs/rescue.\n"
    ).encode()
    files["THIRD_PARTY_NOTICES.md"] = (
        "# Third-party notices\n\n"
        f"This Windows x64 preview includes the self-contained .NET {args.dotnet_runtime} runtime "
        "and a Rust recovery worker.\n"
        "Original .NET runtime-pack notices are in third-party/dotnet.\n"
        "Rust standard library attribution and licenses are in third-party/rust-runtime.\n"
        "RUST-DEPENDENCIES.tsv records the locked Windows normal and build dependency graph. "
        "Original crate notices are in third-party/rust.\n"
        "ClamAV is an optional external scanner.\n"
    ).encode()
    stage = f"KryptoCore-Rescue-{version}-windows-x64"
    args.output_dir.mkdir(parents=True, exist_ok=True)
    archive = args.output_dir / f"{stage}.zip"
    with zipfile.ZipFile(archive, "x") as package:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(f"{stage}/{name}")
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            package.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
    print(f"Packaged {archive}")


if __name__ == "__main__":
    main()
