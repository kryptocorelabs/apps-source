"""Native CLI build; no production signing key is generated or embedded."""
from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import zipfile

root = Path(__file__).resolve().parents[2]
output = Path(sys.argv[1]).resolve()
output.mkdir(parents=True, exist_ok=True)
system = {'win32': 'windows', 'linux': 'linux', 'darwin': 'macos'}[sys.platform]
arch = {'AMD64': 'x86_64', 'x86_64': 'x86_64', 'arm64': 'aarch64', 'aarch64': 'aarch64'}[platform.machine()]
target = system + '-' + arch
subprocess.run(['cargo', 'build', '--locked', '--release', '-p', 'kryptocore-verify'], cwd=root, check=True)
binary = Path(os.environ.get('CARGO_TARGET_DIR', root / 'target')).resolve() / 'release' / ('kryptocore-verify' + ('.exe' if system == 'windows' else ''))
subprocess.run([str(binary), '--help'], check=True)
stage = output / ('KryptoCore-Verify-' + target)
stage.mkdir(exist_ok=False)
shutil.copy2(binary, stage / binary.name)
shutil.copy2(root / 'LICENSE', stage / 'LICENSE')
for name in ('README.md', 'PROTOCOL.md', 'THIRD_PARTY_NOTICES.md'):
    shutil.copy2(Path(__file__).parent / name, stage / name)
shutil.copytree(Path(__file__).parent / 'third-party', stage / 'third-party')
archive = output / (stage.name + ('.zip' if system == 'windows' else '.tar.gz'))
if system == 'windows':
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, strict_timestamps=False) as package:
        for file in stage.rglob('*'):
            if file.is_file():
                package.write(file, stage.name + '/' + file.relative_to(stage).as_posix())
else:
    with tarfile.open(archive, 'w:gz') as package:
        package.add(stage, arcname=stage.name)
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
(output / 'SHA256SUMS.txt').write_text(digest + '  ' + archive.name + '\n', encoding='ascii')
(output / 'BUILD-MANIFEST.json').write_text(json.dumps(dict(
    source_commit=os.environ.get('GITHUB_SHA', 'local-working-tree'), target=target,
    version='0.1.0-preview.1', archive=archive.name, sha256=digest,
    publisher_signed=False, official_release_key_provisioned=False), indent=2) + '\n', encoding='utf-8')
print('Packaged:', archive)
