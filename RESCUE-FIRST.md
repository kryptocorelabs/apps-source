# If the main app stops working

Your encrypted file and its access credentials matter more than the app's
installation. Keep both available before relying on a preview. Rescue provides
a separate, offline interface to supported files; it uses the same format
readers, not an independent cryptographic implementation or a bypass.

## Prepare while everything works

1. Keep dated encrypted backups on separate storage. In Vault, choose
   **Einstellungen → Sicherung erstellen** (Settings → Create backup).
2. Keep the matching password or emergency sheet separately and protected.
   Older backups retain the access credentials that matched them at the time.
3. Keep a [Rescue download](https://github.com/kryptocorelabs/rescue/releases)
   and its notices available offline. Check its origin through the
   [release verification guide](https://github.com/kryptocorelabs/kryptocore/blob/main/VERIFY-DOWNLOADS.md).
4. Practice the steps below with synthetic data and a disposable backup copy.

## Vault: recover your logins without starting Vault

1. Close Vault. Make a **working copy** of the `.kcv` file; preserve the original
   and your backups. If a file looks damaged, keep it rather than overwriting it.
2. Open **KryptoCore-Rescue.exe** on a trusted Windows computer. Choose
   **Datei auswählen …** (Choose file) and select the working copy.
3. Choose **Passwort** (Password). For KCV2 through KCV4, you may instead select
   **Wiederherstellungsschlüssel** (Recovery key) and enter the matching key
   from your emergency sheet. KCV1 does not have that recovery slot.
4. Choose **Speicherort wählen …** (Choose destination) and a new local JSON
   file in a protected, preferably encrypted location. Confirm the plaintext
   warning, then choose **Entschlüsseln und exportieren** (Decrypt and export).
5. In a current development Vault build, choose **Aus JSON-Export umziehen**
   (Move from JSON export), select the Rescue JSON and create a new vault with
   a new password and emergency sheet. Its payload seed is freshly generated.
   See [migration instructions](https://github.com/kryptocorelabs/vault/blob/main/MIGRATION.md).
   Older published Vault previews require manually recreating entries using a
   trusted local editor. Protect the export and remove unneeded copies when
   finished; ordinary deletion does not guarantee secure erasure.

Rescue authenticates before publishing output, leaves the input unchanged and
refuses to overwrite an existing destination. A recognized file marker alone
is not successful authentication. If export fails, keep the source untouched
and try another known-good backup copy with its matching credentials.

KCV3 and KCV4 require a development Rescue build with the shared reader. The
published preview.3 download supports KCV1 and KCV2. Rescue intentionally accepts authentic older backups
and does not enforce the separate Vault GUI high-water mark.

## Container: get your files out

Choose a working copy of the `.kcc` archive, enter its passphrase and select a
**new destination folder**. Confirm the plaintext warning and export. An EXE
containing a supported KCC payload can also be selected as input: Rescue reads
it as data and does not launch it. Extracted files remain untrusted; do not
automatically open programs or documents from an unknown sender.

## What this does not recover

| Situation | Current limit |
| --- | --- |
| Lost file or damaged ciphertext/tag | Rescue cannot reconstruct missing data or bypass authentication. Try a preserved backup. |
| Lost password and no matching configured recovery key | There is no universal master key. |
| MSG identities, contacts or session messages | Marker inspection only. Authenticated MSG recovery is not implemented; session history is not a saved archive. Keep identity files and their sidecars together for use in MSG. |
| Native Linux/macOS Rescue desktop | The Rescue desktop preview is Windows-only. Supported Vault/Container files can be copied to a trusted Windows computer; native recovery GUIs for other systems are not yet available. |

See the [Rescue capabilities and limits](https://github.com/kryptocorelabs/rescue#readme).
Maintainer tests cover synthetic Vault password/recovery exports, Container
extraction, rejected credentials and unchanged sources. An independent audit
and clean-machine checks of exact releases remain pending.
