using Microsoft.Win32;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;

namespace KryptoCore.Desktop;

internal sealed class RescueWindow : Shell
{
    private readonly TextBox input = new() { IsReadOnly = true, IsUndoEnabled = false, TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock format = Text("Noch keine Datei ausgewählt", 22);
    private readonly TextBlock size = Text("", 13, true);
    private readonly TextBlock access = Text("", 14);
    private readonly TextBlock state = Text("Keine Inhaltsprüfung durchgeführt.", 14);
    private string? selected;
    private string? report;
    private string? selectedFormat;
    private readonly PasswordBox secret = new();
    private readonly ComboBox credential = new();
    private readonly TextBox destination = new() { IsReadOnly = true, IsUndoEnabled = false };
    private readonly CheckBox plaintext = new() { Content = "Ich weiß: Die Ausgabe enthält unverschlüsselte Daten.", Margin = new Thickness(0, 12, 0, 12) };
    private readonly Button restore;
    private readonly CheckBox signed = new() { Content = "Absendersignatur prüfen (Container)", Margin = new Thickness(0, 8, 0, 6) };
    private readonly CheckBox scan = new() { Content = "Vor der Freigabe lokal mit ClamAV scannen", Margin = new Thickness(0, 8, 0, 6) };
    private readonly TextBox expectedPublic = new();
    private TextBox signature = null!;
    private TextBox scanner = null!;
    private readonly TextBlock checks = Text("Absender nicht geprüft · Kein Malware-Scan angefordert", 12, true);

    private sealed record Inspection(
        [property: JsonPropertyName("schema_version")] int Schema,
        [property: JsonPropertyName("format")] string Format,
        [property: JsonPropertyName("label")] string Label,
        [property: JsonPropertyName("file_bytes")] ulong FileBytes,
        [property: JsonPropertyName("payload_offset")] ulong Offset,
        [property: JsonPropertyName("payload_bytes")] ulong PayloadBytes,
        [property: JsonPropertyName("credential_routes")] string[] Credentials,
        [property: JsonPropertyName("authenticity")] string Authenticity,
        [property: JsonPropertyName("data_access_available")] bool DataAccessAvailable);

    internal RescueWindow() : base("Rescue", "Dateien prüfen · Daten unabhängig wiederherstellen")
    {
        var source = Section("Verschlüsselte Datei untersuchen", "Die Originaldatei wird nur gelesen.");
        source.Children.Add(Text("Wähle eine Vault- oder Container-Datei. Rescue prüft zuerst das Format und rettet die Daten mit deinem vorhandenen Zugang in ein neues Ziel.", 14, true));
        Field(source, "Ausgewählte Datei", input);
        var again = new Button { Content = "Erneut prüfen", IsEnabled = false };
        var save = new Button { Content = "Diagnosebericht speichern …", IsEnabled = false };
        again.Click += async (_, _) => { if (selected is not null) await Inspect(selected); };
        save.Click += async (_, _) => await SaveReport();
        var open = Button("Datei auswählen …", async () =>
        {
            var picker = new OpenFileDialog { Title = "KryptoCore-Datei auswählen", CheckFileExists = true,
                Filter = "KryptoCore-Dateien|*.kcv;*.kcc;*.kcmi;*.contacts;*.blocked;*.verification;*.policy;*.exe|Alle Dateien|*.*" };
            if (picker.ShowDialog(this) == true) await Inspect(picker.FileName);
        }, true);
        source.Children.Add(Row(open, again, save));

        var details = Section("Ergebnis", "Eine passende Kennung ist kein Echtheitsnachweis.");
        details.Children.Add(format);
        size.Margin = new Thickness(0, 8, 0, 14);
        details.Children.Add(size);
        state.Foreground = Brush("Problem");
        state.Margin = new Thickness(0, 0, 0, 14);
        source.Children.Add(state);
        details.Children.Add(Text("Vorgesehener Zugang laut Format", 12, true));
        details.Children.Add(access);
        details.Children.Add(Text("Die Dateikennung allein bestätigt keine Echtheit. Erst eine erfolgreiche Entschlüsselung prüft die Inhalte. Der Diagnosebericht enthält keine Passwörter, Inhalte oder Dateipfade.", 13, true));
        var recovery = Section("Daten retten", "Vault als JSON-Datei · Container in einen neuen Ordner");
        recovery.Children.Add(Text("Die Ausgabe ist unverschlüsselt. Wähle einen geschützten Speicherort. Absendersignaturen und ein lokaler Malware-Scan sind getrennte, optionale Prüfungen. Dateien werden nie automatisch geöffnet.", 14, true));
        credential.Items.Add(new ComboBoxItem { Content = "Passwort", Tag = "password" });
        credential.Items.Add(new ComboBoxItem { Content = "Wiederherstellungsschlüssel (nur KCV2)", Tag = "recovery_key", IsEnabled = false });
        credential.SelectedIndex = 0;
        Field(recovery, "Zugangsart", credential);
        Field(recovery, "Passwort oder Wiederherstellungsschlüssel", secret);
        Field(recovery, "Neues Ziel", destination);
        recovery.Children.Add(Button("Speicherort wählen …", ChooseDestination));
        var optional = new StackPanel();
        var signerFields = new StackPanel { Visibility = Visibility.Collapsed };
        signature = PathField(signerFields, "KryptoCore-Signatur (.kcsig)", "KryptoCore-Signatur (*.kcsig)|*.kcsig");
        Field(signerFields, "Separat bestätigter öffentlicher Code (KCP1:…)", expectedPublic);
        signerFields.Children.Add(Text("Den Code über einen vertrauenswürdigen Kanal beim Absender bestätigen. Eine mitgelieferte Signatur macht einen Schlüssel nicht vertrauenswürdig.", 12, true));
        var scanFields = new StackPanel { Visibility = Visibility.Collapsed };
        scanner = PathField(scanFields, "Vertrauenswürdiges clamscan.exe", "Programm (*.exe)|*.exe");
        scanFields.Children.Add(Text("ClamAV muss mit aktueller Datenbank installiert sein. Limit: 100 MiB je Datei, 400 MiB insgesamt. Erkennung oder Scanfehler blockiert den Export. Keine Erkennung ist keine Virenfreiheitsgarantie.", 12, true));
        optional.Children.Add(signed); optional.Children.Add(signerFields);
        optional.Children.Add(scan); optional.Children.Add(scanFields);
        recovery.Children.Add(new Expander { Header = "Absender & Malware-Prüfung", Content = optional, Margin = new Thickness(0, 10, 0, 0) });
        recovery.Children.Add(checks);
        recovery.Children.Add(plaintext);
        restore = Button("Entschlüsseln und exportieren", async () => await Recover(), true);
        restore.IsEnabled = false;
        recovery.Children.Add(restore);
        recovery.Children.Add(Text("MSG-Dateien können bisher nur untersucht werden. Eine Wiederherstellung von Identitäten und Kontaktdateien ist noch nicht verfügbar.", 13, true));
        secret.PasswordChanged += (_, _) => UpdateRecovery();
        destination.TextChanged += (_, _) => UpdateRecovery();
        plaintext.Checked += (_, _) => UpdateRecovery();
        plaintext.Unchecked += (_, _) => UpdateRecovery();
        signed.Checked += (_, _) => { signerFields.Visibility = Visibility.Visible; UpdateRecovery(); };
        signed.Unchecked += (_, _) => { signerFields.Visibility = Visibility.Collapsed; UpdateRecovery(); };
        scan.Checked += (_, _) => { scanFields.Visibility = Visibility.Visible; UpdateRecovery(); };
        scan.Unchecked += (_, _) => { scanFields.Visibility = Visibility.Collapsed; UpdateRecovery(); };
        signature.TextChanged += (_, _) => UpdateRecovery();
        expectedPublic.TextChanged += (_, _) => UpdateRecovery();
        scanner.TextChanged += (_, _) => UpdateRecovery();
        var page = new StackPanel();
        var first = Card(source); first.Margin = new Thickness(0, 0, 0, 16);
        page.Children.Add(first);
        page.Children.Add(Card(recovery));
        page.Children.Add(new Expander { Header = "Dateiprüfung und Metadaten", Content = Card(details), Margin = new Thickness(0, 16, 0, 0) });
        Tab("Dateiprüfung", page);
        var boundaries = Section("Unabhängiger Zugang", "Rescue soll vorhandene Zugänge nutzen und Quellen unverändert lassen.");
        boundaries.Children.Add(Text("Vault KCV2: Passwort oder eingerichteter Wiederherstellungsschlüssel. Container und MSG-Identitäten haben derzeit nur einen Passwortzugang. MSG-Kontaktdateien benötigen zusätzlich die zugehörige Identität.", 14));
        boundaries.Children.Add(Text("Ohne gültigen Zugang gibt es keine Entschlüsselung. Fehlende Daten und beschädigte verschlüsselte Inhalte lassen sich nicht durch einen Generalschlüssel reparieren. Rescue ändert kein Passwort und überschreibt weder Quellen noch bestehende Ziele. Aktuelle MSG-Sitzungsverläufe werden nicht dauerhaft gespeichert.", 14, true));
        Tab("Konzept", Card(boundaries));

        async Task Inspect(string path)
        {
            selected = path;
            input.Text = path;
            report = null;
            selectedFormat = null;
            secret.Clear();
            destination.Clear();
            plaintext.IsChecked = false;
            credential.SelectedIndex = 0;
            ((ComboBoxItem)credential.Items[1]).IsEnabled = false;
            restore!.IsEnabled = false;
            signed.IsChecked = false;
            signed.IsEnabled = false;
            expectedPublic.Clear(); signature.Clear();
            checks.Text = "Absender nicht geprüft · Kein Malware-Scan angefordert";
            save.IsEnabled = false;
            again.IsEnabled = true;
            format.Text = "Datei wird gelesen …";
            size.Text = access.Text = "";
            state.Text = "Inhalte sind nicht authentifiziert.";
            state.Foreground = Brush("Problem");
            bool ok = await Run("Dateikennung wird geprüft …", token =>
                Engine.Call(new { action = "inspect", input = path }, cancellation: token), reply =>
                {
                    var result = JsonSerializer.Deserialize<Inspection>(reply.Text ?? "") ?? throw new JsonException();
                    if (result.Schema != 1 || result.Authenticity != "not_verified" || result.DataAccessAvailable)
                        throw new JsonException();
                    format.Text = result.Label;
                    size.Text = $"Dateigröße: {result.FileBytes:N0} Bytes"
                        + (result.Offset != 0 ? $" · Eingebetteter Bereich: {result.PayloadBytes:N0} Bytes" : "");
                    access.Text = string.Join(" oder ", result.Credentials.Select(route => route switch
                    {
                        "password" => "Passwort", "recovery_key" => "Wiederherstellungsschlüssel",
                        "identity_and_password" => "Identitätsdatei mit ihrem Passwort", _ => throw new JsonException()
                    }));
                    report = reply.Text;
                    selectedFormat = result.Format;
                    signed.IsEnabled = result.Format is "container_v1" or "embedded_container_v1";
                    ((ComboBoxItem)credential.Items[1]).IsEnabled = result.Format == "vault_v2";
                    save.IsEnabled = true;
                });
            if (!ok) format.Text = "Keine unterstützte, lesbare Dateistruktur erkannt";
        }

        async Task SaveReport()
        {
            if (report is not { } contents) return;
            var picker = new SaveFileDialog { Title = "Reinen Metadatenbericht speichern", Filter = "JSON-Bericht (*.json)|*.json",
                FileName = "KryptoCore-Rescue-Diagnose.json", OverwritePrompt = false };
            if (picker.ShowDialog(this) != true) return;
            string target = Path.GetFullPath(picker.FileName);
            await Run("Metadatenbericht wird gespeichert …", async token =>
            {
                await MetadataReport.Write(target, contents, token);
                return new Reply(true, "Metadatenbericht gespeichert. Inhalte bleiben ungeprüft.", null, null, null);
            });
        }
    }

    private bool RecoverySupported => selectedFormat is "vault_v1" or "vault_v2" or "container_v1" or "embedded_container_v1";

    private void UpdateRecovery()
    {
        using var password = secret.SecurePassword;
        restore.IsEnabled = RecoverySupported && password.Length > 0 && plaintext.IsChecked == true && destination.Text.Length > 0;
        if (signed.IsChecked == true && (signature.Text.Length == 0 || expectedPublic.Text.Length == 0)) restore.IsEnabled = false;
        if (scan.IsChecked == true && scanner.Text.Length == 0) restore.IsEnabled = false;
    }

    private void ChooseDestination()
    {
        if (!RecoverySupported) { SetStatus("Wähle zuerst eine unterstützte Vault- oder Container-Datei.", true); return; }
        if (selectedFormat is "vault_v1" or "vault_v2")
        {
            var picker = new SaveFileDialog { Title = "Neuen unverschlüsselten Vault-Export speichern", Filter = "JSON-Datei (*.json)|*.json",
                FileName = "KryptoCore-Vault-Rettung.json", OverwritePrompt = false };
            if (picker.ShowDialog(this) == true) destination.Text = picker.FileName;
        }
        else
        {
            var picker = new OpenFolderDialog { Title = "Geschützten Ordner für die geretteten Dateien wählen" };
            if (picker.ShowDialog(this) == true)
                destination.Text = Path.Combine(picker.FolderName, "KryptoCore-Rettung-" + DateTime.Now.ToString("yyyyMMdd-HHmmss"));
        }
    }

    private async Task Recover()
    {
        if (selected is not { } source || !restore.IsEnabled) return;
        string format = selectedFormat!;
        string output = destination.Text;
        string route = (string)((ComboBoxItem)credential.SelectedItem).Tag;
        bool verifySender = signed.IsChecked == true;
        bool scanRequested = scan.IsChecked == true;
        byte[] password = Engine.TakePassword(secret);
        state.Text = "Zugang und vollständige Daten werden geprüft …";
        state.Foreground = Brush("Muted");
        try
        {
            bool ok = await Run("Datei wird authentifiziert und in ein neues Ziel exportiert …", token =>
                {
                    var options = new { signature = verifySender ? FullPath(signature) : null,
                        expected_public = verifySender ? Required(expectedPublic) : null,
                        scanner = scanRequested ? FullPath(scanner) : null };
                    return Engine.Call(new { action = "recover", input = source, output, credential = route, confirm_plaintext = true, options }, password, cancellation: token);
                }, reply =>
                {
                    using var summary = JsonDocument.Parse(reply.Text ?? "");
                    var data = summary.RootElement;
                    if (data.GetProperty("schema_version").GetInt32() != 1 || !data.GetProperty("content_authenticated").GetBoolean()
                        || data.GetProperty("format").GetString() != format) throw new JsonException();
                    state.Text = $"Authentifiziert · {data.GetProperty("entries").GetInt32():N0} Einträge exportiert";
                    state.Foreground = Brush("Mint");
                    string signatureResult = data.GetProperty("signature").GetString() ?? "";
                    string scanResult = data.GetProperty("malware_scan").GetString() ?? "";
                    if (signatureResult != (verifySender ? "verified_expected_key" : "not_checked")
                        || scanResult != (scanRequested ? "completed_no_detection" : "not_requested")) throw new JsonException();
                    checks.Text = "Letzter Export: " + (verifySender ? "Signatur entspricht gewähltem Schlüssel" : "Absender nicht geprüft")
                        + " · " + (scanRequested ? "Malware-Scan abgeschlossen, keine Erkennung" : "Kein Malware-Scan angefordert");
                    SetStatus("Fertig. Die Ausgabe ist unverschlüsselt; die Originaldatei ist unverändert.");
                });
            if (!ok) { state.Text = "Kein erfolgreicher authentifizierter Export."; state.Foreground = Brush("Problem"); checks.Text = "Angeforderte Prüfungen nicht erfolgreich abgeschlossen."; }
        }
        finally { CryptographicOperations.ZeroMemory(password); UpdateRecovery(); }
    }
}
