using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using System.Runtime.InteropServices;

namespace KryptoCore.Desktop;

internal sealed class ContainerWindow : Shell
{
    private const string Archives = "KryptoCore Container (*.kcc)|*.kcc|Alle Dateien (*.*)|*.*";
    private const string SelfOpeningArchives = "Selbstöffnender Windows-Container (*.exe)|*.exe";
    private const string Signatures = "Signaturdatei (*.sig)|*.sig|Alle Dateien (*.*)|*.*";
    private const string Files = "Alle Dateien (*.*)|*.*";
    private const string Tools = "Windows-Programm (*.exe)|*.exe";
    private readonly Brush glass = new SolidColorBrush(Color.FromArgb(245, 27, 40, 50));
    private Action showCreate = null!;
    private Action showOpen = null!;
    private Action<IEnumerable<string>> addSources = null!;
    private Action<string> selectArchive = null!;

    internal ContainerWindow() : this(null) { }

    internal ContainerWindow(string? embedded) : base("Container", "Dateien und Ordner verschlüsselt weitergeben",
        ProductEmblem("KryptoCore-Container;component/Assets/container.png"), "KryptoCore-Container;component/Assets/container.ico")
    {
        if (embedded is not null)
        {
            showOpen = Tab("Öffnen", OpenView(embedded));
            selectArchive(embedded);
        }
        else
        {
            var create = CreateView();
            var open = OpenView(null);
            Tab("Start", HomeView());
            showCreate = Tab("Verschlüsseln", create);
            showOpen = Tab("Öffnen", open);
            Tab("Signaturen", NativeSignatureView());
            Tab("Erweitert", SignatureView());
        }
    }

    internal void OpenFromFile(string path)
    {
        showOpen();
        try
        {
            path = Path.GetFullPath(path);
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or IOException)
        {
            SetStatus("Der Pfad zur Containerdatei ist ungültig.", true);
            return;
        }
        if (IsArchive(path)) selectArchive(path);
        else SetStatus("Wähle eine vorhandene .kcc-Datei.", true);
    }

    private FrameworkElement HomeView()
    {
        var page = new StackPanel();
        var introduction = Section("Dateien sicher weitergeben", "Wähle eine Aktion oder ziehe deine Dateien direkt hierher.");
        ((TextBlock)introduction.Children[0]).FontSize = 27;
        var intro = GlassCard(introduction);
        intro.Background = new LinearGradientBrush(Color.FromRgb(24, 60, 63), Color.FromRgb(27, 40, 50), 0);
        intro.Margin = new Thickness(0, 0, 0, 15);
        page.Children.Add(intro);
        page.Children.Add(Columns(
            HomeTile("+", "Dateien verschlüsseln", "Dateien und Ordner in einen geschützten Container packen.", () => showCreate()),
            HomeTile("↗", "Container öffnen", "Eine empfangene .kcc-Datei mit ihrer Passphrase entpacken.", () => showOpen())
        ));
        page.Children.Add(Row(Text("Lokal · Ohne Konto · Du entscheidest, wohin deine Dateien gehen", 12, true)));
        EnableDrop(page, paths =>
        {
            if (paths.Length == 1 && IsArchive(paths[0]))
            {
                selectArchive(paths[0]);
                showOpen();
            }
            else
            {
                addSources(paths);
                showCreate();
            }
        });
        return page;
    }

    private Button HomeTile(string symbol, string title, string detail, Action activate)
    {
        var content = Section(title, detail);
        var icon = Text(symbol, 24);
        icon.Foreground = Brush("Mint");
        icon.Margin = new Thickness(0, 0, 0, 10);
        content.Children.Insert(0, icon);
        content.HorizontalAlignment = HorizontalAlignment.Stretch;
        var button = Button(title, activate);
        AutomationProperties.SetName(button, title);
        button.Content = content;
        button.ContentTemplate = null;
        button.Background = glass;
        button.Padding = new Thickness(20);
        button.Margin = new Thickness(0, 0, 10, 0);
        button.HorizontalAlignment = HorizontalAlignment.Stretch;
        return button;
    }

    private Border GlassCard(FrameworkElement content)
    {
        var card = Card(content);
        card.Background = glass;
        return card;
    }

    private FrameworkElement CreateView()
    {
        var left = Section("1 · Dateien hinzufügen", "Wähle Dateien oder Ordner aus oder ziehe sie in die Liste.");
        var list = new ListBox { Height = 225, SelectionMode = SelectionMode.Extended, DisplayMemberPath = nameof(SourceItem.Name) };
        AutomationProperties.SetName(list, "Dateien und Ordner im Container");
        var empty = Text("Dateien und Ordner hier ablegen", 15, true);
        empty.IsHitTestVisible = false;
        empty.HorizontalAlignment = HorizontalAlignment.Center;
        empty.VerticalAlignment = VerticalAlignment.Center;
        var dropArea = new Grid();
        dropArea.Children.Add(list);
        dropArea.Children.Add(empty);
        addSources = paths =>
        {
            var known = list.Items.Cast<SourceItem>().Select(item => item.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (string path in paths)
            {
                if (!known.Add(path)) continue;
                string name = Path.GetFileName(Path.TrimEndingDirectorySeparator(path));
                list.Items.Add(new SourceItem(path, string.IsNullOrEmpty(name) ? path : name));
            }
        };
        var itemStyle = new Style(typeof(ListBoxItem), (Style)Application.Current.FindResource(typeof(ListBoxItem)));
        itemStyle.Setters.Add(new Setter(ToolTipProperty, new System.Windows.Data.Binding(nameof(SourceItem.Path))));
        list.ItemContainerStyle = itemStyle;
        EnableDrop(dropArea, paths => addSources(paths));
        left.Children.Add(dropArea);
        var count = Text("Noch nichts ausgewählt", 12, true);
        left.Children.Add(count);
        var remove = Button("Entfernen", () =>
        {
            foreach (var item in list.SelectedItems.Cast<SourceItem>().ToArray()) list.Items.Remove(item);
        });
        remove.IsEnabled = false;
        list.SelectionChanged += (_, _) => remove.IsEnabled = list.SelectedItems.Count > 0;
        left.Children.Add(Row(
            Button("Dateien…", () =>
            {
                var dialog = new OpenFileDialog { Multiselect = true, Filter = Files, CheckFileExists = true };
                if (dialog.ShowDialog(this) == true) addSources(dialog.FileNames);
            }),
            Button("Ordner…", () =>
            {
                var dialog = new OpenFolderDialog { Multiselect = true };
                if (dialog.ShowDialog(this) == true) addSources(dialog.FolderNames);
            }), remove
        ));
        var right = Section("2 · Verschlüsseln & speichern", "Die Passphrase öffnet den Container. Bewahre sie getrennt von der Datei auf.");
        string? output = null;
        string? savedArchive = null;
        bool customOutput = false;
        string? opener = ExecutableContainer.OpenerPath;
        var selfOpening = new CheckBox
        {
            Content = "Selbstöffnende Windows-EXE",
            IsEnabled = opener is not null,
            Margin = new Thickness(0, 4, 0, 6)
        };
        right.Children.Add(selfOpening);
        var exeHint = Text("Der Empfänger öffnet die EXE per Doppelklick. Teile die Passphrase separat.", 12, true);
        exeHint.TextWrapping = TextWrapping.Wrap;
        exeHint.Visibility = Visibility.Collapsed;
        right.Children.Add(exeHint);
        string Extension() => selfOpening.IsChecked == true ? ".exe" : ".kcc";
        var target = Destination(right, "Speicherort");
        var credentials = new StackPanel();
        credentials.Children.Add(Text("Verwende mindestens 15 Zeichen.", 12, true));
        var password = Field(credentials, "Passphrase", new PasswordBox());
        var repeat = Field(credentials, "Passphrase wiederholen", new PasswordBox());
        var own = new Expander { Header = "Eigene Passphrase eingeben", Content = credentials, Margin = new Thickness(0, 8, 0, 8) };
        var generate = Button("Passphrase erzeugen", async () =>
        {
            await Run("Passphrase wird erzeugt …", _ => Engine.Call(new { action = "generate" }), reply =>
            {
                if (reply.Text is not { } secret) return;
                if (ShowPassphrase(secret))
                {
                    password.Password = repeat.Password = secret;
                    own.IsExpanded = false;
                    own.Header = "Passphrase bearbeiten";
                    SetStatus("Passphrase übernommen. Der Container kann jetzt gespeichert werden.");
                }
                else SetStatus("Erzeugte Passphrase verworfen.");
            });
        });
        var savedActions = new StackPanel { Visibility = Visibility.Collapsed };
        savedActions.Children.Add(Row(Button("Speicherordner öffnen", () =>
            OpenFolder(savedArchive is null ? null : Path.GetDirectoryName(savedArchive)))));
        savedActions.Children.Add(Row(Button("Prüfsumme kopieren", async () =>
        {
            if (savedArchive is not { } path) return;
            await Run("SHA-256-Prüfsumme wird berechnet …", async token =>
            {
                await using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                    bufferSize: 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                byte[] hash = await SHA256.HashDataAsync(file, token);
                token.ThrowIfCancellationRequested();
                try
                {
                    Clipboard.SetText(Convert.ToHexString(hash));
                }
                catch (ExternalException)
                {
                    return new Reply(false, "Zwischenablage belegt. Versuche es erneut.", null, null, null);
                }
                return new Reply(true, "SHA-256 kopiert. Gib die Prüfsumme separat über einen vertrauenswürdigen Kanal weiter.",
                    null, null, null);
            }, canCancel: true);
        })));
        var save = Button("Verschlüsseln & speichern", async () =>
        {
            var destination = output;
            if (destination is null) return;
            await Run("Dateien werden verschlüsselt …", _ =>
            {
                var sources = list.Items.Cast<SourceItem>().Select(item => item.Path).ToArray();
                return Engine.WithPassword(new
                {
                    action = "pack", output = destination, sources,
                    opener = selfOpening.IsChecked == true ? opener : null
                }, password, repeat);
            }, _ =>
            {
                savedArchive = destination;
                savedActions.Visibility = Visibility.Visible;
            });
        }, true);
        var chooseOutput = Button("Speicherort ändern…", () =>
        {
            string extension = Extension();
            var dialog = new SaveFileDialog
            {
                Filter = selfOpening.IsChecked == true ? SelfOpeningArchives : Archives,
                DefaultExt = extension, AddExtension = true, OverwritePrompt = false
            };
            if (output is not null)
            {
                dialog.InitialDirectory = Path.GetDirectoryName(output);
                dialog.FileName = Path.GetFileName(output);
            }
            if (dialog.ShowDialog(this) != true) return;
            customOutput = true;
            output = selfOpening.IsChecked == true ? Path.ChangeExtension(dialog.FileName, extension) : dialog.FileName;
            savedArchive = null;
            savedActions.Visibility = Visibility.Collapsed;
            UpdateTarget(target, output, "");
            Refresh();
        });
        right.Children.Add(Row(chooseOutput));
        right.Children.Add(Row(generate));
        right.Children.Add(own);
        right.Children.Add(Row(save));
        right.Children.Add(savedActions);
        void Refresh()
        {
            empty.Visibility = list.Items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            count.Text = list.Items.Count == 0 ? "Noch nichts ausgewählt" : $"{list.Items.Count} ausgewählt";
            using var passphrase = password.SecurePassword;
            using var confirmation = repeat.SecurePassword;
            save.IsEnabled = list.Items.Count > 0 && output is not null && passphrase.Length >= 15 && confirmation.Length > 0;
        }
        void UpdateOutput()
        {
            if (!customOutput)
            {
                var first = list.Items.Count > 0 ? (SourceItem)list.Items[0] : null;
                string? parent = first is null ? null : Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(first.Path));
                output = parent is null ? null : AvailablePath(parent, Path.GetFileNameWithoutExtension(first!.Name), Extension());
            }
            savedArchive = null;
            savedActions.Visibility = Visibility.Collapsed;
            UpdateTarget(target, output, "Wird nach der Dateiauswahl vorgeschlagen");
            Refresh();
        }
        void ChangeFormat()
        {
            customOutput = false;
            exeHint.Visibility = selfOpening.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            UpdateOutput();
        }
        ((System.Collections.Specialized.INotifyCollectionChanged)list.Items).CollectionChanged += (_, _) => UpdateOutput();
        selfOpening.Checked += (_, _) => ChangeFormat();
        selfOpening.Unchecked += (_, _) => ChangeFormat();
        password.PasswordChanged += (_, _) => Refresh();
        repeat.PasswordChanged += (_, _) => Refresh();
        UpdateTarget(target, null, "Wird nach der Dateiauswahl vorgeschlagen");
        Refresh();
        return Columns(GlassCard(left), GlassCard(right));
    }

    private bool ShowPassphrase(string secret)
    {
        var modal = new Window
        {
            Owner = this, Title = "Erzeugte Passphrase", Width = 555, SizeToContent = SizeToContent.Height,
            ResizeMode = ResizeMode.NoResize, WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Background = Brush("Base"), Foreground = Brush("Ink"), FontSize = 14, ShowInTaskbar = false
        };
        var panel = Section("Passphrase aufbewahren", "Wer diese Passphrase hat, kann den Container öffnen. Speichere sie getrennt von der .kcc-Datei.");
        panel.Margin = new Thickness(20);
        var value = Field(panel, "Erzeugte Passphrase", new TextBox
        {
            Text = secret, IsReadOnly = true, FontFamily = new FontFamily("Consolas")
        });
        var clipboardState = Text("", 12, true);
        panel.Children.Add(Row(Button("Kopieren", () =>
        {
            try
            {
                Clipboard.SetText(value.Text);
                clipboardState.Text = "Kopiert. Bewahre die Passphrase getrennt vom Container auf.";
            }
            catch (ExternalException)
            {
                clipboardState.Text = "Zwischenablage gerade nicht verfügbar. Du kannst den Text markieren.";
            }
        }), Button("Passphrase gesichert", () => modal.DialogResult = true, true)));
        panel.Children.Add(clipboardState);
        var cancel = Button("Abbrechen", () => modal.DialogResult = false);
        panel.Children.Add(Row(cancel));
        modal.Content = panel;
        modal.Loaded += (_, _) => { value.Focus(); value.SelectAll(); };
        try { return modal.ShowDialog() == true; }
        finally { value.Clear(); }
    }

    private FrameworkElement OpenView(string? embedded)
    {
        string? input = null;
        string? output = null;
        string? extracted = null;
        var left = embedded is null
            ? Section("1 · Container auswählen", "Wähle die empfangene .kcc-Datei oder ziehe sie auf diese Kachel.")
            : Section("Verschlüsselter Container", "Diese EXE enthält die verschlüsselten Dateien.");
        var source = Destination(left, "Container");
        UpdateTarget(source, null, "Noch keine Datei gewählt");
        var leftCard = GlassCard(left);
        if (embedded is null)
        {
            left.Children.Add(Row(Button("Container auswählen…", () =>
            {
                var dialog = new OpenFileDialog { Filter = Archives, CheckFileExists = true };
                if (dialog.ShowDialog(this) == true) selectArchive(dialog.FileName);
            }, true)));
            EnableDrop(leftCard, paths =>
            {
                if (paths.Length == 1 && IsArchive(paths[0])) selectArchive(paths[0]);
                else SetStatus("Ziehe eine einzelne .kcc-Datei auf diese Kachel.", true);
            });
        }

        var right = Section(embedded is null ? "2 · Dateien entpacken" : "Dateien entpacken",
            "Gib die Passphrase ein. Container prüft die Datei automatisch, bevor er sie entpackt.");
        var password = Field(right, "Passphrase", new PasswordBox());
        var target = Destination(right, "Dateien landen hier");
        UpdateTarget(target, null, "Wird nach der Dateiauswahl vorgeschlagen");
        var options = new StackPanel { Margin = new Thickness(0, 6, 0, 0) };
        var signed = new CheckBox { Content = "Absender anhand einer Signatur prüfen" };
        var scan = new CheckBox { Content = "Vor dem Entpacken mit ClamAV prüfen", Margin = new Thickness(0, 9, 0, 0) };
        var signerPanel = new StackPanel { Visibility = Visibility.Collapsed };
        var scannerPanel = new StackPanel { Visibility = Visibility.Collapsed };
        var signer = new SignerFields(this, signerPanel);
        var nativeSigned = new CheckBox { Content = "KryptoCore-Absendersignatur prüfen (.kcsig)" };
        var nativePanel = new StackPanel { Visibility = Visibility.Collapsed };
        var nativeSignature = PathField(nativePanel, "KryptoCore-Signaturdatei", "KryptoCore-Signatur (*.kcsig)|*.kcsig");
        var expectedPublic = Field(nativePanel, "Separat bestätigter öffentlicher Code (KCP1:…)", new TextBox());
        nativePanel.Children.Add(Text("Den öffentlichen Code unabhängig beim Absender bestätigen. Eine gültige Signatur bestätigt keine Virenfreiheit.", 12, true));
        var scanner = PathField(scannerPanel, "ClamAV-Programm (clamscan.exe)", Tools);
        var openFolder = Button("Entpackte Dateien anzeigen", () => OpenFolder(extracted));
        openFolder.Visibility = Visibility.Collapsed;
        var unpack = Button("Entpacken", async () =>
        {
            var selected = input;
            var destination = output;
            if (selected is null || destination is null) return;
            await Run("Container wird geprüft und entpackt …", _ =>
                Engine.WithPassword(new
                {
                    action = "unpack", input = selected, output = destination, embedded = embedded is not null,
                    signer = signed.IsChecked == true ? signer.Value() : null,
                    native_signer = nativeSigned.IsChecked == true ? new { signature = FullPath(nativeSignature), expected_public = Required(expectedPublic) } : null,
                    scanner = scan.IsChecked == true ? FullPath(scanner) : null
                }, password), _ =>
                {
                    extracted = destination;
                    openFolder.Visibility = Visibility.Visible;
                });
        }, true);
        unpack.IsDefault = true;
        var chooseFolder = Button("Zielordner ändern…", () =>
        {
            if (input is null) return;
            var dialog = new OpenFolderDialog { Title = "Ordner für die entpackten Dateien auswählen" };
            if (dialog.ShowDialog(this) != true) return;
            output = AvailablePath(dialog.FolderName, FileStem(input) + " – Dateien", "");
            openFolder.Visibility = Visibility.Collapsed;
            UpdateTarget(target, output, "");
        });
        right.Children.Add(Row(chooseFolder));
        right.Children.Add(Row(unpack, openFolder));

        Toggle(signed, signerPanel);
        Toggle(nativeSigned, nativePanel);
        nativeSigned.Checked += (_, _) => signed.IsChecked = false;
        signed.Checked += (_, _) => nativeSigned.IsChecked = false;
        Toggle(scan, scannerPanel);
        var check = Button("Nur Datei prüfen", async () =>
        {
            var selected = input;
            if (selected is null) return;
            await Run("Container wird geprüft …", _ =>
                Engine.WithPassword(new { action = "check", input = selected, embedded = embedded is not null }, password));
        });
        options.Children.Add(Row(check));
        if (embedded is null)
        {
            options.Children.Add(nativeSigned);
            options.Children.Add(nativePanel);
        }
        else options.Children.Add(Text("Diese EXE läuft bereits. Prüfe EXE-Signaturen vor dem Start in einer separaten vertrauenswürdigen App, etwa Rescue.", 12, true));
        if (embedded is null)
        {
            options.Children.Add(signed);
            options.Children.Add(signerPanel);
        }
        options.Children.Add(scan);
        options.Children.Add(scannerPanel);
        right.Children.Add(new Expander { Header = "Erweiterte Optionen", Content = options, Margin = new Thickness(0, 12, 0, 0) });
        selectArchive = path =>
        {
            if (!Path.IsPathFullyQualified(path) || !File.Exists(path))
            {
                SetStatus("Die ausgewählte Containerdatei wurde nicht gefunden.", true);
                return;
            }
            input = path;
            output = AvailablePath(Path.GetDirectoryName(path)!, FileStem(path) + " – Dateien", "");
            password.Clear();
            extracted = null;
            openFolder.Visibility = Visibility.Collapsed;
            UpdateTarget(source, input, "");
            UpdateTarget(target, output, "");
            Refresh();
            Dispatcher.InvokeAsync(() => password.Focus(), System.Windows.Threading.DispatcherPriority.Input);
        };
        password.PasswordChanged += (_, _) => Refresh();
        Refresh();
        return Columns(leftCard, GlassCard(right));

        void Refresh()
        {
            using var secret = password.SecurePassword;
            unpack.IsEnabled = check.IsEnabled = input is not null && output is not null && secret.Length > 0;
            chooseFolder.IsEnabled = input is not null;
        }
    }

    private static void Toggle(CheckBox box, Panel panel)
    {
        box.Checked += (_, _) => panel.Visibility = Visibility.Visible;
        box.Unchecked += (_, _) => panel.Visibility = Visibility.Collapsed;
    }

    private sealed record SourceItem(string Path, string Name);

    private static bool IsArchive(string path) => File.Exists(path)
        && string.Equals(Path.GetExtension(path), ".kcc", StringComparison.OrdinalIgnoreCase);

    private static void EnableDrop(FrameworkElement target, Action<string[]> accept)
    {
        target.AllowDrop = true;
        target.PreviewDragOver += (_, e) =>
        {
            e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
            e.Handled = true;
        };
        target.PreviewDrop += (_, e) =>
        {
            if (e.Data.GetData(DataFormats.FileDrop) is not string[] paths || paths.Length == 0) return;
            accept(paths);
            e.Handled = true;
        };
    }

    private sealed record PathDisplay(TextBlock Name, TextBlock Folder);

    private static PathDisplay Destination(Panel panel, string title)
    {
        var caption = Text(title, 12, true);
        caption.Margin = new Thickness(0, 10, 0, 5);
        panel.Children.Add(caption);
        var value = Text("", 13);
        value.FontWeight = FontWeights.SemiBold;
        value.TextWrapping = TextWrapping.NoWrap;
        value.TextTrimming = TextTrimming.CharacterEllipsis;
        AutomationProperties.SetName(value, title);
        var folder = Text("", 12, true);
        folder.TextWrapping = TextWrapping.NoWrap;
        folder.TextTrimming = TextTrimming.CharacterEllipsis;
        var summary = new StackPanel();
        summary.Children.Add(value);
        summary.Children.Add(folder);
        panel.Children.Add(new Border
        {
            Child = summary, Background = Brush("Field"), CornerRadius = new CornerRadius(7),
            Padding = new Thickness(9, 7, 9, 7)
        });
        return new PathDisplay(value, folder);
    }

    private static void UpdateTarget(PathDisplay display, string? path, string placeholder)
    {
        display.Name.Text = path is null ? placeholder : Path.GetFileName(path);
        display.Name.Foreground = Brush(path is null ? "Muted" : "Ink");
        display.Name.ToolTip = path;
        display.Folder.Text = path is null ? "" : Path.GetDirectoryName(path);
        display.Folder.ToolTip = path;
        display.Folder.Visibility = path is null ? Visibility.Collapsed : Visibility.Visible;
    }

    private static string AvailablePath(string parent, string stem, string extension)
    {
        if (string.IsNullOrWhiteSpace(stem)) stem = "Container";
        for (int suffix = 1; suffix <= 100; suffix++)
        {
            string name = suffix == 1 ? stem : $"{stem} ({suffix})";
            string path = Path.Combine(parent, name + extension);
            if (!File.Exists(path) && !Directory.Exists(path)) return path;
        }
        return Path.Combine(parent, $"{stem}-{Guid.NewGuid():N}{extension}");
    }

    private void OpenFolder(string? path)
    {
        if (path is null || !Directory.Exists(path))
        {
            SetStatus("Der Ordner wurde nicht gefunden.", true);
            return;
        }
        try
        {
            using var process = Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
        }
        catch (System.ComponentModel.Win32Exception)
        {
            SetStatus("Der Ordner konnte nicht geöffnet werden.", true);
        }
    }

    private static string FileStem(string name)
    {
        string stem = Path.GetFileNameWithoutExtension(name);
        return string.IsNullOrWhiteSpace(stem) ? "Container" : stem;
    }

    private FrameworkElement NativeSignatureView()
    {
        const string KeyFiles = "Geschützter Signierschlüssel (*.kcsk)|*.kcsk";
        const string NativeSignatures = "KryptoCore-Signatur (*.kcsig)|*.kcsig";
        const string SignedFiles = "Container und Windows-Export|*.kcc;*.exe|Alle Dateien|*.*";
        var page = new StackPanel();
        var create = Section("Eigener Signierschlüssel", "Einmal anlegen. Das Schlüsselpasswort bleibt unabhängig von der Container-Passphrase.");
        var newKey = PathField(create, "Neuer geschützter Schlüssel", KeyFiles, ".kcsk");
        var password = Field(create, "Neues Schlüsselpasswort (mindestens 15 Zeichen)", new PasswordBox());
        var repeat = Field(create, "Schlüsselpasswort wiederholen", new PasswordBox());
        var publicCode = Field(create, "Öffentlicher Signiercode zum Weitergeben", new TextBox { IsReadOnly = true, IsUndoEnabled = false });
        create.Children.Add(Button("Signierschlüssel anlegen", async () => await Run("Signierschlüssel wird geschützt gespeichert …", _ =>
            Engine.WithPassword(new { action = "new_signing_key", output = FullPath(newKey) }, password, repeat), reply => publicCode.Text = reply.Text ?? ""), true));
        create.Children.Add(Text("Nur die .kcsk-Datei und ihr Passwort erlauben das Signieren. Sichere sie getrennt. Den öffentlichen KCP1-Code über einen vertrauenswürdigen Kanal teilen.", 12, true));
        var keyCard = Card(create); keyCard.Margin = new Thickness(0, 0, 0, 16); page.Children.Add(keyCard);

        var signing = Section("Container signieren", "Die Signatur bindet die exakten verschlüsselten Dateibytes. Das Containerformat bleibt unverändert.");
        var input = PathField(signing, "Container für KryptoCore-Signatur", SignedFiles);
        var key = PathField(signing, "Geschützter Signierschlüssel", KeyFiles);
        var unlock = Field(signing, "Schlüsselpasswort", new PasswordBox());
        var output = PathField(signing, "Neue KryptoCore-Signatur", NativeSignatures, ".kcsig");
        signing.Children.Add(Row(Button("Signatur erstellen", async () => await Run("Dateisignatur wird erstellt …", _ =>
            Engine.WithPassword(new { action = "native_sign", input = FullPath(input), key = FullPath(key), output = FullPath(output) }, unlock)), true),
            Button("Öffentlichen Code anzeigen", async () => await Run("Öffentlicher Signiercode wird geladen …", _ =>
                Engine.WithPassword(new { action = "signing_public", key = FullPath(key) }, unlock), reply => publicCode.Text = reply.Text ?? ""))));
        var signCard = Card(signing); signCard.Margin = new Thickness(0, 0, 0, 16); page.Children.Add(signCard);

        var checking = Section("Empfangene Signatur prüfen", "Prüfe den erwarteten öffentlichen Code separat beim Absender. Eine Signatur ersetzt keinen Malware-Scan.");
        var received = PathField(checking, "Signierten Container prüfen", SignedFiles);
        var signature = PathField(checking, "Empfangene KryptoCore-Signatur", NativeSignatures);
        var expected = Field(checking, "Vertrauenswürdig bestätigter öffentlicher Code", new TextBox());
        checking.Children.Add(Button("KryptoCore-Signatur prüfen", async () => await Run("Signatur wird geprüft …", _ =>
            Engine.Call(new { action = "native_verify", input = FullPath(received), signer = new { signature = FullPath(signature), expected_public = Required(expected) } })), true));
        checking.Children.Add(Text("Beim Entpacken kannst du dieselbe Prüfung unter Erweiterte Optionen auswählen. Eine alleinige Prüfung hier bindet keinen später erneut geöffneten Dateistand.", 12, true));
        page.Children.Add(Card(checking));
        return page;
    }

    private FrameworkElement SignatureView()
    {
        var left = Section("Container signieren", "Speichere eine .sig-Datei neben dem Container. Geschützte Schlüssel können über den SSH-Agent verwendet werden.");
        var source = PathField(left, "Zu signierender Container", Archives);
        var tool = ToolField(left);
        var key = PathField(left, "Signierschlüssel (oder öffentlicher Schlüssel für SSH-Agent)", Files);
        var output = PathField(left, "Neue Signaturdatei", Signatures, ".sig");
        left.Children.Add(Row(Button("Signatur erstellen", async () =>
        {
            await Run("Container wird signiert …", _ => Engine.Call(new
            {
                action = "sign", input = FullPath(source), tool = FullPath(tool),
                key = FullPath(key), output = FullPath(output)
            }));
        }, true)));
        var right = Section("Absender prüfen", "Verwende eine eigene allowed_signers-Datei mit einem unabhängig geprüften Absenderschlüssel.");
        var input = PathField(right, "Empfangener Container", Archives);
        var signer = new SignerFields(this, right);
        right.Children.Add(Row(Button("Signatur prüfen", async () =>
        {
            await Run("Signatur wird geprüft …", _ =>
                Engine.Call(new { action = "verify", input = FullPath(input), signer = signer.Value() }));
        }, true)));
        return Columns(GlassCard(left), GlassCard(right));
    }

    private TextBox ToolField(Panel panel)
    {
        var input = PathField(panel, "OpenSSH (ssh-keygen.exe)", Tools);
        string candidate = Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh-keygen.exe");
        if (File.Exists(candidate)) input.Text = candidate;
        return input;
    }

    private sealed class SignerFields
    {
        private readonly TextBox tool;
        private readonly TextBox allowed;
        private readonly TextBox principal;
        private readonly TextBox signature;

        internal SignerFields(ContainerWindow window, Panel panel)
        {
            tool = window.ToolField(panel);
            allowed = window.PathField(panel, "Lokale allowed_signers-Datei", Files);
            principal = Field(panel, "Name in allowed_signers", new TextBox());
            signature = window.PathField(panel, "Empfangene Signaturdatei", Signatures);
        }

        internal object Value() => new
        {
            tool = FullPath(tool), allowed = FullPath(allowed),
            principal = Required(principal), signature = FullPath(signature)
        };
    }
}
