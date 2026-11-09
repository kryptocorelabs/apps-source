using Microsoft.Win32;
using System.IO;
using System.Net;
using System.Security;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace KryptoCore.Desktop;

internal sealed class MsgWindow : Shell
{
    private const string IdentityFiles = "KryptoCore Identität (*.kcmi)|*.kcmi|Alle Dateien (*.*)|*.*";
    private const string InvitationFiles = "MSG-Einladung (*.txt)|*.txt";
    private const string LocalAddress = "127.0.0.1:49424";
    private const int MaxPendingInvitations = 8;
    private string? identityPath;
    private string? publicKey;
    private string? peerKey;
    private string? peerAddress;
    private string? peerName;
    private bool contactOpened;
    private bool encryptedInvitation;
    private bool requireTwoCodes;
    private byte[]? incomingTicket;
    private bool direct;
    private readonly IOnionTransport onionTransport;
    private SecureString? identitySecret;
    private CancellationTokenSource? unlockedSession;
    private OnionIdentity? onionIdentity;
    private bool closed;
    private CancellationTokenSource? chatSession;
    private CancellationTokenSource? contactRequestSession;
    private bool contactRequestsReady;
    private readonly TextBlock profileName = Text("Keine Identität geöffnet", 13, true);
    private readonly TextBlock contactState = Text("Kein Kontakt verbunden", 13, true);
    private readonly TextBlock transportState = Text("TOR", 12);
    private readonly TextBlock linkState = Text("Keine aktive Verbindung", 14);
    private readonly TextBlock linkDetail = Text("Füge einen Kontakt hinzu oder teile deine Adresse für eine Anfrage.", 12, true);
    private readonly TextBox onionAddress = new() { IsReadOnly = true, IsUndoEnabled = false };
    private readonly TextBlock onionState = Text("Entsperre MSG, um deine Tor-Adresse zu aktivieren.", 12, true);
    private readonly TextBox publicAddress = new() { MaxLength = 64 };
    private readonly TextBox localAddress = new() { Text = LocalAddress, MaxLength = 64 };
    private readonly TextBox manualAddress = new() { MaxLength = 64 };
    private readonly TextBox manualKey = new() { MaxLength = 64, FontFamily = new FontFamily("Consolas") };
    private readonly CheckBox verified = new() { Content = "Schlüssel persönlich abgeglichen", Margin = new Thickness(0, 8, 0, 4) };
    private readonly TextBox draft = new() { TextWrapping = TextWrapping.Wrap, MaxLength = 4096, MinHeight = 44, MaxHeight = 90, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
    private readonly StackPanel timeline = new();
    private readonly List<FrameworkElement> bubbles = [];
    private Action showChat = null!;
    private Action showContacts = null!;
    private FrameworkElement contactPage = null!;
    private Action showProfile = null!;
    private Action showSettings = null!;
    private Action refresh = () => { };
    private Action refreshTorSettings = () => { };
    private Action refreshContactRequests = () => { };
    private Action clearContact = () => { };
    private Action clearInvitation = () => { };
    private Action startConversation = () => { };
    private Func<Task> stopConversation = () => Task.CompletedTask;
    private Action shareMyAddress = () => { };
    private Func<string, string?, Task> requestChat = (_, _) => Task.CompletedTask;
    private Task activeChat = Task.CompletedTask;
    private readonly SemaphoreSlim contactSelection = new(1, 1);
    private bool contactSaved;
    private long identitySession;
    private readonly SessionConversations conversations = new();
    private readonly Dictionary<string, SavedContact> knownContacts = new(StringComparer.OrdinalIgnoreCase);
    private ConversationSidebar? sidebar;
    private string? displayedPeer;
    private bool restoringConversation;
    private double bubbleWidth = 520;
    private readonly ConnectionIndicator encryptionIndicator = new();
    private Func<Task> loadContacts = () => Task.CompletedTask;
    private Action resetContactList = () => { };
    private FrameworkElement invitationSettings = null!;
    private Action showRequestOptions = () => { };
    private sealed record SavedContact(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("key")] string Key,
        [property: JsonPropertyName("address")] string? Address,
        [property: JsonPropertyName("verified")] bool Verified = false);
    private sealed record OutgoingInvitation(string Label, string Code, byte[] Ticket);

    internal MsgWindow() : this(new TorRuntime()) { }

    internal MsgWindow(IOnionTransport onionTransport) : base("MSG", "Experimentelle Vorschau",
        PrepareAppearance(), "KryptoCore-MSG;component/Assets/messenger.ico")
    {
        this.onionTransport = onionTransport;
        MinWidth = 880;
        MinHeight = 600;
        Width = Math.Max(MinWidth, Math.Min(1180, SystemParameters.WorkArea.Width - 32));
        Height = Math.Max(MinHeight, Math.Min(850, SystemParameters.WorkArea.Height - 32));
        showChat = Tab("Nachrichten", ChatView(), () => Dispatcher.BeginInvoke(new Action(() => _ = loadContacts())));
        showContacts = Tab("Kontakte", contactPage, () => Dispatcher.BeginInvoke(new Action(() => _ = loadContacts())));
        showProfile = Tab("Mein Profil", ProfileView());
        showSettings = Tab("Einstellungen", SettingsView());
        Closed += (_, _) =>
        {
            closed = true;
            EndIdentitySession();
            ClearTicket(ref incomingTicket);
            clearInvitation();
            ClearSessionConversations();
        };
        refresh();
    }

    private static Brush PrepareAppearance()
    {
        MessengerFrame.ApplyTheme();
        return ProductEmblem("KryptoCore-MSG;component/Assets/messenger.png");
    }

    private static new Border Card(FrameworkElement content) => new()
    {
        Background = Brush("Card"), BorderBrush = Brush("Line"), BorderThickness = new Thickness(1),
        CornerRadius = new CornerRadius(22), Padding = new Thickness(20),
        Margin = new Thickness(0, 0, 12, 0), Child = content
    };

    private FrameworkElement ChatView()
    {
        var page = new StackPanel();
        var start = Section("KryptoCore Messenger", "Öffne deine Identität oder lege eine neue an. Danach kannst du deine Adresse teilen oder jemanden zum Chat anfragen.");
        ((TextBlock)start.Children[0]).FontSize = 26;
        start.Children.Add(Row(Button("Identität einrichten", () => showProfile(), true)));
        var welcome = Card(start);
        welcome.Background = new LinearGradientBrush(Color.FromRgb(24, 60, 63), Color.FromRgb(23, 35, 50), 0);
        welcome.Margin = new Thickness(0, 0, 0, 14);
        var onboarding = new StackPanel();
        onboarding.Children.Add(welcome);
        var steps = new System.Windows.Controls.Primitives.UniformGrid { Columns = 3, Rows = 1 };
        steps.Children.Add(Card(Section("01 · Profil", "Identität erstellen oder öffnen.")));
        steps.Children.Add(Card(Section("02 · Kontakt", "Adresse teilen oder einen Kontakt hinzufügen.")));
        steps.Children.Add(Card(Section("03 · Chat", "Anfrage annehmen und direkt schreiben.")));
        onboarding.Children.Add(steps);
        page.Children.Add(onboarding);

        var contact = Section("Einladung öffnen", "Füge den Code ein oder lade die Einladung als TXT.");
        var code = Field(contact, "Kontaktcode", new TextBox
        {
            TextWrapping = TextWrapping.Wrap, MaxLength = 600, MaxHeight = 110,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, FontFamily = new FontFamily("Consolas")
        });
        var passwordPanel = new StackPanel();
        contact.Children.Add(passwordPanel);
        var codePassword = Field(passwordPanel, "Passphrase des Kontaktcodes", new PasswordBox());
        var import = Button("Kontakt öffnen", async () =>
        {
            await Run("Kontaktcode wird geöffnet …", _ =>
            {
                string input = Required(code);
                var request = new { action = "read_contact", code = input };
                if (RequiresCodePassword(input))
                    return Engine.WithPassword(request, codePassword);
                codePassword.Clear();
                if (!direct && !input.StartsWith("KCM3O-", StringComparison.Ordinal))
                    throw new ArgumentException("Diese Einladung ist ungültig oder gehört zur direkten Verbindung.");
                return Engine.Call(request);
            }, reply =>
            {
                if (string.Equals(publicKey, reply.Text, StringComparison.OrdinalIgnoreCase))
                {
                    SetStatus("Das ist dein eigener Code. Öffne den Code vom anderen Rechner.", true);
                    return;
                }
                if (reply.Ticket is not null && (requireTwoCodes || direct))
                {
                    SetStatus("Diese Identität benötigt einen gegenseitigen Code-Austausch. Die andere Person muss einen Code dafür erstellen.", true);
                    return;
                }
                if (peerKey != reply.Text)
                {
                    LeaveConversation();
                }
                manualKey.Clear();
                manualAddress.Clear();
                peerKey = reply.Text;
                peerAddress = reply.Address;
                peerName = null;
                contactOpened = true;
                string value = code.Text.TrimStart();
                encryptedInvitation = RequiresCodePassword(value) || value.StartsWith("KCM3O-", StringComparison.Ordinal);
                ClearTicket(ref incomingTicket);
                if (reply.Ticket is { } ticket) incomingTicket = Engine.TextBytes(ticket);
                verified.IsChecked = false;
                RestoreConversation();
                SetLink("Kontaktcode geöffnet", incomingTicket is not null
                    ? "Klicke auf „Einladung annehmen“."
                    : encryptedInvitation
                    ? "Öffnet den Chatkanal auf beiden Geräten."
                    : "Vergleiche den Schlüssel, bevor du diesen älteren Kontakt verwendest.");
                refresh();
            });
        }, true);
        contact.Children.Add(Row(import, Button("Einfügen", code.Paste)));
        contact.Children.Add(Row(Button("Einladung aus TXT laden …", async () =>
        {
            var picker = new OpenFileDialog { Filter = InvitationFiles, CheckFileExists = true };
            if (picker.ShowDialog(this) != true) return;
            await Run("Einladung wird geladen …", _ =>
            {
                using var file = File.OpenRead(picker.FileName);
                if (file.Length > 1024) throw new IOException("Diese TXT-Datei ist zu groß für eine MSG-Einladung.");
                var bytes = new byte[(int)file.Length];
                file.ReadExactly(bytes);
                string input = System.Text.Encoding.UTF8.GetString(bytes).Trim(' ', '\t', '\r', '\n', '\uFEFF');
                if (input.Length > code.MaxLength || (!RequiresCodePassword(input)
                    && !input.StartsWith("KCM3O-", StringComparison.Ordinal)
                    && !input.StartsWith("KCM1-", StringComparison.Ordinal)) || input.Any(char.IsWhiteSpace))
                    throw new IOException("Die TXT-Datei muss genau einen MSG-Kontaktcode enthalten.");
                return Task.FromResult(new Reply(true, "Einladung geladen. Gib die Code-Passphrase ein und klicke auf „Kontakt öffnen“.",
                    input, null, null));
            }, reply =>
            {
                code.Text = reply.Text ?? "";
                codePassword.Focus();
            });
        })));

        var details = new StackPanel();
        var ownKeyDisplay = Field(details, "Dein öffentlicher Schlüssel", new TextBox
        {
            IsReadOnly = true, TextWrapping = TextWrapping.Wrap, FontFamily = new FontFamily("Consolas")
        });
        var keyDisplay = Field(details, "Öffentlicher Schlüssel des Kontakts", new TextBox
        {
            IsReadOnly = true, TextWrapping = TextWrapping.Wrap, FontFamily = new FontFamily("Consolas")
        });
        details.Children.Add(Text("Vergleiche den Schlüssel über einen Kanal, auf dem du die Person kennst.", 12, true));
        details.Children.Add(verified);
        var fingerprint = new Expander { Header = "Schlüssel abgleichen (optional)", Content = details, Margin = new Thickness(0, 8, 0, 0) };
        contact.Children.Add(fingerprint);
        contact.Children.Add(contactState);
        contact.Children.Add(Row(Button("Eigenen Code erstellen", () => showProfile())));
        var contactBook = Section("Meine Kontakte", "Wähle eine gespeicherte Person aus.");
        string? loadedForIdentity = null;
        var savedContacts = Field(contactBook, "Gespeicherte Kontakte", new ListBox
        {
            DisplayMemberPath = nameof(SavedContact.Name), MinHeight = 110, MaxHeight = 220
        });
        contactBook.Children.Add(Row(Button("Aktualisieren", async () => await UpdateContacts())));
        var openSaved = Button("Auswählen", async () =>
        {
            if (savedContacts.SelectedItem is not SavedContact item) return;
            await OpenSavedContact(item);
        });
        async Task OpenSavedContact(SavedContact item)
        {
            if (string.Equals(item.Key, ActivePeer, StringComparison.OrdinalIgnoreCase)
                && chatSession is { IsCancellationRequested: false })
            {
                showChat();
                return;
            }
            if (!direct && requireTwoCodes)
            {
                showContacts();
                SetStatus("Diese Identität verlangt gegenseitige Kontaktcodes. Öffne den Code der anderen Person unter Kontakte.");
                return;
            }
            string? path = identityPath;
            long session = identitySession;
            await stopConversation();
            if (path is null || identityPath != path || identitySecret is null || session != identitySession) return;
            LeaveConversation();
            ClearTicket(ref incomingTicket);
            encryptedInvitation = true;
            verified.IsChecked = false;
            code.Clear();
            codePassword.Clear();
            manualKey.Clear();
            manualAddress.Clear();
            peerKey = item.Key;
            peerAddress = item.Address;
            peerName = item.Name;
            contactOpened = true;
            encryptedInvitation = true;
            contactSaved = true;
            verified.IsChecked = item.Verified;
            RestoreConversation();
            SetStatus($"Kontakt ausgewählt · {item.Name}");
            refresh();
            showChat();
            if (!direct && item.Address is { } address) await requestChat(address, item.Key);
            else startConversation();
        }
        var removeSaved = Button("Entfernen", async () =>
        {
            if (savedContacts.SelectedItem is SavedContact item)
                await UpdateContacts(new { kind = "remove", key = item.Key }, item.Key);
        });
        contactBook.Children.Add(Row(openSaved, removeSaved));
        var savePanel = new StackPanel();
        var contactName = Field(savePanel, "Name für den bestätigten Kontakt", new TextBox { MaxLength = 120 });
        var saveContact = Button("Kontakt speichern", async () =>
        {
            await SaveActiveContact(contactName.Text);
        });
        savePanel.Children.Add(Row(saveContact));
        var saveHint = Text("Gib einen Namen ein. Den Schlüssel kannst du zusätzlich persönlich abgleichen.", 12, true);
        savePanel.Children.Add(saveHint);
        var saveOptions = new Expander { Header = "Ausgewählten Kontakt speichern", Content = savePanel, Margin = new Thickness(0, 12, 0, 0) };
        contactBook.Children.Add(saveOptions);
        var requestOptions = TorContactRequests();
        loadContacts = async () =>
        {
            if (identityPath is not null && identityPath != loadedForIdentity) await UpdateContacts();
        };
        resetContactList = () =>
        {
            savedContacts.ItemsSource = null;
            loadedForIdentity = null;
        };

        async Task UpdateContacts(object? update = null, string? removedKey = null, SavedContact? saved = null)
        {
            await RunForIdentity("Kontaktliste wird geöffnet …", token =>
                Engine.Call(new { action = "contacts", path = identityPath, update }, IdentityPassword(), cancellation: token),
                reply =>
                {
                    var loaded = JsonSerializer.Deserialize<SavedContact[]>(reply.Text ?? "[]") ?? [];
                    savedContacts.ItemsSource = loaded;
                    knownContacts.Clear();
                    foreach (var item in loaded) knownContacts[item.Key] = item;
                    loadedForIdentity = identityPath;
                    if (saved is not null && string.Equals(saved.Key, ActivePeer, StringComparison.OrdinalIgnoreCase))
                    {
                        peerName = saved.Name;
                        contactSaved = true;
                    }
                    if (removedKey is not null && string.Equals(removedKey, ActivePeer, StringComparison.OrdinalIgnoreCase))
                    {
                        contactSaved = false;
                        verified.IsChecked = false;
                    }
                    refresh();
                }, canCancel: true);
        }

        async Task SaveActiveContact(string name)
        {
            if (!ContactAccepted || ActivePeer is not { } key) return;
            name = name.Trim();
            if (name.Length == 0) return;
            string? address = direct && manualKey.Text.Trim().Length > 0 ? SendAddress : peerAddress;
            var item = new SavedContact(name, key, address, verified.IsChecked == true);
            await UpdateContacts(new { kind = "save", contact = item }, saved: item);
        }

        var chat = Section("Nachrichten", "Eine angenommene Anfrage öffnet euren Chat automatisch.");
        var selectedContact = Text("Kein Kontakt ausgewählt", 19);
        selectedContact.FontWeight = FontWeights.SemiBold;
        chat.Children.Add(selectedContact);
        var chatSavePanel = new StackPanel { Visibility = Visibility.Collapsed };
        var chatContactName = Field(chatSavePanel, "Wie heißt der Kontakt?", new TextBox { MaxLength = 120 });
        var confirmChatContact = Button("Speichern", async () =>
        {
            await SaveActiveContact(chatContactName.Text);
            if (contactSaved) chatSavePanel.Visibility = Visibility.Collapsed;
        }, true);
        chatSavePanel.Children.Add(Row(confirmChatContact, Button("Abbrechen", () => chatSavePanel.Visibility = Visibility.Collapsed)));
        var endChat = Button("Chat beenden", () => chatSession?.Cancel());
        var saveChatContact = Button("Kontakt übernehmen", () => { chatSavePanel.Visibility = Visibility.Visible; chatContactName.Focus(); });
        var chatActions = Row(saveChatContact, endChat);
        chat.Children.Add(chatActions);
        chat.Children.Add(chatSavePanel);
        var badges = new StackPanel { Orientation = Orientation.Horizontal };
        badges.Children.Add(Badge(transportState));
        chat.Children.Add(badges);
        linkState.FontWeight = FontWeights.SemiBold;
        AutomationProperties.SetLiveSetting(linkState, AutomationLiveSetting.Polite);
        var link = new StackPanel();
        link.Children.Add(linkState);
        link.Children.Add(linkDetail);
        chat.Children.Add(new Border
        {
            Background = Brush("Field"), BorderBrush = Brush("Line"), BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(9), Padding = new Thickness(10),
            Margin = new Thickness(0, 8, 0, 0), Child = link
        });
        var empty = Text("Öffne links einen Chat.\nOder füge einen neuen Kontakt hinzu.", 18, true);
        empty.TextAlignment = TextAlignment.Center;
        empty.Margin = new Thickness(20, 30, 20, 30);
        timeline.Children.Add(empty);
        var history = new ScrollViewer { Content = timeline, Height = 172, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        chat.Children.Add(new Border
        {
            Background = Brush("Field"), BorderBrush = Brush("Line"), BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(9), Padding = new Thickness(8), Margin = new Thickness(0, 10, 0, 3), Child = history
        });
        Field(chat, "Nachricht schreiben", draft);
        var joinInvitation = Button("Einladung annehmen", async () =>
        {
            if (incomingTicket is not { } ticket || identityPath is not { } path
                || ActivePeer is not { } peer || SendAddress is not { } address) return;
            await RunForIdentity("Einladung wird angenommen …", async token =>
            {
                var endpoint = await EnsureTorAsync(token, showLink: true);
                return await Engine.Call(new { action = "join_invitation", path, peer, address,
                    own_address = endpoint.OnionAddress, socks_port = endpoint.SocksPort },
                    IdentityPassword(), ticket.ToArray(), token, ShowLinkProgress);
            }, _ =>
            {
                ClearTicket(ref incomingTicket);
                SetLink("Einladung angenommen", "Der Chat öffnet sich automatisch.", "Mint");
                startConversation();
                showChat();
                refresh();
            }, canCancel: true);
        }, true);
        var joinRow = Row(joinInvitation);
        contact.Children.Add(joinRow);
        Func<object, Task>? channelInput = null;
        string? channelPeer = null;
        bool connected = false;
        bool connectionFailed = false;
        bool localStatus = false;
        bool peerStatus = false;
        bool folderReady = false;
        long? downloadId = null;
        string downloadName = "";
        bool downloadNeedsConfirmation = false, downloadHasFolder = false;
        long downloadSize = 0;
        MsgPrompt? downloadPrompt = null;
        bool writing = false;
        (string Content, string? Draft, CancellationTokenSource Timeout)? pending = null;

        var channelButton = Button("Chat starten", () =>
        {
            if (chatSession is { } active) active.Cancel();
            else startConversation();
        }, true);
        chat.Children.Add(Row(channelButton));

        var send = Button("Senden", async () => await SendAsync(null), true);
        draft.KeyDown += async (_, args) =>
        {
            if (args.Key != Key.Enter) return;
            args.Handled = true;
            if ((Keyboard.Modifiers & ModifierKeys.Shift) != 0) return;
            if (!send.IsEnabled) return;
            await SendAsync(null);
        };
        var sendFile = Button("Datei senden …", async () =>
        {
            var picker = new OpenFileDialog { Title = "Datei zum Senden auswählen", CheckFileExists = true };
            if (picker.ShowDialog(this) == true) await SendAsync(picker.FileName);
        });
        var receiveFolder = Button("Empfangsordner wählen …", async () =>
        {
            var picker = new OpenFolderDialog { Title = "Ordner für empfangene Dateien auswählen" };
            if (picker.ShowDialog(this) == true)
                await WriteCommand(new { kind = "folder", path = picker.FolderName });
        });
        chat.Children.Add(Row(send, sendFile));
        var folderState = Text("Eingehende Dateien fragen nach einem Speicherort.", 12, true);
        chat.Children.Add(folderState);

        var downloadPanel = Section("Datei erhalten", "");
        var downloadInfo = (TextBlock)downloadPanel.Children[1];
        const string saveInFolderLabel = "Im Empfangsordner speichern";
        const string attachmentWarning = "Diese Datei kann Programme, Skripte oder Makros enthalten. Sie kann auch ein einbindbares Laufwerksabbild sein. Speichere sie nur, wenn du sie erwartet hast.";
        var saveInFolder = Button(saveInFolderLabel, async () => await SaveInFolder());
        downloadPanel.Children.Add(Row(
            saveInFolder,
            Button("Speichern unter …", async () => await SaveDownload(false)),
            Button("Ordner wählen …", async () => await SaveDownload(true)),
            Button("Ablehnen", async () =>
            {
                if (downloadId is { } id) await WriteCommand(new { kind = "reject_download", id });
            })));
        var downloadCard = Card(downloadPanel);
        downloadCard.Visibility = Visibility.Collapsed;
        downloadCard.Margin = new Thickness(0, 8, 0, 8);
        chat.Children.Add(downloadCard);

        async Task SaveInFolder()
        {
            if (downloadNeedsConfirmation && downloadHasFolder && downloadId is { } id)
                await WriteCommand(new { kind = "save_in_folder", id });
        }

        async Task SaveDownload(bool folder)
        {
            if (downloadId is not { } id || chatSession is not { } session) return;
            if (folder)
            {
                var picker = new OpenFolderDialog { Title = "Ordner für diese und weitere Dateien wählen" };
                if (picker.ShowDialog(this) == true && downloadId == id && ReferenceEquals(chatSession, session) && !session.IsCancellationRequested)
                    await WriteCommand(new { kind = "download_folder", id, path = picker.FolderName });
            }
            else
            {
                var picker = new SaveFileDialog
                {
                    Title = "Erhaltene Datei speichern", FileName = downloadName,
                    CheckPathExists = true, OverwritePrompt = false, AddExtension = false
                };
                if (picker.ShowDialog(this) == true && downloadId == id && ReferenceEquals(chatSession, session) && !session.IsCancellationRequested)
                    await WriteCommand(new { kind = "save_download", id, path = picker.FileName });
            }
        }

        async Task ShowDownload(CancellationTokenSource session, long id)
        {
            if (!ReferenceEquals(chatSession, session) || session.IsCancellationRequested || downloadId != id || downloadPrompt is not null)
                return;
            bool useReceiveFolder = downloadNeedsConfirmation && downloadHasFolder;
            string question = downloadNeedsConfirmation ? attachmentWarning : "Wo möchtest du die Datei speichern?";
            var shown = new MsgPrompt(this, downloadNeedsConfirmation ? "Datei mit Sicherheitsrisiko" : "Datei erhalten",
                $"{downloadName} · {downloadSize / 1024.0:N1} KiB\n\n{question}",
                useReceiveFolder ? saveInFolderLabel : "Speichern unter …",
                useReceiveFolder ? "Speichern unter …" : "Ordner wählen …", "Ablehnen");
            downloadPrompt = shown;
            shown.Display();
            var choice = await shown.Result;
            if (ReferenceEquals(downloadPrompt, shown)) downloadPrompt = null;
            if (!ReferenceEquals(chatSession, session) || session.IsCancellationRequested || downloadId != id) return;
            if (choice == PromptChoice.First && useReceiveFolder) await SaveInFolder();
            else if (choice is PromptChoice.First or PromptChoice.Second)
                await SaveDownload(choice == PromptChoice.Second && !useReceiveFolder);
            else if (choice == PromptChoice.Third) await WriteCommand(new { kind = "reject_download", id });
        }

        var availability = Text("", 13, true);
        availability.TextWrapping = TextWrapping.Wrap;
        AutomationProperties.SetLiveSetting(availability, AutomationLiveSetting.Polite);
        var statusToggle = Button("Ja, Online-Status teilen", async () =>
        {
            bool enabled = !localStatus;
            if (await WriteCommand(new { kind = "status", enabled }))
            {
                localStatus = enabled;
                refresh();
            }
        });
        var statusPanel = new StackPanel();
        statusPanel.Children.Add(availability);
        statusPanel.Children.Add(Row(statusToggle));
        var chatOptions = new StackPanel();
        chatOptions.Children.Add(statusPanel);
        chatOptions.Children.Add(Row(receiveFolder));
        var optionsExpander = new Expander { Header = "Dateien & Privatsphäre", Content = chatOptions, Margin = new Thickness(2, 8, 0, 0), FontSize = 11 };
        chat.Children.Add(optionsExpander);

        startConversation = () =>
        {
            if (chatSession is null) activeChat = OpenChannel();
        };
        stopConversation = async () =>
        {
            chatSession?.Cancel();
            await activeChat;
        };

        async Task OpenChannel()
        {
            if (identityPath is not { } path || ActivePeer is not { } peer || SendAddress is not { } address || !ContactAccepted)
                return;
            RestoreConversation();
            using var session = new CancellationTokenSource();
            long currentSession = identitySession;
            chatSession = session;
            channelPeer = peer;
            connectionFailed = false;
            using var cancellationDisplay = session.Token.Register(() =>
            {
                void Reset()
                {
                    if (!ReferenceEquals(chatSession, session) || currentSession != identitySession) return;
                    connected = false;
                    encryptionIndicator.Update(ChannelSecurity.Disconnected);
                    SetLink("Verbindung wird beendet …", "Der Kanal ist nicht mehr zum Senden freigegeben.");
                    refresh();
                }
                if (Dispatcher.CheckAccess()) Reset();
                else Dispatcher.BeginInvoke(new Action(Reset));
            });
            SetLink("Verbindung wird aufgebaut …", "MSG verbindet euch nach der Zustimmung automatisch.");
            refresh();
            string detail = "Wähle den Kontakt erneut, um eine neue Verbindung anzufragen.";
            bool failed = false;
            try
            {
                string local = direct ? Endpoint(localAddress) : LocalAddress;
                var endpoint = direct ? null : await EnsureTorAsync(session.Token);
                session.Token.ThrowIfCancellationRequested();
                var request = new { action = "chat", path, peer, address, local, tor = !direct, socks_port = endpoint?.SocksPort };
                var reply = await Engine.Chat(request, IdentityPassword(), session.Token, frame =>
                {
                    if (!ReferenceEquals(chatSession, session) || session.IsCancellationRequested) return;
                    switch (frame.GetProperty("event").GetString())
                    {
                        case "chat_waiting":
                        case "connecting":
                            SetLink("Verbindung wird aufgebaut …", "Warte einen Moment, bis die andere App bereit ist.");
                            break;
                        case "chat_connected":
                            connected = true;
                            SetLink("Verbunden", "Ende-zu-Ende verschlüsselt · Ihr könnt schreiben und Dateien senden.", "Mint");
                            draft.Focus();
                            break;
                        case "chat_text":
                            AddBubble(frame.GetProperty("text").GetString()!, outgoing: false);
                            history.ScrollToEnd();
                            break;
                        case "chat_download":
                            downloadId = frame.GetProperty("id").GetInt64();
                            downloadName = frame.GetProperty("name").GetString()!;
                            downloadSize = frame.GetProperty("size").GetInt64();
                            downloadNeedsConfirmation = frame.GetProperty("confirm").GetBoolean();
                            downloadHasFolder = frame.GetProperty("has_folder").GetBoolean();
                            saveInFolder.Visibility = downloadNeedsConfirmation && downloadHasFolder
                                ? Visibility.Visible : Visibility.Collapsed;
                            downloadInfo.Text = $"{downloadName} · {downloadSize / 1024.0:N1} KiB" +
                                (downloadNeedsConfirmation ? $"\n{attachmentWarning}" : "");
                            long offeredId = downloadId.Value;
                            Dispatcher.BeginInvoke(new Action(() => _ = ShowDownload(session, offeredId)));
                            break;
                        case "chat_download_closed":
                        case "chat_download_expired":
                            if (frame.GetProperty("id").GetInt64() != downloadId) break;
                            downloadId = null;
                            downloadPrompt?.Close();
                            downloadPrompt = null;
                            SetStatus("Datei abgelehnt.");
                            break;
                        case "chat_download_error":
                            SetStatus(frame.GetProperty("message").GetString()!, true);
                            break;
                        case "chat_file":
                            downloadId = null;
                            downloadPrompt?.Close();
                            downloadPrompt = null;
                            if (frame.GetProperty("saved_file").GetString() is { } file)
                            {
                                AddBubble($"Datei gespeichert · {file}", outgoing: false);
                                history.ScrollToEnd();
                            }
                            else SetStatus(frame.GetProperty("message").GetString()!, true);
                            break;
                        case "chat_receipt":
                            if (pending is { } delivery)
                            {
                                delivery.Timeout.Cancel();
                                if (frame.GetProperty("ok").GetBoolean())
                                {
                                    AddBubble(delivery.Content, outgoing: true);
                                    if (delivery.Draft is not null && draft.Text == delivery.Draft) draft.Clear();
                                    history.ScrollToEnd();
                                    SetStatus("Zugestellt.");
                                }
                                else SetStatus("Die andere Person hat die Datei nicht gespeichert.", true);
                            }
                            pending = null;
                            break;
                        case "chat_invalid_payload":
                            pending?.Timeout.Cancel();
                            pending = null;
                            SetStatus("Sende eine Zeile bis 4096 Bytes oder eine reguläre Datei bis 16 MiB.", true);
                            break;
                        case "chat_folder":
                            folderReady = true;
                            SetStatus("Empfangsordner ausgewählt.");
                            break;
                        case "chat_folder_error":
                            SetStatus("Der Empfangsordner ist nicht verfügbar.", true);
                            break;
                        case "chat_status":
                            peerStatus = frame.GetProperty("ok").GetBoolean();
                            break;
                    }
                    refresh();
                }, input =>
                {
                    if (session.IsCancellationRequested) return;
                    channelInput = input;
                    refresh();
                });
                failed = !reply.Ok;
                if (failed) detail = reply.Message;
            }
            catch (OperationCanceledException) when (session.IsCancellationRequested) { }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException
                or System.ComponentModel.Win32Exception or JsonException or InvalidOperationException)
            {
                failed = true;
                detail = "Die Verbindung wurde unterbrochen. Wähle den Kontakt erneut, um eine neue Verbindung anzufragen.";
            }
            finally
            {
                session.Cancel();
                downloadId = null;
                downloadPrompt?.Close();
                downloadPrompt = null;
                if (pending is not null && currentSession == identitySession)
                    SetStatus("Die letzte Übertragung wurde nicht bestätigt. Kläre das vor einem erneuten Versuch.", true);
                channelInput = null;
                channelPeer = null;
                connected = localStatus = peerStatus = folderReady = false;
                connectionFailed = failed;
                pending = null;
                chatSession = null;
                if (currentSession == identitySession && string.Equals(ActivePeer, peer, StringComparison.OrdinalIgnoreCase))
                    SetLink(failed ? "Chatkanal nicht verfügbar" : "Chatkanal geschlossen", detail, failed ? "Problem" : "Ink");
                refresh();
            }
        }

        async Task<bool> WriteCommand(object command)
        {
            if (!connected || writing || channelInput is not { } input || chatSession is not { } session)
                return false;
            writing = true;
            refresh();
            try
            {
                await input(command);
                return ReferenceEquals(chatSession, session) && !session.IsCancellationRequested;
            }
            catch (Exception error) when (error is IOException or OperationCanceledException or ObjectDisposedException)
            {
                if (ReferenceEquals(chatSession, session)) session.Cancel();
                return false;
            }
            finally
            {
                writing = false;
                refresh();
            }
        }

        async Task SendAsync(string? attachment)
        {
            if (!connected || writing || pending is not null || chatSession is not { } session) return;
            string message = draft.Text;
            if (attachment is null && string.IsNullOrWhiteSpace(message)) return;
            object command = attachment is null ? new { kind = "text", text = message }
                : new { kind = "file", path = attachment };
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(session.Token);
            pending = attachment is null ? (message, message, timeout)
                : ($"Datei · {Path.GetFileName(attachment)}", null, timeout);
            if (!await WriteCommand(command))
            {
                if (ReferenceEquals(pending?.Timeout, timeout)) pending = null;
                refresh();
                return;
            }
            if (!ReferenceEquals(pending?.Timeout, timeout)) return;
            SetStatus("Warte auf die Empfangsbestätigung …");
            try
            {
                await Task.Delay(attachment is null ? TimeSpan.FromSeconds(30) : TimeSpan.FromMinutes(5), timeout.Token);
                if (ReferenceEquals(chatSession, session) && ReferenceEquals(pending?.Timeout, timeout)) session.Cancel();
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
        }

        var clear = Button("Verlauf leeren", ClearTimeline);
        chatOptions.Children.Add(Row(clear));

        var goToChat = Button("Zum Chat", () => showChat(), true);
        contact.Children.Add(Row(goToChat));
        var contactMethods = new StackPanel();
        var invitationCard = Card(contact);
        invitationCard.Margin = new Thickness(0, 0, 10, 12);
        contactMethods.Children.Add(invitationCard);
        contactMethods.Children.Add(Card(requestOptions));
        contactPage = Columns(Card(contactBook), contactMethods);
        var columns = Card(chat);
        columns.CornerRadius = new CornerRadius(24);
        columns.Margin = new Thickness(0);
        columns.Padding = new Thickness(22, 18, 22, 16);
        columns.Background = new SolidColorBrush(Color.FromRgb(24, 38, 48));
        // Only history scrolls; the contact header and composer stay in view.
        var historyFrame = (Border)history.Parent;
        chat.Children.Clear();
        link.Children.Clear();
        var chatHeader = new StackPanel();
        var chatFooter = new StackPanel();
        var avatar = MessengerFrame.Avatar("?", 44);
        avatar.Margin = new Thickness(0, 0, 12, 0);
        var contactHeading = new DockPanel();
        var headingActions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        badges.VerticalAlignment = VerticalAlignment.Center;
        badges.Margin = new Thickness(0, 0, 8, 0);
        headingActions.Children.Add(badges);
        headingActions.Children.Add(chatActions);
        DockPanel.SetDock(headingActions, Dock.Right);
        contactHeading.Children.Add(headingActions);
        contactHeading.Children.Add(avatar);
        var contactTitle = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        contactTitle.Children.Add(selectedContact);
        linkState.FontSize = 12;
        linkState.Margin = new Thickness(0, 4, 0, 0);
        var statusLine = new WrapPanel();
        statusLine.Children.Add(linkState);
        statusLine.Children.Add(encryptionIndicator);
        contactTitle.Children.Add(statusLine);
        contactHeading.Children.Add(contactTitle);
        chatHeader.Children.Add(contactHeading);
        linkDetail.FontSize = 12;
        linkDetail.Margin = new Thickness(56, 4, 0, 6);
        chatHeader.Children.Add(linkDetail);
        chatHeader.Children.Add(chatSavePanel);
        var channelRow = (FrameworkElement)channelButton.Parent;
        chatHeader.Children.Add(channelRow);
        historyFrame.BorderThickness = new Thickness(0);
        historyFrame.Background = Brushes.Transparent;
        historyFrame.Padding = new Thickness(0, 16, 0, 14);
        historyFrame.Margin = new Thickness(0);
        history.SizeChanged += (_, _) =>
        {
            bubbleWidth = Math.Max(160, Math.Min(560, history.ActualWidth * .82));
            foreach (var bubble in bubbles) bubble.MaxWidth = bubbleWidth;
        };
        ((Panel)send.Parent).Children.Clear();
        send.MinWidth = 82;
        send.Height = 42;
        sendFile.Content = "+";
        sendFile.ToolTip = "Datei senden …";
        sendFile.FontSize = 24;
        sendFile.Width = 42;
        sendFile.Height = 42;
        sendFile.Padding = new Thickness(0);
        sendFile.Background = Brushes.Transparent;
        sendFile.BorderThickness = new Thickness(0);
        AutomationProperties.SetName(sendFile, "Datei senden");
        var composerRow = new DockPanel { LastChildFill = true };
        DockPanel.SetDock(send, Dock.Right);
        send.Margin = new Thickness(8, 0, 0, 0);
        composerRow.Children.Add(send);
        composerRow.Children.Add(sendFile);
        draft.Background = Brushes.Transparent;
        draft.BorderThickness = new Thickness(0);
        draft.FontSize = 14;
        draft.Padding = new Thickness(10, 10, 8, 8);
        draft.ToolTip = "Nachricht schreiben · Enter zum Senden";
        var draftArea = new Grid();
        draftArea.Children.Add(draft);
        var draftHint = Text("Nachricht schreiben …", 14, true);
        draftHint.VerticalAlignment = VerticalAlignment.Center;
        draftHint.Margin = new Thickness(11, 0, 0, 0);
        draftHint.IsHitTestVisible = false;
        draftArea.Children.Add(draftHint);
        composerRow.Children.Add(draftArea);
        var composer = new Border
        {
            Background = Brush("Field"), BorderBrush = Brush("Line"), BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(18), Padding = new Thickness(6), Child = composerRow
        };
        chatFooter.Children.Add(downloadCard);
        chatFooter.Children.Add(composer);
        chatFooter.Children.Add(optionsExpander);
        chatOptions.Children.Add(folderState);
        var chatLayout = new Grid();
        chatLayout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        chatLayout.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star), MinHeight = 72 });
        chatLayout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        history.Height = double.NaN;
        Grid.SetRow(historyFrame, 1);
        Grid.SetRow(chatFooter, 2);
        chatLayout.Children.Add(chatHeader);
        chatLayout.Children.Add(historyFrame);
        chatLayout.Children.Add(chatFooter);
        columns.Child = chatLayout;
        columns.MinHeight = 440;
        var chatWorkspace = new Grid();
        var sidebarColumn = new ColumnDefinition { Width = new GridLength(250) };
        chatWorkspace.ColumnDefinitions.Add(sidebarColumn);
        chatWorkspace.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        sidebar = new ConversationSidebar(async key =>
        {
            if (knownContacts.TryGetValue(key, out var saved)) await OpenSavedContact(saved);
            else if (string.Equals(key, ActivePeer, StringComparison.OrdinalIgnoreCase)) showChat();
        }, () => showRequestOptions(), () => shareMyAddress());
        Grid.SetColumn(columns, 1);
        chatWorkspace.Children.Add(sidebar);
        chatWorkspace.Children.Add(columns);
        chatWorkspace.MinHeight = 440;
        chatWorkspace.SetBinding(HeightProperty, new System.Windows.Data.Binding("ViewportHeight")
        {
            RelativeSource = new System.Windows.Data.RelativeSource(System.Windows.Data.RelativeSourceMode.FindAncestor, typeof(ScrollViewer), 1)
        });
        chatWorkspace.SizeChanged += (_, size) => sidebarColumn.Width = new GridLength(size.NewSize.Width < 850 ? 205 : 250);
        page.Children.Add(chatWorkspace);
        refresh = () =>
        {
            onboarding.Visibility = identityPath is null ? Visibility.Visible : Visibility.Collapsed;
            chatWorkspace.Visibility = identityPath is null ? Visibility.Collapsed : Visibility.Visible;
            bool hasPeer = ActivePeer is { Length: 64 } key && key.All(char.IsAsciiHexDigit);
            bool canMessage = identityPath is not null && hasPeer && ContactAccepted;
            bool compared = canMessage && verified.IsChecked == true;
            contactPage.IsEnabled = identityPath is not null;
            bool routeAvailable = !string.IsNullOrWhiteSpace(SendAddress);
            if ((!canMessage || !routeAvailable || !string.Equals(channelPeer, ActivePeer, StringComparison.OrdinalIgnoreCase))
                && chatSession is { IsCancellationRequested: false } obsolete)
                obsolete.Cancel();
            bool ready = connected && channelInput is not null && chatSession is { IsCancellationRequested: false };
            goToChat.IsEnabled = canMessage;
            channelButton.Visibility = ready || !canMessage ? Visibility.Collapsed : Visibility.Visible;
            channelRow.Visibility = channelButton.Visibility;
            channelButton.Content = chatSession is null ? "Chat starten" : "Verbindung abbrechen";
            channelButton.IsEnabled = chatSession is { IsCancellationRequested: false }
                || (chatSession is null && canMessage && routeAvailable);
            statusPanel.Visibility = ready ? Visibility.Visible : Visibility.Collapsed;
            statusToggle.IsEnabled = ready && !writing;
            statusToggle.Content = localStatus ? "Statusfreigabe beenden" : "Ja, Online-Status teilen";
            availability.Text = localStatus && peerStatus ? "● Kontakt online"
                : localStatus ? "Deine Zustimmung ist da. Die Anzeige wartet auf die andere Person."
                : "Wollt ihr den Online-Status teilen? Die Anzeige erscheint erst, wenn ihr beide zustimmt.";
            availability.Foreground = Brush(localStatus && peerStatus ? "Mint" : "Muted");
            folderState.Text = folderReady ? "Empfangsordner bereit · Riskante Dateitypen brauchen eine Bestätigung."
                : "Eingehende Dateien fragen nach einem Speicherort · bis 16 MiB.";
            receiveFolder.IsEnabled = ready && !writing;
            downloadCard.Visibility = ready && downloadId is not null ? Visibility.Visible : Visibility.Collapsed;
            downloadCard.IsEnabled = ready && !writing;
            bool encrypted = RequiresCodePassword(code.Text.TrimStart());
            using var secret = codePassword.SecurePassword;
            import.IsEnabled = code.Text.Trim().Length > 0 && (!encrypted || secret.Length > 0);
            codePassword.IsEnabled = encrypted || code.Text.Trim().Length == 0;
            passwordPanel.Visibility = encrypted ? Visibility.Visible : Visibility.Collapsed;
            verified.IsEnabled = hasPeer && incomingTicket is null;
            joinRow.Visibility = incomingTicket is not null ? Visibility.Visible : Visibility.Collapsed;
            joinInvitation.IsEnabled = !direct && !requireTwoCodes && routeAvailable;
            saveContact.IsEnabled = canMessage && !string.IsNullOrWhiteSpace(contactName.Text);
            saveChatContact.Visibility = canMessage && !contactSaved ? Visibility.Visible : Visibility.Collapsed;
            saveChatContact.IsEnabled = canMessage && !contactSaved;
            saveChatContact.Content = contactSaved ? "Kontakt gespeichert" : "Kontakt übernehmen";
            confirmChatContact.IsEnabled = canMessage && !string.IsNullOrWhiteSpace(chatContactName.Text);
            endChat.Visibility = ready ? Visibility.Visible : Visibility.Collapsed;
            saveHint.Visibility = saveContact.IsEnabled ? Visibility.Collapsed : Visibility.Visible;
            saveOptions.Visibility = canMessage ? Visibility.Visible : Visibility.Collapsed;
            openSaved.IsEnabled = removeSaved.IsEnabled = savedContacts.SelectedItem is SavedContact;
            send.IsEnabled = ready && !writing && pending is null && !string.IsNullOrWhiteSpace(draft.Text);
            sendFile.IsEnabled = ready && !writing && pending is null;
            selectedContact.Text = !canMessage ? "Kein Kontakt ausgewählt"
                : (UsingImportedContact ? peerName : "Manuell gewählter Kontakt") ?? "Kontakt aus Einladung";
            ((TextBlock)avatar.Child).Text = !canMessage ? "K" : System.Globalization.StringInfo.GetNextTextElement(selectedContact.Text).ToUpperInvariant();
            linkDetail.Visibility = ready ? Visibility.Collapsed : Visibility.Visible;
            encryptionIndicator.Update(ready ? ChannelSecurity.Encrypted
                : chatSession is { IsCancellationRequested: false } ? ChannelSecurity.Connecting
                : connectionFailed ? ChannelSecurity.Failed : ChannelSecurity.Disconnected);
            linkState.ToolTip = ready ? "Ende-zu-Ende verschlüsselt · Authentifizierte Verbindung" : linkDetail.Text;
            composer.Visibility = canMessage ? Visibility.Visible : Visibility.Collapsed;
            optionsExpander.Visibility = canMessage ? Visibility.Visible : Visibility.Collapsed;
            clear.IsEnabled = bubbles.Count > 0;
            empty.Visibility = bubbles.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            empty.Text = canMessage ? "Noch keine Nachrichten.\nHier beginnt euer Gespräch." : "Öffne links einen Chat.\nOder füge einen neuen Kontakt hinzu.";
            history.VerticalContentAlignment = bubbles.Count == 0 ? VerticalAlignment.Center : VerticalAlignment.Top;
            keyDisplay.Text = hasPeer ? ActivePeer ?? "" : "";
            ownKeyDisplay.Text = publicKey ?? "";
            fingerprint.Visibility = hasPeer ? Visibility.Visible : Visibility.Collapsed;
            contactState.Text = !hasPeer ? "Öffne zuerst einen Kontaktcode."
                : incomingTicket is not null ? "Einladung geladen. Nimm sie hier an, um den Chat zu öffnen."
                : !canMessage ? "Gleiche den Schlüssel ab, um diesen Kontakt zu verwenden."
                : routeAvailable ? (compared ? "Schlüssel abgeglichen." : "Kontakt ausgewählt. Schlüsselabgleich ist optional.")
                : "Für den Chatkanal brauchst du einen aktuellen Kontaktcode mit Adresse.";
            transportState.Text = direct ? "DIREKTE IP" : "TOR";
            refreshContactRequests();
            RefreshConversationList();
        };
        clearContact = () =>
        {
            chatSession?.Cancel();
            connectionFailed = false;
            encryptionIndicator.Update(ChannelSecurity.Disconnected);
            peerName = null;
            contactSaved = false;
            chatSavePanel.Visibility = Visibility.Collapsed;
            chatContactName.Clear();
            chatContactName.ClearUndo();
            ClearTicket(ref incomingTicket);
            encryptedInvitation = false;
            contactName.Clear();
            contactName.ClearUndo();
            code.Clear();
            code.ClearUndo();
            codePassword.Clear();
            LeaveConversation();
        };
        code.TextChanged += (_, _) =>
        {
            contactOpened = false;
            ClearTicket(ref incomingTicket);
            encryptedInvitation = false;
            verified.IsChecked = false;
            ResetLink();
            refresh();
        };
        codePassword.PasswordChanged += (_, _) => refresh();
        savedContacts.SelectionChanged += (_, _) => refresh();
        contactName.TextChanged += (_, _) => refresh();
        chatContactName.TextChanged += (_, _) => refresh();
        verified.Checked += (_, _) =>
        {
            if (chatSession is null) SetLink("Schlüssel abgeglichen", "Öffnet den Chatkanal auf beiden Geräten.");
            refresh();
        };
        verified.Unchecked += (_, _) => refresh();
        draft.TextChanged += (_, _) =>
        {
            draftHint.Visibility = draft.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
            if (!restoringConversation && displayedPeer is { } key && identityPath is not null)
                conversations.Open(key).Draft = draft.Text;
            refresh();
        };
        return page;
    }

    private FrameworkElement ProfileView()
    {
        var identity = Section("Deine Identität", "Entsperre sie einmal für diese Sitzung. Du kannst MSG jederzeit wieder sperren.");
        identity.Children.Add(profileName);
        var createForm = new StackPanel();
        var newPath = PathField(createForm, "Identitätsdatei speichern", IdentityFiles, ".kcmi");
        var newPassword = Field(createForm, "Neue Passphrase", new PasswordBox());
        var repeat = Field(createForm, "Passphrase wiederholen", new PasswordBox());
        var openForm = new StackPanel();
        var existing = PathField(openForm, "Identitätsdatei öffnen", IdentityFiles);
        var password = Field(openForm, "Passphrase deiner Identität", new PasswordBox());
        var createOption = new Expander { Header = "Neue Identität anlegen", Content = createForm, IsExpanded = true, Margin = new Thickness(0, 12, 0, 0) };
        var openOption = new Expander { Header = "Vorhandene Identität öffnen", Content = openForm, Margin = new Thickness(0, 10, 0, 0) };
        createOption.Expanded += (_, _) => openOption.IsExpanded = false;
        openOption.Expanded += (_, _) => createOption.IsExpanded = false;
        identity.Children.Add(createOption);
        identity.Children.Add(openOption);

        var policy = new StackPanel();
        policy.Children.Add(Text("Diese Einstellung wird für deine geöffnete Identität gespeichert.", 12, true));
        var twoCodes = new CheckBox { Content = "Gegenseitigen Code-Austausch verlangen", Margin = new Thickness(0, 8, 0, 6) };
        policy.Children.Add(twoCodes);
        policy.Children.Add(Text("Aktiviert müssen beide einen Code austauschen. Anfragen nur über die Tor-Adresse werden dann ausgeschaltet.", 12, true));
        var savePolicy = Button("Einstellung speichern", async () =>
        {
            if (identityPath is not { } path) return;
            bool required = twoCodes.IsChecked == true;
            await RunForIdentity("Einladungseinstellung wird gespeichert …", token =>
                Engine.Call(new { action = "set_contact_policy", path, required }, IdentityPassword(), cancellation: token),
                _ =>
                {
                    requireTwoCodes = required;
                    if (required) contactRequestSession?.Cancel();
                    clearInvitation();
                    if (incomingTicket is not null)
                    {
                        contactOpened = false;
                        clearContact();
                    }
                    refresh();
                });
        });
        policy.Children.Add(Row(savePolicy));
        invitationSettings = policy;

        var share = Section("Einladung erstellen", "Teile den Code oder speichere ihn als TXT.");
        var identityHint = Text("Öffne zuerst deine Identität.", 13, true);
        share.Children.Add(identityHint);
        var shareForm = new StackPanel { Visibility = Visibility.Collapsed };
        var receiveHint = Text("", 13, true);
        var configure = Row(Button("Empfangsadresse einrichten", () => showSettings()));
        shareForm.Children.Add(receiveHint);
        shareForm.Children.Add(configure);
        var protect = new CheckBox { Content = "Mit Code-Passphrase schützen", IsChecked = true, Margin = new Thickness(0, 8, 0, 4) };
        shareForm.Children.Add(protect);
        var passphraseHint = Text("Ohne Code-Passphrase kann jede Person mit dem Code die Einladung verwenden.", 12, true);
        passphraseHint.TextWrapping = TextWrapping.Wrap;
        shareForm.Children.Add(passphraseHint);
        var passwordForm = new StackPanel();
        shareForm.Children.Add(passwordForm);
        var codePassword = Field(passwordForm, "Code-Passphrase · mindestens 20 Zeichen", new PasswordBox());
        var recipientPanel = new StackPanel();
        shareForm.Children.Add(recipientPanel);
        var recipient = Field(recipientPanel, "Für wen ist die Einladung? (optional)", new TextBox { MaxLength = 60 });
        var pendingPanel = new StackPanel();
        shareForm.Children.Add(pendingPanel);
        var pendingInvitations = Field(pendingPanel, "Offene Einladungen", new ListBox
        {
            DisplayMemberPath = nameof(OutgoingInvitation.Label), MinHeight = 42, MaxHeight = 145
        });
        int invitationNumber = 0;
        var code = Field(shareForm, "Dein Einladungscode", new TextBox
        {
            IsReadOnly = true, TextWrapping = TextWrapping.Wrap, MaxHeight = 125,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, FontFamily = new FontFamily("Consolas")
        });
        var waitPanel = new StackPanel();
        var withdraw = new Button { Content = "Ausgewählte zurückziehen" };
        void RemoveInvitation(OutgoingInvitation item)
        {
            CryptographicOperations.ZeroMemory(item.Ticket);
            pendingInvitations.Items.Remove(item);
            pendingInvitations.SelectedIndex = pendingInvitations.Items.Count - 1;
            if (pendingInvitations.SelectedItem is null) code.Clear();
            UpdateShare();
        }
        createForm.Children.Add(Row(Button("Identität erstellen", async () =>
        {
            using var unlocked = newPassword.SecurePassword;
            string path = "";
            await Run("Identität wird erstellt …", _ =>
            {
                path = FullPath(newPath);
                return Engine.WithPassword(new { action = "new_identity", path }, newPassword, repeat);
            }, reply => UseIdentity(path, reply, unlocked));
        }, true)));
        openForm.Children.Add(Row(Button("Identität öffnen", async () =>
        {
            using var unlocked = password.SecurePassword;
            string path = "";
            await Run("Identität wird geöffnet …", _ =>
            {
                path = FullPath(existing);
                return Engine.WithPassword(new { action = "public_key", path }, password);
            }, reply => UseIdentity(path, reply, unlocked));
        }, true)));
        var lockRow = Row(Button("MSG sperren", () =>
        {
            EndIdentitySession();
            identityPath = publicKey = peerKey = peerAddress = null;
            contactOpened = false;
            requireTwoCodes = false;
            manualKey.Clear();
            manualAddress.Clear();
            verified.IsChecked = false;
            recipient.Clear();
            codePassword.Clear();
            clearContact();
            clearInvitation();
            ClearSessionConversations();
            ResetLink();
            profileName.Text = "MSG ist gesperrt";
            openOption.IsExpanded = true;
            refresh();
            password.Focus();
        }));
        identity.Children.Add(lockRow);
        var copy = Button("Code kopieren", () => CopyText(code.Text,
            pendingInvitations.SelectedItem is OutgoingInvitation item ? $"{item.Label} kopiert." : "Kontaktcode kopiert."));
        var saveInvitation = Button("Als TXT speichern …", async () =>
        {
            string value = code.Text;
            if (value.Length == 0) return;
            var picker = new SaveFileDialog { Filter = InvitationFiles, DefaultExt = ".txt", FileName = "MSG-Einladung.txt" };
            if (picker.ShowDialog(this) != true) return;
            await Run("Einladung wird gespeichert …", async _ =>
            {
                await File.WriteAllTextAsync(picker.FileName, value + Environment.NewLine);
                return new Reply(true, RequiresCodePassword(value) ? "Einladung gespeichert. Gib die Code-Passphrase separat weiter."
                    : "Einladung gespeichert. Teile sie nur mit der gewünschten Person.", null, null, null);
            });
        });
        shareForm.Children.Add(Row(Button("Einladung erstellen", async () =>
        {
            await RunForIdentity("Kontaktcode wird erstellt …", async token =>
            {
                if (pendingInvitations.Items.Count >= MaxPendingInvitations)
                    throw new ArgumentException("Es sind bereits acht Einladungen offen. Ziehe zuerst eine zurück.");
                string address = direct ? Endpoint(publicAddress) : (await EnsureTorAsync(token)).OnionAddress;
                bool withoutPassword = protect.IsChecked != true;
                var request = new { action = "make_contact", key = publicKey, address,
                    one_code = !requireTwoCodes && !direct, without_password = withoutPassword };
                return withoutPassword ? await Engine.Call(request, cancellation: token)
                    : await Engine.WithPassword(request, codePassword, cancellation: token);
            }, reply =>
            {
                if (reply.Ticket is { } ticket && reply.Text is { } invitationCode)
                {
                    string name = recipient.Text.Trim();
                    string label = $"Einladung #{++invitationNumber}";
                    if (name.Length > 0) label += $" für {name}";
                    var item = new OutgoingInvitation(label, invitationCode, Engine.TextBytes(ticket));
                    pendingInvitations.Items.Add(item);
                    pendingInvitations.SelectedItem = item;
                    recipient.Clear();
                    SetStatus($"{label} erstellt. Teile den Code und klicke auf „Auf Annahme warten“.");
                }
                else code.Text = reply.Text ?? "";
            }, canCancel: true);
        }, true), copy));
        shareForm.Children.Add(Row(saveInvitation, Button("Zu den Nachrichten", () => showChat())));
        withdraw.Click += (_, _) =>
        {
            if (pendingInvitations.SelectedItem is OutgoingInvitation item)
            {
                RemoveInvitation(item);
                SetStatus($"{item.Label} zurückgezogen.");
            }
        };
        waitPanel.Children.Add(Row(withdraw));
        waitPanel.Children.Add(Row(Button("Auf Annahme warten", async () =>
        {
            if (identityPath is not { } path || pendingInvitations.Items.Count == 0) return;
            long currentSession = identitySession;
            var batch = pendingInvitations.Items.Cast<OutgoingInvitation>().ToArray();
            bool started = false;
            bool finished = false;
            await RunForIdentity("Einladung wird bereitgestellt …", async token =>
            {
                if (chatSession is not null)
                    throw new ArgumentException("Schließe zuerst den Chatkanal und warte dann auf die Annahme.");
                await EnsureTorAsync(token);
                if (pendingInvitations.Items.Count != batch.Length)
                    throw new ArgumentException("Die Tor-Adresse hat sich geändert. Erstelle eine neue Einladung.");
                byte[] tickets = new byte[batch.Length * batch[0].Ticket.Length];
                for (int i = 0; i < batch.Length; i++)
                    batch[i].Ticket.CopyTo(tickets, i * batch[0].Ticket.Length);
                started = true;
                var result = await Engine.Call(new { action = "wait_invitation", path }, IdentityPassword(),
                    tickets, token, status =>
                    {
                        if (status == "invitation_listening")
                            SetStatus($"Wartet auf Annahme · {batch.Length} offen (5 Minuten). Abbrechen zieht diese Codes zurück.");
                    });
                finished = !result.Ok || result.InvitationIndex is int index && index >= 0 && index < batch.Length;
                if (!finished) throw new IOException("MSG konnte die angenommene Einladung nicht zuordnen.");
                return result;
            }, reply =>
            {
                var accepted = batch[reply.InvitationIndex!.Value];
                RemoveInvitation(accepted);
                clearContact();
                peerKey = reply.Text;
                peerAddress = reply.Address;
                peerName = $"Über {accepted.Label}";
                contactOpened = true;
                encryptedInvitation = true;
                verified.IsChecked = false;
                SetLink($"{accepted.Label} angenommen", "Der Chat öffnet sich automatisch.", "Mint");
                startConversation();
                showChat();
                refresh();
            }, canCancel: true);
            if (started && !finished && currentSession == identitySession)
            {
                clearInvitation();
                SetStatus("Warten unterbrochen. Die offenen Einladungen wurden zurückgezogen.");
            }
        }, true)));
        shareForm.Children.Add(waitPanel);
        share.Children.Add(shareForm);
        void UpdateShare()
        {
            identityHint.Visibility = publicKey is null ? Visibility.Visible : Visibility.Collapsed;
            shareForm.Visibility = publicKey is null ? Visibility.Collapsed : Visibility.Visible;
            policy.IsEnabled = identityPath is not null;
            createOption.Visibility = openOption.Visibility = identityPath is null ? Visibility.Visible : Visibility.Collapsed;
            lockRow.Visibility = identityPath is null ? Visibility.Collapsed : Visibility.Visible;
            bool oneCode = !direct && !requireTwoCodes;
            recipientPanel.Visibility = oneCode ? Visibility.Visible : Visibility.Collapsed;
            pendingPanel.Visibility = waitPanel.Visibility =
                oneCode && pendingInvitations.Items.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            withdraw.IsEnabled = pendingInvitations.SelectedItem is OutgoingInvitation;
            passwordForm.Visibility = protect.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
            passphraseHint.Visibility = protect.IsChecked == true ? Visibility.Collapsed : Visibility.Visible;
            configure.Visibility = direct ? Visibility.Visible : Visibility.Collapsed;
            receiveHint.Text = direct ? "Die Einladung enthält deine erreichbare IP-Adresse."
                : requireTwoCodes ? "Tauscht beide eure Codes aus."
                : "Eine Einladung reicht. Teile sie und warte auf die Annahme.";
            copy.IsEnabled = saveInvitation.IsEnabled = code.Text.Length > 0;
        }
        clearInvitation = () =>
        {
            foreach (OutgoingInvitation item in pendingInvitations.Items)
                CryptographicOperations.ZeroMemory(item.Ticket);
            pendingInvitations.Items.Clear();
            code.Clear();
            UpdateShare();
        };
        code.TextChanged += (_, _) => UpdateShare();
        pendingInvitations.SelectionChanged += (_, _) =>
        {
            code.Text = (pendingInvitations.SelectedItem as OutgoingInvitation)?.Code ?? "";
            UpdateShare();
        };
        protect.Checked += (_, _) => UpdateShare();
        protect.Unchecked += (_, _) => { codePassword.Clear(); UpdateShare(); };
        onionAddress.TextChanged += (_, _) => clearInvitation();
        publicAddress.TextChanged += (_, _) => clearInvitation();
        var updateChat = refresh;
        refresh = () => { updateChat(); UpdateShare(); };
        return Columns(Card(identity), Card(share));

        void UseIdentity(string path, Reply reply, SecureString unlocked)
        {
            if (closed) return;
            EndIdentitySession();
            if (identityPath != path || publicKey != reply.Text)
            {
                peerKey = null;
                peerAddress = null;
                manualKey.Clear();
                manualAddress.Clear();
                verified.IsChecked = false;
                codePassword.Clear();
                clearContact();
                ClearSessionConversations();
            }
            identityPath = path;
            identitySecret = unlocked.Copy();
            identitySecret.MakeReadOnly();
            unlockedSession = new CancellationTokenSource();
            publicKey = reply.Text;
            requireTwoCodes = reply.TwoCodes == true;
            twoCodes.IsChecked = requireTwoCodes;
            profileName.Text = Path.GetFileName(path);
            clearInvitation();
            existing.Text = path;
            createOption.IsExpanded = openOption.IsExpanded = false;
            refresh();
            showChat();
            StartTorForIdentity();
        }

    }

    private FrameworkElement TorContactRequests()
    {
        var panel = Section("Kontakt hinzufügen",
            "Gib die Tor-Adresse ein. Sobald die andere Person annimmt, öffnet sich euer Chat.");
        var addressInput = Field(panel, "Tor-Adresse des Kontakts", new TextBox { MaxLength = 72 });
        var send = Button("Verbindung anfragen", async () =>
            await requestChat(addressInput.Text, null), true);
        panel.Children.Add(Row(send));
        panel.Children.Add(Text("Eine Anfrage teilt deinen öffentlichen Schlüssel und deine Tor-Adresse mit der Gegenstelle.", 12, true));
        var listeningState = Text("Du bist für neue Anfragen nicht erreichbar.", 13);
        panel.Children.Add(listeningState);
        var requestInfo = Text("", 13);
        requestInfo.TextWrapping = TextWrapping.Wrap;
        panel.Children.Add(requestInfo);
        Func<object, Task>? submit = null;
        long? pending = null;
        string? pendingKey = null;
        bool deciding = false;
        long requestGeneration = 0;
        MsgPrompt? prompt = null;
        var allow = new Button { Content = "Für Anfragen erreichbar werden" };
        var accept = new Button { Content = "Annehmen" };
        var reject = new Button { Content = "Ablehnen" };
        var block = new Button { Content = "Blockieren" };
        var decisions = Row(accept, reject, block);
        panel.Children.Add(decisions);
        panel.Children.Add(Row(allow));
        panel.Children.Add(Text("Jede neue Anfrage braucht deine Zustimmung. Sperren schaltet die Erreichbarkeit aus.", 12, true));
        var section = new Expander { Header = "Per Tor-Adresse verbinden", Content = panel, Margin = new Thickness(0, 12, 0, 0) };

        void Update()
        {
            section.Visibility = identityPath is not null && !direct && !requireTwoCodes ? Visibility.Visible : Visibility.Collapsed;
            send.IsEnabled = !string.IsNullOrWhiteSpace(addressInput.Text);
            allow.Content = contactRequestSession is null ? "Für Anfragen erreichbar werden" : "Keine neuen Anfragen";
            allow.IsEnabled = contactRequestSession is not { IsCancellationRequested: true };
            bool open = pending.HasValue && contactRequestSession is { IsCancellationRequested: false };
            requestInfo.Visibility = decisions.Visibility = open ? Visibility.Visible : Visibility.Collapsed;
            accept.IsEnabled = reject.IsEnabled = block.IsEnabled = open && !deciding && submit is not null;
        }

        async Task Decide(bool accepted, bool blocked = false)
        {
            if (pending is not { } id || submit is not { } input || deciding
                || contactRequestSession is not { IsCancellationRequested: false } session) return;
            deciding = true;
            Update();
            try
            {
                if (blocked && string.Equals(pendingKey, ActivePeer, StringComparison.OrdinalIgnoreCase))
                    await stopConversation();
                session.Token.ThrowIfCancellationRequested();
                await input(new { id, accept = accepted, block = blocked });
                session.Token.ThrowIfCancellationRequested();
                SetStatus(blocked ? "Kontakt wird blockiert …" : accepted ? "Anfrage angenommen. Chat wird geöffnet …" : "Anfrage abgelehnt.");
            }
            catch (Exception error) when (error is IOException or InvalidOperationException or OperationCanceledException)
            {
                if (ReferenceEquals(contactRequestSession, session)) session.Cancel();
            }
        }

        async Task ShowRequest(long id, string address, long generation)
        {
            if (pending != id || generation != requestGeneration || deciding || prompt is not null
                || contactRequestSession is not { IsCancellationRequested: false } session) return;
            var shown = new MsgPrompt(this, "Neue Kontaktanfrage",
                $"Jemand möchte mit dir chatten.\n\n{address}\n\nMit Annehmen wird der Chat geöffnet."
                + (chatSession is not null ? " Dabei wechselst du von deinem aktuellen Chat zu diesem Kontakt." : ""),
                "Annehmen", "Ablehnen", "Blockieren");
            prompt = shown;
            shown.Display();
            var choice = await shown.Result;
            if (ReferenceEquals(prompt, shown)) prompt = null;
            if (pending != id || generation != requestGeneration || deciding || session.IsCancellationRequested) return;
            await Decide(choice == PromptChoice.First, choice == PromptChoice.Third);
        }

        async Task Listen(string path)
        {
            using var session = new CancellationTokenSource();
            long currentSession = identitySession;
            contactRequestSession = session;
            contactRequestsReady = false;
            listeningState.Text = "Erreichbarkeit wird vorbereitet …";
            Update();
            try
            {
                while (!session.IsCancellationRequested && identityPath == path && !direct && !requireTwoCodes)
                {
                    long generation = ++requestGeneration;
                    var reply = await Engine.Chat(new { action = "listen_contact_requests", path }, IdentityPassword(),
                        session.Token, frame =>
                        {
                            if (session.IsCancellationRequested) return;
                            switch (frame.GetProperty("event").GetString())
                            {
                                case "request_listening":
                                    contactRequestsReady = true;
                                    listeningState.Text = "Du bist für neue Anfragen erreichbar.";
                                    SetStatus("Bereit für Kontaktanfragen.");
                                    break;
                                case "incoming_request":
                                    pending = frame.GetProperty("id").GetInt64();
                                    pendingKey = frame.GetProperty("key").GetString();
                                    string address = frame.GetProperty("address").GetString()!;
                                    requestInfo.Text = $"Neue Anfrage von {address}";
                                    SetStatus("Neue Kontaktanfrage.");
                                    long id = pending.Value;
                                    Dispatcher.BeginInvoke(new Action(() => _ = ShowRequest(id, address, generation)));
                                    break;
                                case "request_block_error":
                                    SetStatus("Die Anfrage wurde abgelehnt. Die Blockierung konnte nicht gespeichert werden.", true);
                                    break;
                                case "request_blocked":
                                    SetStatus("Kontakt blockiert. Weitere Anfragen dieses Kontakts werden abgelehnt.");
                                    break;
                                case "request_cleared":
                                    pending = null;
                                    pendingKey = null;
                                    deciding = false;
                                    prompt?.Close();
                                    prompt = null;
                                    break;
                            }
                            Update();
                            RefreshConversationList();
                        }, input =>
                        {
                            if (session.IsCancellationRequested) return;
                            submit = input;
                            Update();
                        });
                    session.Token.ThrowIfCancellationRequested();
                    submit = null;
                    if (reply.Ok && reply.Text is not null) await SelectContact(reply);
                    else
                    {
                        if (!reply.Ok) SetStatus(reply.Message, true);
                        break;
                    }
                }
            }
            catch (OperationCanceledException) when (session.IsCancellationRequested) { }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException
                or InvalidOperationException or System.ComponentModel.Win32Exception or JsonException)
            {
                if (currentSession == identitySession)
                    SetStatus("Kontaktanfragen wurden unterbrochen. Aktiviere die Erreichbarkeit erneut.", true);
            }
            finally
            {
                pending = null;
                pendingKey = null;
                prompt?.Close();
                prompt = null;
                contactRequestSession = null;
                contactRequestsReady = false;
                submit = null;
                deciding = false;
                requestInfo.Text = "";
                listeningState.Text = "Du bist für neue Anfragen nicht erreichbar.";
                Update();
                refresh();
            }
        }

        async Task SelectContact(Reply reply)
        {
            string? path = identityPath;
            long currentSession = identitySession;
            await contactSelection.WaitAsync();
            try
            {
                await stopConversation();
                if (path is null || identityPath != path || identitySecret is null || currentSession != identitySession) return;
                clearContact();
                peerKey = reply.Text;
                peerAddress = reply.Address;
                knownContacts.TryGetValue(reply.Text!, out var saved);
                peerName = saved?.Name ?? "Neuer Kontakt";
                contactSaved = saved is not null;
                contactOpened = true;
                encryptedInvitation = true;
                verified.IsChecked = saved?.Verified == true;
                RestoreConversation();
                SetStatus("Anfrage angenommen. Der Chat öffnet sich …");
                showChat();
                refresh();
                startConversation();
            }
            finally { contactSelection.Release(); }
        }

        async Task EnableRequests(bool copyAddress)
        {
            if (identityPath is not { } path || direct || requireTwoCodes) return;
            long currentSession = identitySession;
            string? address = null;
            bool ready = await RunForIdentity("Tor wird vorbereitet …", async token =>
            {
                address = (await EnsureTorAsync(token)).OnionAddress;
                return new Reply(true, "Erreichbarkeit wird aktiviert.", null, null, null);
            }, canCancel: true);
            if (!ready || identityPath != path || currentSession != identitySession) return;
            if (contactRequestSession is null) _ = Listen(path);
            if (copyAddress && address is not null)
                CopyText(address.Split(':')[0], "Adresse kopiert. Du bist für Anfragen erreichbar.");
            refresh();
        }

        requestChat = async (input, expectedKey) =>
        {
            if (identityPath is not { } path || direct || requireTwoCodes) return;
            long currentSession = identitySession;
            string address = input.Trim().ToLowerInvariant();
            if (address.EndsWith(".onion", StringComparison.Ordinal)) address += $":{OnionEndpoint.ChatPort}";
            Reply? acceptedReply = null;
            await RunForIdentity("Verbindung wird angefragt …", async token =>
            {
                if (!IsOnionEndpoint(address)) throw new ArgumentException("Gib eine gültige .onion-Adresse ein.");
                var endpoint = await EnsureTorAsync(token);
                return await Engine.Call(new { action = "send_contact_request", path, address,
                    own_address = endpoint.OnionAddress, socks_port = endpoint.SocksPort }, IdentityPassword(),
                    cancellation: token, onProgress: status =>
                    {
                        if (status == "request_waiting") SetStatus("Die andere Person entscheidet über deine Anfrage …");
                    });
            }, reply => acceptedReply = reply, canCancel: true);
            if (acceptedReply is null || identityPath != path || currentSession != identitySession) return;
            if (expectedKey is not null && !string.Equals(expectedKey, acceptedReply.Text, StringComparison.OrdinalIgnoreCase))
            {
                SetStatus("Der Schlüssel passt nicht zum gespeicherten Kontakt. Gleiche ihn mit der Person ab.", true);
                return;
            }
            await SelectContact(acceptedReply);
        };
        shareMyAddress = () => _ = EnableRequests(copyAddress: true);
        allow.Click += async (_, _) =>
        {
            if (contactRequestSession is { } active)
            {
                active.Cancel();
                Update();
                return;
            }
            await EnableRequests(copyAddress: false);
        };
        accept.Click += async (_, _) => await Decide(true);
        reject.Click += async (_, _) => await Decide(false);
        block.Click += async (_, _) => await Decide(false, blocked: true);
        addressInput.TextChanged += (_, _) => Update();
        refreshContactRequests = Update;
        showRequestOptions = () =>
        {
            showContacts();
            section.IsExpanded = true;
            section.BringIntoView();
            addressInput.Focus();
        };
        Update();
        return section;
    }

    private FrameworkElement BlockedContactsView()
    {
        var panel = Section("Blockierte Kontakte", "Blockierte Geräteschlüssel können dir keine neuen Tor-Anfragen stellen.");
        var list = new ListBox { DisplayMemberPath = "Value", MinHeight = 70, MaxHeight = 180 };
        panel.Children.Add(list);
        var remove = Button("Blockierung aufheben", async () =>
        {
            if (list.SelectedItem is KeyValuePair<string, string> item) await Load(item.Key);
        });
        panel.Children.Add(Row(Button("Aktualisieren", async () => await Load()), remove));
        remove.IsEnabled = false;
        list.SelectionChanged += (_, _) =>
        {
            remove.IsEnabled = list.SelectedItem is KeyValuePair<string, string>;
            list.ToolTip = list.SelectedItem is KeyValuePair<string, string> item ? item.Key : null;
        };
        var section = new Expander { Header = "Blockierte Kontakte", Content = panel, Margin = new Thickness(0, 12, 0, 0) };
        section.Expanded += async (_, _) => await Load();
        return section;

        async Task Load(string? removeKey = null)
        {
            if (identityPath is not { } path) return;
            await RunForIdentity("Blockierte Kontakte werden geladen …", token =>
                Engine.Call(new { action = "blocked_contacts", path, remove = removeKey },
                    IdentityPassword(), cancellation: token), reply =>
                {
                    var keys = JsonSerializer.Deserialize<string[]>(reply.Text ?? "[]") ?? [];
                    list.ItemsSource = keys.Select(key => new KeyValuePair<string, string>(key,
                        $"Kontakt · {key[..12].ToUpperInvariant()}")).ToArray();
                });
        }
    }

    private FrameworkElement SettingsView()
    {
        var preferences = Section("Kontakte & Freigaben", "Lege fest, wie dich neue Kontakte erreichen dürfen.");
        preferences.Children.Add(invitationSettings);
        preferences.Children.Add(BlockedContactsView());
        preferences.Children.Add(Row(Button("Kontaktanfragen verwalten", () => showRequestOptions())));
        preferences.Children.Add(Text("Anfragen per Tor-Adresse erlaubst du für die aktuelle Sitzung. Sperren beendet die Freigabe. Online-Status teilt ihr im Chat nur mit beidseitiger Zustimmung.", 12, true));
        var tor = Section("Tor · Automatisch", "Jede Identität hat eine eigene Tor-Adresse. MSG aktiviert sie beim Entsperren und beendet Tor beim Sperren.");
        tor.Children.Add(Row(Button("Tor starten und prüfen", async () =>
            await Run("Tor wird gestartet …", async token =>
            {
                await EnsureTorAsync(token);
                return new Reply(true, "Tor ist mit dem Netzwerk verbunden.", null, null, null);
            }, canCancel: true), true)));
        Field(tor, "Meine Onion-Adresse", onionAddress);
        tor.Children.Add(onionState);
        var rotate = Button("Neue Tor-Adresse erstellen …", async () => await ChangeAddress(import: false));
        var import = Button("Frühere Tor-Adresse übernehmen …", async () => await ChangeAddress(import: true));
        tor.Children.Add(Row(rotate, import));
        refreshTorSettings = () =>
        {
            rotate.IsEnabled = onionIdentity is not null;
            import.Visibility = onionTransport.HasLegacyKey ? Visibility.Visible : Visibility.Collapsed;
            import.IsEnabled = onionIdentity is not null;
        };
        refreshTorSettings();
        var notices = new Expander { Header = "Lizenzhinweise zu Tor", Margin = new Thickness(0, 10, 0, 0) };
        notices.Expanded += (_, _) => notices.Content ??= TorNotices();
        tor.Children.Add(notices);

        var advanced = Section("Erweitert", "Direkte Verbindungen setzen voraus, dass die Empfangsadresse erreichbar ist.");
        var mode = new CheckBox { Content = "Direkte IP-Verbindung verwenden", Margin = new Thickness(0, 5, 0, 5) };
        advanced.Children.Add(mode);
        var inputs = new StackPanel { Visibility = Visibility.Collapsed };
        Field(inputs, "Meine erreichbare IP-Adresse mit Port", publicAddress);
        Field(inputs, "Lokale Empfangsadresse mit Port", localAddress);
        Field(inputs, "Manueller Kontakt · öffentlicher Schlüssel", manualKey);
        Field(inputs, "Zieladresse für manuellen Kontakt", manualAddress);
        advanced.Children.Add(inputs);
        manualKey.TextChanged += (_, _) =>
        {
            verified.IsChecked = false;
            ResetLink();
            LeaveConversation();
            refresh();
        };
        manualAddress.TextChanged += (_, _) => refresh();
        localAddress.TextChanged += (_, _) => chatSession?.Cancel();
        mode.Checked += (_, _) => SetMode(true);
        mode.Unchecked += (_, _) => SetMode(false);
        var transport = new StackPanel();
        transport.Children.Add(Card(tor));
        transport.Children.Add(Card(new Expander { Header = "Erweiterte Verbindungseinstellungen", Content = advanced }));
        var page = Columns(Card(preferences), transport);
        page.MaxWidth = Width - 64;
        ((FrameworkElement)Content).SizeChanged += (_, size) => page.MaxWidth = Math.Max(0, size.NewSize.Width);
        return page;

        async Task ChangeAddress(bool import)
        {
            if (onionIdentity is not { } owner) return;
            string title = import ? "Frühere Tor-Adresse übernehmen" : "Tor-Adresse wechseln";
            string detail = import
                ? "Die frühere Adresse wird dieser Identität zugeordnet und ersetzt ihre aktuelle Adresse. Teile die übernommene Adresse nur mit Kontakten, die diese Identität erreichen sollen."
                : "Nur diese Identität erhält eine neue Adresse. Teile anschließend einen neuen Kontaktcode mit deinen Kontakten.";
            if (MessageBox.Show(this, detail, title, MessageBoxButton.YesNo, MessageBoxImage.Question,
                    MessageBoxResult.No) != MessageBoxResult.Yes || !IsCurrentOnionIdentity(owner)) return;

            await RunForIdentity(import ? "Frühere Tor-Adresse wird übernommen …" : "Neue Tor-Adresse wird erstellt …", async token =>
            {
                chatSession?.Cancel();
                contactRequestSession?.Cancel();
                var changedOwner = owner with { };
                onionIdentity = changedOwner;
                onionTransport.Stop();
                onionAddress.Clear();
                onionState.Text = "Tor-Adresse wird aktualisiert …";
                ResetLink();
                try
                {
                    var endpoint = import ? await onionTransport.ImportLegacyAsync(changedOwner, token)
                        : await onionTransport.RotateAsync(changedOwner, token);
                    ConfirmTorAddress(changedOwner, endpoint, token);
                    return new Reply(true, import ? "Frühere Tor-Adresse übernommen."
                        : "Neue Tor-Adresse aktiv. Erstelle unter „Mein Profil“ einen neuen Kontaktcode.", null, null, null);
                }
                catch (CryptographicException)
                {
                    throw new IOException("Die Tor-Adresse konnte nicht sicher gespeichert oder gelesen werden.");
                }
                finally
                {
                    if (IsCurrentOnionIdentity(changedOwner))
                    {
                        if (onionAddress.Text.Length == 0) onionState.Text = "Tor ist derzeit nicht verbunden. Du kannst es erneut prüfen.";
                        refreshTorSettings();
                    }
                }
            }, canCancel: true);
        }

        void SetMode(bool enabled)
        {
            chatSession?.Cancel();
            contactRequestSession?.Cancel();
            direct = enabled;
            clearInvitation();
            if (direct) StopTor();
            else StartTorForIdentity();
            ResetLink();
            inputs.Visibility = enabled ? Visibility.Visible : Visibility.Collapsed;
            verified.IsChecked = false;
            refresh();
            SetStatus(enabled ? "Direkte IP-Verbindung ausgewählt." : "Tor ausgewählt.");
        }
    }

    private string? ActivePeer => direct && manualKey.Text.Trim().Length > 0 ? manualKey.Text.Trim()
        : contactOpened ? peerKey : null;

    private bool UsingImportedContact => contactOpened && (!direct || string.IsNullOrWhiteSpace(manualKey.Text));

    private bool ContactAccepted => incomingTicket is null && (verified.IsChecked == true || (UsingImportedContact && encryptedInvitation));

    private static bool RequiresCodePassword(string code) => code.StartsWith("KCM2-", StringComparison.Ordinal)
        || code.StartsWith("KCM3-", StringComparison.Ordinal);

    private static void ClearTicket(ref byte[]? ticket)
    {
        if (ticket is not null) CryptographicOperations.ZeroMemory(ticket);
        ticket = null;
    }

    private string? SendAddress
    {
        get
        {
            string? address = direct && manualKey.Text.Trim().Length > 0 ? manualAddress.Text.Trim() : peerAddress;
            if (string.IsNullOrWhiteSpace(address)) return null;
            if (direct) return IPEndPoint.TryParse(address, out var endpoint) && endpoint.Port != 0 ? address : null;
            return IsOnionEndpoint(address) ? address : null;
        }
    }

    private byte[] IdentityPassword() => Engine.PasswordBytes(identitySecret
        ?? throw new ArgumentException("Entsperre MSG zuerst unter „Mein Profil“."));

    private Task<bool> RunForIdentity(string waiting, Func<CancellationToken, Task<Reply>> operation,
        Action<Reply>? success = null, bool canCancel = false) => Run(waiting, async token =>
    {
        if (unlockedSession is not { } session)
            throw new ArgumentException("Entsperre MSG zuerst unter „Mein Profil“.");
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(session.Token, token);
        cancellation.Token.ThrowIfCancellationRequested();
        var reply = await operation(cancellation.Token);
        cancellation.Token.ThrowIfCancellationRequested();
        return reply;
    }, success, canCancel);

    private void EndIdentitySession()
    {
        identitySession++;
        chatSession?.Cancel();
        contactRequestSession?.Cancel();
        unlockedSession?.Cancel();
        unlockedSession?.Dispose();
        unlockedSession = null;
        StopTor();
        identitySecret?.Dispose();
        identitySecret = null;
    }

    private void StopTor()
    {
        onionIdentity = null;
        onionTransport.Stop();
        onionAddress.Clear();
        onionState.Text = direct ? "Direkte IP-Verbindung ausgewählt."
            : "Entsperre MSG, um deine Tor-Adresse zu aktivieren.";
        refreshTorSettings();
    }

    private void StartTorForIdentity()
    {
        if (direct || identityPath is not { } path || publicKey is not { } key
            || identitySecret is not { } secret || unlockedSession is not { } session) return;
        var token = session.Token;
        var owner = new OnionIdentity(path, key, () =>
        {
            token.ThrowIfCancellationRequested();
            return Engine.PasswordBytes(secret);
        });
        onionIdentity = owner;
        refreshTorSettings();
        _ = ConnectInBackground();

        async Task ConnectInBackground()
        {
            try { await EnsureTorAsync(token, showProgress: false); }
            catch (OperationCanceledException) { }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException
                or System.ComponentModel.Win32Exception or JsonException or InvalidOperationException)
            {
                if (IsCurrentOnionIdentity(owner)) onionState.Text = error.Message;
            }
        }
    }

    private static new WrapPanel Row(params UIElement[] children)
    {
        var row = new WrapPanel { Margin = new Thickness(0, 4, 0, 2) };
        foreach (UIElement child in children)
        {
            if (child is FrameworkElement element) element.Margin = new Thickness(0, 0, 8, 6);
            row.Children.Add(child);
        }
        return row;
    }

    private bool IsCurrentOnionIdentity(OnionIdentity owner) => !closed && ReferenceEquals(onionIdentity, owner);

    private void ConfirmTorAddress(OnionIdentity owner, OnionEndpoint endpoint, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!IsCurrentOnionIdentity(owner)) throw new OperationCanceledException();
        onionAddress.Text = endpoint.OnionAddress;
        onionState.Text = "Tor ist verbunden.";
    }

    private async Task<OnionEndpoint> EnsureTorAsync(CancellationToken token, bool showLink = false, bool showProgress = true)
    {
        if (direct) throw new ArgumentException("Schalte in den Einstellungen zuerst wieder auf Tor um.");
        if (onionIdentity is not { } owner || unlockedSession is not { } session)
            throw new ArgumentException("Entsperre MSG zuerst unter „Mein Profil“.");
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token, session.Token);
        if (onionAddress.Text.Length == 0) onionState.Text = "Tor verbindet sich …";
        try
        {
            var endpoint = await onionTransport.StartAsync(owner, percent =>
            {
                if (!IsCurrentOnionIdentity(owner) || cancellation.IsCancellationRequested) return;
                string status = $"Tor verbindet sich … {percent} %";
                onionState.Text = status;
                if (showProgress) SetStatus(status);
                if (showLink) SetLink("Tor startet", status);
            }, cancellation.Token);
            ConfirmTorAddress(owner, endpoint, cancellation.Token);
            return endpoint;
        }
        catch (CryptographicException)
        {
            throw new IOException("Die Tor-Adresse konnte nicht sicher gespeichert oder gelesen werden.");
        }
        finally
        {
            if (IsCurrentOnionIdentity(owner))
            {
                if (onionAddress.Text.Length == 0) onionState.Text = "Tor ist derzeit nicht verbunden. Du kannst es erneut prüfen.";
                refreshTorSettings();
            }
        }
    }

    private static TextBox TorNotices()
    {
        var notices = new List<string>();
        var assembly = typeof(MsgWindow).Assembly;
        foreach (string name in new[] { "Tor.License.txt", "Tor.Libevent.txt", "Tor.OpenSSL.txt", "Tor.Zlib.txt" })
        {
            using var resource = assembly.GetManifestResourceStream(name);
            if (resource is null) continue;
            using var reader = new StreamReader(resource);
            notices.Add(reader.ReadToEnd());
        }
        return new TextBox
        {
            Text = string.Join(Environment.NewLine + Environment.NewLine, notices),
            IsReadOnly = true, TextWrapping = TextWrapping.Wrap, MaxHeight = 200,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        };
    }

    private void SetLink(string state, string detail, string color = "Ink")
    {
        linkState.Text = state;
        linkState.Foreground = Brush(color);
        linkDetail.Text = detail;
        if (UIElementAutomationPeer.FromElement(linkState) is { } peer)
            peer.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
    }

    private void ResetLink() =>
        SetLink("Nicht verbunden", "Wähle einen Kontakt aus oder teile deine Adresse für eine Anfrage.");

    private void ShowLinkProgress(string status)
    {
        switch (status)
        {
            case "tor_retry":
                SetLink("Tor versucht es erneut", "Prüfe, ob die andere Person auf die Annahme wartet.");
                break;
            case "connecting":
                SetLink("Verbindet", direct ? "MSG verbindet sich direkt mit der Gegenstelle."
                    : "MSG sucht die Gegenstelle über Tor.");
                break;
            case "handshake":
                SetLink("Prüft die Gegenstelle", "MSG gleicht den Geräteschlüssel ab.");
                break;
        }
    }

    private void AddBubble(string message, bool outgoing)
    {
        if (ActivePeer is not { } key || identityPath is null) return;
        if (!string.Equals(displayedPeer, key, StringComparison.OrdinalIgnoreCase)) RestoreConversation();
        RenderBubble(conversations.Add(key, message, outgoing));
        refresh();
    }

    private void RenderBubble(SessionConversations.Message message)
    {
        bool outgoing = message.Outgoing;
        var body = new StackPanel();
        var label = Text($"{message.Time:HH:mm}{(outgoing ? "  ✓" : "")}", 10, true);
        label.ToolTip = outgoing ? "Zugestellt" : "Empfangen";
        label.Margin = new Thickness(0, 5, 0, 0);
        label.HorizontalAlignment = HorizontalAlignment.Right;
        var text = new TextBox
        {
            Text = message.Text, IsReadOnly = true, IsUndoEnabled = false, TextWrapping = TextWrapping.Wrap, MinHeight = 0,
            Padding = new Thickness(0), Background = Brushes.Transparent, BorderThickness = new Thickness(0)
        };
        text.FontSize = 14;
        body.Children.Add(text);
        body.Children.Add(label);
        var bubble = new Border
        {
            Child = body, CornerRadius = outgoing ? new CornerRadius(16, 16, 4, 16) : new CornerRadius(16, 16, 16, 4),
            Padding = new Thickness(14, 10, 14, 8), MaxWidth = bubbleWidth,
            HorizontalAlignment = outgoing ? HorizontalAlignment.Right : HorizontalAlignment.Left,
            Background = Brush(outgoing ? "BubbleOutgoing" : "BubbleIncoming"),
            Margin = new Thickness(0, 4, 6, 4)
        };
        if (bubbles.Count == 50)
        {
            timeline.Children.Remove(bubbles[0]);
            bubbles.RemoveAt(0);
        }
        bubbles.Add(bubble);
        timeline.Children.Add(bubble);
    }

    private void ClearTimeline()
    {
        if (displayedPeer is { } key && conversations.Find(key) is { } conversation)
            conversation.Messages.Clear();
        ClearTimelineView();
        refresh();
    }

    private void ClearTimelineView()
    {
        foreach (var bubble in bubbles) timeline.Children.Remove(bubble);
        bubbles.Clear();
    }

    private void LeaveConversation()
    {
        if (displayedPeer is { } key) conversations.Open(key).Draft = draft.Text;
        displayedPeer = null;
        restoringConversation = true;
        try { draft.Clear(); draft.ClearUndo(); ClearTimelineView(); }
        finally { restoringConversation = false; }
    }

    private void RestoreConversation()
    {
        string? key = ActivePeer;
        if (key is null || string.Equals(displayedPeer, key, StringComparison.OrdinalIgnoreCase)) return;
        LeaveConversation();
        displayedPeer = key;
        var conversation = conversations.Open(key);
        restoringConversation = true;
        try
        {
            draft.Text = conversation.Draft;
            draft.ClearUndo();
            foreach (var message in conversation.Messages) RenderBubble(message);
        }
        finally { restoringConversation = false; }
    }

    private void ClearSessionConversations()
    {
        LeaveConversation();
        conversations.Clear();
        knownContacts.Clear();
        resetContactList();
        sidebar?.Reset();
    }

    private void RefreshConversationList()
    {
        if (sidebar is null) return;
        var contacts = knownContacts.Values.ToList();
        if (ActivePeer is { } active && contacts.All(item => !string.Equals(item.Key, active, StringComparison.OrdinalIgnoreCase)))
            contacts.Add(new SavedContact(peerName ?? "Neuer Kontakt", active, peerAddress));
        var items = contacts.OrderByDescending(item => string.Equals(item.Key, ActivePeer, StringComparison.OrdinalIgnoreCase))
            .ThenBy(item => item.Name, StringComparer.CurrentCultureIgnoreCase)
            .Select(item =>
            {
                var conversation = conversations.Find(item.Key);
                string detail = conversation?.Draft is { Length: > 0 } pending ? $"Entwurf: {pending}"
                    : conversation?.Messages.LastOrDefault()?.Text ?? "Noch keine Nachrichten in dieser Sitzung";
                detail = detail.Replace('\r', ' ').Replace('\n', ' ');
                if (detail.Length > 90) detail = detail[..90] + "…";
                bool selected = string.Equals(item.Key, ActivePeer, StringComparison.OrdinalIgnoreCase);
                string state = selected ? linkState.Text : "Gespeicherter Kontakt";
                return new ConversationSidebar.Item(item.Key, item.Name, detail, selected, state);
            }).ToArray();
        sidebar.Update(items, contactRequestsReady && contactRequestSession is { IsCancellationRequested: false }, !direct && !requireTwoCodes);
    }

    private static Border Badge(TextBlock label)
    {
        label.Foreground = Brush("Mint");
        label.FontWeight = FontWeights.SemiBold;
        return new Border { Child = label, CornerRadius = new CornerRadius(8), Background = Brush("Field"), Padding = new Thickness(9, 4, 9, 4) };
    }

    private void CopyText(string value, string status)
    {
        try { Clipboard.SetText(value); SetStatus(status); }
        catch (System.Runtime.InteropServices.ExternalException)
        {
            SetStatus("Zwischenablage gerade nicht verfügbar. Markiere den Code im Feld.", true);
        }
    }

    private static string Endpoint(TextBox input)
    {
        if (!IPEndPoint.TryParse(Required(input), out var parsed) || parsed.Port == 0)
            throw new ArgumentException("Gib eine IP-Adresse mit Port ein, zum Beispiel 127.0.0.1:49424.");
        return parsed.ToString();
    }

    private static bool IsOnionEndpoint(string value)
    {
        int separator = value.LastIndexOf(':');
        return separator == 62 && value.AsSpan(56, 6).SequenceEqual(".onion")
            && value[..56].All(c => c is >= 'a' and <= 'z' or >= '2' and <= '7')
            && ushort.TryParse(value.AsSpan(separator + 1), out ushort port) && port != 0;
    }

}
