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
    private readonly TorRuntime managedTor = new();
    private SecureString? identitySecret;
    private CancellationTokenSource? chatSession;
    private CancellationTokenSource? contactRequestSession;
    private readonly TextBlock profileName = Text("Keine Identität geöffnet", 13, true);
    private readonly TextBlock contactState = Text("Kein Kontakt verbunden", 13, true);
    private readonly TextBlock transportState = Text("TOR", 12);
    private readonly TextBlock linkState = Text("Keine aktive Verbindung", 14);
    private readonly TextBlock linkDetail = Text("Wählt euren Kontakt und öffnet den Chatkanal auf beiden Geräten.", 12, true);
    private readonly TextBox onionAddress = new() { IsReadOnly = true };
    private readonly TextBox publicAddress = new() { MaxLength = 64 };
    private readonly TextBox localAddress = new() { Text = LocalAddress, MaxLength = 64 };
    private readonly TextBox manualAddress = new() { MaxLength = 64 };
    private readonly TextBox manualKey = new() { MaxLength = 64, FontFamily = new FontFamily("Consolas") };
    private readonly CheckBox verified = new() { Content = "Schlüssel persönlich abgeglichen", Margin = new Thickness(0, 8, 0, 4) };
    private readonly TextBox draft = new() { TextWrapping = TextWrapping.Wrap, MaxLength = 4096, MinHeight = 72 };
    private readonly StackPanel timeline = new();
    private readonly List<FrameworkElement> bubbles = [];
    private Action showChat = null!;
    private Action showContacts = null!;
    private FrameworkElement contactPage = null!;
    private Action showProfile = null!;
    private Action showSettings = null!;
    private Action refresh = () => { };
    private Action refreshContactRequests = () => { };
    private Action clearContact = () => { };
    private Action clearInvitation = () => { };
    private Func<Task> loadContacts = () => Task.CompletedTask;
    private FrameworkElement invitationSettings = null!;
    private Action showRequestOptions = () => { };
    private sealed record SavedContact(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("key")] string Key,
        [property: JsonPropertyName("address")] string? Address);
    private sealed record OutgoingInvitation(string Label, string Code, byte[] Ticket);

    internal MsgWindow() : base("MSG", "Ein Kontakt. Eine verschlüsselte Verbindung.",
        ProductEmblem("KryptoCore-MSG;component/Assets/messenger.png"), "KryptoCore-MSG;component/Assets/messenger.ico")
    {
        showChat = Tab("Nachrichten", ChatView());
        showContacts = Tab("Kontakte", contactPage, () => _ = loadContacts());
        showProfile = Tab("Mein Profil", ProfileView());
        showSettings = Tab("Einstellungen", SettingsView());
        Closed += (_, _) =>
        {
            ClearTicket(ref incomingTicket);
            clearInvitation();
            chatSession?.Cancel();
            contactRequestSession?.Cancel();
            identitySecret?.Dispose();
            managedTor.Dispose();
        };
        refresh();
    }

    private FrameworkElement ChatView()
    {
        var page = new StackPanel();
        var start = Section("KryptoCore Messenger", "Öffne deine Identität oder lege eine neue an. Danach kannst du einen Kontaktcode übernehmen.");
        ((TextBlock)start.Children[0]).FontSize = 26;
        start.Children.Add(Row(Button("Identität einrichten", () => showProfile(), true)));
        var welcome = Card(start);
        welcome.Background = new LinearGradientBrush(Color.FromRgb(24, 60, 63), Color.FromRgb(23, 35, 50), 0);
        welcome.Margin = new Thickness(0, 0, 0, 14);
        var onboarding = new StackPanel();
        onboarding.Children.Add(welcome);
        var steps = new System.Windows.Controls.Primitives.UniformGrid { Columns = 3, Rows = 1 };
        steps.Children.Add(Card(Section("01 · Profil", "Identität erstellen oder öffnen.")));
        steps.Children.Add(Card(Section("02 · Kontakt", "Eine Einladung erstellen oder eine erhaltene öffnen.")));
        steps.Children.Add(Card(Section("03 · Chat", "Öffnet den Chatkanal auf beiden Geräten.")));
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
                    draft.Clear();
                    ClearTimeline();
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
        var openSaved = Button("Auswählen", () =>
        {
            if (savedContacts.SelectedItem is not SavedContact item) return;
            chatSession?.Cancel();
            ClearTicket(ref incomingTicket);
            encryptedInvitation = false;
            verified.IsChecked = false;
            code.Clear();
            codePassword.Clear();
            manualKey.Clear();
            manualAddress.Clear();
            draft.Clear();
            ClearTimeline();
            peerKey = item.Key;
            peerAddress = item.Address;
            peerName = item.Name;
            contactOpened = true;
            verified.IsChecked = true;
            SetStatus($"Kontakt ausgewählt · {item.Name}");
            refresh();
            showChat();
        });
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
            if (verified.IsChecked != true || ActivePeer is not { } key) return;
            string? address = direct && manualKey.Text.Trim().Length > 0 ? SendAddress : peerAddress;
            var item = new SavedContact(contactName.Text, key, address);
            await UpdateContacts(new { kind = "save", contact = item });
        });
        savePanel.Children.Add(Row(saveContact));
        var saveHint = Text("Zum Speichern gib einen Namen ein und gleiche den Schlüssel mit der Person ab.", 12, true);
        savePanel.Children.Add(saveHint);
        var saveOptions = new Expander { Header = "Ausgewählten Kontakt speichern", Content = savePanel, Margin = new Thickness(0, 12, 0, 0) };
        contactBook.Children.Add(saveOptions);
        var requestOptions = TorContactRequests();
        loadContacts = async () =>
        {
            if (identityPath is not null && identityPath != loadedForIdentity) await UpdateContacts();
        };

        async Task UpdateContacts(object? update = null, string? removedKey = null)
        {
            await Run("Kontaktliste wird geöffnet …", token =>
                Engine.Call(new { action = "contacts", path = identityPath, update }, IdentityPassword(), cancellation: token),
                reply =>
                {
                    savedContacts.ItemsSource = JsonSerializer.Deserialize<SavedContact[]>(reply.Text ?? "[]");
                    loadedForIdentity = identityPath;
                    if (removedKey is not null && string.Equals(removedKey, ActivePeer, StringComparison.OrdinalIgnoreCase))
                    {
                        verified.IsChecked = false;
                    }
                    refresh();
                }, canCancel: true);
        }

        var chat = Section("Unterhaltung", "Im offenen Chatkanal könnt ihr beide schreiben und Dateien senden.");
        var selectedContact = Text("Kein Kontakt ausgewählt", 15);
        chat.Children.Add(selectedContact);
        var chooseContact = Button("Kontakt auswählen", () => showContacts());
        chat.Children.Add(Row(chooseContact));
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
        var empty = Text("Hier erscheinen gesendete und empfangene Nachrichten.", 13, true);
        empty.Margin = new Thickness(6, 10, 6, 10);
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
            await Run("Einladung wird angenommen …", async token =>
            {
                var endpoint = await EnsureTorAsync(token, showLink: true);
                return await Engine.Call(new { action = "join_invitation", path, peer, address,
                    own_address = endpoint.OnionAddress, socks_port = endpoint.SocksPort },
                    IdentityPassword(), ticket.ToArray(), token, ShowLinkProgress);
            }, _ =>
            {
                ClearTicket(ref incomingTicket);
                SetLink("Einladung angenommen", "Öffnet jetzt den Chatkanal auf beiden Geräten.", "Mint");
                showChat();
                refresh();
            }, canCancel: true);
        }, true);
        var joinRow = Row(joinInvitation);
        contact.Children.Add(joinRow);
        Func<object, Task>? channelInput = null;
        string? channelPeer = null;
        bool connected = false;
        bool localStatus = false;
        bool peerStatus = false;
        bool folderReady = false;
        bool writing = false;
        (string Content, string? Draft, CancellationTokenSource Timeout)? pending = null;

        var channelButton = Button("Chatkanal öffnen", async () =>
        {
            if (chatSession is { } active)
            {
                active.Cancel();
                return;
            }
            if (identityPath is not { } path || ActivePeer is not { } peer || SendAddress is not { } address
                || !ContactAccepted) return;
            string local = LocalAddress;
            TorRuntime.Endpoint? endpoint = null;
            await Run("Chatkanal wird vorbereitet …", async token =>
            {
                if (direct) local = Endpoint(localAddress);
                else endpoint = await EnsureTorAsync(token, showLink: true);
                return new Reply(true, "Chatkanal wird geöffnet.", null, null, null);
            }, reply => _ = OpenChannel(new
            {
                action = "chat", path, peer, address, local, tor = !direct, socks_port = endpoint?.SocksPort
            }, peer), canCancel: true);
        }, true);
        chat.Children.Add(Row(channelButton));

        var send = Button("Senden", async () => await SendAsync(null), true);
        draft.KeyDown += async (_, args) =>
        {
            if (args.Key != Key.Enter || !send.IsEnabled) return;
            args.Handled = true;
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
        chat.Children.Add(Row(send, sendFile, receiveFolder));
        var folderState = Text("Dateien bis 16 MiB. Zum Empfangen wähle einen Ordner.", 12, true);
        chat.Children.Add(folderState);

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
        chat.Children.Add(statusPanel);

        async Task OpenChannel(object request, string peer)
        {
            using var session = new CancellationTokenSource();
            chatSession = session;
            channelPeer = peer;
            SetLink("Chatkanal öffnet sich …", "Die andere Person öffnet den Chatkanal ebenfalls.");
            refresh();
            string detail = "Öffnet den Chatkanal erneut, wenn ihr weiterschreiben möchtet.";
            bool failed = false;
            try
            {
                var reply = await Engine.Chat(request, IdentityPassword(), session.Token, frame =>
                {
                    switch (frame.GetProperty("event").GetString())
                    {
                        case "chat_waiting":
                        case "connecting":
                            SetLink("Wartet auf die andere Person", "Öffnet den Chatkanal auf beiden Geräten.");
                            break;
                        case "chat_connected":
                            connected = true;
                            SetLink("Chatkanal offen", "Ende-zu-Ende verschlüsselt · Ihr könnt beide schreiben.", "Mint");
                            break;
                        case "chat_text":
                            AddBubble(frame.GetProperty("text").GetString()!, outgoing: false);
                            history.ScrollToEnd();
                            break;
                        case "chat_file":
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
                                else SetStatus("Datei nicht gespeichert. Die andere Person kann den Empfangsordner prüfen.", true);
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
                detail = "Die Verbindung wurde unterbrochen. Öffnet den Chatkanal erneut.";
            }
            finally
            {
                session.Cancel();
                if (pending is not null)
                    SetStatus("Die letzte Übertragung wurde nicht bestätigt. Kläre das vor einem erneuten Versuch.", true);
                channelInput = null;
                channelPeer = null;
                connected = localStatus = peerStatus = folderReady = false;
                pending = null;
                chatSession = null;
                if (string.Equals(ActivePeer, peer, StringComparison.OrdinalIgnoreCase))
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
        chat.Children.Add(Row(clear));

        var goToChat = Button("Zum Chat", () => showChat(), true);
        contact.Children.Add(Row(goToChat));
        var contactMethods = new StackPanel();
        var invitationCard = Card(contact);
        invitationCard.Margin = new Thickness(0, 0, 10, 12);
        contactMethods.Children.Add(invitationCard);
        contactMethods.Children.Add(Card(requestOptions));
        contactPage = Columns(Card(contactBook), contactMethods);
        var columns = Card(chat);
        page.Children.Add(columns);
        refresh = () =>
        {
            onboarding.Visibility = identityPath is null ? Visibility.Visible : Visibility.Collapsed;
            columns.Visibility = identityPath is null ? Visibility.Collapsed : Visibility.Visible;
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
            channelButton.Content = chatSession is null ? "Chatkanal öffnen"
                : connected ? "Chatkanal schließen" : "Öffnen abbrechen";
            channelButton.IsEnabled = chatSession is { IsCancellationRequested: false }
                || (chatSession is null && canMessage && routeAvailable);
            statusPanel.Visibility = ready ? Visibility.Visible : Visibility.Collapsed;
            statusToggle.IsEnabled = ready && !writing;
            statusToggle.Content = localStatus ? "Statusfreigabe beenden" : "Ja, Online-Status teilen";
            availability.Text = localStatus && peerStatus ? "● Kontakt online"
                : localStatus ? "Deine Zustimmung ist da. Die Anzeige wartet auf die andere Person."
                : "Wollt ihr den Online-Status teilen? Die Anzeige erscheint erst, wenn ihr beide zustimmt.";
            availability.Foreground = Brush(localStatus && peerStatus ? "Mint" : "Muted");
            folderState.Text = folderReady ? "Empfangsordner bereit · Dateien bis 16 MiB."
                : "Dateien bis 16 MiB. Zum Empfangen wähle einen Ordner.";
            receiveFolder.IsEnabled = ready && !writing;
            bool encrypted = RequiresCodePassword(code.Text.TrimStart());
            using var secret = codePassword.SecurePassword;
            import.IsEnabled = code.Text.Trim().Length > 0 && (!encrypted || secret.Length > 0);
            codePassword.IsEnabled = encrypted || code.Text.Trim().Length == 0;
            passwordPanel.Visibility = encrypted ? Visibility.Visible : Visibility.Collapsed;
            verified.IsEnabled = hasPeer && incomingTicket is null;
            joinRow.Visibility = incomingTicket is not null ? Visibility.Visible : Visibility.Collapsed;
            joinInvitation.IsEnabled = !direct && !requireTwoCodes && routeAvailable;
            saveContact.IsEnabled = compared && !string.IsNullOrWhiteSpace(contactName.Text);
            saveHint.Visibility = saveContact.IsEnabled ? Visibility.Collapsed : Visibility.Visible;
            saveOptions.Visibility = canMessage ? Visibility.Visible : Visibility.Collapsed;
            openSaved.IsEnabled = removeSaved.IsEnabled = savedContacts.SelectedItem is SavedContact;
            send.IsEnabled = ready && !writing && pending is null && !string.IsNullOrWhiteSpace(draft.Text);
            sendFile.IsEnabled = ready && !writing && pending is null;
            chooseContact.Content = canMessage ? "Kontakt wechseln" : "Kontakt auswählen";
            selectedContact.Text = !canMessage ? "Kein Kontakt ausgewählt"
                : (UsingImportedContact ? peerName : "Manuell gewählter Kontakt") ?? "Kontakt aus Einladung";
            clear.IsEnabled = bubbles.Count > 0;
            empty.Visibility = bubbles.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
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
        };
        clearContact = () =>
        {
            chatSession?.Cancel();
            peerName = null;
            ClearTicket(ref incomingTicket);
            encryptedInvitation = false;
            savedContacts.ItemsSource = null;
            loadedForIdentity = null;
            contactName.Clear();
            code.Clear();
            codePassword.Clear();
            draft.Clear();
            ClearTimeline();
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
        verified.Checked += (_, _) =>
        {
            if (chatSession is null) SetLink("Schlüssel abgeglichen", "Öffnet den Chatkanal auf beiden Geräten.");
            refresh();
        };
        verified.Unchecked += (_, _) => refresh();
        draft.TextChanged += (_, _) => refresh();
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
            await Run("Einladungseinstellung wird gespeichert …", token =>
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
            chatSession?.Cancel();
            contactRequestSession?.Cancel();
            identitySecret?.Dispose();
            identitySecret = null;
            managedTor.Dispose();
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
            await Run("Kontaktcode wird erstellt …", async token =>
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
            var batch = pendingInvitations.Items.Cast<OutgoingInvitation>().ToArray();
            bool started = false;
            bool finished = false;
            await Run("Einladung wird bereitgestellt …", async token =>
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
                SetLink($"{accepted.Label} angenommen", "Öffnet jetzt den Chatkanal auf beiden Geräten. Ihr könnt den Schlüssel persönlich abgleichen.", "Mint");
                showChat();
                refresh();
            }, canCancel: true);
            if (started && !finished)
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
            if (identityPath != path || publicKey != reply.Text)
            {
                contactRequestSession?.Cancel();
                peerKey = null;
                peerAddress = null;
                manualKey.Clear();
                manualAddress.Clear();
                verified.IsChecked = false;
                codePassword.Clear();
                clearContact();
            }
            identityPath = path;
            identitySecret?.Dispose();
            identitySecret = unlocked.Copy();
            identitySecret.MakeReadOnly();
            publicKey = reply.Text;
            requireTwoCodes = reply.TwoCodes == true;
            twoCodes.IsChecked = requireTwoCodes;
            profileName.Text = Path.GetFileName(path);
            clearInvitation();
            existing.Text = path;
            createOption.IsExpanded = openOption.IsExpanded = false;
            refresh();
            showChat();
        }

    }

    private FrameworkElement TorContactRequests()
    {
        var panel = Section("Kontakt per Tor-Adresse",
            "Sende eine Anfrage an eine .onion-Adresse. Dabei gibst du auch deine eigene Tor-Adresse weiter.");
        var addressInput = Field(panel, "Tor-Adresse des Kontakts", new TextBox { MaxLength = 72 });
        var send = Button("Anfrage senden", async () =>
        {
            if (identityPath is not { } path || direct || requireTwoCodes || chatSession is not null) return;
            string address = addressInput.Text.Trim().ToLowerInvariant();
            if (address.EndsWith(".onion", StringComparison.Ordinal)) address += $":{TorRuntime.OnionPort}";
            await Run("Kontaktanfrage wird vorbereitet …", async token =>
            {
                if (!IsOnionEndpoint(address))
                    throw new ArgumentException("Gib eine gültige .onion-Adresse ein.");
                var endpoint = await EnsureTorAsync(token);
                return await Engine.Call(new { action = "send_contact_request", path, address,
                    own_address = endpoint.OnionAddress, socks_port = endpoint.SocksPort }, IdentityPassword(),
                    cancellation: token, onProgress: status =>
                    {
                        if (status == "request_waiting") SetStatus("Wartet auf die Entscheidung der anderen Person …");
                    });
            }, SelectContact, canCancel: true);
        });
        panel.Children.Add(Row(send));
        var listeningState = Text("Eingehende Anfragen sind aus.", 13);
        panel.Children.Add(listeningState);
        var requestInfo = Text("", 13);
        requestInfo.TextWrapping = TextWrapping.Wrap;
        panel.Children.Add(requestInfo);
        Func<object, Task>? submit = null;
        long? pending = null;
        bool deciding = false;
        var allow = new Button { Content = "Anfragen erlauben" };
        var accept = new Button { Content = "Annehmen" };
        var reject = new Button { Content = "Ablehnen" };
        var decisions = Row(accept, reject);
        panel.Children.Add(decisions);
        panel.Children.Add(Row(allow));
        panel.Children.Add(Text("Du entscheidest bei jeder Anfrage. Sperren schaltet den Empfang wieder aus.", 12, true));
        var copyAddress = Button("Eigene Tor-Adresse kopieren", async () =>
        {
            await Run("Eigene Tor-Adresse wird geladen …", async token =>
            {
                var endpoint = await EnsureTorAsync(token);
                return new Reply(true, "Eigene Tor-Adresse geladen.", endpoint.OnionAddress, null, null);
            }, reply =>
            {
                if (reply.Text is { } endpoint) CopyText(endpoint.Split(':')[0], "Eigene Tor-Adresse kopiert.");
            }, canCancel: true);
        });
        panel.Children.Add(Row(copyAddress));
        var section = new Expander { Header = "Kontakt per Tor-Adresse", Content = panel, Margin = new Thickness(0, 12, 0, 0) };

        void Update()
        {
            section.Visibility = identityPath is not null && !direct && !requireTwoCodes ? Visibility.Visible : Visibility.Collapsed;
            send.IsEnabled = chatSession is null && !string.IsNullOrWhiteSpace(addressInput.Text);
            allow.Content = contactRequestSession is null ? "Anfragen erlauben" : "Anfragen ausschalten";
            allow.IsEnabled = contactRequestSession is not { IsCancellationRequested: true };
            bool open = pending.HasValue && contactRequestSession is { IsCancellationRequested: false };
            requestInfo.Visibility = decisions.Visibility = open ? Visibility.Visible : Visibility.Collapsed;
            accept.IsEnabled = open && !deciding && submit is not null && chatSession is null;
            reject.IsEnabled = open && !deciding && submit is not null;
            accept.ToolTip = chatSession is null ? null : "Schließe zuerst den aktiven Chatkanal.";
        }

        async Task Decide(bool accepted)
        {
            if (pending is not { } id || submit is not { } input || deciding) return;
            deciding = true;
            Update();
            try { await input(new { id, accept = accepted }); }
            catch (Exception error) when (error is IOException or InvalidOperationException or OperationCanceledException)
            {
                contactRequestSession?.Cancel();
            }
        }

        async Task Listen(string path)
        {
            using var session = new CancellationTokenSource();
            contactRequestSession = session;
            listeningState.Text = "Kontaktanfragen werden aktiviert …";
            Update();
            try
            {
                var reply = await Engine.Chat(new { action = "listen_contact_requests", path }, IdentityPassword(),
                    session.Token, frame =>
                    {
                        switch (frame.GetProperty("event").GetString())
                        {
                            case "request_listening":
                                listeningState.Text = "Eingehende Anfragen sind an.";
                                SetStatus("Kontaktanfragen sind aktiv.");
                                break;
                            case "incoming_request":
                                pending = frame.GetProperty("id").GetInt64();
                                requestInfo.Text = $"Neue Anfrage von {frame.GetProperty("address").GetString()}\nMöchtest du diesen Kontakt annehmen? Die Anfrage läuft nach 45 Sekunden ab.";
                                SetStatus("Neue Kontaktanfrage · Öffne Kontakte und dann „Kontakt per Tor-Adresse“.");
                                section.IsExpanded = true;
                                break;
                            case "request_cleared":
                                if (deciding) SetStatus("Kontaktanfrage beantwortet.");
                                else SetStatus("Kontaktanfrage abgelaufen.");
                                pending = null;
                                deciding = false;
                                break;
                        }
                        Update();
                    }, input => { submit = input; Update(); });
                if (reply.Ok && reply.Text is not null) SelectContact(reply);
                else if (!reply.Ok) SetStatus(reply.Message, true);
            }
            catch (OperationCanceledException) when (session.IsCancellationRequested) { }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException
                or InvalidOperationException or System.ComponentModel.Win32Exception or JsonException)
            {
                SetStatus("Kontaktanfragen wurden unterbrochen.", true);
            }
            finally
            {
                contactRequestSession = null;
                pending = null;
                submit = null;
                deciding = false;
                requestInfo.Text = "";
                listeningState.Text = "Eingehende Anfragen sind aus.";
                Update();
            }
        }

        void SelectContact(Reply reply)
        {
            clearContact();
            peerKey = reply.Text;
            peerAddress = reply.Address;
            peerName = "Kontakt per Tor-Adresse";
            contactOpened = true;
            encryptedInvitation = true;
            verified.IsChecked = false;
            SetLink("Kontaktanfrage angenommen", "Öffnet den Chatkanal auf beiden Geräten. Ihr könnt eure Schlüssel unter Kontakte abgleichen.", "Mint");
            SetStatus(reply.Message);
            showChat();
            refresh();
        }

        allow.Click += async (_, _) =>
        {
            if (contactRequestSession is { } active)
            {
                active.Cancel();
                Update();
                return;
            }
            if (identityPath is not { } path || direct || requireTwoCodes) return;
            await Run("Tor wird vorbereitet …", async token =>
            {
                await EnsureTorAsync(token);
                return new Reply(true, "Kontaktanfragen werden aktiviert.", null, null, null);
            }, reply => _ = Listen(path), canCancel: true);
        };
        accept.Click += async (_, _) => await Decide(true);
        reject.Click += async (_, _) => await Decide(false);
        addressInput.TextChanged += (_, _) => Update();
        refreshContactRequests = Update;
        showRequestOptions = () =>
        {
            showContacts();
            section.IsExpanded = true;
            section.BringIntoView();
        };
        Update();
        return section;
    }

    private FrameworkElement SettingsView()
    {
        var preferences = Section("Kontakte & Freigaben", "Lege fest, wie dich neue Kontakte erreichen dürfen.");
        preferences.Children.Add(invitationSettings);
        preferences.Children.Add(Row(Button("Kontaktanfragen verwalten", () => showRequestOptions())));
        preferences.Children.Add(Text("Anfragen per Tor-Adresse erlaubst du für die aktuelle Sitzung. Sperren beendet die Freigabe. Online-Status teilt ihr im Chat nur mit beidseitiger Zustimmung.", 12, true));
        var tor = Section("Tor · Automatisch", "MSG startet das integrierte Tor bei Bedarf. Deine Onion-Adresse bleibt bei einem Neustart erhalten.");
        tor.Children.Add(Row(Button("Tor starten und prüfen", async () =>
            await Run("Tor wird gestartet …", async token =>
            {
                await EnsureTorAsync(token);
                return new Reply(true, "Tor ist mit dem Netzwerk verbunden.", null, null, null);
            }, canCancel: true), true)));
        Field(tor, "Meine Onion-Adresse", onionAddress);
        tor.Children.Add(Row(Button("Neue Tor-Adresse erstellen …", async () =>
        {
            if (MessageBox.Show(this,
                    "Kontakte brauchen danach einen neuen Kontaktcode, um dich zu erreichen. Möchtest du deine Tor-Adresse wechseln?",
                    "Tor-Adresse wechseln", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
                return;
            await Run("Neue Tor-Adresse wird erstellt …", async token =>
            {
                chatSession?.Cancel();
                contactRequestSession?.Cancel();
                var endpoint = await managedTor.RotateAsync(token);
                onionAddress.Text = endpoint.OnionAddress;
                ResetLink();
                return new Reply(true, "Neue Tor-Adresse aktiv. Erstelle unter „Mein Profil“ einen neuen Kontaktcode.", null, null, null);
            }, canCancel: true);
        })));
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
            draft.Clear();
            ClearTimeline();
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

        void SetMode(bool enabled)
        {
            chatSession?.Cancel();
            contactRequestSession?.Cancel();
            direct = enabled;
            clearInvitation();
            if (direct) managedTor.Dispose();
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

    private async Task<TorRuntime.Endpoint> EnsureTorAsync(CancellationToken token, bool showLink = false)
    {
        var endpoint = await managedTor.StartAsync(percent =>
        {
            string status = $"Tor verbindet sich … {percent} %";
            SetStatus(status);
            if (showLink) SetLink("Tor startet", status);
        }, token);
        onionAddress.Text = endpoint.OnionAddress;
        return endpoint;
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
        SetLink("Kein offener Chatkanal", "Wählt euren Kontakt und öffnet den Chatkanal auf beiden Geräten.");

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
        var body = new StackPanel();
        var label = Text(outgoing ? "Du · zugestellt" : "Kontakt · empfangen", 11, true);
        label.Margin = new Thickness(0, 0, 0, 3);
        body.Children.Add(label);
        var text = new TextBox
        {
            Text = message, IsReadOnly = true, TextWrapping = TextWrapping.Wrap, MinHeight = 0,
            Padding = new Thickness(0), Background = Brushes.Transparent, BorderThickness = new Thickness(0)
        };
        body.Children.Add(text);
        var bubble = new Border
        {
            Child = body, CornerRadius = new CornerRadius(8), Padding = new Thickness(9),
            Background = Brush(outgoing ? "Line" : "Card"),
            Margin = outgoing ? new Thickness(24, 3, 0, 3) : new Thickness(0, 3, 24, 3)
        };
        if (bubbles.Count == 50)
        {
            timeline.Children.Remove(bubbles[0]);
            bubbles.RemoveAt(0);
        }
        bubbles.Add(bubble);
        timeline.Children.Add(bubble);
        refresh();
    }

    private void ClearTimeline()
    {
        foreach (var bubble in bubbles) timeline.Children.Remove(bubble);
        bubbles.Clear();
        refresh();
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
