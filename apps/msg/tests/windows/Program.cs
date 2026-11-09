using System.IO;
using System.Reflection;
using System.Text;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

internal static class Program
{
    private const BindingFlags Fields = BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public;
    [STAThread]
    private static void Main(string[] args)
    {
        SessionChecks.Run();
        if (args is ["--session-only"]) return;
        var app = new Application();
        app.DispatcherUnhandledException += (_, e) => { Console.WriteLine(e.Exception); Environment.Exit(2); };
        SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(app.Dispatcher));
        var assembly = Assembly.LoadFrom(Path.GetFullPath(args[0]));
        app.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri("/KryptoCore-MSG;component/Theme.xaml", UriKind.Relative) });
        var type = assembly.GetType("KryptoCore.Desktop.MsgWindow", true)!;
        var runtime = assembly.GetType("KryptoCore.Desktop.TorRuntime", true)!;
        using var proxy = args.Contains("--loopback") ? new LoopbackProxy() : null;
        var fixtures = Directory.CreateDirectory(Path.Combine(AppContext.BaseDirectory, "fixtures", Guid.NewGuid().ToString("N")));
        Window alice = NewWindow("alice"), bob = NewWindow("bob");
        const string password = "only a synthetic preview identity password";
        try
        {
            Create(alice, "Alice");
            Create(bob, "Bob");
            Click(bob, "Meine Adresse");
            Wait(() => Field(bob, "contactRequestSession") is not null && Text(bob, "Bereit für Kontaktanfragen."), "Bob reachable", 150);
            AssertSecurity(alice, "Disconnected");
            AssertSecurity(bob, "Disconnected");
            string bobAddress = ((TextBox)Field(bob, "onionAddress")!).Text;
            Click(alice, "Neuer Kontakt");
            Wait(() => !Busy(alice), "contacts ready");
            Find<TextBox>(alice, "Tor-Adresse des Kontakts").Text = bobAddress;

            Request();
            var request = Prompt(bob, "Neue Kontaktanfrage");
            Render(request, "request");
            Click(request, "Ablehnen");
            Wait(() => !Busy(alice), "rejection");
            AssertNoPrompt(bob);

            Request();
            Click(Prompt(bob, "Neue Kontaktanfrage"), "Blockieren");
            Wait(() => Text(bob, "Kontakt blockiert. Weitere Anfragen dieses Kontakts werden abgelehnt.") && !Busy(alice), "block");
            Request();
            Wait(() => !Busy(alice), "blocked request rejected");
            AssertNoPrompt(bob);

            Click(bob, "Einstellungen");
            var blockPanel = Elements(bob).OfType<Expander>().Single(x => Equals(x.Header, "Blockierte Kontakte"));
            blockPanel.IsExpanded = true;
            Wait(() => !Busy(bob), "load blocks");
            var blocked = Elements(blockPanel).OfType<ListBox>().Single();
            if (blocked.Items.Count != 1) throw new Exception("Block was not persisted");
            blocked.SelectedIndex = 0;
            Click(bob, "Blockierung aufheben");
            Wait(() => !Busy(bob) && blocked.Items.Count == 0, "unblock");

            var wrongPin = ((Func<string, string?, Task>)Field(alice, "requestChat")!)(bobAddress, new string('1', 64));
            Click(Prompt(bob, "Neue Kontaktanfrage"), "Annehmen");
            Wait(() => wrongPin.IsCompleted, "stored key mismatch rejected");
            wrongPin.GetAwaiter().GetResult();
            AssertSecurity(alice, "Disconnected");
            if (Field(alice, "chatSession") is not null) throw new Exception("Mismatched peer opened a local channel");
            Wait(() => Field(bob, "chatSession") is not null, "receiver is awaiting cryptographic confirmation");
            AssertSecurity(bob, "Connecting");
            Click(bob, "Verbindung abbrechen");
            AssertSecurity(bob, "Disconnected");
            Wait(() => Field(bob, "chatSession") is null, "unconfirmed channel canceled");

            Request();
            Click(Prompt(bob, "Neue Kontaktanfrage"), "Annehmen");
            Wait(() => Text(alice, "Verbunden") && Text(bob, "Verbunden"), "automatic chat after one acceptance", 210);
            AssertSecurity(alice, "Encrypted");
            AssertSecurity(bob, "Encrypted");
            Console.WriteLine($"{(proxy is null ? "Live Tor" : "Loopback SOCKS")}: request popup, reject, persisted block, silent rejection, unblock and automatic chat passed.");
            Wait(() => !Busy(alice) && !Busy(bob), "initial contact loading finished");
            Click(alice, "Kontakt übernehmen");
            Find<TextBox>(alice, "Wie heißt der Kontakt?").Text = "Bob";
            Click(alice, "Speichern");
            Wait(() => Has(alice, "Kontakt gespeichert") && Text(alice, "Bob"), "save accepted contact");
            if (((CheckBox)Field(alice, "verified")!).IsChecked == true) throw new Exception("Saving falsely marked a comparison");
            Send(alice, bob, "Hallo Bob, der Chat ist direkt offen.");
            Send(bob, alice, "Ja, eine Annahme reicht.");
            var sessionBefore = Field(alice, "chatSession");
            Find<TextBox>(alice, "Nachricht schreiben").Text = "Entwurf nur für Bob";
            ClickChat(alice, "Bob");
            if (!ReferenceEquals(sessionBefore, Field(alice, "chatSession"))) throw new Exception("Active chat was unnecessarily reconnected");
            Find<TextBox>(alice, "Chats durchsuchen").Text = "Niemand";
            Wait(() => Text(alice, "Kein passender Kontakt."), "filter chats");
            Find<TextBox>(alice, "Chats durchsuchen").Clear();
            if (Find<TextBox>(alice, "Nachricht schreiben").Text != "Entwurf nur für Bob") throw new Exception("Filtering lost the draft");
            if (alice.WindowStyle != WindowStyle.None) throw new Exception("Messenger frame is not active");
            foreach (string caption in new[] { "Fenster minimieren", "Fenster maximieren", "Fenster schließen" })
                if (!Elements(alice).OfType<Button>().Any(button => AutomationProperties.GetName(button) == caption)) throw new Exception("Missing caption control: " + caption);
            if (!Equals(Elements(alice).OfType<Button>().Single(button => Equals(button.Content, "Nachrichten")).Tag, "selected"))
                throw new Exception("Selected navigation state is missing");
            Render(alice, "chat");
            double originalWidth = alice.Width, originalHeight = alice.Height;
            alice.Width = 960; alice.Height = 700;
            Wait(() => Math.Abs(alice.ActualWidth - 960) < 1 && Math.Abs(alice.ActualHeight - 700) < 1, "compact window size");
            alice.UpdateLayout();
            var composer = Find<TextBox>(alice, "Nachricht schreiben");
            var sendButton = Elements(alice).OfType<Button>().Single(button => Equals(button.Content, "Senden"));
            foreach (var control in new FrameworkElement[] { composer, sendButton })
            {
                Point topLeft = control.TransformToAncestor(alice).Transform(new Point());
                if (topLeft.Y < 40 || topLeft.Y + control.ActualHeight > alice.ActualHeight - 10
                    || topLeft.X + control.ActualWidth > alice.ActualWidth - 10)
                    throw new Exception("Composer is outside the compact viewport");
            }
            Render(alice, "chat-compact");
            alice.Width = originalWidth; alice.Height = originalHeight;
            Wait(() => Math.Abs(alice.ActualWidth - originalWidth) < 1, "restore desktop size");

            var source = new FileInfo(Path.Combine(fixtures.FullName, "Beispiel.txt"));
            File.WriteAllText(source.FullName, "Synthetic attachment in the new workflow.");
            var sendFile = SendAttachment(alice, source.FullName);
            var download = Prompt(bob, "Datei erhalten");
            Render(download, "download");
            Click(download, "Ablehnen");
            Wait(() => Local(bob, "downloadId") is null, "decline file");
            Wait(() => sendFile.IsCompleted, "declined attachment sender notified");
            sendFile.GetAwaiter().GetResult();
            sendFile = SendAttachment(alice, source.FullName);
            Prompt(bob, "Datei erhalten");
            long id = (long)Local(bob, "downloadId")!;
            string saved = Path.Combine(fixtures.FullName, "selected.txt");
            var save = Input(bob)(new { kind = "save_download", id, path = saved });
            Wait(() => save.IsCompleted && File.Exists(saved) && Local(bob, "downloadId") is null, "save attachment");
            save.GetAwaiter().GetResult();
            Wait(() => sendFile.IsCompleted, "saved attachment sender notified");
            sendFile.GetAwaiter().GetResult();
            if (File.ReadAllText(saved) != File.ReadAllText(source.FullName)) throw new Exception("Attachment changed");
            Send(bob, alice, "Datei gespeichert, wir können weiter schreiben.");
            Render(bob, "chat-file");
            Click(alice, "Chat beenden");
            AssertSecurity(alice, "Disconnected");
            Wait(() => Field(alice, "chatSession") is null && Field(bob, "chatSession") is null, "end both chat sessions");
            AssertSecurity(bob, "Disconnected");
            string bobKey = (string)Field(alice, "peerKey")!;
            string otherKey = new string('b', 64);
            Invoke(alice, "LeaveConversation");
            type.GetField("peerKey", Fields)!.SetValue(alice, otherKey);
            type.GetField("peerName", Fields)!.SetValue(alice, "Anderer Testkontakt");
            Invoke(alice, "RestoreConversation");
            if (Find<TextBox>(alice, "Nachricht schreiben").Text.Length != 0 || HasMessage(alice, "Hallo Bob, der Chat ist direkt offen."))
                throw new Exception("A different peer saw Bob's draft or conversation");
            Find<TextBox>(alice, "Nachricht schreiben").Text = "Entwurf für anderen Kontakt";
            Invoke(alice, "LeaveConversation");
            type.GetField("peerKey", Fields)!.SetValue(alice, bobKey);
            type.GetField("peerName", Fields)!.SetValue(alice, "Bob");
            Invoke(alice, "RestoreConversation");
            if (Find<TextBox>(alice, "Nachricht schreiben").Text != "Entwurf nur für Bob" || !HasMessage(alice, "Hallo Bob, der Chat ist direkt offen."))
                throw new Exception("Bob's draft or conversation was not restored");
            if (Find<TextBox>(alice, "Nachricht schreiben").CanUndo) throw new Exception("Another contact's text survived in the undo stack");
            string identityFile = (string)Field(alice, "identityPath")!;
            string hiddenIdentity = identityFile + ".test-hidden";
            File.Move(identityFile, hiddenIdentity);
            try
            {
                ((Action)Field(alice, "startConversation")!)();
                Wait(() => Field(alice, "chatSession") is null && Security(alice) == "Failed", "failed identity load never marks channel encrypted");
                AssertSecurity(alice, "Failed");
            }
            finally { File.Move(hiddenIdentity, identityFile); }
            ClickChat(alice, "Bob");
            Click(Prompt(bob, "Neue Kontaktanfrage"), "Annehmen");
            Wait(() => Text(alice, "Verbunden") && Text(bob, "Verbunden"), "reconnect saved chat from sidebar", 210);
            if (Find<TextBox>(alice, "Nachricht schreiben").Text != "Entwurf nur für Bob") throw new Exception("Reconnecting lost the draft");
            Render(alice, "chat-restored");
            Click(alice, "Mein Profil");
            Render(alice, "profile");
            Click(alice, "MSG sperren");
            AssertSecurity(alice, "Disconnected");
            Wait(() => Text(alice, "MSG ist gesperrt") && Text(bob, "Chatkanal geschlossen"), "lock closes channel");
            AssertSecurity(bob, "Disconnected");
            var store = Field(alice, "conversations")!;
            if (((TextBox)Field(alice, "draft")!).CanUndo) throw new Exception("Lock retained draft undo data");
            var contactPage = (DependencyObject)Field(alice, "contactPage")!;
            if (Find<ListBox>(contactPage, "Gespeicherte Kontakte").Items.Count != 0) throw new Exception("Lock retained the hidden contact list");
            if (store.GetType().GetMethod("Find", Fields)!.Invoke(store, [bobKey]) is not null
                || store.GetType().GetMethod("Find", Fields)!.Invoke(store, [otherKey]) is not null
                || HasMessage(alice, "Hallo Bob, der Chat ist direkt offen.")) throw new Exception("Lock retained chat data");
            Find<PasswordBox>(alice, "Passphrase deiner Identität").Password = password;
            Click(alice, "Identität öffnen");
            Wait(() => HasChat(alice, "Bob") && !Busy(alice), "reload saved contacts after unlock");
            if (store.GetType().GetMethod("Find", Fields)!.Invoke(store, [bobKey]) is not null
                || Find<TextBox>(alice, "Nachricht schreiben").Text.Length != 0) throw new Exception("Unlock restored discarded session contents");
            Click(alice, "Mein Profil");
            Elements(alice).OfType<Expander>().Single(x => Equals(x.Header, "Neue Identität anlegen")).IsExpanded = true;
            Find<TextBox>(alice, "Identitätsdatei speichern").Text = Path.Combine(fixtures.FullName, "different.kcmi");
            Find<PasswordBox>(alice, "Neue Passphrase").Password = password;
            Find<PasswordBox>(alice, "Passphrase wiederholen").Password = password;
            Click(alice, "Identität erstellen");
            Wait(() => !Busy(alice) && !HasChat(alice, "Bob"), "identity switch isolates contact list");
            Console.WriteLine("Windows preview passed: save contact without key-comparison claim, replies, visible download prompt, decline/save and continued chat.");
        }
        catch
        {
            foreach (var w in new[] { alice, bob })
                Console.WriteLine(string.Join(" | ", Elements(w).OfType<TextBlock>().Select(t => t.Text)));
            throw;
        }
        finally
        {
            foreach (var w in app.Windows.Cast<Window>().ToArray()) w.Close();
        }

        Window NewWindow(string name)
        {
            var tor = Activator.CreateInstance(runtime, Fields, null, [Path.Combine(fixtures.FullName, name)], null)!;
            var w = (Window)Activator.CreateInstance(type, Fields, null, [tor], null)!;
            if (proxy is not null)
            {
                var startup = (Task)runtime.GetMethod("StartAsync", Fields)!.Invoke(tor, [null, CancellationToken.None, false])!;
                Wait(() => startup.IsCompleted, "offline Tor address", 30);
                startup.GetAwaiter().GetResult();
                var endpoint = startup.GetType().GetProperty("Result")!.GetValue(startup)!;
                string address = (string)endpoint.GetType().GetProperty("OnionAddress")!.GetValue(endpoint)!;
                proxy.Hosts.Add(address.Split(':')[0]);
                runtime.GetField("ready", Fields)!.SetValue(tor, Activator.CreateInstance(endpoint.GetType(), Fields, null, [proxy.Port, address], null));
            }
            w.WindowStartupLocation = WindowStartupLocation.Manual;
            w.Left = -10000; w.Top = -10000;
            w.ShowInTaskbar = false;
            w.Show();
            return w;
        }
        void Create(Window w, string name)
        {
            Click(w, "Identität einrichten");
            Find<TextBox>(w, "Identitätsdatei speichern").Text = Path.Combine(fixtures.FullName, name + ".kcmi");
            Find<PasswordBox>(w, "Neue Passphrase").Password = password;
            Find<PasswordBox>(w, "Passphrase wiederholen").Password = password;
            Click(w, "Identität erstellen");
            Wait(() => Has(w, "Neuer Kontakt") && !Busy(w), name + " identity");
            AssertSecurity(w, "Disconnected");
        }
        void Request()
        {
            if (!Has(alice, "Verbindung anfragen")) Click(alice, "Kontakte");
            Wait(() => !Busy(alice), "request form ready");
            Click(alice, "Verbindung anfragen");
        }
        object? Field(Window w, string name) => type.GetField(name, Fields)!.GetValue(w);
        void AssertSecurity(Window w, string expected)
        {
            string actual = Security(w);
            if (actual != expected) throw new Exception($"Security indicator: expected {expected}, got {actual}");
        }
        string Security(Window w)
        {
            var indicator = Field(w, "encryptionIndicator")!;
            return indicator.GetType().GetProperty("Current", Fields)!.GetValue(indicator)!.ToString()!;
        }
        void Invoke(Window w, string name) => type.GetMethod(name, Fields)!.Invoke(w, null);
        bool Busy(Window w) => (bool)type.BaseType!.GetField("busy", Fields)!.GetValue(w)!;
        object Closure(Window w) => ((Action)Field(w, "startConversation")!).Target!;
        object? Local(Window w, string name)
        {
            var closure = Closure(w);
            return closure.GetType().GetField(name, Fields)!.GetValue(closure);
        }
        Func<object, Task> Input(Window w) => (Func<object, Task>)Local(w, "channelInput")!;
        Task SendAttachment(Window w, string path)
        {
            var closure = Closure(w);
            return (Task)closure.GetType().GetMethods(Fields).Single(m => m.Name.Contains("g__SendAsync|")).Invoke(closure, [path])!;
        }
    }

    private static Window Prompt(Window owner, string title)
    {
        Wait(() => Application.Current.Windows.Cast<Window>().Any(w => w.Owner == owner && w.Title == title), title, 150);
        return Application.Current.Windows.Cast<Window>().Single(w => w.Owner == owner && w.Title == title);
    }
    private static void AssertNoPrompt(Window owner)
    {
        if (Application.Current.Windows.Cast<Window>().Any(w => w.Owner == owner && w.Title == "Neue Kontaktanfrage"))
            throw new Exception("Unexpected request popup");
    }
    private static void Send(Window sender, Window recipient, string text)
    {
        Find<TextBox>(sender, "Nachricht schreiben").Text = text;
        Click(sender, "Senden");
        Wait(() => Elements(sender).OfType<TextBox>().Any(box => box.IsReadOnly && box.Text == text)
            && Elements(recipient).OfType<TextBox>().Any(box => box.IsReadOnly && box.Text == text), text);
    }
    private static bool HasMessage(Window window, string text) =>
        Elements(window).OfType<TextBox>().Any(box => box.IsReadOnly && box.Text == text);
    private static void ClickChat(Window window, string name) =>
        Elements(window).OfType<Button>().Single(button => AutomationProperties.GetName(button) == $"Chat mit {name}")
            .RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
    private static bool HasChat(Window window, string name) =>
        Elements(window).OfType<Button>().Any(button => AutomationProperties.GetName(button) == $"Chat mit {name}");
    private static T Find<T>(DependencyObject root, string title) where T : DependencyObject =>
        Elements(root).OfType<T>().Single(control => AutomationProperties.GetName(control) == title);
    private static bool Text(Window window, string text) =>
        Elements(window).OfType<TextBlock>().Any(control => control.Text == text);
    private static bool Has(Window window, string text) =>
        Elements(window).OfType<Button>().Any(control => Equals(control.Content, text));
    private static void Click(DependencyObject root, string title)
    {
        var button = Elements(root).OfType<Button>().Single(control => Equals(control.Content, title));
        if (!button.IsEnabled) throw new Exception(title + " disabled");
        button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
    }
    private static IEnumerable<DependencyObject> Elements(DependencyObject node)
    {
        yield return node;
        foreach (var child in LogicalTreeHelper.GetChildren(node).OfType<DependencyObject>())
            foreach (var descendant in Elements(child)) yield return descendant;
    }
    private static void Wait(Func<bool> ready, string stage, int seconds = 30)
    {
        Console.WriteLine("Checking: " + stage);
        var limit = DateTime.UtcNow.AddSeconds(seconds);
        var frame = new DispatcherFrame();
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(30) };
        timer.Tick += (_, _) => { if (ready() || DateTime.UtcNow >= limit) frame.Continue = false; };
        timer.Start();
        Dispatcher.PushFrame(frame);
        timer.Stop();
        if (!ready()) throw new TimeoutException(stage);
        Console.WriteLine("Passed: " + stage);
    }
    private static void Render(Window window, string name)
    {
        window.UpdateLayout();
        var root = (FrameworkElement)window.Content;
        root.UpdateLayout();
        int width = Math.Max(1, (int)Math.Ceiling(window.ActualWidth));
        int height = Math.Max(1, (int)Math.Ceiling(window.ActualHeight));
        var visual = new DrawingVisual();
        using (var drawing = visual.RenderOpen())
        {
            var bounds = new Rect(0, 0, width, height);
            drawing.DrawRectangle(window.Background, null, bounds);
            drawing.DrawRectangle(new VisualBrush(root)
            {
                ViewboxUnits = BrushMappingMode.Absolute, Viewbox = new Rect(window.RenderSize),
                Stretch = Stretch.None, AlignmentX = AlignmentX.Left, AlignmentY = AlignmentY.Top
            }, null, bounds);
        }
        var bitmap = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(window);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var file = File.Create(Path.Combine(AppContext.BaseDirectory, name + ".png"));
        encoder.Save(file);
    }
}

