namespace KryptoCore.Desktop;

// Deliberately session-only. No message or draft is written to disk.
internal sealed class SessionConversations
{
    internal const int ConversationLimit = 20;
    internal const int MessageLimit = 50;
    internal sealed record Message(string Text, bool Outgoing, DateTimeOffset Time);
    internal sealed class Conversation
    {
        internal List<Message> Messages { get; } = [];
        internal string Draft { get; set; } = "";
        internal long LastUse { get; set; }
    }

    private readonly Dictionary<string, Conversation> entries = new(StringComparer.OrdinalIgnoreCase);
    private long clock;

    internal Conversation? Find(string key) => entries.GetValueOrDefault(key);

    internal Conversation Open(string key)
    {
        if (!entries.TryGetValue(key, out var entry))
        {
            if (entries.Count == ConversationLimit)
                entries.Remove(entries.MinBy(pair => pair.Value.LastUse).Key);
            entry = new Conversation();
            entries.Add(key, entry);
        }
        entry.LastUse = ++clock;
        return entry;
    }

    internal Message Add(string key, string text, bool outgoing)
    {
        var entry = Open(key);
        var message = new Message(text, outgoing, DateTimeOffset.Now);
        if (entry.Messages.Count == MessageLimit) entry.Messages.RemoveAt(0);
        entry.Messages.Add(message);
        return message;
    }

    internal void Forget(string key) => entries.Remove(key);
    internal void Clear() => entries.Clear();
}
