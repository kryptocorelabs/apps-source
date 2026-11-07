using KryptoCore.Desktop;

internal static class SessionChecks
{
    internal static void Run()
    {
        var memory = new SessionConversations();
        memory.Open("ALICE").Draft = "private draft for Alice";
        memory.Add("alice", "only Alice receives this", true);
        memory.Add("bob", "only Bob receives this", false);
        Assert(memory.Find("ALICE")!.Messages.Single().Text == "only Alice receives this", "case-insensitive identity key");
        Assert(memory.Find("bob")!.Draft.Length == 0 && memory.Find("bob")!.Messages.Single().Text == "only Bob receives this", "conversation isolation");
        for (int i = 0; i <= SessionConversations.MessageLimit; i++) memory.Add("alice", "message-" + i, false);
        Assert(memory.Find("alice")!.Messages.Count == SessionConversations.MessageLimit
            && memory.Find("alice")!.Messages[0].Text == "message-1", "bounded message retention");
        memory.Clear();
        for (int i = 0; i < SessionConversations.ConversationLimit; i++) memory.Open("peer-" + i);
        memory.Open("peer-0");
        memory.Open("new peer");
        Assert(memory.Find("peer-0") is not null && memory.Find("peer-1") is null, "bounded least-recently-used conversations");
        memory.Forget("peer-0");
        Assert(memory.Find("peer-0") is null, "forget selected conversation");
        memory.Clear();
        Assert(memory.Find("new peer") is null, "lock clears session data");
        Console.WriteLine("Session model passed: isolation, key matching, message bounds, eviction, forgetting and clearing.");
    }

    private static void Assert(bool condition, string name)
    {
        if (!condition) throw new Exception(name);
    }
}
