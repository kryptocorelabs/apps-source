using System.Windows.Controls.Primitives;

namespace KryptoCore.Desktop;

internal static class TextPrivacy
{
    internal static void ClearUndo(this TextBoxBase text)
    {
        if (!text.IsUndoEnabled) return;
        // WPF clears undo/redo on disabling undo; re-enable normal editing afterwards.
        // https://learn.microsoft.com/dotnet/api/system.windows.controls.primitives.textboxbase.isundoenabled
        text.IsUndoEnabled = false;
        text.IsUndoEnabled = true;
    }
}
