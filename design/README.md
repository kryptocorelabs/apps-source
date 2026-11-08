# Application design

The Messenger interface is the visual reference for the desktop family:
quiet dark surfaces, mint accents, rounded cards and a small product mark.
Product names and status text remain visible; color alone does not communicate
whether a vault is unlocked, a peer is authenticated or a scan has completed.

| Token | Value | Use |
| --- | --- | --- |
| Base | `#101923` | Window background |
| Rail | `#14212B` | Navigation and caption |
| Card | `#1B2832` | Grouped content |
| Field | `#13212B` | Text and password inputs |
| Line | `#30454E` | Surface boundaries |
| Ink | `#E4EDF3` | Main text |
| Muted | `#99AEBB` | Supporting text |
| Mint | `#80E5CF` | Primary actions and focus |
| Problem | `#FFBAA6` | Errors, with an explanatory message |

## Shared Windows interface

`apps/desktop/windows/Shared/Theme.xaml` owns WPF controls and the palette.
`DesktopFrame.cs` owns the frameless caption and navigation. Messenger keeps
only chat-specific bubble brushes in its own theme; Container and Rescue use
the shared frame directly. Use 12 px control corners and approximately 20–22 px
card corners. Keep 16 px between content groups and distinguish the primary
action from secondary controls.

Action rows wrap and paired cards stack when the content area is narrow.
Navigation and content scroll independently. The common caption retains
minimize, maximize/restore and close controls, keyboard access, system resizing
and accessible labels. On supported Windows 11 systems, Mica affects only the
background. Solid surfaces are the fallback; text and password fields do not
become transparent. This is a visual treatment, not a security property.

## Vault and browser companion

Vault's Qt stylesheet follows the same palette, spacing and rounded surfaces.
Keep its compact start tiles rather than forcing a wide navigation rail into
a small window. Settings and recovery dialogs scroll on smaller screens.
Password reveal, recovery, locking and pairing behavior remain separate from
appearance changes.

The extension's browser-independent markup and `popup.css` use the same
surfaces and focus treatment. Pairing, locked, ready and save-offer states keep
their explicit text. In-page actions remain inside their existing isolated
shadow root. Do not loosen origin, frame or permission checks to match a style.

## Review before release

Render every navigation page at normal and minimum window sizes. Review empty,
disabled, error and expanded states, not just the welcome page. Check keyboard
focus and custom window controls. Run the existing application workflow and
browser-session tests after changing shared resources. Screenshots use only
synthetic data. A design build is not a signed release or an accessibility
certification.
