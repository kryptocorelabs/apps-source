use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    VaultV1,
    VaultV2,
    VaultV3,
    ContainerV1,
    EmbeddedContainerV1,
    MsgIdentityV1,
    MsgStoreV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRoute {
    Password,
    RecoveryKey,
    IdentityAndPassword,
}

pub(crate) struct Descriptor {
    pub format: Format,
    pub label: &'static str,
    pub minimum: u64,
    pub maximum: u64,
    pub credentials: &'static [CredentialRoute],
}

pub(crate) fn identify(header: &[u8]) -> Option<Descriptor> {
    use CredentialRoute::*;
    use Format::*;
    let (format, label, minimum, maximum, credentials): (_, _, _, _, &'static [_]) =
        if header.starts_with(b"KCV1\0") {
            (VaultV1, "Vault / KCV1", 61, 4 * 1024 * 1024, &[Password])
        } else if header.starts_with(b"KCV2\0") {
            (
                VaultV2,
                "Vault / KCV2",
                221,
                4 * 1024 * 1024,
                &[Password, RecoveryKey],
            )
        } else if header.starts_with(b"KCV3\0") {
            (
                VaultV3,
                "Vault / KCV3",
                245,
                4 * 1024 * 1024,
                &[Password, RecoveryKey],
            )
        } else if header.starts_with(b"KCC\0\0\0\0\x01") {
            // 115-byte wrapping header plus the 21-byte authenticated end frame.
            (
                ContainerV1,
                "Container / KCC v1",
                136,
                2 * 1024_u64.pow(4),
                &[Password],
            )
        } else if header.starts_with(b"KCMI\0\0\0\x01") {
            (
                MsgIdentityV1,
                "MSG identity / KCMI v1",
                128,
                128,
                &[Password],
            )
        } else if header.starts_with(b"KCMB\0\0\0\x01") {
            (
                MsgStoreV1,
                "MSG sidecar / KCMB v1",
                48,
                64 * 1024 + 48,
                &[IdentityAndPassword],
            )
        } else {
            return None;
        };
    Some(Descriptor {
        format,
        label,
        minimum,
        maximum,
        credentials,
    })
}

pub(crate) fn has_known_family(header: &[u8]) -> bool {
    [b"KCV".as_slice(), b"KCC", b"KCMI", b"KCMB"]
        .iter()
        .any(|prefix| header.starts_with(prefix))
}
