#![forbid(unsafe_code)]

mod container;
pub use container::*;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    pub origin: String,
    pub username: String,
    pub password: String,
}

impl Drop for Login {
    fn drop(&mut self) {
        self.origin.zeroize();
        self.username.zeroize();
        self.password.zeroize();
    }
}
