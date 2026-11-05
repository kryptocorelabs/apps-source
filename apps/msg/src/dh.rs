use curve25519_dalek::montgomery::MontgomeryPoint;
use snow::{
    params::{CipherChoice, DHChoice, HashChoice},
    resolvers::{CryptoResolver, DefaultResolver},
    types::{Cipher, Dh, Hash, Random},
    Error,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub struct Resolver;

impl CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        DefaultResolver.resolve_rng()
    }
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        matches!(choice, DHChoice::Curve25519)
            .then(|| Box::<CheckedX25519>::default() as Box<dyn Dh>)
    }
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        DefaultResolver.resolve_hash(choice)
    }
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        DefaultResolver.resolve_cipher(choice)
    }
}

#[derive(Default)]
struct CheckedX25519 {
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*private).to_bytes()
}

impl Dh for CheckedX25519 {
    fn name(&self) -> &'static str {
        "25519"
    }
    fn pub_len(&self) -> usize {
        32
    }
    fn priv_len(&self) -> usize {
        32
    }
    fn set(&mut self, private: &[u8]) {
        self.private.copy_from_slice(private);
        self.public = public_key(&self.private);
    }
    fn generate(&mut self, rng: &mut dyn Random) -> Result<(), Error> {
        rng.try_fill_bytes(&mut self.private[..])?;
        self.public = public_key(&self.private);
        Ok(())
    }
    fn pubkey(&self) -> &[u8] {
        &self.public
    }
    fn privkey(&self) -> &[u8] {
        &self.private[..]
    }
    fn dh(&self, peer: &[u8], output: &mut [u8]) -> Result<(), Error> {
        let point = MontgomeryPoint(
            peer.get(..32)
                .ok_or(Error::Dh)?
                .try_into()
                .map_err(|_| Error::Dh)?,
        );
        let shared = Zeroizing::new(point.mul_clamped(*self.private).to_bytes());
        if bool::from(shared.ct_eq(&[0; 32])) {
            return Err(Error::Dh);
        }
        output
            .get_mut(..32)
            .ok_or(Error::Dh)?
            .copy_from_slice(&shared[..]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn rfc7748_alice_and_bob_agree_on_the_published_secret() {
        let mut alice = CheckedX25519::default();
        alice.set(&hex!(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        ));
        let mut bob = CheckedX25519::default();
        bob.set(&hex!(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        ));
        assert_eq!(
            alice.pubkey(),
            hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bob.pubkey(),
            hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let expected = hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        let mut shared = [0; 32];
        alice.dh(bob.pubkey(), &mut shared).unwrap();
        assert_eq!(shared, expected);
        bob.dh(alice.pubkey(), &mut shared).unwrap();
        assert_eq!(shared, expected);
    }
}
