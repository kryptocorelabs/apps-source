use super::*;
use std::{net::TcpListener, thread};

#[test]
fn contact_trust_and_blocks_are_separate_identity_bound_stores() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("alice.kcmi");
    let alice = Identity::generate().unwrap();
    let contacts = ContactBook::open(&path, &alice).unwrap();
    let blocks = ContactBook::blocked(&path, &alice).unwrap();
    let trust = ContactBook::verification(&path, &alice).unwrap();
    contacts.write(b"original contacts").unwrap();
    blocks.write(b"blocked identity").unwrap();
    trust.write(b"unverified identity").unwrap();
    assert_eq!(contacts.read().unwrap().as_slice(), b"original contacts");
    assert_eq!(blocks.read().unwrap().as_slice(), b"blocked identity");
    assert_eq!(trust.read().unwrap().as_slice(), b"unverified identity");
    drop(blocks);
    let stranger = Identity::generate().unwrap();
    let other = ContactBook::blocked(&path, &stranger).unwrap();
    assert!(other.read().is_err());
    drop(other);
    fs::copy(
        temp.path().join("alice.kcmi.blocked"),
        temp.path().join("alice.kcmi.verification"),
    )
    .unwrap();
    assert!(trust.read().is_err());
}

#[test]
fn received_file_can_use_a_chosen_name_without_overwriting_existing_data() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("chosen.bin");
    save_received_file_as(&path, b"first").unwrap();
    assert!(save_received_file_as(&path, b"replacement").is_err());
    assert_eq!(fs::read(path).unwrap(), b"first");
}

#[test]
fn onion_contact_request_requires_a_decision_and_returns_the_accepted_key() {
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let alice_key = alice.public();
    let bob_key = bob.public();
    let own: tor::OnionTarget = format!("{}.onion:49424", "a".repeat(56)).parse().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let incoming = thread::spawn(move || {
        for accepted in [false, true] {
            let (mut stream, _) = listener.accept().unwrap();
            let contact = contact_request::receive(&mut stream, &bob, |contact, _| {
                assert_eq!(contact.key, alice_key);
                accepted
            })
            .unwrap();
            assert_eq!(contact.is_some(), accepted);
        }
    });
    for expected in [None, Some(bob_key)] {
        let mut stream = TcpStream::connect(endpoint).unwrap();
        assert_eq!(
            contact_request::send(&mut stream, &alice, &own).unwrap(),
            expected
        );
    }
    incoming.join().unwrap();
}

#[test]
fn one_code_pairing_requires_ticket_and_learns_the_joining_identity() {
    let host = Identity::generate().unwrap();
    let guest = Identity::generate().unwrap();
    let host_key = host.public();
    let guest_key = guest.public();
    let ticket = [42; 32];
    let address: tor::OnionTarget = format!("{}.onion:49424", "a".repeat(56)).parse().unwrap();
    let host_contact =
        contact::Contact::new(host_key, Some(contact::Target::Onion(address.clone()))).unwrap();
    for password in [b"".as_slice(), b"long synthetic invitation password"] {
        let encoded = contact::encode_invitation(&host_contact, Some(&ticket), password).unwrap();
        let (decoded, secret) = contact::decode_invitation(&encoded, password).unwrap();
        assert_eq!(decoded, host_contact);
        assert_eq!(*secret.unwrap(), ticket);
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let incoming = thread::spawn(move || {
        let other_ticket = [44; 32];
        for attempt in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut contact = None;
            let result = pairing::accept_any(
                &mut stream,
                &host,
                [&other_ticket, &ticket],
                Instant::now() + SESSION_TIMEOUT,
                |index, value| {
                    contact = Some((index, value));
                },
            );
            if attempt == 0 {
                assert!(result.is_err());
                assert!(contact.is_none());
            } else {
                result.unwrap();
                let (index, contact) = contact.unwrap();
                assert_eq!(index, 1);
                assert_eq!(contact.key, guest_key);
            }
        }
    });
    let mut socket = TcpStream::connect(endpoint).unwrap();
    assert!(pairing::join(&mut socket, &guest, &host_key, &[43; 32], &address).is_err());
    let mut socket = TcpStream::connect(endpoint).unwrap();
    pairing::join(&mut socket, &guest, &host_key, &ticket, &address).unwrap();
    incoming.join().unwrap();
}

#[test]
fn persisted_identity_rejects_wrong_password_and_modified_public_key() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("alice.kcmi");
    let password = b"test-only-passphrase-83";
    let identity = Identity::generate().unwrap();
    identity.save(&path, password).unwrap();
    assert_eq!(
        identity.public(),
        Identity::load(&path, password).unwrap().public()
    );
    let original = fs::read(&path).unwrap();
    assert!(!original.windows(32).any(|window| window == &identity.0[..]));
    assert!(Identity::generate().unwrap().save(&path, password).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    assert!(Identity::load(&path, b"wrong").is_err());
    let mut modified = original;
    modified[25] ^= 1;
    fs::write(&path, modified).unwrap();
    assert!(Identity::load(&path, password).is_err());
}

#[test]
fn actual_loopback_delivery_and_encrypted_receipt() {
    let sender = Identity::generate().unwrap();
    let recipient = Identity::generate().unwrap();
    let sender_key = sender.public();
    let recipient_key = recipient.public();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let receiver = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        receive(&mut stream, &recipient, &sender_key, |text| {
            assert_eq!(text, "Grüße vom Test 🔒");
            Ok(())
        })
        .unwrap();
    });
    let mut stream = TcpStream::connect(address).unwrap();
    send(&mut stream, &sender, &recipient_key, "Grüße vom Test 🔒").unwrap();
    receiver.join().unwrap();
}

#[test]
fn wrong_pin_and_low_order_handshake_never_deliver_text() {
    for low_order in [false, true] {
        let sender = Identity::generate().unwrap();
        let recipient = Identity::generate().unwrap();
        let expected_sender = Identity::generate().unwrap().public();
        let recipient_key = recipient.public();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let receiver = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert!(matches!(
                receive(&mut stream, &recipient, &expected_sender, |_| panic!(
                    "untrusted message"
                )),
                Err(Error::Protocol)
            ));
        });
        let mut stream = TcpStream::connect(address).unwrap();
        if low_order {
            let mut connection = Connection::new(&mut stream);
            connection.write_frame(&[0; 48]).unwrap();
        } else {
            assert!(send(&mut stream, &sender, &recipient_key, "do not deliver").is_err());
        }
        receiver.join().unwrap();
    }
}

#[test]
fn rejects_replay_in_new_session_and_oversized_frame() {
    let sender = Identity::generate().unwrap();
    let recipient = Identity::generate().unwrap();
    let sender_key = sender.public();
    let recipient_key = recipient.public();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let receiver = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        receive(&mut stream, &recipient, &sender_key, |message| {
            assert_eq!(message, "once");
            Ok(())
        })
        .unwrap();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            assert!(matches!(
                receive(&mut stream, &recipient, &sender_key, |_| panic!(
                    "invalid message"
                )),
                Err(Error::Protocol)
            ));
        }
    });
    let mut socket = TcpStream::connect(address).unwrap();
    let mut conn = Connection::new(&mut socket);
    let mut session = conn.handshake(&sender, &recipient_key, true).unwrap();
    let mut captured = [0; 20];
    session.write_message(b"once", &mut captured).unwrap();
    conn.write_frame(&captured).unwrap();
    let mut ack = [0; 16 + RECEIPT.len()];
    conn.read_frame(&mut ack, 16 + RECEIPT.len()).unwrap();
    drop(socket);
    let mut socket = TcpStream::connect(address).unwrap();
    let mut conn = Connection::new(&mut socket);
    conn.handshake(&sender, &recipient_key, true).unwrap();
    conn.write_frame(&captured).unwrap();
    drop(socket);
    let mut socket = TcpStream::connect(address).unwrap();
    let mut conn = Connection::new(&mut socket);
    conn.handshake(&sender, &recipient_key, true).unwrap();
    conn.write_all(&u16::MAX.to_be_bytes()).unwrap();
    receiver.join().unwrap();
}

#[test]
fn terminal_controls_are_rejected() {
    for message in ["", "   ", "line\nbreak", "\x1b[31m", "abc\u{202e}def"] {
        assert!(validate_message(message).is_err());
    }
    assert!(validate_message(&"x".repeat(MAX_MESSAGE + 1)).is_err());
    assert!(validate_message("Valid UTF-8: Grüße 🌍").is_ok());
}

#[test]
fn file_delivery_requires_complete_authenticated_chunks_and_never_overwrites() {
    let sender = Identity::generate().unwrap();
    let recipient = Identity::generate().unwrap();
    let sender_key = sender.public();
    let recipient_key = recipient.public();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("Grüße.bin");
    let payload = (0..70_003).map(|n| (n % 251) as u8).collect::<Vec<_>>();
    fs::write(&source, &payload).unwrap();
    let folder = temp.path().to_owned();
    let receiver = thread::spawn(move || {
        for attempt in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            let result = receive_payload_until(
                &mut stream,
                &recipient,
                &sender_key,
                Instant::now() + SESSION_TIMEOUT,
                true,
                |incoming| match incoming {
                    Incoming::File { name, bytes } if attempt != 0 => {
                        assert_eq!(name, "Grüße.bin");
                        save_received_file(&folder, name, bytes)?;
                        Ok(())
                    }
                    _ => panic!("unexpected payload"),
                },
            );
            assert_eq!(result.is_ok(), attempt == 1);
            if attempt == 0 {
                assert!(!folder.join("MSG-Grüße.bin").exists());
            }
        }
    });
    let mut socket = TcpStream::connect(address).unwrap();
    let mut conn = Connection::new(&mut socket);
    let mut session = conn.handshake(&sender, &recipient_key, true).unwrap();
    let mut header = file::PREFIX.to_vec();
    header.extend_from_slice(&70_003u64.to_be_bytes());
    header.extend_from_slice("Grüße.bin".as_bytes());
    let mut sealed = [0; 80];
    let length = session.write_message(&header, &mut sealed).unwrap();
    conn.write_frame(&sealed[..length]).unwrap();
    conn.read_frame(&mut sealed, 17).unwrap();
    drop(socket);
    let mut socket = TcpStream::connect(address).unwrap();
    send_file(&mut socket, &sender, &recipient_key, &source, |_| {}).unwrap();
    fs::write(&source, b"different").unwrap();
    let mut socket = TcpStream::connect(address).unwrap();
    assert!(send_file(&mut socket, &sender, &recipient_key, &source, |_| {}).is_err());
    receiver.join().unwrap();
    assert_eq!(
        fs::read(temp.path().join("MSG-Grüße.bin")).unwrap(),
        payload
    );
    assert!(save_received_file(temp.path(), "../escape", b"x").is_err());
    assert!(save_received_file(temp.path(), "file.txt:stream", b"x").is_err());
}

#[test]
fn contact_book_is_bound_to_the_identity_and_rejects_tampering() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("alice.kcmi");
    let alice = Identity::generate().unwrap();
    let book = ContactBook::open(&path, &alice).unwrap();
    assert_eq!(book.read().unwrap().as_slice(), b"[]");
    let data = b"local contact name";
    book.write(data).unwrap();
    assert_eq!(book.read().unwrap().as_slice(), data);
    let sidecar = temp.path().join("alice.kcmi.contacts");
    let mut ciphertext = fs::read(&sidecar).unwrap();
    assert!(ciphertext.starts_with(b"KCMB\0\0\0\x02"));
    assert!(!ciphertext.windows(data.len()).any(|bytes| bytes == data));
    drop(book);
    let bob = Identity::generate().unwrap();
    let other = ContactBook::open(&path, &bob).unwrap();
    assert!(other.read().is_err());
    drop(other);
    fs::write(temp.path().join("alice.kcmi.blocked"), &ciphertext).unwrap();
    assert!(ContactBook::blocked(&path, &alice).unwrap().read().is_err());
    *ciphertext.last_mut().unwrap() ^= 1;
    fs::write(sidecar, ciphertext).unwrap();
    assert!(ContactBook::open(&path, &alice).unwrap().read().is_err());
}

#[test]
fn contact_book_migrates_authenticated_v1_stores_only() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("alice.kcmi");
    let sidecar = temp.path().join("alice.kcmi.contacts");
    let alice = Identity::generate().unwrap();
    let legacy_header = b"KCMB\0\0\0\x01";
    let legacy_key = kryptocore::derive_key(&alice.0[..], b"KCMB v1 contacts").unwrap();
    let data = b"legacy contact data";
    let (nonce, ciphertext) = kryptocore::encrypt(&legacy_key, data, legacy_header).unwrap();
    let mut legacy = [legacy_header.as_slice(), nonce.as_slice(), &ciphertext].concat();
    let last = legacy.len() - 1;
    legacy[last] ^= 1;
    fs::write(&sidecar, &legacy).unwrap();
    let book = ContactBook::open(&path, &alice).unwrap();
    assert!(book.read().is_err());
    assert_eq!(fs::read(&sidecar).unwrap(), legacy);
    legacy[last] ^= 1;
    fs::write(&sidecar, legacy).unwrap();
    assert_eq!(book.read().unwrap().as_slice(), data);
    assert!(fs::read(&sidecar).unwrap().starts_with(b"KCMB\0\0\0\x02"));
    drop(book);
    assert_eq!(
        ContactBook::open(&path, &alice)
            .unwrap()
            .read()
            .unwrap()
            .as_slice(),
        data
    );
}

#[test]
fn presence_rejects_a_different_peer() {
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let alice_key = alice.public();
    let bob_key = bob.public();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let receiver = thread::spawn(move || {
        for expected in [true, false] {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(
                presence::respond(&mut stream, &bob, &alice_key).is_ok(),
                expected
            );
        }
    });
    let mut socket = TcpStream::connect(address).unwrap();
    presence::check(&mut socket, &alice, &bob_key).unwrap();
    let mut socket = TcpStream::connect(address).unwrap();
    assert!(presence::check(&mut socket, &Identity::generate().unwrap(), &bob_key).is_err());
    receiver.join().unwrap();
}

#[test]
fn chat_rejects_an_unknown_key_and_carries_a_reply_on_the_same_socket() {
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let unknown = Identity::generate().unwrap();
    let alice_key = alice.public();
    let bob_key = bob.public();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (wrong, _) = listener.accept().unwrap();
        assert!(chat::Channel::open(wrong, &bob, &alice_key, false).is_err());
        let (socket, _) = listener.accept().unwrap();
        let channel = chat::Channel::open(socket, &bob, &alice_key, false).unwrap();
        let mut confirmed = false;
        let _ = channel.read(|event| {
            match event {
                chat::Event::Text("Hello") => {
                    channel.receipt(true)?;
                    channel.send_text("Reply")?;
                }
                chat::Event::Receipt(true) => {
                    confirmed = true;
                    channel.close();
                }
                _ => panic!("Unexpected chat frame"),
            }
            Ok(())
        });
        assert!(confirmed);
    });
    let wrong = TcpStream::connect(address).unwrap();
    assert!(chat::Channel::open(wrong, &unknown, &bob_key, true).is_err());
    let socket = TcpStream::connect(address).unwrap();
    let channel = chat::Channel::open(socket, &alice, &bob_key, true).unwrap();
    channel.send_text("Hello").unwrap();
    let mut received = false;
    let mut confirmed = false;
    let _ = channel.read(|event| {
        match event {
            chat::Event::Text("Reply") => {
                received = true;
                channel.receipt(true)?;
            }
            chat::Event::Receipt(true) => confirmed = true,
            _ => panic!("Unexpected chat frame"),
        }
        Ok(())
    });
    assert!(received && confirmed);
    server.join().unwrap();
}

#[test]
fn chat_does_not_open_without_a_valid_encrypted_confirmation() {
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let alice_key = alice.public();
    let bob_key = bob.public();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (socket, _) = listener.accept().unwrap();
            assert!(chat::Channel::open(socket, &bob, &alice_key, false).is_err());
        }
    });
    for corrupt_confirmation in [false, true] {
        let mut socket = TcpStream::connect(address).unwrap();
        let mut connection = Connection::new(&mut socket);
        let mut state = connection
            .handshake_for(&alice, &bob_key, true, b"KryptoCore MSG chat v1")
            .unwrap();
        if corrupt_confirmation {
            let mut sealed = [0; 17];
            let length = state.write_message(&[0], &mut sealed).unwrap();
            sealed[length - 1] ^= 1;
            connection.write_frame(&sealed[..length]).unwrap();
        }
        drop(connection);
        drop(socket);
    }
    server.join().unwrap();
}

#[test]
fn chat_never_delivers_tampered_ciphertext_to_its_callback() {
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let alice_key = alice.public();
    let bob_key = bob.public();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let channel = chat::Channel::open(socket, &bob, &alice_key, false).unwrap();
        let mut callbacks = 0;
        assert!(channel
            .read(|_| {
                callbacks += 1;
                Ok(())
            })
            .is_err());
        assert_eq!(callbacks, 0);
        channel.close();
    });
    let mut socket = TcpStream::connect(address).unwrap();
    let mut connection = Connection::new(&mut socket);
    let mut state = connection
        .handshake_for(&alice, &bob_key, true, b"KryptoCore MSG chat v1")
        .unwrap();
    let mut sealed = [0; 64];
    let length = state.write_message(&[0], &mut sealed).unwrap();
    connection.write_frame(&sealed[..length]).unwrap();
    connection.read_frame(&mut sealed[..17], 17).unwrap();
    let mut plain = [0];
    assert_eq!(state.read_message(&sealed[..17], &mut plain).unwrap(), 1);
    assert_eq!(plain, [0]);
    let length = state
        .write_message(b"\x01synthetic text", &mut sealed)
        .unwrap();
    sealed[length - 1] ^= 1;
    connection.write_frame(&sealed[..length]).unwrap();
    server.join().unwrap();
}
