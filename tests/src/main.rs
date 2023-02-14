use rand::prelude::{RngCore, SeedableRng, StdRng};
use solana_remote_wallet::{
    ledger::{LedgerSettings, LedgerWallet},
    ledger_error::LedgerError,
    locator::Manufacturer,
    remote_wallet::{initialize_wallet_manager, RemoteWallet, RemoteWalletError},
};
use solana_sdk::{
    address_lookup_table_account::AddressLookupTableAccount,
    derivation_path::DerivationPath,
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::{v0::Message as MessageV0, Message},
    pubkey::Pubkey,
    stake::{
        instruction as stake_instruction, program as solana_stake_program, state as stake_state,
    },
    system_instruction, system_program,
};
use solana_vote_program::{vote_instruction, vote_state};
use spl_associated_token_account::{
    get_associated_token_address, instruction::create_associated_token_account,
};
use std::{collections::HashSet, sync::Arc};

fn get_ledger() -> (Arc<LedgerWallet>, Pubkey) {
    let wallet_manager = initialize_wallet_manager().expect("Couldn't start wallet manager");

    // Update device list
    const NO_DEVICE_HELP: &str = "No Ledger found, make sure you have a unlocked Ledger connected with the Ledger Wallet Solana running";
    wallet_manager.update_devices().expect(NO_DEVICE_HELP);
    assert!(
        !wallet_manager.list_devices().is_empty(),
        "{}",
        NO_DEVICE_HELP
    );

    // Fetch the device path and base pubkey of a connected ledger device
    let (base_pubkey, device_path) = wallet_manager
        .list_devices()
        .iter()
        .find(|d| d.manufacturer == Manufacturer::Ledger)
        .cloned()
        .map(|d| (d.pubkey, d.host_device_path))
        .expect("No ledger device detected");

    let ledger = wallet_manager.get_ledger(&device_path).expect("get device");

    (ledger, base_pubkey)
}

fn test_ledger_pubkey() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let mut pubkey_set = HashSet::new();
    pubkey_set.insert(ledger_base_pubkey);

    let pubkey_0_0 = ledger.get_pubkey(&DerivationPath::new_bip44(Some(0), Some(0)), false)?;
    pubkey_set.insert(pubkey_0_0);
    let pubkey_0_1 = ledger.get_pubkey(&DerivationPath::new_bip44(Some(0), Some(1)), false)?;
    pubkey_set.insert(pubkey_0_1);
    let pubkey_1 = ledger.get_pubkey(&DerivationPath::new_bip44(Some(1), None), false)?;
    pubkey_set.insert(pubkey_1);
    let pubkey_1_0 = ledger.get_pubkey(&DerivationPath::new_bip44(Some(1), Some(0)), false)?;
    pubkey_set.insert(pubkey_1_0);

    assert_eq!(pubkey_set.len(), 5); // Ensure keys at various derivation paths are unique
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_ledger_sign_transaction() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let instruction = system_instruction::transfer(&from, &ledger_base_pubkey, 42);
    let message = Message::new(&[instruction], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));

    // Test large transaction
    let recipients: Vec<(Pubkey, u64)> = (0..10).map(|_| (Pubkey::new_unique(), 42)).collect();
    let instructions = system_instruction::transfer_many(&from, &recipients);
    let message = Message::new(&instructions, Some(&ledger_base_pubkey)).serialize();
    let hash = solana_sdk::hash::hash(&message);
    println!("Expected hash: {}", hash);
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_ledger_sign_versioned_transaction() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let instruction = system_instruction::transfer(&from, &ledger_base_pubkey, 42);
    let message = MessageV0::try_compile(&ledger_base_pubkey, &[instruction], &[], Hash::default())
        .unwrap()
        .serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));

    // Test large transaction
    let recipients: Vec<(Pubkey, u64)> = (0..10).map(|_| (Pubkey::new_unique(), 42)).collect();
    let instructions = system_instruction::transfer_many(&from, &recipients);
    let message = MessageV0::try_compile(&ledger_base_pubkey, &instructions, &[], Hash::default())
        .unwrap()
        .serialize();
    let hash = solana_sdk::hash::hash(&message);
    println!("Expected hash: {}", hash);
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_ledger_sign_versioned_transaction_with_table() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let instruction = system_instruction::transfer(&from, &ledger_base_pubkey, 42);
    let lookup_table = AddressLookupTableAccount {
        key: solana_sdk::pubkey::Pubkey::new_unique(),
        addresses: vec![from, ledger_base_pubkey],
    };
    let message = MessageV0::try_compile(
        &from,
        &[instruction],
        &[lookup_table.clone()],
        Hash::default(),
    )
    .unwrap()
    .serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));

    // Test large transaction
    let recipients: Vec<(Pubkey, u64)> = (0..10).map(|_| (Pubkey::new_unique(), 42)).collect();
    let instructions = system_instruction::transfer_many(&from, &recipients);
    let message = MessageV0::try_compile(&from, &instructions, &[lookup_table], Hash::default())
        .unwrap()
        .serialize();
    let hash = solana_sdk::hash::hash(&message);
    println!("Expected hash: {}", hash);
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

fn test_ledger_sign_transaction_too_big() -> Result<(), RemoteWalletError> {
    // Test too big of a transaction
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let recipients: Vec<(Pubkey, u64)> = (0..100).map(|_| (Pubkey::new_unique(), 42)).collect();
    let instructions = system_instruction::transfer_many(&from, &recipients);
    let message = Message::new(&instructions, Some(&ledger_base_pubkey)).serialize();
    ledger.sign_message(&derivation_path, &message).unwrap_err();
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_ledger_sign_offchain_message_ascii() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;

    let message = solana_sdk::offchain_message::OffchainMessage::new(0, b"Test message")
        .map_err(|_| RemoteWalletError::InvalidInput("Bad message".to_string()))?
        .serialize()
        .map_err(|_| RemoteWalletError::InvalidInput("Failed to serialize message".to_string()))?;
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));

    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_ledger_sign_offchain_message_utf8() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;

    let message =
        solana_sdk::offchain_message::OffchainMessage::new(0, "Тестовое сообщение".as_bytes())
            .map_err(|_| RemoteWalletError::InvalidInput("Bad message".to_string()))?
            .serialize()
            .map_err(|_| {
                RemoteWalletError::InvalidInput("Failed to serialize message".to_string())
            })?;
    let hash = solana_sdk::hash::hash(&message);
    println!("Expected hash: {}", hash);
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));

    Ok(())
}

/// This test requires interactive approval of message signing on the ledger.
fn test_ledger_delegate_stake() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let authorized_pubkey = ledger.get_pubkey(&derivation_path, false)?;
    let stake_pubkey = ledger_base_pubkey;
    let vote_pubkey = Pubkey::default();
    let instruction =
        stake_instruction::delegate_stake(&stake_pubkey, &authorized_pubkey, &vote_pubkey);
    let message = Message::new(&[instruction], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(authorized_pubkey.as_ref(), &message));
    Ok(())
}

/// This test requires interactive approval of message signing on the ledger.
fn test_ledger_delegate_stake_with_nonce() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let authorized_pubkey = ledger.get_pubkey(&derivation_path, false)?;
    let stake_pubkey = ledger_base_pubkey;
    let vote_pubkey = Pubkey::new(&[1u8; 32]);
    let instruction =
        stake_instruction::delegate_stake(&stake_pubkey, &authorized_pubkey, &vote_pubkey);
    let nonce_account = Pubkey::new(&[2u8; 32]);
    let message =
        Message::new_with_nonce(vec![instruction], None, &nonce_account, &authorized_pubkey)
            .serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(authorized_pubkey.as_ref(), &message));
    Ok(())
}

fn test_create_stake_account_and_delegate() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let stake_account = ledger_base_pubkey;
    let authorized = stake_state::Authorized {
        staker: Pubkey::new(&[3u8; 32]),
        withdrawer: Pubkey::new(&[4u8; 32]),
    };
    let mut instructions = stake_instruction::create_account(
        &from,
        &stake_account,
        &authorized,
        &stake_state::Lockup {
            epoch: 1,
            unix_timestamp: 1,
            ..stake_state::Lockup::default()
        },
        42,
    );
    let vote_pubkey = Pubkey::new(&[5u8; 32]);
    let instruction =
        stake_instruction::delegate_stake(&stake_account, &authorized.staker, &vote_pubkey);
    instructions.push(instruction);
    let message = Message::new(&instructions, Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

fn test_create_stake_account_with_seed_and_delegate() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let base = from;
    let seed = "seedseedseedseedseedseedseedseed";
    let stake_account = Pubkey::create_with_seed(&base, seed, &solana_stake_program::id()).unwrap();
    let authorized = stake_state::Authorized {
        staker: Pubkey::new(&[3u8; 32]),
        withdrawer: Pubkey::new(&[4u8; 32]),
    };
    let mut instructions = stake_instruction::create_account_with_seed(
        &from,
        &stake_account,
        &base,
        seed,
        &authorized,
        &stake_state::Lockup {
            epoch: 1,
            unix_timestamp: 1,
            ..stake_state::Lockup::default()
        },
        42,
    );
    let vote_pubkey = Pubkey::new(&[5u8; 32]);
    let instruction =
        stake_instruction::delegate_stake(&stake_account, &authorized.staker, &vote_pubkey);
    instructions.push(instruction);
    let message = Message::new(&instructions, Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

/// This test requires interactive approval of message signing on the ledger.
fn test_ledger_advance_nonce_account() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let authorized_pubkey = ledger.get_pubkey(&derivation_path, false)?;
    let nonce_account = Pubkey::new(&[1u8; 32]);
    let instruction = system_instruction::advance_nonce_account(&nonce_account, &authorized_pubkey);
    let message = Message::new(&[instruction], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(authorized_pubkey.as_ref(), &message));
    Ok(())
}

/// This test requires interactive approval of message signing on the ledger.
fn test_ledger_advance_nonce_account_separate_fee_payer() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let authorized_pubkey = ledger.get_pubkey(&derivation_path, false)?;
    let nonce_account = Pubkey::new(&[1u8; 32]);
    let fee_payer = Pubkey::new(&[2u8; 32]);
    let instruction = system_instruction::advance_nonce_account(&nonce_account, &authorized_pubkey);
    let message = Message::new(&[instruction], Some(&fee_payer)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(authorized_pubkey.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_ledger_transfer_with_nonce() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let nonce_account = Pubkey::new(&[1u8; 32]);
    let nonce_authority = Pubkey::new(&[2u8; 32]);
    let instruction = system_instruction::transfer(&from, &ledger_base_pubkey, 42);
    let message =
        Message::new_with_nonce(vec![instruction], None, &nonce_account, &nonce_authority)
            .serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_create_stake_account_with_seed_and_nonce() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let nonce_account = Pubkey::new(&[1u8; 32]);
    let nonce_authority = Pubkey::new(&[2u8; 32]);
    let base = from;
    let seed = "seedseedseedseedseedseedseedseed";
    let stake_account = Pubkey::create_with_seed(&base, seed, &solana_stake_program::id()).unwrap();
    let authorized = stake_state::Authorized {
        staker: Pubkey::new(&[3u8; 32]),
        withdrawer: Pubkey::new(&[4u8; 32]),
    };
    let instructions = stake_instruction::create_account_with_seed(
        &from,
        &stake_account,
        &base,
        seed,
        &authorized,
        &stake_state::Lockup::default(),
        42,
    );
    let message =
        Message::new_with_nonce(instructions, None, &nonce_account, &nonce_authority).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_create_stake_account() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let stake_account = ledger_base_pubkey;
    let authorized = stake_state::Authorized {
        staker: Pubkey::new(&[3u8; 32]),
        withdrawer: Pubkey::new(&[4u8; 32]),
    };
    let instructions = stake_instruction::create_account(
        &from,
        &stake_account,
        &authorized,
        &stake_state::Lockup {
            epoch: 1,
            unix_timestamp: 1,
            ..stake_state::Lockup::default()
        },
        42,
    );
    let message = Message::new(&instructions, Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

fn test_create_stake_account_no_lockup() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let stake_account = ledger_base_pubkey;
    let authorized = stake_state::Authorized {
        staker: Pubkey::new(&[3u8; 32]),
        withdrawer: Pubkey::new(&[4u8; 32]),
    };
    let instructions = stake_instruction::create_account(
        &from,
        &stake_account,
        &authorized,
        &stake_state::Lockup::default(),
        42,
    );
    let message = Message::new(&instructions, Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_create_stake_account_checked() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let stake_account = ledger_base_pubkey;
    let authorized = stake_state::Authorized {
        staker: Pubkey::new(&[3u8; 32]),
        withdrawer: Pubkey::new(&[4u8; 32]),
    };
    let instructions =
        stake_instruction::create_account_checked(&from, &stake_account, &authorized, 42);
    let message = Message::new(&instructions, Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_create_stake_account_checked_with_seed_and_nonce() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let nonce_account = Pubkey::new(&[1u8; 32]);
    let nonce_authority = Pubkey::new(&[2u8; 32]);
    let base = from;
    let seed = "seedseedseedseedseedseedseedseed";
    let stake_account = Pubkey::create_with_seed(&base, seed, &solana_stake_program::id()).unwrap();
    let authorized = stake_state::Authorized {
        staker: Pubkey::new(&[3u8; 32]),
        withdrawer: Pubkey::new(&[4u8; 32]),
    };
    let instructions = stake_instruction::create_account_with_seed_checked(
        &from,
        &stake_account,
        &base,
        seed,
        &authorized,
        42,
    );
    let message =
        Message::new_with_nonce(instructions, None, &nonce_account, &nonce_authority).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_create_nonce_account_with_seed() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let base = from;
    let seed = "seedseedseedseedseedseedseedseed";
    let nonce_account = Pubkey::create_with_seed(&base, seed, &system_program::id()).unwrap();
    let instructions = system_instruction::create_nonce_account_with_seed(
        &from,
        &nonce_account,
        &base,
        seed,
        &Pubkey::new(&[1u8; 32]),
        42,
    );
    let message = Message::new(&instructions, Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_create_nonce_account() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let nonce_account = ledger_base_pubkey;
    let instructions = system_instruction::create_nonce_account(
        &from,
        &nonce_account,
        &Pubkey::new(&[1u8; 32]),
        42,
    );
    let message = Message::new(&instructions, Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_sign_full_shred_of_garbage_tx() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;

    let program_id = Pubkey::new(&[1u8; 32]);
    let mut data = [0u8; 1232 - 106].to_vec();
    let mut rng = StdRng::seed_from_u64(0);
    rng.fill_bytes(&mut data);
    let instruction = Instruction {
        program_id,
        accounts: Vec::from([AccountMeta::new_readonly(from, true)]),
        data,
    };
    let message = Message::new(&[instruction], Some(&ledger_base_pubkey)).serialize();
    let hash = solana_sdk::hash::hash(&message);
    println!("Expected hash: {}", hash);
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_create_vote_account() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let vote_account = ledger_base_pubkey;
    let vote_init = vote_state::VoteInit {
        node_pubkey: Pubkey::new(&[1u8; 32]),
        authorized_voter: Pubkey::new(&[2u8; 32]),
        authorized_withdrawer: Pubkey::new(&[3u8; 32]),
        commission: 50u8,
    };
    let instructions = vote_instruction::create_account(&from, &vote_account, &vote_init, 42);
    let message = Message::new(&instructions, Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_create_vote_account_with_seed() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let base = from;
    let seed = "seedseedseedseedseedseedseedseed";
    let vote_account = Pubkey::create_with_seed(&base, seed, &solana_vote_program::id()).unwrap();
    let vote_init = vote_state::VoteInit {
        node_pubkey: Pubkey::new(&[1u8; 32]),
        authorized_voter: Pubkey::new(&[2u8; 32]),
        authorized_withdrawer: Pubkey::new(&[3u8; 32]),
        commission: 50u8,
    };
    let instructions = vote_instruction::create_account_with_seed(
        &from,
        &vote_account,
        &base,
        seed,
        &vote_init,
        42,
    );
    let message = Message::new(&instructions, Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_nonce_withdraw() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let nonce_account = ledger_base_pubkey;
    let nonce_authority = ledger.get_pubkey(&derivation_path, false)?;
    let to = Pubkey::new(&[1u8; 32]);
    let instruction =
        system_instruction::withdraw_nonce_account(&nonce_account, &nonce_authority, &to, 42);
    let message = Message::new(&[instruction], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(nonce_authority.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_stake_withdraw() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let stake_account = ledger_base_pubkey;
    let stake_authority = ledger.get_pubkey(&derivation_path, false)?;
    let to = Pubkey::new(&[1u8; 32]);
    let instruction = stake_instruction::withdraw(&stake_account, &stake_authority, &to, 42, None);
    let message = Message::new(&[instruction], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(stake_authority.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_vote_withdraw() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let vote_account = ledger_base_pubkey;
    let vote_authority = ledger.get_pubkey(&derivation_path, false)?;
    let to = Pubkey::new(&[1u8; 32]);
    let instruction = vote_instruction::withdraw(&vote_account, &vote_authority, 42, &to);
    let message = Message::new(&[instruction], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(vote_authority.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_nonce_authorize() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let nonce_account = ledger_base_pubkey;
    let nonce_authority = ledger.get_pubkey(&derivation_path, false)?;
    let new_authority = Pubkey::new(&[1u8; 32]);
    let instruction = system_instruction::authorize_nonce_account(
        &nonce_account,
        &nonce_authority,
        &new_authority,
    );
    let message = Message::new(&[instruction], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(nonce_authority.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_stake_authorize() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let stake_account = ledger_base_pubkey;
    let stake_authority = ledger.get_pubkey(&derivation_path, false)?;
    let new_authority = Pubkey::new(&[1u8; 32]);
    let stake_auth = stake_instruction::authorize(
        &stake_account,
        &stake_authority,
        &new_authority,
        stake_state::StakeAuthorize::Staker,
        None,
    );

    // Authorize staker
    let message = Message::new(&[stake_auth.clone()], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(stake_authority.as_ref(), &message));

    let custodian = Pubkey::new_unique();
    for maybe_custodian in &[None, Some(&custodian)] {
        let new_authority = Pubkey::new(&[2u8; 32]);
        let withdraw_auth = stake_instruction::authorize(
            &stake_account,
            &stake_authority,
            &new_authority,
            stake_state::StakeAuthorize::Withdrawer,
            *maybe_custodian,
        );

        // Authorize withdrawer
        let message = Message::new(&[withdraw_auth.clone()], Some(&ledger_base_pubkey)).serialize();
        let signature = ledger.sign_message(&derivation_path, &message)?;
        assert!(signature.verify(stake_authority.as_ref(), &message));

        // Authorize both
        // Note: Instruction order must match CLI; staker first, withdrawer second
        let message = Message::new(
            &[stake_auth.clone(), withdraw_auth],
            Some(&ledger_base_pubkey),
        )
        .serialize();
        let signature = ledger.sign_message(&derivation_path, &message)?;
        assert!(signature.verify(stake_authority.as_ref(), &message));
    }
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_stake_authorize_checked() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let stake_account = ledger_base_pubkey;
    let stake_authority = ledger.get_pubkey(&derivation_path, false)?;
    let new_authority = Pubkey::new(&[1u8; 32]);
    let stake_auth = stake_instruction::authorize_checked(
        &stake_account,
        &stake_authority,
        &new_authority,
        stake_state::StakeAuthorize::Staker,
        None,
    );

    // Authorize staker
    let message = Message::new(&[stake_auth.clone()], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(stake_authority.as_ref(), &message));

    let custodian = Pubkey::new_unique();
    for maybe_custodian in &[None, Some(&custodian)] {
        let new_authority = Pubkey::new(&[2u8; 32]);
        let withdraw_auth = stake_instruction::authorize_checked(
            &stake_account,
            &stake_authority,
            &new_authority,
            stake_state::StakeAuthorize::Withdrawer,
            *maybe_custodian,
        );

        // Authorize withdrawer
        let message = Message::new(&[withdraw_auth.clone()], Some(&ledger_base_pubkey)).serialize();
        let signature = ledger.sign_message(&derivation_path, &message)?;
        assert!(signature.verify(stake_authority.as_ref(), &message));

        // Authorize both
        // Note: Instruction order must match CLI; staker first, withdrawer second
        let message = Message::new(
            &[stake_auth.clone(), withdraw_auth],
            Some(&ledger_base_pubkey),
        )
        .serialize();
        let signature = ledger.sign_message(&derivation_path, &message)?;
        assert!(signature.verify(stake_authority.as_ref(), &message));
    }
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_vote_authorize() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let vote_account = ledger_base_pubkey;
    let vote_authority = ledger.get_pubkey(&derivation_path, false)?;
    let new_authority = Pubkey::new(&[1u8; 32]);
    let vote_auth = vote_instruction::authorize(
        &vote_account,
        &vote_authority,
        &new_authority,
        vote_state::VoteAuthorize::Voter,
    );

    // Authorize voter
    let message = Message::new(&[vote_auth.clone()], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(vote_authority.as_ref(), &message));

    let new_authority = Pubkey::new(&[2u8; 32]);
    let withdraw_auth = vote_instruction::authorize(
        &vote_account,
        &vote_authority,
        &new_authority,
        vote_state::VoteAuthorize::Withdrawer,
    );

    // Authorize withdrawer
    let message = Message::new(&[withdraw_auth.clone()], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(vote_authority.as_ref(), &message));

    // Authorize both
    // Note: Instruction order must match CLI; voter first, withdrawer second
    let message = Message::new(&[vote_auth, withdraw_auth], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(vote_authority.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_vote_authorize_checked() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let vote_account = ledger_base_pubkey;
    let vote_authority = ledger.get_pubkey(&derivation_path, false)?;
    let new_authority = Pubkey::new(&[1u8; 32]);
    let vote_auth = vote_instruction::authorize_checked(
        &vote_account,
        &vote_authority,
        &new_authority,
        vote_state::VoteAuthorize::Voter,
    );

    // Authorize voter
    let message = Message::new(&[vote_auth.clone()], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(vote_authority.as_ref(), &message));

    let new_authority = Pubkey::new(&[2u8; 32]);
    let withdraw_auth = vote_instruction::authorize_checked(
        &vote_account,
        &vote_authority,
        &new_authority,
        vote_state::VoteAuthorize::Withdrawer,
    );

    // Authorize withdrawer
    let message = Message::new(&[withdraw_auth.clone()], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(vote_authority.as_ref(), &message));

    // Authorize both
    // Note: Instruction order must match CLI; voter first, withdrawer second
    let message = Message::new(&[vote_auth, withdraw_auth], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(vote_authority.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_vote_update_validator_identity() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let vote_account = ledger_base_pubkey;
    let vote_authority = ledger.get_pubkey(&derivation_path, false)?;
    let new_node = Pubkey::new(&[1u8; 32]);
    let instruction =
        vote_instruction::update_validator_identity(&vote_account, &vote_authority, &new_node);
    let message = Message::new(&[instruction], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(vote_authority.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_vote_update_commission() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let vote_account = ledger_base_pubkey;
    let vote_authority = ledger.get_pubkey(&derivation_path, false)?;
    let new_commission = 42u8;
    let instruction =
        vote_instruction::update_commission(&vote_account, &vote_authority, new_commission);
    let message = Message::new(&[instruction], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(vote_authority.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_stake_deactivate() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let stake_account = ledger_base_pubkey;
    let stake_authority = ledger.get_pubkey(&derivation_path, false)?;
    let instruction = stake_instruction::deactivate_stake(&stake_account, &stake_authority);
    let message = Message::new(&[instruction], Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(stake_authority.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_stake_set_lockup() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let stake_account = ledger_base_pubkey;
    let stake_custodian = ledger.get_pubkey(&derivation_path, false)?;
    let new_custodian = Pubkey::new(&[1u8; 32]);
    for maybe_new_custodian in &[None, Some(new_custodian)] {
        let lockup = stake_instruction::LockupArgs {
            unix_timestamp: Some(1),
            epoch: Some(2),
            custodian: *maybe_new_custodian,
        };
        let instruction = stake_instruction::set_lockup(&stake_account, &lockup, &stake_custodian);
        let message = Message::new(&[instruction], Some(&ledger_base_pubkey)).serialize();
        let signature = ledger.sign_message(&derivation_path, &message)?;
        assert!(signature.verify(stake_custodian.as_ref(), &message));
    }
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_stake_set_lockup_checked() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let stake_account = ledger_base_pubkey;
    let stake_custodian = ledger.get_pubkey(&derivation_path, false)?;
    let new_custodian = Pubkey::new(&[1u8; 32]);
    for maybe_new_custodian in &[None, Some(new_custodian)] {
        let lockup = stake_instruction::LockupArgs {
            unix_timestamp: Some(1),
            epoch: Some(2),
            custodian: *maybe_new_custodian,
        };
        let instruction =
            stake_instruction::set_lockup_checked(&stake_account, &lockup, &stake_custodian);
        let message = Message::new(&[instruction], Some(&ledger_base_pubkey)).serialize();
        let signature = ledger.sign_message(&derivation_path, &message)?;
        assert!(signature.verify(stake_custodian.as_ref(), &message));
    }
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
// Add a nonce here to exercise worst case instruction usage
fn test_stake_split_with_nonce() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let stake_authority = ledger.get_pubkey(&derivation_path, false)?;
    let stake_account = ledger_base_pubkey;
    let split_account = Pubkey::new(&[1u8; 32]);
    let nonce_account = Pubkey::new(&[2u8; 32]);
    let nonce_authority = Pubkey::new(&[3u8; 32]);
    let instructions =
        stake_instruction::split(&stake_account, &stake_authority, 42, &split_account);
    let message =
        Message::new_with_nonce(instructions, None, &nonce_account, &nonce_authority).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(stake_authority.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_stake_split_with_seed() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let stake_authority = ledger.get_pubkey(&derivation_path, false)?;
    let stake_account = ledger_base_pubkey;
    let base = stake_authority;
    let seed = "seedseedseedseedseedseedseedseed";
    let split_account = Pubkey::create_with_seed(&base, seed, &solana_stake_program::id()).unwrap();
    let instructions = stake_instruction::split_with_seed(
        &stake_account,
        &stake_authority,
        42,
        &split_account,
        &base,
        seed,
    );
    let message = Message::new(&instructions, Some(&ledger_base_pubkey)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(stake_authority.as_ref(), &message));
    Ok(())
}

fn test_stake_merge() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let stake_authority = ledger.get_pubkey(&derivation_path, false)?;
    let source = Pubkey::new_unique();
    let destination = Pubkey::new_unique();

    let instructions = stake_instruction::merge(&destination, &source, &stake_authority);
    let message = Message::new(&instructions, Some(&stake_authority)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(stake_authority.as_ref(), &message));
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn test_ledger_reject_unexpected_signer() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = Pubkey::new(&[1u8; 32]);
    let instruction = system_instruction::transfer(&from, &ledger_base_pubkey, 42);
    let message = Message::new(&[instruction], Some(&ledger_base_pubkey)).serialize();
    assert!(ledger.sign_message(&derivation_path, &message).is_err());
    Ok(())
}

fn test_spl_token_create_mint() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let owner = ledger.get_pubkey(&derivation_path, false)?;
    let mint = Pubkey::new(&[1u8; 32]);

    let instructions = vec![
        system_instruction::create_account(
            &owner,
            &mint,
            501,
            std::mem::size_of::<spl_token::state::Mint>() as u64,
            &spl_token::id(),
        ),
        spl_token::instruction::initialize_mint(&spl_token::id(), &mint, &owner, None, 2).unwrap(),
    ];
    let message = Message::new(&instructions, Some(&owner)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(owner.as_ref(), &message));
    Ok(())
}

fn test_spl_token_create_account() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let owner = ledger.get_pubkey(&derivation_path, false)?;
    let account = Pubkey::new(&[1u8; 32]);
    let mint = Pubkey::new(&[2u8; 32]);

    let instructions = vec![
        system_instruction::create_account(
            &owner,
            &account,
            501,
            std::mem::size_of::<spl_token::state::Mint>() as u64,
            &spl_token::id(),
        ),
        spl_token::instruction::initialize_account(&spl_token::id(), &account, &mint, &owner)
            .unwrap(),
    ];
    let message = Message::new(&instructions, Some(&owner)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(owner.as_ref(), &message));
    Ok(())
}

fn test_spl_token_create_account2() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let owner = ledger.get_pubkey(&derivation_path, false)?;
    let account = Pubkey::new(&[1u8; 32]);
    let mint = Pubkey::new(&[2u8; 32]);

    let instructions = vec![
        system_instruction::create_account(
            &owner,
            &account,
            501,
            std::mem::size_of::<spl_token::state::Mint>() as u64,
            &spl_token::id(),
        ),
        spl_token::instruction::initialize_account2(&spl_token::id(), &account, &mint, &owner)
            .unwrap(),
    ];
    let message = Message::new(&instructions, Some(&owner)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(owner.as_ref(), &message));
    Ok(())
}

fn test_spl_token_create_multisig() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let owner = ledger.get_pubkey(&derivation_path, false)?;
    let account = Pubkey::new(&[1u8; 32]);
    let signers = [
        Pubkey::new(&[2u8; 32]),
        Pubkey::new(&[3u8; 32]),
        Pubkey::new(&[4u8; 32]),
    ];

    let instructions = vec![
        system_instruction::create_account(
            &owner,
            &account,
            501,
            std::mem::size_of::<spl_token::state::Mint>() as u64,
            &spl_token::id(),
        ),
        spl_token::instruction::initialize_multisig(
            &spl_token::id(),
            &account,
            &signers.iter().collect::<Vec<_>>(),
            2,
        )
        .unwrap(),
    ];
    let message = Message::new(&instructions, Some(&owner)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(owner.as_ref(), &message));
    Ok(())
}

fn test_spl_token_transfer() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let owner = ledger.get_pubkey(&derivation_path, false)?;
    let sender = Pubkey::new(&[1u8; 32]);
    let recipient = Pubkey::new(&[2u8; 32]);
    let mint = spl_token::native_mint::id();

    let instruction = spl_token::instruction::transfer_checked(
        &spl_token::id(),
        &sender,
        &mint,
        &recipient,
        &owner,
        &[],
        42,
        9,
    )
    .unwrap();
    let message = Message::new(&[instruction], Some(&owner)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(owner.as_ref(), &message));
    Ok(())
}

fn test_spl_token_approve() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let owner = ledger.get_pubkey(&derivation_path, false)?;
    let account = Pubkey::new(&[1u8; 32]);
    let delegate = Pubkey::new(&[2u8; 32]);
    let mint = spl_token::native_mint::id();

    let instruction = spl_token::instruction::approve_checked(
        &spl_token::id(),
        &account,
        &mint,
        &delegate,
        &owner,
        &[],
        42,
        9,
    )
    .unwrap();
    let message = Message::new(&[instruction], Some(&owner)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(owner.as_ref(), &message));
    Ok(())
}

fn test_spl_token_revoke() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let owner = ledger.get_pubkey(&derivation_path, false)?;
    let account = Pubkey::new(&[1u8; 32]);

    let instruction =
        spl_token::instruction::revoke(&spl_token::id(), &account, &owner, &[]).unwrap();
    let message = Message::new(&[instruction], Some(&owner)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(owner.as_ref(), &message));
    Ok(())
}

fn test_spl_token_set_authority() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let owner = ledger.get_pubkey(&derivation_path, false)?;
    let account = Pubkey::new(&[1u8; 32]);
    let new_owner = Pubkey::new(&[2u8; 32]);

    let instruction = spl_token::instruction::set_authority(
        &spl_token::id(),
        &account,
        Some(&new_owner),
        spl_token::instruction::AuthorityType::AccountOwner,
        &owner,
        &[],
    )
    .unwrap();
    let message = Message::new(&[instruction], Some(&owner)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(owner.as_ref(), &message));
    Ok(())
}

fn test_spl_token_mint_to() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let owner = ledger.get_pubkey(&derivation_path, false)?;
    let mint = spl_token::native_mint::id();
    let account = Pubkey::new(&[2u8; 32]);

    let instruction = spl_token::instruction::mint_to_checked(
        &spl_token::id(),
        &mint,
        &account,
        &owner,
        &[],
        42,
        9,
    )
    .unwrap();
    let message = Message::new(&[instruction], Some(&owner)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(owner.as_ref(), &message));
    Ok(())
}

fn test_spl_token_burn() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let owner = ledger.get_pubkey(&derivation_path, false)?;
    let account = Pubkey::new(&[1u8; 32]);
    let mint = spl_token::native_mint::id();

    let instruction =
        spl_token::instruction::burn_checked(&spl_token::id(), &account, &mint, &owner, &[], 42, 9)
            .unwrap();
    let message = Message::new(&[instruction], Some(&owner)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(owner.as_ref(), &message));
    Ok(())
}

fn test_spl_token_close_account() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let owner = ledger.get_pubkey(&derivation_path, false)?;
    let account = Pubkey::new(&[1u8; 32]);
    let destination = Pubkey::new(&[2u8; 32]);

    let instruction = spl_token::instruction::close_account(
        &spl_token::id(),
        &account,
        &destination,
        &owner,
        &[],
    )
    .unwrap();
    let message = Message::new(&[instruction], Some(&owner)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(owner.as_ref(), &message));
    Ok(())
}

fn test_spl_token_transfer_multisig() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let signer = ledger.get_pubkey(&derivation_path, false)?;
    let owner = Pubkey::new(&[1u8; 32]);
    let sender = Pubkey::new(&[2u8; 32]);
    let recipient = Pubkey::new(&[3u8; 32]);
    let mint = Pubkey::new(&[4u8; 32]); // Bad mint show symbol "???"
    let signers = [Pubkey::new(&[5u8; 32]), signer];

    let instruction = spl_token::instruction::transfer_checked(
        &spl_token::id(),
        &sender,
        &mint,
        &recipient,
        &owner,
        &signers.iter().collect::<Vec<_>>(),
        42,
        9,
    )
    .unwrap();
    let message = Message::new(&[instruction], Some(&signer)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(signer.as_ref(), &message));
    Ok(())
}

fn test_spl_token_approve_multisig() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let signer = ledger.get_pubkey(&derivation_path, false)?;
    let owner = Pubkey::new(&[1u8; 32]);
    let account = Pubkey::new(&[2u8; 32]);
    let delegate = Pubkey::new(&[3u8; 32]);
    let mint = Pubkey::new(&[4u8; 32]);
    let signers = [Pubkey::new(&[5u8; 32]), signer];

    let instruction = spl_token::instruction::approve_checked(
        &spl_token::id(),
        &account,
        &mint,
        &delegate,
        &owner,
        &signers.iter().collect::<Vec<_>>(),
        42,
        9,
    )
    .unwrap();
    let message = Message::new(&[instruction], Some(&signer)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(signer.as_ref(), &message));
    Ok(())
}

fn test_spl_token_revoke_multisig() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let signer = ledger.get_pubkey(&derivation_path, false)?;
    let owner = Pubkey::new(&[1u8; 32]);
    let account = Pubkey::new(&[2u8; 32]);
    let signers = [Pubkey::new(&[3u8; 32]), signer];

    let instruction = spl_token::instruction::revoke(
        &spl_token::id(),
        &account,
        &owner,
        &signers.iter().collect::<Vec<_>>(),
    )
    .unwrap();
    let message = Message::new(&[instruction], Some(&signer)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(signer.as_ref(), &message));
    Ok(())
}

fn test_spl_token_set_authority_multisig() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let signer = ledger.get_pubkey(&derivation_path, false)?;
    let owner = Pubkey::new(&[1u8; 32]);
    let account = Pubkey::new(&[2u8; 32]);
    let new_owner = Pubkey::new(&[3u8; 32]);
    let signers = [Pubkey::new(&[4u8; 32]), signer];

    let instruction = spl_token::instruction::set_authority(
        &spl_token::id(),
        &account,
        Some(&new_owner),
        spl_token::instruction::AuthorityType::AccountOwner,
        &owner,
        &signers.iter().collect::<Vec<_>>(),
    )
    .unwrap();
    let message = Message::new(&[instruction], Some(&signer)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(signer.as_ref(), &message));
    Ok(())
}

fn test_spl_token_mint_to_multisig() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let signer = ledger.get_pubkey(&derivation_path, false)?;
    let owner = Pubkey::new(&[1u8; 32]);
    let mint = Pubkey::new(&[2u8; 32]);
    let account = Pubkey::new(&[3u8; 32]);
    let signers = [Pubkey::new(&[4u8; 32]), signer];

    let instruction = spl_token::instruction::mint_to_checked(
        &spl_token::id(),
        &mint,
        &account,
        &owner,
        &signers.iter().collect::<Vec<_>>(),
        42,
        9,
    )
    .unwrap();
    let message = Message::new(&[instruction], Some(&signer)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(signer.as_ref(), &message));
    Ok(())
}

fn test_spl_token_burn_multisig() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let signer = ledger.get_pubkey(&derivation_path, false)?;
    let owner = Pubkey::new(&[1u8; 32]);
    let account = Pubkey::new(&[2u8; 32]);
    let signers = [Pubkey::new(&[3u8; 32]), signer];
    let mint = Pubkey::new(&[4u8; 32]);

    let instruction = spl_token::instruction::burn_checked(
        &spl_token::id(),
        &account,
        &mint,
        &owner,
        &signers.iter().collect::<Vec<_>>(),
        42,
        9,
    )
    .unwrap();
    let message = Message::new(&[instruction], Some(&signer)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(signer.as_ref(), &message));
    Ok(())
}

fn test_spl_token_close_account_multisig() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let signer = ledger.get_pubkey(&derivation_path, false)?;
    let owner = Pubkey::new(&[1u8; 32]);
    let account = Pubkey::new(&[2u8; 32]);
    let destination = Pubkey::new(&[3u8; 32]);
    let signers = [Pubkey::new(&[4u8; 32]), signer];

    let instruction = spl_token::instruction::close_account(
        &spl_token::id(),
        &account,
        &destination,
        &owner,
        &signers.iter().collect::<Vec<_>>(),
    )
    .unwrap();
    let message = Message::new(&[instruction], Some(&signer)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(signer.as_ref(), &message));
    Ok(())
}

fn test_spl_token_freeze_account() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let signer = ledger.get_pubkey(&derivation_path, false)?;
    let freeze_auth = signer;
    let account = Pubkey::new(&[1u8; 32]);
    let mint = Pubkey::new(&[2u8; 32]);

    let instruction = spl_token::instruction::freeze_account(
        &spl_token::id(),
        &account,
        &mint,
        &freeze_auth,
        &[],
    )
    .unwrap();
    let message = Message::new(&[instruction], Some(&signer)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(signer.as_ref(), &message));
    Ok(())
}

fn test_spl_token_freeze_account_multisig() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let signer = ledger.get_pubkey(&derivation_path, false)?;
    let freeze_auth = signer;
    let account = Pubkey::new(&[1u8; 32]);
    let mint = Pubkey::new(&[2u8; 32]);
    let signers = [Pubkey::new(&[3u8; 32]), signer];

    let instruction = spl_token::instruction::freeze_account(
        &spl_token::id(),
        &account,
        &mint,
        &freeze_auth,
        &signers.iter().collect::<Vec<_>>(),
    )
    .unwrap();
    let message = Message::new(&[instruction], Some(&signer)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(signer.as_ref(), &message));
    Ok(())
}

fn test_spl_token_thaw_account() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let signer = ledger.get_pubkey(&derivation_path, false)?;
    let thaw_auth = signer;
    let account = Pubkey::new(&[1u8; 32]);
    let mint = Pubkey::new(&[2u8; 32]);

    let instruction =
        spl_token::instruction::thaw_account(&spl_token::id(), &account, &mint, &thaw_auth, &[])
            .unwrap();
    let message = Message::new(&[instruction], Some(&signer)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(signer.as_ref(), &message));
    Ok(())
}

fn test_spl_token_thaw_account_multisig() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let signer = ledger.get_pubkey(&derivation_path, false)?;
    let thaw_auth = signer;
    let account = Pubkey::new(&[1u8; 32]);
    let mint = Pubkey::new(&[2u8; 32]);
    let signers = [Pubkey::new(&[3u8; 32]), signer];

    let instruction = spl_token::instruction::thaw_account(
        &spl_token::id(),
        &account,
        &mint,
        &thaw_auth,
        &signers.iter().collect::<Vec<_>>(),
    )
    .unwrap();
    let message = Message::new(&[instruction], Some(&signer)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(signer.as_ref(), &message));
    Ok(())
}

fn test_spl_token_sync_native() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let signer = ledger.get_pubkey(&derivation_path, false)?;
    let account = Pubkey::new(&[1u8; 32]);

    let instruction = spl_token::instruction::sync_native(&spl_token::id(), &account).unwrap();
    let message = Message::new(&[instruction], Some(&signer)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(signer.as_ref(), &message));
    Ok(())
}

fn test_spl_associated_token_account_create() -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let owner = ledger.get_pubkey(&derivation_path, false)?;
    let mint = Pubkey::new_unique();
    let instruction =
        create_associated_token_account(&owner, &owner, &mint, &spl_associated_token_account::id());
    let message = Message::new(&[instruction], Some(&owner)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(owner.as_ref(), &message));
    Ok(())
}

fn test_spl_associated_token_account_create_with_transfer_checked() -> Result<(), RemoteWalletError>
{
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let sender = ledger.get_pubkey(&derivation_path, false)?;
    let mint = Pubkey::new_unique();
    let sender_holder = get_associated_token_address(&sender, &mint);
    let recipient = Pubkey::new_unique();
    let recipient_holder = get_associated_token_address(&recipient, &mint);
    let instructions = vec![
        create_associated_token_account(
            &sender,
            &recipient,
            &mint,
            &spl_associated_token_account::id(),
        ),
        spl_token::instruction::transfer_checked(
            &spl_token::id(),
            &sender_holder,
            &mint,
            &recipient_holder,
            &sender,
            &[],
            42,
            9,
        )
        .unwrap(),
    ];
    let message = Message::new(&instructions, Some(&sender)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(sender.as_ref(), &message));
    Ok(())
}

mod serum_assert_owner_program {
    use super::*;

    solana_sdk::declare_id!("4MNPdKu9wFMvEeZBMt3Eipfs5ovVWTJb31pEXDJAAxX5");

    pub mod instruction {
        use super::*;

        pub fn check(account: &Pubkey, expected_program_id: &Pubkey) -> Instruction {
            Instruction::new_with_bincode(
                super::id(),
                expected_program_id,
                vec![AccountMeta::new_readonly(*account, false)],
            )
        }
    }
}

fn test_spl_associated_token_account_create_with_transfer_checked_and_serum_assert_owner(
) -> Result<(), RemoteWalletError> {
    let (ledger, _ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);
    let sender = ledger.get_pubkey(&derivation_path, false)?;
    let mint = Pubkey::new_unique();
    let sender_holder = get_associated_token_address(&sender, &mint);
    let recipient = Pubkey::new_unique();
    let recipient_holder = get_associated_token_address(&recipient, &mint);
    let instructions = vec![
        serum_assert_owner_program::instruction::check(&recipient, &system_program::id()),
        create_associated_token_account(
            &sender,
            &recipient,
            &mint,
            &spl_associated_token_account::id(),
        ),
        spl_token::instruction::transfer_checked(
            &spl_token::id(),
            &sender_holder,
            &mint,
            &recipient_holder,
            &sender,
            &[],
            42,
            9,
        )
        .unwrap(),
    ];
    let message = Message::new(&instructions, Some(&sender)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(sender.as_ref(), &message));
    Ok(())
}

// This test requires interactive approval of message signing on the ledger.
fn test_ledger_transfer_with_memos() -> Result<(), RemoteWalletError> {
    let (ledger, ledger_base_pubkey) = get_ledger();

    let derivation_path = DerivationPath::new_bip44(Some(12345), None);

    let from = ledger.get_pubkey(&derivation_path, false)?;
    let instructions = vec![
        spl_memo::build_memo(b"hello", &[]),
        system_instruction::transfer(&from, &ledger_base_pubkey, 42),
        spl_memo::build_memo(b"world", &[]),
    ];
    let message = Message::new(&instructions, Some(&from)).serialize();
    let signature = ledger.sign_message(&derivation_path, &message)?;
    assert!(signature.verify(from.as_ref(), &message));
    Ok(())
}

fn ensure_blind_signing() -> Result<(), RemoteWalletError> {
    let (ledger, _pubkey) = get_ledger();
    let LedgerSettings {
        enable_blind_signing,
        ..
    } = ledger.get_settings()?;
    if !enable_blind_signing {
        println!(
            " >>> Please enable Blind Signing in app settings before running this test suite <<<"
        );
        std::process::exit(1);
    }
    Ok(())
}

fn main() {
    solana_logger::setup();
    match do_run_tests() {
        Err(e @ RemoteWalletError::LedgerError(LedgerError::UserCancel)) => {
            println!(" >>> {} <<<", e);
        }
        Err(e) => Err(e).unwrap(),
        Ok(()) => (),
    }
}

macro_rules! run {
    ($test:ident) => {
        println!(" >>> Running {} <<<", stringify!($test));
        $test()?;
    };
}
fn do_run_tests() -> Result<(), RemoteWalletError> {
    ensure_blind_signing()?;

    run!(test_ledger_sign_versioned_transaction);
    run!(test_ledger_sign_versioned_transaction_with_table);
    run!(test_ledger_sign_offchain_message_ascii);
    run!(test_ledger_sign_offchain_message_utf8);
    run!(test_ledger_transfer_with_memos);
    run!(test_spl_associated_token_account_create_with_transfer_checked_and_serum_assert_owner);
    run!(test_spl_associated_token_account_create_with_transfer_checked);
    run!(test_spl_associated_token_account_create);
    run!(test_stake_merge);
    run!(test_spl_token_freeze_account);
    run!(test_spl_token_freeze_account_multisig);
    run!(test_spl_token_thaw_account);
    run!(test_spl_token_thaw_account_multisig);
    run!(test_spl_token_sync_native);
    run!(test_spl_token_burn);
    run!(test_spl_token_burn_multisig);
    run!(test_spl_token_mint_to);
    run!(test_spl_token_mint_to_multisig);
    run!(test_spl_token_approve);
    run!(test_spl_token_approve_multisig);
    run!(test_spl_token_transfer);
    run!(test_spl_token_transfer_multisig);
    run!(test_spl_token_set_authority);
    run!(test_spl_token_set_authority_multisig);
    run!(test_spl_token_create_mint);
    run!(test_spl_token_revoke_multisig);
    run!(test_spl_token_close_account_multisig);
    run!(test_spl_token_create_account);
    run!(test_spl_token_create_account2);
    run!(test_spl_token_create_multisig);
    run!(test_spl_token_revoke);
    run!(test_spl_token_close_account);
    run!(test_ledger_reject_unexpected_signer);
    run!(test_stake_split_with_nonce);
    run!(test_stake_split_with_seed);
    run!(test_stake_set_lockup);
    run!(test_stake_set_lockup_checked);
    run!(test_stake_deactivate);
    run!(test_vote_update_commission);
    run!(test_vote_update_validator_identity);
    run!(test_vote_authorize);
    run!(test_vote_authorize_checked);
    run!(test_stake_authorize);
    run!(test_stake_authorize_checked);
    run!(test_nonce_authorize);
    run!(test_vote_withdraw);
    run!(test_stake_withdraw);
    run!(test_nonce_withdraw);
    run!(test_create_vote_account);
    run!(test_create_vote_account_with_seed);
    run!(test_create_nonce_account);
    run!(test_create_nonce_account_with_seed);
    run!(test_create_stake_account);
    run!(test_create_stake_account_no_lockup);
    run!(test_create_stake_account_checked);
    run!(test_ledger_pubkey);
    run!(test_ledger_sign_transaction);
    run!(test_ledger_sign_transaction_too_big);
    run!(test_ledger_delegate_stake);
    run!(test_ledger_delegate_stake_with_nonce);
    run!(test_create_stake_account_and_delegate);
    run!(test_create_stake_account_with_seed_and_delegate);
    run!(test_ledger_advance_nonce_account);
    run!(test_ledger_advance_nonce_account_separate_fee_payer);
    run!(test_ledger_delegate_stake_with_nonce);
    run!(test_ledger_transfer_with_nonce);
    run!(test_create_stake_account_with_seed_and_nonce);
    run!(test_create_stake_account_checked_with_seed_and_nonce);
    run!(test_sign_full_shred_of_garbage_tx);

    Ok(())
}
