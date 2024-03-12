// Reference: https://github.com/rust-bitcoin/rust-miniscript/blob/master/bitcoind-tests/tests/test_desc.rs
use std::str::FromStr;

use bitcoind::{
    bitcoincore_rpc::{json, Client, RpcApi as _},
    BitcoinD,
};
use miniscript::{
    bitcoin::{
        absolute,
        psbt::{self, Psbt},
        sighash::{self, SighashCache},
        taproot, transaction, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Txid,
    },
    descriptor::Tr,
    psbt::{PsbtExt as _, PsbtInputExt},
    DefiniteDescriptorKey, Descriptor,
};
use secp256k1::{
    hashes::Hash as _,
    rand::{rngs::OsRng, RngCore},
    Keypair, Secp256k1,
};

// Find the Outpoint by spk
fn get_vout(cl: &Client, txid: Txid, value: Amount, spk: ScriptBuf) -> (OutPoint, TxOut) {
    let tx = cl
        .get_transaction(&txid, None)
        .unwrap()
        .transaction()
        .unwrap();
    for (i, txout) in tx.output.into_iter().enumerate() {
        if txout.value == value && spk == txout.script_pubkey {
            return (OutPoint::new(txid, i as u32), txout);
        }
    }
    unreachable!("Only call get vout on functions which have the expected outpoint");
}

fn mine(cl: &Client, n: usize) {
    let blocks = cl
        .generate_to_address(
            n as u64,
            &cl.get_new_address(None, None).unwrap().assume_checked(),
        )
        .unwrap();
    assert_eq!(blocks.len(), n);
}

fn main() {
    // Generate a secp256k1 key pair
    let secp = Secp256k1::new();
    let internal_keypair = Keypair::new(&secp, &mut OsRng);
    let pk = DefiniteDescriptorKey::from_str(
        &PublicKey {
            inner: secp256k1::PublicKey::from_keypair(&internal_keypair),
            compressed: true,
        }
        .to_string(),
    )
    .unwrap();

    // Create a taproot with only the key spending path.
    let tr = Tr::new(pk, None).unwrap();
    let desc: Descriptor<DefiniteDescriptorKey> = tr.clone().into();
    let address = tr.address(Network::Regtest);
    println!("address: {}", address);

    // Start bitcoind
    let bitcoind = BitcoinD::from_downloaded().unwrap();
    let cl = &bitcoind.client;
    // Generate some blocks
    mine(cl, 101);
    assert_eq!(
        cl.get_balance(Some(1), None).unwrap(),
        Amount::from_int_btc(50)
    );

    // Send some btc to the address
    let faucet_txid = cl
        .send_to_address(
            &address,
            Amount::ONE_BTC,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    mine(cl, 2);

    // Create a psbt to spend the UTXO owned by the address
    let mut psbt = Psbt {
        unsigned_tx: Transaction {
            version: transaction::Version::TWO,
            // 10/28/2020 @ 6:25am (UTC)
            lock_time: absolute::LockTime::from_time(1_603_866_330).expect("valid timestamp"),
            input: vec![],
            output: vec![],
        },
        unknown: Default::default(),
        proprietary: Default::default(),
        xpub: Default::default(),
        version: 0,
        inputs: vec![],
        outputs: vec![],
    };

    let (outpoint, witness_utxo) = get_vout(cl, faucet_txid, Amount::ONE_BTC, tr.script_pubkey());
    let txin = TxIn {
        previous_output: outpoint,
        sequence: Sequence::from_height(1),
        ..Default::default()
    };
    psbt.unsigned_tx.input.push(txin);

    // Get a new script pubkey from the node so that
    // the node wallet tracks the receiving transaction
    // and we can check it by gettransaction RPC.
    let receiver = cl
        .get_new_address(None, Some(json::AddressType::Bech32))
        .unwrap()
        .assume_checked();
    psbt.unsigned_tx.output.push(TxOut {
        value: Amount::from_sat(99_997_000),
        script_pubkey: receiver.script_pubkey(),
    });

    let mut input = psbt::Input::default();
    // Set taproot fields in psbt
    input.update_with_descriptor_unchecked(&desc).unwrap();
    input.witness_utxo = Some(witness_utxo.clone());
    psbt.inputs.push(input);
    psbt.outputs.push(psbt::Output::default());

    // Sign the transaction
    let hash_ty = sighash::TapSighashType::Default;
    let prevouts = [witness_utxo];
    let prevouts = sighash::Prevouts::All(&prevouts);
    let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash_msg = sighash_cache
        .taproot_key_spend_signature_hash(0, &prevouts, hash_ty)
        .unwrap();
    let msg = secp256k1::Message::from_digest(sighash_msg.to_byte_array());
    let mut aux_rand = [0u8; 32];
    OsRng.fill_bytes(&mut aux_rand);
    let tweaked_keypair = internal_keypair
        .add_xonly_tweak(&secp, &tr.spend_info().tap_tweak().to_scalar())
        .unwrap();
    let schnorr_sig = secp.sign_schnorr_with_aux_rand(&msg, &tweaked_keypair, &aux_rand);
    psbt.inputs[0].tap_key_sig = Some(taproot::Signature {
        sig: schnorr_sig,
        hash_ty,
    });

    psbt.finalize_mut(&secp).unwrap();
    let tx = psbt.extract(&secp).expect("Extraction error");
    cl.send_raw_transaction(&tx)
        .unwrap_or_else(|_| panic!("send tx failed for desc {}", tr));
}
