import Transport from "@ledgerhq/hw-transport";
import { TransportError } from "@ledgerhq/errors";
import bs58 from "bs58";
import * as solana from "@solana/web3.js";

const INS_GET_PUBKEY = 0x05;
const INS_SIGN_MESSAGE = 0x06;

const P1_NON_CONFIRM = 0x00;
const P1_CONFIRM = 0x01;

const P2_EXTEND = 0x01;
const P2_MORE = 0x02;

const MAX_PAYLOAD = 255;

const LEDGER_CLA = 0xe0;

const STATUS_OK = 0x9000;

/*
 * Helper for chunked send of large payloads
 */
async function solana_send(transport: Transport, instruction: number, p1: number, payload: Buffer) {
  var p2 = 0;
  var payload_offset = 0;

  if (payload.length > MAX_PAYLOAD) {
    while (payload.length - payload_offset > MAX_PAYLOAD) {
      const buf = payload.slice(payload_offset, payload_offset + MAX_PAYLOAD);
      payload_offset += MAX_PAYLOAD;
      console.log("send", (p2 | P2_MORE).toString(16), buf.length.toString(16), buf);
      const reply = await transport.send(LEDGER_CLA, instruction, p1, p2 | P2_MORE, buf);
      if (reply.length != 2) {
        //TODO: fix
        throw TransportError(
          "solana_send: Received unexpected reply payload",
          "UnexpectedReplyPayload"
        );
      }
      p2 |= P2_EXTEND;
    }
  }

  const buf = payload.slice(payload_offset);
  console.log("send", p2.toString(16), buf.length.toString(16), buf);
  const reply = await transport.send(LEDGER_CLA, instruction, p1, p2, buf);

  return reply.slice(0, reply.length - 2);
}

const BIP32_HARDENED_BIT = (1 << 31) >>> 0;
function _harden(n: number) {
  return (n | BIP32_HARDENED_BIT) >>> 0;
}

function solana_derivation_path(account?: number, change?: number) {
  var length;
  if (typeof account === "number") {
    if (typeof change === "number") {
      length = 4;
    } else {
      length = 3;
    }
  } else {
    length = 2;
  }

  var derivation_path = Buffer.alloc(1 + length * 4);
  var offset = 0;
  offset = derivation_path.writeUInt8(length, offset);
  offset = derivation_path.writeUInt32BE(_harden(44), offset); // Using BIP44
  offset = derivation_path.writeUInt32BE(_harden(501), offset); // Solana's BIP44 path

  if (length > 2) {
    offset = derivation_path.writeUInt32BE(_harden(account as number), offset);
    if (length == 4) {
      offset = derivation_path.writeUInt32BE(_harden(change as number), offset);
    }
  }

  return derivation_path;
}

async function solana_ledger_get_pubkey(transport: Transport, derivation_path: Buffer) {
  return solana_send(transport, INS_GET_PUBKEY, P1_NON_CONFIRM, derivation_path);
}

async function solana_ledger_sign_transaction(
  transport: Transport,
  derivation_path: Buffer,
  transaction: solana.Transaction
) {
  const msg_bytes = transaction.compileMessage().serialize();

  // XXX: Ledger app only supports a single derivation_path per call ATM
  var num_paths = Buffer.alloc(1);
  num_paths.writeUInt8(1);

  const payload = Buffer.concat([num_paths, derivation_path, msg_bytes]);

  return solana_send(transport, INS_SIGN_MESSAGE, P1_CONFIRM, payload);
}

export async function runSignTest(transport: Transport) {
  const from_derivation_path = solana_derivation_path();
  const from_pubkey_bytes = await solana_ledger_get_pubkey(transport, from_derivation_path);
  const from_pubkey_string = bs58.encode(from_pubkey_bytes);
  console.log("---", from_pubkey_string);

  const to_derivation_path = solana_derivation_path(1);
  const to_pubkey_bytes = await solana_ledger_get_pubkey(transport, to_derivation_path);
  const to_pubkey_string = bs58.encode(to_pubkey_bytes);
  console.log("---", to_pubkey_string);

  const from_pubkey = new solana.PublicKey(from_pubkey_string);
  const to_pubkey = new solana.PublicKey(to_pubkey_string);
  const ix = solana.SystemProgram.transfer({
    fromPubkey: from_pubkey,
    toPubkey: to_pubkey,
    lamports: 42,
  });

  // XXX: Fake blockhash so this example doesn't need a
  // network connection. It should be queried from the
  // cluster in normal use.
  const recentBlockhash = bs58.encode(
    Buffer.from([
      3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
      3,
    ])
  );

  var tx = new solana.Transaction({
    recentBlockhash,
    feePayer: from_pubkey,
  }).add(ix);

  const sig_bytes = await solana_ledger_sign_transaction(transport, from_derivation_path, tx);

  const sig_string = bs58.encode(sig_bytes);
  console.log("--- len:", sig_bytes.length, "sig:", sig_string);

  tx.addSignature(from_pubkey, sig_bytes);
  console.log("--- verifies:", tx.verifySignatures());
}
