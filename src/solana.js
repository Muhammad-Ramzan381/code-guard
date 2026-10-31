import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from '@solana/web3.js';

export const MEMO_PROGRAM_ID = new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
const RPC_URL = process.env.SOLANA_RPC_URL ?? 'https://api.devnet.solana.com';
const MIN_REGISTER_SOL = 0.01;
const MEMO_PREFIX = 'codeguard:v1';

export const connect = () => new Connection(RPC_URL, 'confirmed');
export const explorerUrl = (signature) => `https://explorer.solana.com/tx/${signature}?cluster=devnet`;

export function loadWallet(path) {
  if (!existsSync(path)) throw new Error(`No wallet at ${path}. Run: codeguard wallet`);
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(path, 'utf8'))));
}

/** Creates a devnet wallet once. An existing file is never overwritten, since that would lose its funds. */
export function ensureWallet(path) {
  if (existsSync(path)) return { wallet: loadWallet(path), created: false };
  const wallet = Keypair.generate();
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify([...wallet.secretKey]), { mode: 0o600, flag: 'wx' });
  return { wallet, created: true };
}

export async function balanceSol(connection, publicKey) {
  return (await connection.getBalance(publicKey)) / LAMPORTS_PER_SOL;
}

/** Registers the agent on the Solana Agent Registry (8004) on devnet. */
export async function registerAgent(connection, wallet, tokenUri) {
  if (!tokenUri || !/^(https:\/\/|ipfs:\/\/)/.test(tokenUri)) throw new Error('Provide --uri with a public HTTPS or IPFS agent metadata URI');
  const balance = await balanceSol(connection, wallet.publicKey);
  if (balance < MIN_REGISTER_SOL) {
    throw new Error(
      `Wallet holds ${balance} SOL; registering needs about ${MIN_REGISTER_SOL}. ` +
        `Fund ${wallet.publicKey.toBase58()} at https://faucet.solana.com (devnet).`,
    );
  }
  const { SolanaSDK } = await import('8004-solana');
  const sdk = new SolanaSDK({ cluster: 'devnet', signer: wallet, rpcUrl: RPC_URL });
  const result = await sdk.registerAgent(tokenUri);
  if (result.success === false || !result.signature || !result.asset) {
    throw new Error(`Registration failed: ${result.error ?? 'no signature or asset returned'}`);
  }
  return { asset: result.asset.toBase58(), signature: result.signature };
}

export const formatMemo = ({ agentAsset, reportHash, counts }) =>
  `${MEMO_PREFIX}:${agentAsset}:${reportHash}:c${counts.critical}h${counts.high}m${counts.medium}l${counts.low}`;

export function buildMemoInstruction(memo, signer) {
  return new TransactionInstruction({
    programId: MEMO_PROGRAM_ID,
    keys: [{ pubkey: signer, isSigner: true, isWritable: false }],
    data: Buffer.from(memo, 'utf8'),
  });
}

export async function attestReport(connection, wallet, memo) {
  const tx = new Transaction().add(buildMemoInstruction(memo, wallet.publicKey));
  return sendAndConfirmTransaction(connection, tx, [wallet]);
}

/** Fetches a transaction and confirms it holds this memo, signed by the expected wallet. */
export async function verifyAttestation(connection, signature, { memo, signer }) {
  const tx = await connection.getParsedTransaction(signature, {
    commitment: 'confirmed',
    maxSupportedTransactionVersion: 0,
  });
  if (!tx) return { ok: false, reason: 'transaction not found on devnet' };
  if (tx.meta?.err) return { ok: false, reason: 'transaction failed onchain' };
  const memoIx = tx.transaction.message.instructions.find((ix) => ix.programId.equals(MEMO_PROGRAM_ID));
  if (memoIx?.parsed !== memo) return { ok: false, reason: `memo mismatch: found ${memoIx?.parsed ?? 'none'}` };
  const signed = tx.transaction.message.accountKeys.some((k) => k.signer && k.pubkey.toBase58() === signer);
  if (!signed) return { ok: false, reason: `not signed by ${signer}` };
  return { ok: true, slot: tx.slot };
}
