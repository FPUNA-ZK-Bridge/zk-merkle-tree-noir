// main.nr — Fase 3 del verificador MPT, CON binding de (recipient, amount).
//
// Reemplaza noir-merkle/src/main.nr. Agrega `recipient` y `amount` como inputs
// PÚBLICOS y un `calldata_offset` privado (hint). Requiere src/bind.nr.
//
// Inputs públicos, EN ESTE ORDEN (importa para el contrato):
//   transactions_root [u8;32]  → publicInputs[0..32]
//   recipient         [u8;20]  → publicInputs[32..52]
//   amount            [u8;32]  → publicInputs[52..84]
// Total: 84 campos públicos (un byte por campo, ABI de Noir para arrays de u8).

mod keccak;
mod mpt;
mod rlp;
mod types;
mod bind;
mod tests;

use types::{MAX_NODE_LEN, MAX_PROOF_NODES, MAX_TX_LEN};

fn main(
    transactions_root: pub [u8; 32],
    recipient: pub [u8; 20],
    amount: pub [u8; 32],
    tx_index: u32,
    serialized_tx: [u8; MAX_TX_LEN],
    tx_len: u32,
    calldata_offset: u32,
    proof_nodes: [[u8; MAX_NODE_LEN]; MAX_PROOF_NODES],
    proof_node_lens: [u32; MAX_PROOF_NODES],
    proof_len: u32,
) {
    // 1) Inclusión de la tx en el trie (igual que Fase 1).
    mpt::verify_inclusion(
        transactions_root,
        tx_index,
        serialized_tx,
        tx_len,
        proof_nodes,
        proof_node_lens,
        proof_len,
    );

    // 2) NUEVO: la tx incluida es un lock(recipient, amount).
    bind::assert_lock_calldata(serialized_tx, calldata_offset, recipient, amount);
}
