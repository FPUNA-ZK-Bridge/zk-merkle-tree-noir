// Verificador de inclusión de transacciones Ethereum vía prueba MPT.
//
// Entrada pública : transactions_root (header del bloque).
// Entradas privadas: tx_index, serialized_tx (+ tx_len), proof_nodes
//                    (+ proof_node_lens, proof_len), con padding a los
//                    máximos definidos en types.nr.
//
// El circuito no devuelve nada: si todas las constraints se satisfacen,
// la inclusión queda demostrada (RF-01..RF-08).

mod keccak;
mod mpt;
mod rlp;
mod types;
mod tests;

use types::{MAX_NODE_LEN, MAX_PROOF_NODES, MAX_TX_LEN};

fn main(
    transactions_root: pub [u8; 32],
    tx_index: u32,
    serialized_tx: [u8; MAX_TX_LEN],
    tx_len: u32,
    proof_nodes: [[u8; MAX_NODE_LEN]; MAX_PROOF_NODES],
    proof_node_lens: [u32; MAX_PROOF_NODES],
    proof_len: u32,
) {
    mpt::verify_inclusion(
        transactions_root,
        tx_index,
        serialized_tx,
        tx_len,
        proof_nodes,
        proof_node_lens,
        proof_len,
    );
}
