// Verificación de prueba de inclusión sobre el Merkle Patricia Trie de
// transacciones de Ethereum (RF-01..RF-07).
//
// Recorre proof_nodes desde la raíz hasta la hoja:
//  - cada nodo debe hashear (Keccak-256) al hash esperado por su padre
//    (el primero, al transactions_root público),
//  - los nibbles de RLP(tx_index) guían el descenso por branch/extension,
//  - la hoja debe contener exactamente serialized_tx como valor.
//
// Limitaciones del MVP (documentadas en el README):
//  - solo referencias por hash (nodos embebidos < 32 bytes no soportados),
//  - sin terminación en el slot de valor de un branch (las claves RLP(i)
//    son prefix-free, por lo que en el trie de transacciones la terminación
//    ocurre siempre en una hoja).

use crate::keccak;
use crate::rlp;
use crate::types::{MAX_ITEMS, MAX_NIBBLES, MAX_NODE_LEN, MAX_PROOF_NODES, MAX_TX_LEN, NODE_HASH_BLOCKS};

// Nibble t del path hex-prefix codificado en node[poff .. poff+plen].
// La secuencia de nibbles del path codificado es [flag, (pad|n0), n1, ...]:
// si el path es impar, los nibbles útiles comienzan en el índice global 1;
// si es par, en el índice global 2.
fn hp_path_nibble<let N: u32>(node: [u8; N], poff: u32, odd: bool, t: u32) -> u8 {
    let g = if odd { t + 1 } else { t + 2 };
    let byte = node[poff + g / 2];
    if g % 2 == 0 {
        byte >> 4
    } else {
        byte & 0x0f
    }
}

pub fn verify_inclusion(
    transactions_root: [u8; 32],
    tx_index: u32,
    serialized_tx: [u8; MAX_TX_LEN],
    tx_len: u32,
    proof_nodes: [[u8; MAX_NODE_LEN]; MAX_PROOF_NODES],
    proof_node_lens: [u32; MAX_PROOF_NODES],
    proof_len: u32,
) {
    assert(proof_len >= 1);
    assert(proof_len <= MAX_PROOF_NODES);
    assert(tx_len >= 1);
    assert(tx_len <= MAX_TX_LEN);

    // RF-02: clave del trie = nibbles de RLP(tx_index).
    let (key, key_bytes) = rlp::tx_index_key(tx_index);
    let (nibbles, key_len) = rlp::key_nibbles(key, key_bytes);

    let mut expected: [u8; 32] = transactions_root;
    let mut key_pos: u32 = 0;
    let mut finished: bool = false;

    for i in 0..MAX_PROOF_NODES {
        let active = (i < proof_len) & !finished;
        if active {
            let node = proof_nodes[i];
            let node_len = proof_node_lens[i];
            assert(node_len >= 1);
            assert(node_len <= MAX_NODE_LEN);

            // RF-04 / RF-06: el nodo debe corresponder al hash esperado.
            let h = keccak::keccak256::<MAX_NODE_LEN, NODE_HASH_BLOCKS>(node, node_len);
            for k in 0..32 {
                assert(h[k] == expected[k]);
            }

            // RF-03: el nodo es una lista RLP que ocupa exactamente node_len bytes.
            let list = rlp::decode_header(node, 0, node_len);
            assert(list.is_list);
            assert(list.offset + list.len == node_len);

            // Escanear los items de la lista (2 = leaf/extension, 17 = branch).
            let end = list.offset + list.len;
            let mut item_off = [0 as u32; MAX_ITEMS];
            let mut item_len = [0 as u32; MAX_ITEMS];
            let mut item_is_list = [false; MAX_ITEMS];
            let mut cursor = list.offset;
            let mut count: u32 = 0;
            for j in 0..MAX_ITEMS {
                if cursor < end {
                    let it = rlp::decode_header(node, cursor, end);
                    item_off[j] = it.offset;
                    item_len[j] = it.len;
                    item_is_list[j] = it.is_list;
                    cursor = it.offset + it.len;
                    count += 1;
                }
            }
            // Todo el payload debe consumirse en <= 17 items.
            assert(cursor == end);
            assert((count == 2) | (count == 17));

            if count == 17 {
                // ---- Branch ----
                // Las claves RLP(i) son prefix-free: nunca terminamos en un branch.
                assert(key_pos < key_len);
                let nib = nibbles[key_pos] as u32;
                let child_off = item_off[nib];
                let child_len = item_len[nib];
                assert(!item_is_list[nib]);
                // MVP: la referencia al hijo debe ser un hash de 32 bytes.
                assert(child_len == 32);
                for k in 0..32 {
                    expected[k] = node[child_off + k];
                }
                key_pos += 1;
            } else {
                // ---- Leaf o Extension ----
                let poff = item_off[0];
                let plen = item_len[0];
                assert(!item_is_list[0]);
                assert(plen >= 1);

                let first = node[poff];
                let flag = first >> 4;
                assert(flag < 4); // 0/1 extension, 2/3 leaf
                let is_leaf = flag >= 2;
                let odd = (flag == 1) | (flag == 3);
                if !odd {
                    assert((first & 0x0f) == 0);
                }
                let n_path = if odd { 2 * plen - 1 } else { 2 * (plen - 1) };

                // El path debe coincidir con los nibbles pendientes de la clave.
                assert(key_pos + n_path <= key_len);
                for t in 0..MAX_NIBBLES {
                    if t < n_path {
                        let pn = hp_path_nibble(node, poff, odd, t);
                        assert(pn == nibbles[key_pos + t]);
                    }
                }

                let voff = item_off[1];
                let vlen = item_len[1];

                if is_leaf {
                    // RF-05: la clave debe consumirse por completo y el valor
                    // debe ser exactamente serialized_tx.
                    assert(key_pos + n_path == key_len);
                    assert(!item_is_list[1]);
                    assert(vlen == tx_len);
                    for k in 0..MAX_TX_LEN {
                        if k < tx_len {
                            assert(node[voff + k] == serialized_tx[k]);
                        }
                    }
                    // La hoja debe ser el último nodo declarado de la prueba.
                    assert(i as u32 == proof_len - 1);
                    finished = true;
                } else {
                    // Extension: al menos un nibble y referencia hash al hijo.
                    assert(n_path >= 1);
                    assert(!item_is_list[1]);
                    assert(vlen == 32);
                    for k in 0..32 {
                        expected[k] = node[voff + k];
                    }
                    key_pos += n_path;
                }
            }
        }
    }

    // RF-06 / RF-07: la prueba debe haber terminado en una hoja válida.
    assert(finished);
}
