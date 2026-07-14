"""Genera fixtures sintéticas para el verificador MPT.

Construye un "bloque" sintético de 300 transacciones, calcula su
transactionsRoot y genera pruebas de inclusión para varios índices:
  - idx 5   : camino branch -> branch -> leaf
  - idx 0   : clave RLP(0) = 0x80 (caso especial)
  - idx 258 : camino con nodo extension (claves 0x82 01 xx comparten prefijo)

Salidas:
  fixtures/*.json  : casos en formato de prepare_inputs.py
  Prover.toml      : ejemplo verificable listo para `nargo execute`
  src/tests.nr     : suite de tests Noir con fixtures embebidas

Uso: python3 scripts/gen_fixtures.py   (desde la raíz del repo)
"""

import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(__file__))
from trie import build_tx_trie, rlp_encode, rlp_encode_int  # noqa: E402
from prepare_inputs import build_inputs, to_prover_toml, MAX_NODE_LEN, MAX_PROOF_NODES, MAX_TX_LEN  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
N_TXS = 300
CASES = [0, 5, 258]


def synth_tx(rng: random.Random, i: int) -> bytes:
    """Transacción sintética tipo legacy: rlp([nonce, gasprice, gas, to, value, data, v, r, s])."""
    fields = [
        rng.randbytes(2),               # nonce
        rng.randbytes(4),               # gasPrice
        rng.randbytes(3),               # gas
        rng.randbytes(20),              # to
        rng.randbytes(4),               # value
        rng.randbytes(rng.randint(0, 40)),  # data
        bytes([27 + (i % 2)]),          # v
        rng.randbytes(32),              # r
        rng.randbytes(32),              # s
    ]
    return rlp_encode([f.lstrip(b"\x00") or b"" for f in fields])


def main():
    rng = random.Random(42)
    txs = [synth_tx(rng, i) for i in range(N_TXS)]
    trie = build_tx_trie(txs)
    root_hex = "0x" + trie.root.hex()
    print(f"transactionsRoot sintético: {root_hex}")

    os.makedirs(os.path.join(ROOT, "fixtures"), exist_ok=True)
    fixtures = {}
    for idx in CASES:
        proof = trie.prove(rlp_encode_int(idx))
        case = {
            "transactions_root": root_hex,
            "tx_index": idx,
            "serialized_tx": "0x" + txs[idx].hex(),
            "proof_nodes": ["0x" + n.hex() for n in proof],
        }
        path = os.path.join(ROOT, "fixtures", f"tx_{idx}.json")
        json.dump(case, open(path, "w"), indent=2)
        fixtures[idx] = build_inputs(case)  # valida límites y hace padding
        kinds = []
        for n in proof:
            items = 17 if n[0] >= 0xF7 and len(n) > 100 else 2  # heurística solo informativa
            kinds.append(str(len(n)))
        print(f"  idx {idx}: {len(proof)} nodos ({', '.join(kinds)} bytes)")

    # Ejemplo verificable en la raíz del repo.
    open(os.path.join(ROOT, "Prover.toml"), "w").write(to_prover_toml(fixtures[258]))
    print("escrito Prover.toml (ejemplo: tx_index=258, camino con extension)")

    # Suite de tests Noir.
    write_tests_nr(fixtures)
    print("escrito src/tests.nr")


def _nr_arr(xs) -> str:
    return "[" + ", ".join(str(x) for x in xs) + "]"


def _nr_fixture(name: str, fx: dict) -> str:
    nodes = ",\n        ".join(_nr_arr(n) for n in fx["proof_nodes"])
    return f"""// ---- fixture tx_index = {fx["tx_index"]} ----
pub global {name}_TX_INDEX: u32 = {fx["tx_index"]};
pub global {name}_TX_LEN: u32 = {fx["tx_len"]};
pub global {name}_PROOF_LEN: u32 = {fx["proof_len"]};
pub global {name}_ROOT: [u8; 32] = {_nr_arr(fx["transactions_root"])};
pub global {name}_TX: [u8; {MAX_TX_LEN}] = {_nr_arr(fx["serialized_tx"])};
pub global {name}_NODE_LENS: [u32; {MAX_PROOF_NODES}] = {_nr_arr(fx["proof_node_lens"])};
pub global {name}_NODES: [[u8; {MAX_NODE_LEN}]; {MAX_PROOF_NODES}] = [
        {nodes}
];
"""


def write_tests_nr(fixtures: dict):
    a = fixtures[5]    # caso base: branch -> branch -> leaf
    b = fixtures[258]  # camino con extension
    c = fixtures[0]    # clave RLP(0)

    src = f"""// Tests generados por scripts/gen_fixtures.py — NO EDITAR A MANO.
// Fixtures: bloque sintético de 300 transacciones (semilla determinística 42).
//
// Ejecutar con: nargo test

use crate::mpt::verify_inclusion;

{_nr_fixture("A", a)}
{_nr_fixture("B", b)}
{_nr_fixture("C", c)}

// Caso de uso 1: prueba válida (branch -> branch -> leaf).
#[test]
fn test_valid_inclusion() {{
    verify_inclusion(A_ROOT, A_TX_INDEX, A_TX, A_TX_LEN, A_NODES, A_NODE_LENS, A_PROOF_LEN);
}}

// Caso de uso 1 (variante): camino que atraviesa un nodo extension.
#[test]
fn test_valid_inclusion_extension_path() {{
    verify_inclusion(B_ROOT, B_TX_INDEX, B_TX, B_TX_LEN, B_NODES, B_NODE_LENS, B_PROOF_LEN);
}}

// Caso de uso 1 (variante): tx_index = 0, clave RLP(0) = 0x80.
#[test]
fn test_valid_inclusion_index_zero() {{
    verify_inclusion(C_ROOT, C_TX_INDEX, C_TX, C_TX_LEN, C_NODES, C_NODE_LENS, C_PROOF_LEN);
}}

// Caso de uso 2: mismo conjunto de nodos con tx_index distinto -> rechazo.
#[test(should_fail)]
fn test_wrong_tx_index() {{
    verify_inclusion(A_ROOT, A_TX_INDEX + 1, A_TX, A_TX_LEN, A_NODES, A_NODE_LENS, A_PROOF_LEN);
}}

// Caso de uso 3: transacción alterada -> rechazo.
#[test(should_fail)]
fn test_altered_tx() {{
    let mut tx = A_TX;
    tx[10] ^= 1;
    verify_inclusion(A_ROOT, A_TX_INDEX, tx, A_TX_LEN, A_NODES, A_NODE_LENS, A_PROOF_LEN);
}}

// Caso de uso 4: transactions_root incorrecto -> rechazo.
#[test(should_fail)]
fn test_wrong_root() {{
    let mut root = A_ROOT;
    root[0] ^= 1;
    verify_inclusion(root, A_TX_INDEX, A_TX, A_TX_LEN, A_NODES, A_NODE_LENS, A_PROOF_LEN);
}}

// Prueba mal formada: un byte corrupto en un nodo intermedio -> rechazo.
#[test(should_fail)]
fn test_corrupted_node() {{
    let mut nodes = A_NODES;
    nodes[1][5] ^= 1;
    verify_inclusion(A_ROOT, A_TX_INDEX, A_TX, A_TX_LEN, nodes, A_NODE_LENS, A_PROOF_LEN);
}}

// Prueba mal formada: estructura RLP inconsistente (longitud truncada) -> rechazo.
#[test(should_fail)]
fn test_truncated_node() {{
    let mut lens = A_NODE_LENS;
    lens[0] -= 1;
    verify_inclusion(A_ROOT, A_TX_INDEX, A_TX, A_TX_LEN, A_NODES, lens, A_PROOF_LEN);
}}

// Prueba incompleta: proof_len menor al camino real -> rechazo.
#[test(should_fail)]
fn test_truncated_proof() {{
    verify_inclusion(A_ROOT, A_TX_INDEX, A_TX, A_TX_LEN, A_NODES, A_NODE_LENS, A_PROOF_LEN - 1);
}}
"""
    open(os.path.join(ROOT, "src", "tests.nr"), "w").write(src)


if __name__ == "__main__":
    main()
