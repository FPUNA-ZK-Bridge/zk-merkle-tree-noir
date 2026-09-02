#!/usr/bin/env python3
"""Fase 3 — genera un fixture donde la tx probada ES un lock(recipient, amount).

Construye un bloque sintético con una transacción `lock(...)` real, arma su prueba
de inclusión MPT y calcula `calldata_offset`. Escribe Prover.fase3.toml con TODOS
los inputs que espera el circuito Fase 3 (incluye recipient, amount, calldata_offset).

Uso (desde noir-merkle/):  python3 scripts/gen_lock_fixture.py
Requiere: pycryptodome.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from trie import build_tx_trie, rlp_encode, rlp_encode_int, keccak256  # noqa: E402
from prepare_inputs import build_inputs, to_prover_toml  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# keccak256("lock(address,uint256)")[0:4]
LOCK_SELECTOR = bytes([0x28, 0x2D, 0x3F, 0xDF])

# ── Valores del lock (cambialos si querés) ────────────────────────────────────
SENDER    = bytes.fromhex("cf7ed3acca5a467e9e704c703e8d87f634fb0fc9")  # to = Sender (informativo; el circuito aún no chequea `to`)
RECIPIENT = bytes.fromhex("f39fd6e51aad88f6f4ce6ab8827279cfffb92266")  # 20 bytes
AMOUNT    = 10 * 10**18                                                # 10 GUA (18 dec)
TX_INDEX  = 3                                                          # posición del lock en el bloque


def imin(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def lock_calldata(recipient: bytes, amount: int) -> bytes:
    # selector(4) || padding(12) || recipient(20) || amount(32) = 68 bytes
    return LOCK_SELECTOR + b"\x00" * 12 + recipient + amount.to_bytes(32, "big")


def legacy_tx(nonce, gasprice, gas, to, value, data, v, r, s) -> bytes:
    return rlp_encode([imin(nonce), imin(gasprice), imin(gas), to, imin(value), data,
                       bytes([v]), r, s])


def main():
    calldata = lock_calldata(RECIPIENT, AMOUNT)
    assert len(calldata) == 68, len(calldata)

    lock_tx = legacy_tx(7, 3_000_000_000, 100_000, SENDER, 0, calldata, 27, b"\x11" * 32, b"\x22" * 32)

    # bloque sintético; el lock va en TX_INDEX
    txs = []
    for i in range(6):
        if i == TX_INDEX:
            txs.append(lock_tx)
        else:
            txs.append(legacy_tx(i + 1, 1_000_000_000, 21_000, bytes([i]) * 20, i, b"", 27,
                                  b"\x33" * 32, b"\x44" * 32))

    # offset del calldata dentro de la tx serializada (único por el selector)
    calldata_offset = lock_tx.index(calldata)

    # ── sanity: espejo de bind.nr (lo que exige el circuito) ──────────────────
    assert lock_tx[calldata_offset:calldata_offset + 4] == LOCK_SELECTOR
    assert lock_tx[calldata_offset + 4:calldata_offset + 16] == b"\x00" * 12
    assert lock_tx[calldata_offset + 16:calldata_offset + 36] == RECIPIENT
    assert lock_tx[calldata_offset + 36:calldata_offset + 68] == AMOUNT.to_bytes(32, "big")

    trie = build_tx_trie(txs)
    proof = trie.prove(rlp_encode_int(TX_INDEX))
    assert keccak256(proof[0]) == trie.root, "el primer nodo no hashea al root"

    case = {
        "transactions_root": "0x" + trie.root.hex(),
        "tx_index": TX_INDEX,
        "serialized_tx": "0x" + lock_tx.hex(),
        "proof_nodes": ["0x" + n.hex() for n in proof],
    }
    inputs = build_inputs(case)  # padding + chequeo de límites del circuito

    def arr(xs):
        return "[" + ", ".join(str(x) for x in xs) + "]"

    toml = to_prover_toml(inputs)
    toml += f"recipient = {arr(list(RECIPIENT))}\n"
    toml += f"amount = {arr(list(AMOUNT.to_bytes(32, 'big')))}\n"
    toml += f"calldata_offset = {calldata_offset}\n"

    out = os.path.join(ROOT, "Prover.fase3.toml")
    open(out, "w").write(toml)

    # rawCase para el relayer/prover (NoirJS): mismo formato que fixtures + campos Fase 3
    case["recipient"] = "0x" + RECIPIENT.hex()
    case["amount"] = str(AMOUNT)
    case["calldata_offset"] = calldata_offset
    raw_out = os.path.join(ROOT, "lock-rawcase.json")
    json.dump(case, open(raw_out, "w"))

    print("✅ Fixture de lock generado y validado")
    print("  transactions_root:", case["transactions_root"])
    print("  tx_index:", TX_INDEX, " calldata_offset:", calldata_offset,
          " serialized_tx:", len(lock_tx), "bytes")
    print("  proof_nodes:", len(proof))
    print("  recipient:", "0x" + RECIPIENT.hex(), " amount:", AMOUNT)
    print("  → escrito:", out)
    print("\nPara ejecutar el circuito:  cp Prover.fase3.toml Prover.toml && nargo execute")


if __name__ == "__main__":
    main()
