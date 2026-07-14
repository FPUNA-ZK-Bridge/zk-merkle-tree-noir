"""Prepara inputs para el circuito Noir (padding + formato).

Uso:
    python3 prepare_inputs.py caso.json [--prover salida/Prover.toml] [--json salida/inputs.json]

Formato de caso.json:
{
  "transactions_root": "0x...32 bytes hex",
  "tx_index": 5,
  "serialized_tx": "0x...hex",
  "proof_nodes": ["0x...hex", ...]        # nodos RLP, de la raíz a la hoja
}

Genera Prover.toml (para `nargo prove/execute`) y/o inputs.json (para noir_js),
con las entradas padded a los límites del circuito (ver src/types.nr).
"""

import argparse
import json
import sys

# Límites: deben coincidir con src/types.nr.
MAX_PROOF_NODES = 6
MAX_NODE_LEN = 532
MAX_TX_LEN = 512


def _unhex(s: str) -> bytes:
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


def check_limits(root: bytes, tx_index: int, tx: bytes, nodes: list):
    errors = []
    if len(root) != 32:
        errors.append(f"transactions_root debe tener 32 bytes, tiene {len(root)}")
    if not (0 <= tx_index < 65536):
        errors.append("tx_index debe estar en [0, 65536)")
    if not (1 <= len(tx) <= MAX_TX_LEN):
        errors.append(f"serialized_tx: {len(tx)} bytes (máx {MAX_TX_LEN})")
    if not (1 <= len(nodes) <= MAX_PROOF_NODES):
        errors.append(f"proof_nodes: {len(nodes)} nodos (máx {MAX_PROOF_NODES})")
    for i, n in enumerate(nodes):
        if len(n) > MAX_NODE_LEN:
            errors.append(f"nodo {i}: {len(n)} bytes (máx {MAX_NODE_LEN})")
        if i > 0 and len(n) < 32:
            errors.append(f"nodo {i}: nodo embebido (<32 bytes) no soportado por el MVP")
    if errors:
        raise ValueError("inputs fuera de los límites del circuito:\n  - " + "\n  - ".join(errors))


def build_inputs(case: dict) -> dict:
    root = _unhex(case["transactions_root"])
    tx = _unhex(case["serialized_tx"])
    nodes = [_unhex(n) for n in case["proof_nodes"]]
    tx_index = int(case["tx_index"])
    check_limits(root, tx_index, tx, nodes)

    pad_tx = list(tx) + [0] * (MAX_TX_LEN - len(tx))
    pad_nodes = [list(n) + [0] * (MAX_NODE_LEN - len(n)) for n in nodes]
    pad_nodes += [[0] * MAX_NODE_LEN] * (MAX_PROOF_NODES - len(nodes))
    node_lens = [len(n) for n in nodes] + [0] * (MAX_PROOF_NODES - len(nodes))

    return {
        "transactions_root": list(root),
        "tx_index": tx_index,
        "serialized_tx": pad_tx,
        "tx_len": len(tx),
        "proof_nodes": pad_nodes,
        "proof_node_lens": node_lens,
        "proof_len": len(nodes),
    }


def to_prover_toml(inputs: dict) -> str:
    def arr(xs):
        return "[" + ", ".join(str(x) for x in xs) + "]"

    lines = [
        f"transactions_root = {arr(inputs['transactions_root'])}",
        f"tx_index = {inputs['tx_index']}",
        f"serialized_tx = {arr(inputs['serialized_tx'])}",
        f"tx_len = {inputs['tx_len']}",
        "proof_nodes = [",
    ]
    for node in inputs["proof_nodes"]:
        lines.append("    " + arr(node) + ",")
    lines.append("]")
    lines.append(f"proof_node_lens = {arr(inputs['proof_node_lens'])}")
    lines.append(f"proof_len = {inputs['proof_len']}")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("case", help="JSON con transactions_root, tx_index, serialized_tx, proof_nodes")
    ap.add_argument("--prover", help="ruta de salida para Prover.toml")
    ap.add_argument("--json", dest="json_out", help="ruta de salida para inputs.json (noir_js)")
    args = ap.parse_args()

    case = json.load(open(args.case))
    inputs = build_inputs(case)

    if args.prover:
        open(args.prover, "w").write(to_prover_toml(inputs))
        print(f"escrito {args.prover}")
    if args.json_out:
        json.dump(inputs, open(args.json_out, "w"))
        print(f"escrito {args.json_out}")
    if not args.prover and not args.json_out:
        json.dump(inputs, sys.stdout)


if __name__ == "__main__":
    main()
