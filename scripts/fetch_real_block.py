"""Baja un bloque real de Ethereum por RPC y genera una fixture verificable.

Reconstruye byte-a-byte cada transacción del bloque (legacy + typed EIP-2930/1559/
4844/7702), arma el Merkle Patricia Trie de transacciones con scripts/trie.py y
**verifica** que la raíz reconstruida coincide con el `transactionsRoot` del header.
Solo entonces elige una transacción que quepa en los límites del circuito, extrae su
prueba de inclusión y escribe una fixture en el formato de prepare_inputs.py.

La verificación de la raíz es la garantía de correctitud: si el re-encoding de alguna
tx fuera incorrecto (p. ej. un tipo no soportado), la raíz no coincidiría y el script
aborta en lugar de emitir una fixture inválida.

Uso:
    python3 scripts/fetch_real_block.py                      # bloque por defecto (all-legacy, seguro)
    python3 scripts/fetch_real_block.py --block finalized    # bloque finalizado actual
    python3 scripts/fetch_real_block.py --block 20000000     # por número
    python3 scripts/fetch_real_block.py --index 3            # una tx concreta
    python3 scripts/fetch_real_block.py --rpc https://mi-endpoint

Requiere: pycryptodome (ya usado por trie.py). Sin más dependencias (urllib stdlib).
"""

import argparse
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
from trie import build_tx_trie, rlp_encode, rlp_encode_int  # noqa: E402
from prepare_inputs import build_inputs, MAX_PROOF_NODES, MAX_NODE_LEN, MAX_TX_LEN  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RPC = os.environ.get("ETH_RPC_URL", "https://ethereum-rpc.publicnode.com")
# Bloque pre-Berlin (2020): todas las txs son legacy, reconstrucción garantizada.
DEFAULT_BLOCK = "11000000"

# Muchos RPC públicos están detrás de Cloudflare y rechazan el User-Agent por
# defecto de urllib con 403. Usamos uno de navegador.
USER_AGENT = "Mozilla/5.0 (compatible; noir-mpt-verifier/1.0)"

# RPCs públicos sin API key, probados en orden si el principal falla.
FALLBACK_RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
    "https://rpc.flashbots.net",
    "https://cloudflare-eth.com",
]


# ----------------------------------------------------------- helpers de campo

def q(x) -> int:
    """Hex-quantity ('0x1a') -> int."""
    return int(x, 16) if isinstance(x, str) else int(x)


def to_b(n: int) -> bytes:
    """int -> bytes big-endian mínimos (0 -> b'', como exige RLP)."""
    return b"" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big")


def data_b(x) -> bytes:
    if x in (None, "0x", "", "0x0"):
        return b""
    return bytes.fromhex(x[2:])


def addr_b(x) -> bytes:
    """Dirección de 20 bytes; None (creación de contrato) -> b''."""
    return b"" if x in (None, "0x", "") else bytes.fromhex(x[2:])


def y_parity(tx) -> int:
    return q(tx["yParity"]) if "yParity" in tx else q(tx["v"])


def enc_access_list(al):
    out = []
    for e in (al or []):
        out.append([addr_b(e["address"]), [bytes.fromhex(k[2:]) for k in e.get("storageKeys", [])]])
    return out


def enc_auth_list(al):
    out = []
    for e in (al or []):
        out.append([
            to_b(q(e["chainId"])), addr_b(e["address"]), to_b(q(e["nonce"])),
            to_b(q(e.get("yParity", e.get("v")))), to_b(q(e["r"])), to_b(q(e["s"])),
        ])
    return out


# ----------------------------------------------------- re-encoding de tx -> bytes

def encode_tx(tx: dict) -> bytes:
    """Serialización canónica de la transacción tal como se almacena en el trie."""
    t = q(tx.get("type", "0x0"))
    to = tx.get("to")

    if t == 0:  # legacy
        return rlp_encode([
            to_b(q(tx["nonce"])), to_b(q(tx["gasPrice"])), to_b(q(tx["gas"])),
            addr_b(to), to_b(q(tx["value"])), data_b(tx["input"]),
            to_b(q(tx["v"])), to_b(q(tx["r"])), to_b(q(tx["s"])),
        ])
    if t == 1:  # EIP-2930
        return b"\x01" + rlp_encode([
            to_b(q(tx["chainId"])), to_b(q(tx["nonce"])), to_b(q(tx["gasPrice"])),
            to_b(q(tx["gas"])), addr_b(to), to_b(q(tx["value"])), data_b(tx["input"]),
            enc_access_list(tx.get("accessList")), to_b(y_parity(tx)), to_b(q(tx["r"])), to_b(q(tx["s"])),
        ])
    if t == 2:  # EIP-1559
        return b"\x02" + rlp_encode([
            to_b(q(tx["chainId"])), to_b(q(tx["nonce"])), to_b(q(tx["maxPriorityFeePerGas"])),
            to_b(q(tx["maxFeePerGas"])), to_b(q(tx["gas"])), addr_b(to), to_b(q(tx["value"])),
            data_b(tx["input"]), enc_access_list(tx.get("accessList")),
            to_b(y_parity(tx)), to_b(q(tx["r"])), to_b(q(tx["s"])),
        ])
    if t == 3:  # EIP-4844 (blob)
        return b"\x03" + rlp_encode([
            to_b(q(tx["chainId"])), to_b(q(tx["nonce"])), to_b(q(tx["maxPriorityFeePerGas"])),
            to_b(q(tx["maxFeePerGas"])), to_b(q(tx["gas"])), addr_b(to), to_b(q(tx["value"])),
            data_b(tx["input"]), enc_access_list(tx.get("accessList")),
            to_b(q(tx["maxFeePerBlobGas"])), [bytes.fromhex(h[2:]) for h in tx["blobVersionedHashes"]],
            to_b(y_parity(tx)), to_b(q(tx["r"])), to_b(q(tx["s"])),
        ])
    if t == 4:  # EIP-7702 (set code)
        return b"\x04" + rlp_encode([
            to_b(q(tx["chainId"])), to_b(q(tx["nonce"])), to_b(q(tx["maxPriorityFeePerGas"])),
            to_b(q(tx["maxFeePerGas"])), to_b(q(tx["gas"])), addr_b(to), to_b(q(tx["value"])),
            data_b(tx["input"]), enc_access_list(tx.get("accessList")),
            enc_auth_list(tx.get("authorizationList")), to_b(y_parity(tx)), to_b(q(tx["r"])), to_b(q(tx["s"])),
        ])
    raise ValueError(f"tipo de transacción no soportado: {t}")


# ------------------------------------------------------------------------ RPC

def rpc(url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    })
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.load(r)
    if out.get("error"):
        raise RuntimeError(f"RPC error: {out['error']}")
    return out["result"]


def get_block(user_rpc: str, tag: str):
    """Prueba el RPC del usuario primero y luego los de respaldo hasta obtener el bloque."""
    urls, seen = [], set()
    for u in [user_rpc, *FALLBACK_RPCS]:
        if u and u not in seen:
            seen.add(u)
            urls.append(u)
    last = None
    for u in urls:
        try:
            print(f"  · {u} …", end=" ", flush=True)
            blk = rpc(u, "eth_getBlockByNumber", [tag, True])
            if blk is not None:
                print("ok")
                return blk, u
            print("bloque no encontrado")
            last = f"{u}: bloque no encontrado"
        except Exception as e:  # noqa: BLE001 — red/HTTP/JSON: probamos el siguiente
            print("falló")
            last = f"{u}: {e}"
    raise SystemExit(
        f"No se pudo obtener el bloque de ningún RPC. Último error -> {last}\n"
        "Pasa uno propio con --rpc o export ETH_RPC_URL=…"
    )


def block_tag(s: str) -> str:
    if s in ("latest", "finalized", "safe", "pending", "earliest"):
        return s
    return s if s.startswith("0x") else hex(int(s))


# ----------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Bloque real de Ethereum -> fixture del circuito MPT")
    ap.add_argument("--rpc", default=DEFAULT_RPC, help=f"endpoint JSON-RPC (def: {DEFAULT_RPC})")
    ap.add_argument("--block", default=DEFAULT_BLOCK, help="número, 0x-hex o tag (latest/finalized/…)")
    ap.add_argument("--index", type=int, default=None, help="índice de tx a probar (def: auto, la más pequeña que quepa)")
    ap.add_argument("--out", default=os.path.join(ROOT, "fixtures", "real_block.json"), help="ruta de salida")
    args = ap.parse_args()

    print(f"Bloque: {args.block}  ->  descargando…")
    blk, used_rpc = get_block(args.rpc, block_tag(args.block))
    print(f"RPC usado: {used_rpc}")

    txs = blk["transactions"]
    number = q(blk["number"])
    header_root = blk["transactionsRoot"].lower()
    print(f"Bloque #{number}: {len(txs)} transacciones · transactionsRoot {header_root[:18]}…")
    if not txs:
        sys.exit("El bloque no tiene transacciones; prueba otro.")

    # Re-serializar TODAS las txs (el trie completo es necesario para cualquier prueba).
    types_seen = {}
    try:
        raw = [encode_tx(t) for t in txs]
    except (KeyError, ValueError) as e:
        sys.exit(f"No se pudo re-serializar una tx ({e}). Prueba un bloque más antiguo (--block 11000000).")
    for t in txs:
        ty = q(t.get("type", "0x0"))
        types_seen[ty] = types_seen.get(ty, 0) + 1

    # Verificación de correctitud: raíz reconstruida == header.
    trie = build_tx_trie(raw)
    recon_root = "0x" + trie.root.hex()
    if recon_root != header_root:
        print(f"  tipos de tx presentes: {types_seen}")
        sys.exit(
            "La raíz reconstruida NO coincide con transactionsRoot:\n"
            f"  reconstruida: {recon_root}\n  header:       {header_root}\n"
            "Probablemente hay un tipo de tx no soportado en este bloque. "
            "Prueba un bloque pre-Berlin (todas legacy), p. ej. --block 11000000."
        )
    print(f"✓ raíz reconstruida coincide con el header (tipos: {types_seen})")

    # Elegir tx objetivo: la indicada, o la más pequeña que satisfaga los límites.
    def fits(i):
        try:
            proof = trie.prove(rlp_encode_int(i))
            case = {
                "transactions_root": recon_root,
                "tx_index": i,
                "serialized_tx": "0x" + raw[i].hex(),
                "proof_nodes": ["0x" + n.hex() for n in proof],
            }
            build_inputs(case)  # valida TODOS los límites del circuito
            return case, proof
        except (ValueError, AssertionError, KeyError):
            return None

    chosen = None
    if args.index is not None:
        r = fits(args.index)
        if not r:
            sys.exit(f"La tx #{args.index} no cabe en los límites del circuito "
                     f"(máx {MAX_TX_LEN}B tx, {MAX_PROOF_NODES} nodos, {MAX_NODE_LEN}B/nodo). Prueba otra.")
        chosen = (args.index, *r)
    else:
        for _, i in sorted((len(b), i) for i, b in enumerate(raw)):
            r = fits(i)
            if r:
                chosen = (i, *r)
                break
        if not chosen:
            sys.exit("Ninguna tx de este bloque cabe en los límites del circuito. Prueba otro bloque.")

    idx, case, proof = chosen
    with open(args.out, "w") as f:
        json.dump(case, f, indent=2)

    print()
    print(f"✓ Fixture escrita: {args.out}")
    print(f"  tx_index    : {idx}")
    print(f"  tx bytes    : {len(raw[idx])} / {MAX_TX_LEN}")
    print(f"  profundidad : {len(proof)} nodos / {MAX_PROOF_NODES}  (tamaños: {', '.join(str(len(n)) for n in proof)})")
    print(f"  tx hash     : {txs[idx].get('hash')}")
    print()
    print("Pégalo en el front (botón «Pegar mi propio JSON»):")
    print(json.dumps(case))


if __name__ == "__main__":
    main()
