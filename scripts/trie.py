"""Merkle Patricia Trie de transacciones de Ethereum (off-chain).

Implementación mínima para construir el trie de transacciones de un bloque,
calcular transactionsRoot y generar pruebas de inclusión (lista ordenada de
nodos RLP desde la raíz hasta la hoja).

Requiere: pycryptodome (Keccak-256).
"""

from Crypto.Hash import keccak as _keccak


def keccak256(data: bytes) -> bytes:
    return _keccak.new(digest_bits=256, data=data).digest()


# ---------------------------------------------------------------- RLP

def rlp_encode(item) -> bytes:
    """RLP de bytes o listas anidadas de bytes."""
    if isinstance(item, bytes):
        if len(item) == 1 and item[0] < 0x80:
            return item
        return _rlp_len(len(item), 0x80) + item
    if isinstance(item, list):
        payload = b"".join(rlp_encode(x) for x in item)
        return _rlp_len(len(payload), 0xC0) + payload
    raise TypeError(f"tipo no soportado: {type(item)}")


def _rlp_len(n: int, offset: int) -> bytes:
    if n <= 55:
        return bytes([offset + n])
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(n_bytes)]) + n_bytes


def rlp_encode_int(n: int) -> bytes:
    """RLP de un entero no negativo (big-endian sin ceros a la izquierda)."""
    if n == 0:
        return rlp_encode(b"")
    return rlp_encode(n.to_bytes((n.bit_length() + 7) // 8, "big"))


# ---------------------------------------------------------------- Trie

def to_nibbles(key: bytes) -> tuple:
    out = []
    for b in key:
        out.append(b >> 4)
        out.append(b & 0x0F)
    return tuple(out)


def hp_encode(nibbles: tuple, is_leaf: bool) -> bytes:
    flag = 2 if is_leaf else 0
    if len(nibbles) % 2 == 1:
        nibs = (flag + 1,) + nibbles
    else:
        nibs = (flag, 0) + nibbles
    return bytes(nibs[i] * 16 + nibs[i + 1] for i in range(0, len(nibs), 2))


def hp_decode_path(hp: bytes) -> tuple:
    flag = hp[0] >> 4
    nibs = to_nibbles(hp)
    return nibs[1:] if flag in (1, 3) else nibs[2:]


class Trie:
    """Trie hexario inmutable construido a partir de pares (clave, valor).

    Estructura de nodo (forma RLP directa):
      leaf      -> [hp_path, value]
      extension -> [hp_path, ref(child)]
      branch    -> [ref0..ref15, value]
    donde ref(x) = keccak256(rlp(x)) si len(rlp(x)) >= 32, o el nodo embebido.
    """

    def __init__(self, items):
        self._by_hash = {}
        pairs = sorted((to_nibbles(k), v) for k, v in items)
        if not pairs:
            self.root_node = None
            self.root = keccak256(rlp_encode(b""))
            return
        self.root_node = self._build(pairs)
        self.root = keccak256(rlp_encode(self.root_node))

    def _build(self, pairs):
        if len(pairs) == 1:
            nibs, value = pairs[0]
            node = [hp_encode(nibs, True), value]
        else:
            first = pairs[0][0]
            prefix_len = len(first)
            for nibs, _ in pairs[1:]:
                common = 0
                while common < min(prefix_len, len(nibs)) and nibs[common] == first[common]:
                    common += 1
                prefix_len = min(prefix_len, common)
            if prefix_len > 0:
                child = self._build([(nibs[prefix_len:], v) for nibs, v in pairs])
                node = [hp_encode(first[:prefix_len], False), self._ref(child)]
            else:
                groups = {}
                branch_value = b""
                for nibs, v in pairs:
                    if len(nibs) == 0:
                        branch_value = v  # no ocurre con claves RLP(i): son prefix-free
                    else:
                        groups.setdefault(nibs[0], []).append((nibs[1:], v))
                node = [b""] * 17
                for nib, group in groups.items():
                    node[nib] = self._ref(self._build(group))
                node[16] = branch_value
        self._by_hash[keccak256(rlp_encode(node))] = node
        return node

    def _ref(self, node):
        encoded = rlp_encode(node)
        return node if len(encoded) < 32 else keccak256(encoded)

    def prove(self, key: bytes):
        """Prueba de inclusión: [nodos RLP] desde la raíz hasta la hoja.

        Solo incluye nodos referenciados por hash (>= 32 bytes); un nodo
        embebido en el camino lanza error (no soportado por el circuito MVP).
        """
        nibs = to_nibbles(key)
        proof = []
        node = self.root_node
        while True:
            proof.append(rlp_encode(node))
            if len(node) == 17:  # branch
                assert nibs, "clave agotada en un branch"
                ref = node[nibs[0]]
                assert ref != b"", "la clave no existe en el trie"
                nibs = nibs[1:]
                node = self._resolve(ref)
            else:  # leaf / extension
                flag = node[0][0] >> 4
                path = hp_decode_path(node[0])
                if flag >= 2:  # leaf
                    assert nibs == path, "la clave no coincide con la hoja"
                    return proof
                assert nibs[: len(path)] == path, "la clave no coincide con la extensión"
                nibs = nibs[len(path):]
                node = self._resolve(node[1])

    def _resolve(self, ref):
        if isinstance(ref, list):
            raise ValueError("nodo embebido en el camino: no soportado por el MVP")
        return self._by_hash[bytes(ref)]

def build_tx_trie(txs):
    """Trie de transacciones: clave RLP(i), valor = transacción serializada."""
    return Trie([(rlp_encode_int(i), tx) for i, tx in enumerate(txs)])
