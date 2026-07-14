# noir-mpt-verifier

Circuito en **Noir** que verifica la inclusión de una transacción Ethereum en el trie de transacciones de un bloque, validando una prueba de **Merkle Patricia Trie (MPT)** contra el `transactionsRoot` del header.

No reconstruye el bloque: recibe una prueba (secuencia de nodos RLP de la raíz a la hoja) preparada off-chain y verifica dentro del circuito que la clave `RLP(tx_index)` conduce exactamente al valor `serialized_tx` y que el encadenamiento Keccak-256 termina en la raíz pública.

## Estructura

```
src/main.nr        Entradas del circuito y orquestación
src/mpt.nr         Recorrido del trie: branch / extension / leaf
src/rlp.nr         Decodificación mínima de headers RLP y clave RLP(tx_index)
src/keccak.nr      Keccak-256 autocontenido (padding 0x01…0x80, rate 136)
src/types.nr       Límites máximos del circuito y tipos
src/tests.nr       Suite de tests (generada por scripts/gen_fixtures.py)
scripts/trie.py            MPT off-chain: construcción, raíz y pruebas
scripts/gen_fixtures.py    Genera fixtures sintéticas, Prover.toml y tests.nr
scripts/prepare_inputs.py  Padding y formato de inputs (Prover.toml / JSON)
fixtures/          Casos de ejemplo en JSON
Prover.toml        Ejemplo verificable (tx_index=258, camino con extension)
```

## Interfaz del circuito

| Entrada | Tipo | Visibilidad |
|---|---|---|
| `transactions_root` | `[u8; 32]` | **pública** |
| `tx_index` | `u32` | privada |
| `serialized_tx` | `[u8; 512]` (padded) + `tx_len: u32` | privada |
| `proof_nodes` | `[[u8; 532]; 6]` (padded) + `proof_node_lens` | privada |
| `proof_len` | `u32` | privada |

El circuito no devuelve datos: si todas las constraints se satisfacen, la inclusión queda demostrada. Cualquier inconsistencia (índice, valor, RLP, hash o raíz) hace fallar la prueba.

## Límites del circuito (src/types.nr)

| Constante | Valor | Significado |
|---|---|---|
| `MAX_PROOF_NODES` | 6 | Profundidad máxima del camino raíz→hoja |
| `MAX_NODE_LEN` | 532 | Bytes máximos por nodo RLP (branch lleno = 532) |
| `MAX_TX_LEN` | 512 | Bytes máximos de la transacción serializada |
| `MAX_NIBBLES` | 6 | Clave `RLP(tx_index)` con `tx_index < 65536` |

Para cambiarlos: editar `types.nr` (y `NODE_HASH_BLOCKS = ceil((MAX_NODE_LEN+1)/136)`), replicar los valores en `scripts/prepare_inputs.py` y regenerar fixtures.

### Limitaciones del MVP
- Solo referencias entre nodos por hash Keccak-256 (32 bytes). Los nodos embebidos (RLP < 32 bytes) no están soportados; `prepare_inputs.py` los rechaza. En tries de transacciones reales prácticamente no ocurren, porque los valores (transacciones) superan los 32 bytes.
- Sin terminación en el slot de valor de un branch: las claves `RLP(i)` son prefix-free, así que la terminación ocurre siempre en una hoja.
- `tx_index < 65536` (cubre cualquier bloque real).

## Uso

Requisitos: [nargo](https://noir-lang.org) ≥ 1.0.0 (probado con 1.0.0-beta.22) y Python 3 con `pycryptodome` para los scripts off-chain.

```bash
pip install pycryptodome

# Regenerar fixtures, Prover.toml y src/tests.nr (bloque sintético de 300 txs)
python3 scripts/gen_fixtures.py

# Correr la suite de tests (3 positivos + 6 negativos)
nargo test

# Ejecutar el ejemplo verificable (Prover.toml)
nargo execute
```

### Verificar una transacción propia

1. Obtener off-chain: `transactionsRoot` del bloque, `tx_index`, la transacción serializada (RLP legacy o typed envelope completo, **no** el hash) y los nodos RLP de la prueba MPT (p. ej. construyendo el trie con `scripts/trie.py` a partir de todas las transacciones del bloque).
2. Escribir un JSON con ese formato (ver `fixtures/tx_5.json`).
3. Generar inputs padded:

```bash
python3 scripts/prepare_inputs.py caso.json --prover Prover.toml
nargo execute
```

## Formato de la prueba

`proof_nodes[0]` es el nodo raíz (su Keccak-256 debe ser `transactions_root`); cada nodo siguiente debe hashear al valor referenciado por su padre según el nibble correspondiente de la clave. El último nodo es la hoja cuyo valor es exactamente `serialized_tx`. El padding a los tamaños máximos se hace fuera del circuito.

## Tests

`src/tests.nr` cubre los casos de uso del documento de requerimientos:

- válido: camino branch→branch→leaf (idx 5), camino con extension (idx 258), clave `RLP(0)` (idx 0)
- rechazo: `tx_index` incorrecto, transacción alterada, raíz incorrecta, nodo corrupto, RLP truncado, prueba incompleta

Las fixtures son sintéticas y deterministas (semilla 42), generadas con la misma semántica MPT de Ethereum (verificada contra la raíz del trie vacío `0x56e81f...b421`).
