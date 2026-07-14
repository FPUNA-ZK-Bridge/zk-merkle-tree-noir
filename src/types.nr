// Límites máximos del circuito (ver README).
// Cambiarlos requiere recompilar el circuito y regenerar inputs con el mismo padding.

// Cantidad máxima de nodos en una prueba MPT (profundidad del camino raíz -> hoja).
pub global MAX_PROOF_NODES: u32 = 6;

// Tamaño máximo en bytes de un nodo RLP.
// Un branch lleno con 17 referencias hash ocupa 532 bytes: es la cota dominante.
pub global MAX_NODE_LEN: u32 = 532;

// Bloques Keccak necesarios para hashear un nodo: ceil((MAX_NODE_LEN + 1) / 136).
pub global NODE_HASH_BLOCKS: u32 = 4;

// Tamaño máximo de la transacción serializada (RLP o typed tx envelope).
// Debe cumplir MAX_TX_LEN + ~16 <= MAX_NODE_LEN para que el nodo hoja quepa.
pub global MAX_TX_LEN: u32 = 512;

// Longitud máxima de la clave del trie en nibbles.
// La clave es RLP(tx_index); con tx_index < 65536 ocupa a lo sumo 3 bytes = 6 nibbles.
pub global MAX_KEY_BYTES: u32 = 3;
pub global MAX_NIBBLES: u32 = 6;

// Máximo de items en un nodo RLP (branch = 17).
pub global MAX_ITEMS: u32 = 17;

// Resultado de decodificar un header RLP.
pub struct RlpItem {
    // Offset del payload dentro del buffer.
    pub offset: u32,
    // Longitud del payload en bytes.
    pub len: u32,
    // true si el item es una lista, false si es un string.
    pub is_list: bool,
}
