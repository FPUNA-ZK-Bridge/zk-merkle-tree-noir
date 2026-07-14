// Utilidades RLP mínimas: solo lo indispensable para verificar la prueba MPT.
use crate::types::{MAX_KEY_BYTES, MAX_NIBBLES, RlpItem};

// Decodifica el header RLP del item que comienza en buf[offset].
// `limit` es el fin válido del buffer (longitud real de datos en buf).
// Devuelve offset y longitud del payload, y si es lista o string.
pub fn decode_header<let N: u32>(buf: [u8; N], offset: u32, limit: u32) -> RlpItem {
    assert(limit <= N);
    assert(offset < limit);
    let prefix = buf[offset];

    let mut item = RlpItem { offset: 0, len: 0, is_list: false };

    if prefix < 0x80 {
        // Byte único, su propio payload.
        item = RlpItem { offset, len: 1, is_list: false };
    } else if prefix < 0xb8 {
        // String corto (0-55 bytes).
        item = RlpItem { offset: offset + 1, len: (prefix as u32) - 0x80, is_list: false };
    } else if prefix == 0xb8 {
        // String largo, longitud en 1 byte.
        assert(offset + 1 < limit);
        let l = buf[offset + 1] as u32;
        assert(l > 55); // canonicidad mínima
        item = RlpItem { offset: offset + 2, len: l, is_list: false };
    } else if prefix == 0xb9 {
        // String largo, longitud en 2 bytes.
        assert(offset + 2 < limit);
        let l = (buf[offset + 1] as u32) * 256 + (buf[offset + 2] as u32);
        assert(l > 255);
        item = RlpItem { offset: offset + 3, len: l, is_list: false };
    } else if prefix < 0xf8 {
        assert(prefix >= 0xc0);
        // Lista corta.
        item = RlpItem { offset: offset + 1, len: (prefix as u32) - 0xc0, is_list: true };
    } else if prefix == 0xf8 {
        assert(offset + 1 < limit);
        let l = buf[offset + 1] as u32;
        assert(l > 55);
        item = RlpItem { offset: offset + 2, len: l, is_list: true };
    } else if prefix == 0xf9 {
        assert(offset + 2 < limit);
        let l = (buf[offset + 1] as u32) * 256 + (buf[offset + 2] as u32);
        assert(l > 255);
        item = RlpItem { offset: offset + 3, len: l, is_list: true };
    } else {
        // Longitudes de 3+ bytes exceden MAX_NODE_LEN: no soportado.
        assert(false);
    }

    // El payload debe caber dentro del buffer válido.
    assert(item.offset + item.len <= limit);
    item
}

// RLP(tx_index) para tx_index < 65536. Devuelve (bytes, longitud).
pub fn tx_index_key(tx_index: u32) -> ([u8; MAX_KEY_BYTES], u32) {
    assert(tx_index < 65536);
    let mut key = [0 as u8; MAX_KEY_BYTES];
    let mut len: u32 = 0;
    if tx_index == 0 {
        key[0] = 0x80; // RLP de string vacío: el entero 0 se codifica como b""
        len = 1;
    } else if tx_index < 0x80 {
        key[0] = tx_index as u8;
        len = 1;
    } else if tx_index < 0x100 {
        key[0] = 0x81;
        key[1] = tx_index as u8;
        len = 2;
    } else {
        key[0] = 0x82;
        key[1] = (tx_index >> 8) as u8;
        key[2] = (tx_index & 0xff) as u8;
        len = 3;
    }
    (key, len)
}

// Expande los bytes de la clave a nibbles. Devuelve (nibbles, cantidad).
pub fn key_nibbles(key: [u8; MAX_KEY_BYTES], key_len: u32) -> ([u8; MAX_NIBBLES], u32) {
    let mut nibbles = [0 as u8; MAX_NIBBLES];
    for i in 0..MAX_KEY_BYTES {
        if i < key_len {
            nibbles[2 * i] = key[i] >> 4;
            nibbles[2 * i + 1] = key[i] & 0x0f;
        }
    }
    (nibbles, 2 * key_len)
}
