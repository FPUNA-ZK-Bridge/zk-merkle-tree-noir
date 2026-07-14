// Keccak-256 (padding original de Keccak: 0x01 ... 0x80), rate = 136 bytes.
// Implementación autocontenida para no depender de librerías externas.
// N      = tamaño máximo del buffer de entrada (compile-time).
// BLOCKS = cantidad máxima de bloques de 136 bytes a absorber (compile-time).
//          Debe cumplir BLOCKS * 136 >= N + 1 (por el byte de padding).

global RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

// Offsets de rotación rho, indexados como x + 5*y.
global ROT: [u8; 25] = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
];

fn rotl64(x: u64, n: u8) -> u64 {
    if n == 0 {
        x
    } else {
        (x << (n as u64)) | (x >> ((64 - n) as u64))
    }
}

fn keccakf(state: [u64; 25]) -> [u64; 25] {
    let mut s = state;
    for round in 0..24 {
        // theta
        let mut c = [0 as u64; 5];
        for x in 0..5 {
            c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
            for y in 0..5 {
                s[x + 5 * y] ^= d;
            }
        }
        // rho + pi
        let mut b = [0 as u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(s[x + 5 * y], ROT[x + 5 * y]);
            }
        }
        // chi
        for x in 0..5 {
            for y in 0..5 {
                s[x + 5 * y] = b[x + 5 * y] ^ ((!b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y]);
            }
        }
        // iota
        s[0] ^= RC[round];
    }
    s
}

// Keccak-256 de input[0..len]. Los bytes >= len se ignoran.
pub fn keccak256<let N: u32, let BLOCKS: u32>(input: [u8; N], len: u32) -> [u8; 32] {
    assert(len <= N);
    assert(BLOCKS * 136 >= N + 1);

    // Buffer con padding: 0x01 tras el mensaje, 0x80 al final del último bloque usado.
    let mut padded = [0 as u8; 136 * BLOCKS];
    for i in 0..N {
        if i < len {
            padded[i] = input[i];
        }
    }
    padded[len] = 0x01;
    let nb = (len + 136) / 136; // ceil((len + 1) / 136): bloques realmente usados
    let last = nb * 136 - 1;
    padded[last] = padded[last] | 0x80;

    let mut state = [0 as u64; 25];
    for b in 0..BLOCKS {
        let active = b < nb;
        let mut st = state;
        for lane in 0..17 {
            let mut v = 0 as u64;
            for k in 0..8 {
                v |= (padded[b * 136 + lane * 8 + k] as u64) << ((8 * k) as u64);
            }
            st[lane] ^= v;
        }
        let st = keccakf(st);
        if active {
            state = st;
        }
    }

    let mut out = [0 as u8; 32];
    for lane in 0..4 {
        for k in 0..8 {
            out[lane * 8 + k] = ((state[lane] >> ((8 * k) as u64)) & 0xff) as u8;
        }
    }
    out
}
