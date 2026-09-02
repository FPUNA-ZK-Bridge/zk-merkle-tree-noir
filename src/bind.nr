// bind.nr — Fase 3: ata la prueba MPT a un lock(recipient, amount) concreto.
//
// Va DENTRO del proyecto Noir (noir-merkle): copialo a src/bind.nr y agregá
// `mod bind;` en src/main.nr. NO fue compilado en el entorno donde se generó;
// probable que necesite ajustes de tipos al correr `nargo compile`.
//
// Idea: el calldata de `lock(address,uint256)` es determinista:
//   selector(4) || padding(12 ceros) || recipient(20) || amount(32)  = 68 bytes
// El prover pasa `calldata_offset` (dónde arranca ese calldata dentro de la tx
// serializada) como HINT privado; el circuito verifica que esos bytes coincidan
// con los inputs públicos recipient/amount. Así, una prueba válida garantiza que
// la tx incluida en el bloque es un lock a esos valores.

use crate::types::MAX_TX_LEN;

// keccak256("lock(address,uint256)")[0..4] = 0x282d3fdf
global LOCK_SELECTOR: [u8; 4] = [40, 45, 63, 223];

pub fn assert_lock_calldata(
    tx: [u8; MAX_TX_LEN],
    off: u32,
    recipient: [u8; 20],
    amount: [u8; 32],
) {
    // selector (4 bytes)
    for i in 0..4 {
        assert(tx[off + i] == LOCK_SELECTOR[i]);
    }
    // padding ABI de la address (12 bytes en cero)
    for i in 0..12 {
        assert(tx[off + 4 + i] == 0);
    }
    // recipient (20 bytes) == input público
    for i in 0..20 {
        assert(tx[off + 16 + i] == recipient[i]);
    }
    // amount (32 bytes, big-endian, igual que uint256) == input público
    for i in 0..32 {
        assert(tx[off + 36 + i] == amount[i]);
    }
}

// NOTA de robustez (hardening pendiente): esto NO verifica que el campo `to` de la
// transacción sea el contrato Sender. Para cerrarlo del todo hay que parsear el
// sobre RLP de la tx y comparar `to == SENDER_ADDR`. Con lo de arriba ya se ata
// (recipient, amount) a un calldata con forma de lock dentro de una tx incluida y
// finalizada; el binding de `to` es el siguiente paso.
