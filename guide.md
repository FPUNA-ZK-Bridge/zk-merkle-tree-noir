# Guía paso a paso: compilar, ejecutar, probar y verificar

Flujo completo del verificador de inclusión MPT, desde cero hasta una prueba ZK verificada. Todos los comandos se ejecutan desde la raíz del repo.

## Requisitos

| Herramienta | Para qué |
|---|---|
| `nargo` (Noir ≥ 1.0.0) | Compilar el circuito, correr tests y generar el witness |
| `bb` (Barretenberg) | Generar y verificar la prueba ZK |
| Python 3 + `pycryptodome` | Scripts off-chain (trie, fixtures, padding de inputs) |

```bash
# Instalar toolchain de Noir (si no lo tienes)
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup

# Instalar Barretenberg (si no lo tienes)
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
bbup

# Dependencia de los scripts off-chain
pip install pycryptodome
```

## 1. Generar las entradas (off-chain)

```bash
python3 scripts/gen_fixtures.py
```

**Qué hace:** construye un bloque sintético de 300 transacciones, arma su Merkle Patricia Trie y calcula el `transactionsRoot`. Genera las pruebas de inclusión y escribe tres salidas: `fixtures/*.json` (casos crudos), `Prover.toml` (entradas ya padded para el circuito, caso `tx_index=258`) y `src/tests.nr` (suite de tests con las fixtures embebidas).

**Por qué existe:** el circuito no consulta ningún nodo Ethereum; toda la preparación de datos (RF-08) ocurre fuera. Este script cumple ese rol con datos sintéticos deterministas (semilla 42).

Para verificar una transacción propia en lugar de las fixtures:

```bash
python3 scripts/prepare_inputs.py mi_caso.json --prover Prover.toml
```

**Qué hace:** toma un JSON con `transactions_root`, `tx_index`, `serialized_tx` y `proof_nodes` (hex), valida que respete los límites del circuito (máx. 6 nodos, 532 bytes/nodo, tx ≤ 512 bytes) y escribe el `Prover.toml` con el padding correcto.

## 2. Correr la suite de tests

```bash
nargo test
```

**Qué hace:** compila el proyecto y ejecuta los 9 tests de `src/tests.nr`: 3 positivos (camino branch→branch→leaf, camino con nodo extension, clave `RLP(0)`) y 6 negativos marcados `should_fail` (índice incorrecto, transacción alterada, raíz incorrecta, nodo corrupto, RLP truncado, prueba incompleta).

**Para qué sirve:** confirma que el circuito acepta pruebas válidas y rechaza todas las variantes inválidas antes de generar pruebas reales.

## 3. Compilar el circuito

```bash
nargo compile
```

**Qué hace:** compila `src/` a ACIR (la representación de constraints que consume el prover) y escribe `target/noir_mpt_verifier.json`. 

**Nota:** `nargo execute` (paso 4) compila automáticamente si hace falta, así que este paso es opcional como comando separado.

## 4. Ejecutar el circuito y generar el witness

```bash
nargo execute
```

**Qué hace:** lee las entradas de `Prover.toml`, ejecuta el circuito con ellas y, si todas las constraints se satisfacen (la prueba MPT es válida), escribe el **witness** en `target/noir_mpt_verifier.gz`. Si alguna entrada es inconsistente, falla aquí con "Cannot satisfy constraint".

**Para qué sirve:** el witness es la asignación completa de valores del circuito; es el insumo que necesita `bb` para generar la prueba ZK.

## 5. Generar la verification key

```bash
bb write_vk -b target/noir_mpt_verifier.json -o target
```

**Qué hace:** deriva del circuito compilado (`-b`) la **verification key** y la guarda en `target/vk`.

**Para qué sirve:** la vk identifica unívocamente al circuito. El verificador la usa para comprobar que una prueba corresponde a *este* circuito y no a otro. Debe generarse antes de `bb prove` (tu versión de `bb` la exige) y regenerarse cada vez que cambie el código del circuito.

## 6. Generar la prueba ZK

```bash
bb prove -b target/noir_mpt_verifier.json -w target/noir_mpt_verifier.gz -k target/vk -o target
```

**Qué hace:** con el circuito (`-b`), el witness (`-w`) y la vk (`-k`), genera la prueba ZK (esquema UltraHonk) y la escribe en `target/proof`, junto con `target/public_inputs` (el `transactions_root`, única entrada pública).

**Para qué sirve:** esta prueba demuestra criptográficamente que conoces una transacción y una prueba MPT válidas que la incluyen bajo ese `transactionsRoot`, **sin revelar** la transacción, su índice ni los nodos del camino.

## 7. Verificar la prueba

```bash
bb verify -k target/vk -p target/proof -i target/public_inputs
```

(Si tu versión de `bb` no acepta `-i`, omítelo: `bb verify -k target/vk -p target/proof`.)

**Qué hace:** comprueba la prueba (`-p`) contra la verification key (`-k`) y las entradas públicas (`-i`). Devuelve éxito solo si la prueba es válida para ese circuito y ese `transactions_root`.

**Para qué sirve:** es lo que haría cualquier tercero (u otro sistema, p. ej. un contrato verificador en Solidity) para convencerse de la inclusión sin ver los datos privados.

## Resumen en orden lineal

```bash
python3 scripts/gen_fixtures.py                                  # 1. entradas off-chain
nargo test                                                       # 2. suite de tests
nargo execute                                                    # 3-4. compilar + witness
bb write_vk -b target/noir_mpt_verifier.json -o target           # 5. verification key
bb prove -b target/noir_mpt_verifier.json \
         -w target/noir_mpt_verifier.gz -k target/vk -o target   # 6. prueba ZK
bb verify -k target/vk -p target/proof -i target/public_inputs   # 7. verificación
```

## Errores comunes

| Error | Causa | Solución |
|---|---|---|
| `Unable to open file: ./target/vk` en `bb prove` | Falta la verification key | Correr `bb write_vk` antes de `bb prove` |
| `Cannot satisfy constraint` en `nargo execute` | Entradas inválidas: índice/tx/raíz/prueba inconsistentes | Regenerar el `Prover.toml` con `prepare_inputs.py` |
| `inputs fuera de los límites del circuito` en los scripts | La prueba excede los máximos de `src/types.nr` | Ajustar los límites y recompilar (ver README) |
| `bb verify` falla con `-i` | Versión de `bb` con otra interfaz | Probar sin `-i` |
