# Requerimientos funcionales para construir un verificador de inclusión de transacciones de Ethereum en Noir

## Objetivo del proyecto
Construir un proyecto en **Noir** que permita verificar, dentro de un circuito, que una transacción Ethereum específica pertenece al trie de transacciones de un bloque, validando su inclusión contra el `transactionsRoot` del header del bloque.[cite:16]

El sistema debe replicar conceptualmente la estrategia del proyecto actual en Rust, pero adaptada a las restricciones y al modelo de ejecución de Noir: verificación mediante prueba de **Merkle Patricia Trie (MPT)**, no reconstrucción completa del bloque dentro del circuito.[cite:16]

## Contexto funcional
El proyecto base en Rust verifica inclusión de transacciones Ethereum usando el campo `transactionsRoot` del bloque.[cite:16]
En el README se especifica que Ethereum no usa un árbol de Merkle binario simple para transacciones, sino un **Merkle Patricia Trie**, donde la clave es `RLP(tx_index)`, el valor es la transacción serializada en bytes, los nodos están codificados con RLP y las referencias a nodos grandes usan `Keccak-256`.[cite:16]

Por lo tanto, el proyecto en Noir debe validar una **prueba de inclusión MPT** a partir de una raíz pública conocida y una prueba compuesta por nodos RLP.[cite:16]

## Alcance
El sistema debe enfocarse en la verificación criptográfica de inclusión mediante prueba MPT.[cite:16]
No debe depender de conectividad directa a un nodo Ethereum dentro del circuito; la información de entrada debe ser provista externamente, igual que en el proyecto actual.[cite:16]

El proyecto debe contemplar:
- Recepción de `transactionsRoot` como entrada pública.[cite:16]
- Recepción de `tx_index`, transacción serializada y prueba MPT como entradas privadas.[cite:16]
- Validación de que la transacción indicada corresponde exactamente al valor almacenado en el trie en la clave `RLP(tx_index)`.[cite:16]
- Validación de que la prueba conduce exactamente a la raíz pública esperada.[cite:16]

El proyecto no necesita, en una primera versión, descargar datos on-chain, descubrir pruebas automáticamente ni reconstruir el `transactionsRoot` a partir de todas las transacciones del bloque.[cite:16]

## Entradas requeridas
El sistema debe aceptar las siguientes entradas funcionales:

| Entrada | Tipo lógico | Visibilidad | Descripción |
|---|---|---|---|
| `transactions_root` | bytes32 | Pública | Valor del campo `transactionsRoot` del bloque.[cite:16] |
| `tx_index` | entero no negativo | Privada | Índice cero-basado de la transacción dentro del bloque.[cite:16] |
| `serialized_tx` | bytes | Privada | Transacción Ethereum serializada completa en RLP, no el hash de la transacción.[cite:16] |
| `proof_nodes` | lista de bytes | Privada | Secuencia ordenada de nodos MPT codificados en RLP que forman la prueba de inclusión.[cite:16] |

El sistema debe asumir que estas entradas fueron preparadas fuera del circuito y entregadas ya normalizadas al formato esperado.[cite:16]

## Salida esperada
El circuito debe producir un resultado booleano implícito mediante constraints: la prueba es válida solo si todas las verificaciones se satisfacen y la raíz calculada coincide con `transactions_root`.[cite:16]
No es necesario que el circuito devuelva datos adicionales si la verificación es exitosa.[cite:16]

## Requerimientos funcionales principales

### RF-01 — Verificación de inclusión por prueba MPT
El sistema debe implementar la verificación de inclusión de una transacción Ethereum usando una prueba de Merkle Patricia Trie compuesta por nodos codificados con RLP.[cite:16]
La verificación debe seguir la semántica del `transactionsRoot` de Ethereum y no la de un árbol de Merkle binario clásico.[cite:16]

### RF-02 — Construcción de la clave del trie
El sistema debe derivar la clave del trie a partir de `tx_index` usando la codificación RLP correspondiente al índice de la transacción.[cite:16]
Luego debe transformar esa clave al formato de recorrido necesario para el MPT, es decir, una secuencia de nibbles o equivalente funcional para comparar prefijos y avanzar por ramas del trie.[cite:16]

### RF-03 — Validación estructural de nodos MPT
El sistema debe soportar el parsing y validación de nodos `branch`, `extension` y `leaf` codificados en RLP, de acuerdo con la estructura funcional requerida para una prueba de inclusión Ethereum.[cite:16]
Debe verificar que cada nodo de la prueba sea coherente con el paso actual del recorrido de la clave.[cite:16]

### RF-04 — Resolución de referencias entre nodos
El sistema debe validar que cada salto entre nodos de la prueba sea correcto, incluyendo referencias directas o referencias comprometidas mediante `Keccak-256`, según corresponda por tamaño y codificación del nodo.[cite:16]
La lógica de encadenamiento entre nodos debe asegurar que la prueba provista describe exactamente un camino válido desde la raíz hasta la hoja esperada.[cite:16]

### RF-05 — Verificación del valor terminal
Al llegar al nodo terminal, el sistema debe comprobar que el valor almacenado en la prueba coincide exactamente con `serialized_tx`.[cite:16]
No debe aceptarse el hash de la transacción como sustituto del valor, porque el README establece que el trie almacena la transacción serializada completa.[cite:16]

### RF-06 — Verificación de raíz final
El sistema debe comprobar que la raíz reconstruida a partir de la prueba coincide exactamente con `transactions_root`.[cite:16]
La prueba solo debe considerarse válida cuando esa igualdad se cumple y todos los pasos intermedios fueron consistentes.[cite:16]

### RF-07 — Rechazo de pruebas inválidas
El sistema debe fallar cuando ocurra cualquiera de estas condiciones:
- El `tx_index` no corresponde al camino de la prueba.[cite:16]
- La prueba termina en un valor distinto de `serialized_tx`.[cite:16]
- La estructura RLP de uno o más nodos es inválida o incompatible con el tipo de nodo esperado.[cite:16]
- El encadenamiento hash/referencia entre nodos no coincide.[cite:16]
- La raíz final calculada difiere de `transactions_root`.[cite:16]

### RF-08 — Separación entre preparación y verificación
El proyecto debe separar claramente las responsabilidades fuera y dentro del circuito.[cite:16]
La obtención de datos del bloque, extracción de la transacción, construcción de la prueba y padding de entradas deben ocurrir fuera del circuito, mientras que el circuito Noir debe encargarse exclusivamente de verificar la prueba de inclusión.[cite:16]

## Requerimientos de arquitectura

### Módulos funcionales sugeridos
La implementación debe organizarse en módulos o componentes equivalentes con responsabilidades claras:

| Módulo | Responsabilidad |
|---|---|
| `main` | Orquestación de entradas, ejecución del verificador y constraints finales. |
| `rlp` | Decodificación mínima o utilidades necesarias para interpretar índices y nodos codificados en RLP.[cite:16] |
| `mpt` | Lógica de recorrido del trie, comparación de prefijos, manejo de `branch`, `extension` y `leaf`.[cite:16] |
| `keccak` | Cálculo o integración de `Keccak-256` para validar referencias comprometidas.[cite:16] |
| `types` o equivalente | Definición de estructuras de datos estáticas compatibles con Noir para nodos, rutas y prueba. |
| `helpers_offchain` | Preparación de entradas, padding, serialización y normalización fuera del circuito. |

### Restricciones de diseño
La arquitectura debe contemplar que Noir trabaja mejor con tamaños acotados y estructuras estáticas que con datos altamente dinámicos.
Por lo tanto, deben definirse límites máximos configurables para:
- Cantidad máxima de nodos de una prueba.
- Tamaño máximo en bytes de cada nodo RLP.
- Tamaño máximo de la transacción serializada.
- Longitud máxima de la ruta en nibbles.

Estos máximos deben ser explícitos en la especificación del proyecto para que otra IA pueda construir una primera versión viable del circuito.

## Requerimientos de una primera versión (MVP)
La primera versión del proyecto debe priorizar viabilidad sobre cobertura completa.
Se recomienda que el MVP implemente:

- Verificación de una prueba MPT de inclusión para una sola transacción.[cite:16]
- Longitud máxima fija de prueba y padding de entradas fuera del circuito.
- Soporte inicial para casos comunes de trayectorias con `branch`, `extension` y `leaf`.
- Validación de `transactions_root` contra una entrada pública.[cite:16]
- Verificación exacta del valor `serialized_tx` como hoja terminal.[cite:16]

No es obligatorio en el MVP:
- Soportar extracción automática de pruebas desde RPC.[cite:16]
- Soportar pruebas multiproof.
- Recalcular el trie completo desde todas las transacciones del bloque.[cite:16]
- Soportar todos los edge cases de Ethereum desde la primera entrega.

## Casos de uso

### Caso de uso 1 — Verificación válida
Dado un `transactions_root` público, un `tx_index`, una transacción serializada y una prueba MPT válida, el circuito debe aceptar la prueba y considerar demostrada la inclusión de esa transacción en el bloque.[cite:16]

### Caso de uso 2 — Índice incorrecto
Dado el mismo conjunto de nodos pero con un `tx_index` distinto, el circuito debe rechazar la prueba.[cite:16]

### Caso de uso 3 — Transacción alterada
Dado el mismo índice y la misma prueba, pero con una transacción serializada distinta, el circuito debe rechazar la prueba.[cite:16]

### Caso de uso 4 — Raíz incorrecta
Si `transactions_root` no coincide con la raíz que implica la prueba, el circuito debe rechazarla.[cite:16]

## Requerimientos de testing
El proyecto debe incluir pruebas automatizadas que cubran al menos:
- Caso positivo de inclusión válida.[cite:16]
- Caso negativo con `tx_index` incorrecto.[cite:16]
- Caso negativo con transacción alterada.[cite:16]
- Caso negativo con raíz incorrecta.[cite:16]
- Caso negativo con prueba mal formada o con nodos RLP inconsistentes.[cite:16]

Las fixtures de prueba deben poder generarse off-chain a partir de datos reales o sintéticos, manteniendo coherencia con el enfoque actual del proyecto Rust, que usa datos externos y no consulta un nodo directamente desde la librería principal.[cite:16]

## Requerimientos no funcionales relevantes para la implementación
Aunque el objetivo principal es funcional, la IA que construya el proyecto debe respetar estas restricciones técnicas:

- El circuito debe evitar lógica innecesaria fuera del objetivo de verificación MPT.
- El parsing dentro del circuito debe ser mínimo y orientado solo a los campos indispensables para verificar la prueba.
- La preparación de inputs complejos debe hacerse fuera del circuito para reducir costo y complejidad.
- La implementación debe ser modular para facilitar sustitución futura de componentes como RLP o Keccak.
- Deben documentarse claramente los límites máximos aceptados por el circuito.

## Entregables esperados
La IA que construya el proyecto debe producir como mínimo:

| Entregable | Descripción |
|---|---|
| Proyecto Noir funcional | Código fuente del circuito y módulos auxiliares. |
| Scripts off-chain | Utilidades para preparar entradas, padding y fixtures de prueba. |
| Suite de tests | Pruebas positivas y negativas reproducibles. |
| README técnico | Instrucciones de instalación, ejecución y formato de inputs. |
| Ejemplo verificable | Un caso de prueba completo con `transactions_root`, `tx_index`, `serialized_tx` y `proof_nodes`. |

## Criterios de aceptación
El proyecto se considerará aceptado cuando cumpla todos los siguientes puntos:

- Verifica correctamente inclusión de una transacción Ethereum contra `transactionsRoot` usando una prueba MPT.[cite:16]
- Usa como clave `RLP(tx_index)` y como valor la transacción serializada completa.[cite:16]
- Rechaza entradas alteradas, raíces incorrectas y pruebas inválidas.[cite:16]
- Separa preparación off-chain de verificación in-circuit.[cite:16]
- Incluye tests reproducibles y documentación de uso.[cite:16]
- Define límites explícitos para tamaños y cantidad de elementos procesados por el circuito.

## Instrucciones para la IA implementadora
La IA que reciba este documento debe construir el proyecto con prioridad en exactitud funcional y claridad modular.
Debe evitar modelar el problema como un árbol de Merkle binario simple, porque el objetivo real es verificar una prueba de inclusión sobre el **Merkle Patricia Trie de transacciones de Ethereum**.[cite:16]

La implementación debe comenzar por un MVP con límites fijos y una prueba de inclusión individual, y luego dejar el diseño preparado para ampliar cobertura y compatibilidad con más casos reales de Ethereum.
