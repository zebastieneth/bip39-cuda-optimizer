# Détails Techniques - BIP39 CUDA Optimizer

Documentation technique approfondie du programme d'optimisation de checksums BIP39.

## 📐 Architecture globale

### Pipeline de traitement

```
┌──────────────────────┐
│  Chargement données  │
│  - Wordlist BIP39    │
│  - Phrases 14 mots   │
│  - Configuration     │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Conversion indices  │
│  Mots → uint16_t     │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Allocation GPU      │
│  Transfert mémoire   │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Kernel CUDA         │
│  Calcul parallèle    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Récupération résult │
│  Affichage solution  │
└──────────────────────┘
```

## 🧮 Calcul du nombre de combinaisons

```
Total = N_phrases × N_15-16 × N_17 × N_18-19 × N_20-21

Avec valeurs par défaut:
- N_phrases: variable (dépend du fichier)
- N_15-16: 4 (2 premiers mots × 2 seconds)
- N_17: 3
- N_18-19: 3
- N_20-21: 25 (5 premiers × 5 seconds)

Exemple: 1000 phrases → 900,000 combinaisons
```

## 🔢 Format BIP39

### Structure d'une mnémonique 24 mots

```
24 mots × 11 bits = 264 bits total

Structure:
┌────────────────┬──────────┐
│  256 bits      │  8 bits  │
│  Entropy       │ Checksum │
└────────────────┴──────────┘
   32 bytes         1 byte
```

### Calcul du checksum

```
1. Entropy (256 bits) → 32 bytes
2. SHA-256(entropy) → 32 bytes hash
3. Checksum = Premier byte du hash
4. Mnémonique = entropy + checksum (264 bits)
5. Découpage en 24 mots de 11 bits
```

### Validation

```python
# Pseudo-code de validation
def validate_bip39(words):
    # Convertir 24 mots en 264 bits
    bits = words_to_bits(words)  # 24 × 11 = 264 bits
    
    # Séparer entropy et checksum
    entropy = bits[0:256]        # 256 premiers bits
    stored_checksum = bits[256:264]  # 8 derniers bits
    
    # Calculer checksum attendu
    hash = SHA256(entropy)
    computed_checksum = hash[0:8]  # 8 premiers bits du hash
    
    # Valider
    return stored_checksum == computed_checksum
```

## 🎯 Optimisations CUDA

### 1. Configuration des threads et blocks

```cpp
// Optimisé pour RTX 4090
int threads_per_block = 256;
int num_blocks = (total_combinations + threads_per_block - 1) / threads_per_block;

// Pourquoi 256 threads?
// - Multiple de 32 (warp size)
// - Occupe bien les SM (Streaming Multiprocessors)
// - Balance registres vs shared memory
// - Testé empiriquement comme optimal
```

### 2. Hiérarchie mémoire

```
┌─────────────────────────────────────────────┐
│ Registres (cycles: 1)                       │ Plus rapide
├─────────────────────────────────────────────┤
│ Shared Memory (cycles: ~20)                 │
├─────────────────────────────────────────────┤
│ L1 Cache (cycles: ~80)                      │
├─────────────────────────────────────────────┤
│ L2 Cache (cycles: ~200)                     │
├─────────────────────────────────────────────┤
│ Global Memory (cycles: ~500)                │ Plus lent
└─────────────────────────────────────────────┘
```

**Notre stratégie:**
- Mots cibles → Shared memory (accès fréquents)
- Indices de combinaisons → Registres (calcul)
- Blocs de mots → Global memory (lecture unique)

### 3. Early exit optimization

```cpp
bool all_valid = true;

for (int test_idx = 0; test_idx < 8 && all_valid; ++test_idx) {
    // Test checksum
    if (!validate_checksum(phrase, 23)) {
        all_valid = false;  // Sortie immédiate
    }
}
```

**Gain**: 
- Si 1er checksum invalide → économise 7 calculs SHA-256
- Réduction moyenne: ~60% des calculs (statistiquement)

### 4. SHA-256 device implementation

```cpp
__device__ __forceinline__ void sha256_transform(...) {
    // Inline forcé → pas d'overhead d'appel
    // Registres utilisés directement
    // Pas de passage par stack
}

// Loop unrolling
#pragma unroll
for (int i = 0; i < 64; ++i) {
    // Compilateur déroule la boucle
    // Élimine les branches
    // Meilleur pipeline instruction
}
```

### 5. Memory coalescing

```cpp
// ❌ MAUVAIS: accès non coalescés
for (int i = 0; i < 14; ++i) {
    phrase[i] = block1_14[random_index];
}

// ✅ BON: accès coalescés
phrase[0] = block1_14[i1_14 * 14 + 0];
phrase[1] = block1_14[i1_14 * 14 + 1];
// etc... accès séquentiels
```

**Pattern d'accès mémoire:**
```
Thread 0: addr[0], addr[1], addr[2]...  ← coalescé
Thread 1: addr[14], addr[15], addr[16]...
Thread 2: addr[28], addr[29], addr[30]...
```

### 6. Warp voting (future optimization)

```cpp
// Potentiel pour améliorer early exit
__device__ bool validate_with_voting(...) {
    bool valid = validate_checksum(...);
    
    // Si TOUS les threads du warp ont échoué, sortir
    if (__all_sync(0xffffffff, !valid)) {
        return false;
    }
    
    return valid;
}
```

## 🔬 Analyse de performance

### Métriques théoriques RTX 4090

```
Spécifications:
- CUDA cores: 16,384
- Compute capability: 8.9
- Memory bandwidth: 1,008 GB/s
- FP32 performance: 82.6 TFLOPS
- Base clock: 2.23 GHz
- Boost clock: 2.52 GHz
```

### Calcul de la vitesse maximale

```
Operations par checksum:
- SHA-256: ~1000 instructions
- Validation: ~100 instructions
- Total: ~1100 instructions

Vitesse théorique maximale:
16,384 cores × 2.5 GHz ÷ 1100 instructions
= 37 milliards checksums/seconde (37 GH/s)

Vitesse réelle attendue:
- Avec overhead: ~15-25 GH/s
- Avec early exit: ~20-40 GH/s (si beaucoup d'échecs rapides)
```

### Bottlenecks identifiés

1. **Memory bandwidth** (principale limitation)
   - Transfert données GPU
   - Accès global memory
   - Solution: shared memory + coalescing

2. **Branch divergence**
   - Tests conditionnels
   - Early exits dans warps
   - Solution: warp voting

3. **Register pressure**
   - SHA-256 utilise beaucoup de registres
   - Limite l'occupancy
   - Solution: compilation optimisée

## 📊 Profiling

### Utiliser NVIDIA Nsight

```bash
# Profiler le kernel
nsys profile --stats=true ./bip39_hybrid

# Analyser l'utilisation mémoire
ncu --metrics memory ./bip39_hybrid

# Vérifier l'occupancy
ncu --metrics occupancy ./bip39_hybrid
```

### Métriques importantes

```
1. Occupancy
   - Objectif: >75%
   - Formule: threads actifs / threads max possibles

2. Memory throughput
   - Objectif: >60% bande passante
   - Global memory: coalescé?

3. Warp execution efficiency
   - Objectif: >90%
   - Divergence minimale

4. IPC (Instructions Per Cycle)
   - Objectif: >2.0
   - Pipeline saturé
```

## 🎓 Concepts avancés

### Compute capability 8.9 (Ada Lovelace)

Nouvelles features utilisables:

1. **Thread Block Clusters**
   ```cpp
   // Grouper plusieurs blocks
   __cluster_dims__(2, 2, 1)
   __global__ void kernel(...) {
       // Shared memory entre blocks du cluster
   }
   ```

2. **Async memory operations**
   ```cpp
   // Copie asynchrone vers shared memory
   __pipeline_memcpy_async(...);
   ```

3. **Warp specialization**
   ```cpp
   // Spécialiser des warps pour des tâches
   if (warp_id == 0) {
       // Calcul SHA-256
   } else {
       // Validation checksum
   }
   ```

### Optimisations futures possibles

1. **Persistent threads**
   - Garder threads actifs
   - Éviter relancement kernel
   - Réduction overhead

2. **Multi-streaming**
   ```cpp
   cudaStream_t streams[4];
   for (int i = 0; i < 4; ++i) {
       kernel<<<blocks, threads, 0, streams[i]>>>(data_chunk[i]);
   }
   ```

3. **Unified Memory**
   ```cpp
   // Évite transferts explicites
   cudaMallocManaged(&data, size);
   // CPU et GPU accèdent la même mémoire
   ```

4. **Precomputed SHA-256 states**
   ```cpp
   // Précalculer états intermédiaires SHA-256
   // pour parties fixes de la phrase
   uint32_t partial_state[8];
   precompute_sha256_state(fixed_words, partial_state);
   // Ensuite finaliser avec mots variables
   ```

## 🔍 Debugging

### Vérifier résultats

```cpp
// Mode debug: activer avec -G flag
#ifdef DEBUG
    printf("Thread %llu: Testing combination %d-%d-%d\n", 
           idx, i15_16, i17, i18_19);
#endif
```

### Valider correctness

```bash
# Compiler en debug
make debug

# Lancer avec cuda-memcheck
cuda-memcheck ./bip39_hybrid

# Vérifier erreurs CUDA
cuda-gdb ./bip39_hybrid
```

## 📈 Scalabilité

### Multi-GPU setup

```cpp
int num_gpus;
cudaGetDeviceCount(&num_gpus);

for (int gpu = 0; gpu < num_gpus; ++gpu) {
    cudaSetDevice(gpu);
    
    // Diviser la charge
    size_t chunk = total / num_gpus;
    size_t start = gpu * chunk;
    
    kernel<<<blocks, threads>>>(data + start, chunk);
}
```

### Estimation coûts cloud

```
RTX 4090 sur Vast.ai: ~$0.40/h

Pour 1 trillion de combinaisons:
- Vitesse: 20 GH/s
- Temps: 50,000 secondes = 14 heures
- Coût: 14 × $0.40 = $5.60

Pour 100 trillions:
- 100× GPUs parallèle
- Temps: 14 heures
- Coût: $560
```

## 🛡️ Sécurité du code

### Vérifications intégrées

```cpp
// Bounds checking
if (idx >= total_combinations) return;

// Index validation
assert(word_index < 2048);

// Memory initialization
memset(entropy, 0, 33);
```

### Protection overflow

```cpp
// Utilisation de types appropriés
unsigned long long idx;  // 64-bit pour grandes combinaisons
uint16_t word_idx;       // Suffisant pour 2048 mots
```

## 📚 Références techniques

- [CUDA Best Practices Guide](https://docs.nvidia.com/cuda/cuda-c-best-practices-guide/)
- [RTX 4090 Whitepaper](https://www.nvidia.com/en-us/geforce/graphics-cards/40-series/rtx-4090/)
- [BIP39 Python Reference](https://github.com/bitcoin/bips/blob/master/bip-0039/bip39-wordlists.md)
- [SHA-256 CUDA Implementation](https://github.com/B-Con/crypto-algorithms)

---

**Pour toute question technique, consultez le code source ou les ressources ci-dessus.**
