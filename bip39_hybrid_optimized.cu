#include <cuda_runtime.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <cstdint>
#include <chrono>
#include <cstring>

// ============================================================================
// SHA256 CONSTANTS AND MACROS
// ============================================================================

__device__ __constant__ uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

// ============================================================================
// OPTIMIZED SHA256 IMPLEMENTATION
// ============================================================================

__device__ __forceinline__ void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t m[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    
    // Prepare message schedule with unrolling
    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        int j = i << 2;
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    }
    
    #pragma unroll
    for (int i = 16; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }
    
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    
    // Main loop unrolled
    #pragma unroll
    for (int i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

__device__ void sha256_hash(const uint8_t* data, size_t len, uint8_t* hash) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    uint8_t block[64];
    size_t i = 0;
    
    while (len >= 64) {
        memcpy(block, data + i, 64);
        sha256_transform(state, block);
        i += 64;
        len -= 64;
    }
    
    memset(block, 0, 64);
    memcpy(block, data + i, len);
    block[len] = 0x80;
    
    if (len >= 56) {
        sha256_transform(state, block);
        memset(block, 0, 64);
    }
    
    uint64_t bitlen = (i + len) * 8;
    for (int j = 0; j < 8; ++j) {
        block[63 - j] = bitlen >> (j * 8);
    }
    
    sha256_transform(state, block);
    
    for (int j = 0; j < 8; ++j) {
        hash[j * 4] = (state[j] >> 24) & 0xff;
        hash[j * 4 + 1] = (state[j] >> 16) & 0xff;
        hash[j * 4 + 2] = (state[j] >> 8) & 0xff;
        hash[j * 4 + 3] = state[j] & 0xff;
    }
}

// ============================================================================
// BIP39 CHECKSUM VALIDATION
// ============================================================================

__device__ bool validate_checksum(const uint16_t* indices, int checksum_word_idx) {
    // Convert indices to entropy bytes
    uint8_t entropy[33]; // 24 words * 11 bits = 264 bits = 33 bytes
    memset(entropy, 0, 33);
    
    // Pack 11-bit indices into entropy
    int bit_pos = 0;
    for (int i = 0; i < 24; ++i) {
        uint16_t idx = indices[i];
        for (int b = 10; b >= 0; --b) {
            int byte_pos = bit_pos / 8;
            int bit_in_byte = 7 - (bit_pos % 8);
            if (idx & (1 << b)) {
                entropy[byte_pos] |= (1 << bit_in_byte);
            }
            bit_pos++;
        }
    }
    
    // Hash the first 32 bytes
    uint8_t hash[32];
    sha256_hash(entropy, 32, hash);
    
    // Extract checksum bits (first 8 bits of hash)
    uint8_t computed_checksum = hash[0];
    
    // Extract checksum from last word (last 8 bits of entropy)
    uint8_t stored_checksum = entropy[32];
    
    return computed_checksum == stored_checksum;
}

// ============================================================================
// KERNEL: PARALLEL CHECKSUM TESTING
// ============================================================================

__global__ void test_combinations_kernel(
    const uint16_t* block1_14,    // Mots 1-14 du fichier
    const uint16_t* block15_16,   // Mots 15-16 (4 mots)
    const uint16_t* block17,      // Mot 17 (3 mots)
    const uint16_t* block18_19,   // Mots 18-19 (3 mots)
    const uint16_t* block20_21,   // Mots 20-21 (25 groupes de 2)
    const uint16_t* block22_24,   // Mots 22-24 fixes
    const uint16_t* target_words, // 8 mots cibles
    int num_block1_14,
    bool* found,
    uint16_t* result
) {
    // Shared memory pour les mots cibles (optimisation)
    __shared__ uint16_t s_targets[8];
    if (threadIdx.x < 8) {
        s_targets[threadIdx.x] = target_words[threadIdx.x];
    }
    __syncthreads();
    
    // Calcul de l'index global
    unsigned long long idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    // Early exit si déjà trouvé
    if (*found) return;
    
    // Calcul des indices pour chaque bloc
    unsigned long long total_combinations = 
        (unsigned long long)num_block1_14 * 4 * 3 * 3 * 25;
    
    if (idx >= total_combinations) return;
    
    // Décomposition de l'index
    int i1_14 = idx % num_block1_14;
    unsigned long long temp = idx / num_block1_14;
    
    int i15_16 = temp % 4;
    temp /= 4;
    
    int i17 = temp % 3;
    temp /= 3;
    
    int i18_19 = temp % 3;
    temp /= 3;
    
    int i20_21 = temp % 25;
    
    // Construction de la phrase complète
    uint16_t phrase[24];
    
    // Mots 1-14
    phrase[0] = block1_14[i1_14 * 14 + 0];
    phrase[1] = block1_14[i1_14 * 14 + 1];
    phrase[2] = block1_14[i1_14 * 14 + 2];
    phrase[3] = block1_14[i1_14 * 14 + 3];
    phrase[4] = block1_14[i1_14 * 14 + 4];
    phrase[5] = block1_14[i1_14 * 14 + 5];
    phrase[6] = block1_14[i1_14 * 14 + 6];
    phrase[7] = block1_14[i1_14 * 14 + 7];
    phrase[8] = block1_14[i1_14 * 14 + 8];
    phrase[9] = block1_14[i1_14 * 14 + 9];
    phrase[10] = block1_14[i1_14 * 14 + 10];
    phrase[11] = block1_14[i1_14 * 14 + 11];
    phrase[12] = block1_14[i1_14 * 14 + 12];
    phrase[13] = block1_14[i1_14 * 14 + 13];
    
    // Mots 15-16
    phrase[14] = block15_16[i15_16 * 2 + 0];
    phrase[15] = block15_16[i15_16 * 2 + 1];
    
    // Mot 17
    phrase[16] = block17[i17];
    
    // Mots 18-19
    phrase[17] = block18_19[i18_19 * 2 + 0];
    phrase[18] = block18_19[i18_19 * 2 + 1];
    
    // Mots 20-21
    phrase[19] = block20_21[i20_21 * 2 + 0];
    phrase[20] = block20_21[i20_21 * 2 + 1];
    
    // Mots 22-24 (fixes)
    phrase[21] = block22_24[0];
    phrase[22] = block22_24[1];
    phrase[23] = block22_24[2];
    
    // Test des 8 checksums avec early exit
    bool all_valid = true;
    
    for (int test_idx = 0; test_idx < 8 && all_valid; ++test_idx) {
        // Remplacer le mot de test
        uint16_t original = phrase[21 + (test_idx % 3)];
        phrase[21 + (test_idx % 3)] = s_targets[test_idx];
        
        // Valider checksum
        if (!validate_checksum(phrase, 23)) {
            all_valid = false;
        }
        
        // Restaurer
        phrase[21 + (test_idx % 3)] = original;
    }
    
    // Si toutes les checksums sont valides
    if (all_valid) {
        *found = true;
        for (int i = 0; i < 24; ++i) {
            result[i] = phrase[i];
        }
    }
}

// ============================================================================
// HOST CODE
// ============================================================================

std::vector<std::string> load_wordlist(const std::string& filename) {
    std::vector<std::string> words;
    std::ifstream file(filename);
    std::string line;
    
    while (std::getline(file, line)) {
        if (!line.empty()) {
            words.push_back(line);
        }
    }
    
    return words;
}

uint16_t word_to_index(const std::string& word, const std::vector<std::string>& wordlist) {
    auto it = std::find(wordlist.begin(), wordlist.end(), word);
    if (it != wordlist.end()) {
        return static_cast<uint16_t>(it - wordlist.begin());
    }
    return 0;
}

int main() {
    std::cout << "=== BIP39 CUDA OPTIMIZER - RTX 4090 ===" << std::endl;
    
    // Charger la wordlist BIP39
    std::vector<std::string> wordlist = load_wordlist("english.txt");
    if (wordlist.size() != 2048) {
        std::cerr << "Erreur: wordlist invalide" << std::endl;
        return 1;
    }
    
    // Charger les phrases 1-14
    std::vector<std::vector<uint16_t>> phrases_1_14;
    std::ifstream phrases_file("phrases_14_mots.txt");
    std::string line;
    
    while (std::getline(phrases_file, line)) {
        std::istringstream iss(line);
        std::vector<uint16_t> phrase;
        std::string word;
        
        while (iss >> word && phrase.size() < 14) {
            phrase.push_back(word_to_index(word, wordlist));
        }
        
        if (phrase.size() == 14) {
            phrases_1_14.push_back(phrase);
        }
    }
    
    std::cout << "Phrases 1-14 chargées: " << phrases_1_14.size() << std::endl;
    
    // Définir les blocs de mots
    std::vector<std::pair<std::string, std::string>> block15_16 = {
        {"laitue", "peser"}, {"laitue", "pouvoir"},
        {"prairie", "peser"}, {"prairie", "pouvoir"}
    };
    
    std::vector<std::string> block17 = {"motif", "peintre", "sécher"};
    
    std::vector<std::pair<std::string, std::string>> block18_19 = {
        {"écrire", "histoire"}, {"écrire", "mérite"}, {"histoire", "mérite"}
    };
    
    std::vector<std::pair<std::string, std::string>> block20_21 = {
        {"énergie", "fleur"}, {"énergie", "ombre"}, {"énergie", "poésie"}, 
        {"énergie", "énorme"}, {"énergie", "cloche"},
        {"anarchie", "fleur"}, {"anarchie", "ombre"}, {"anarchie", "poésie"}, 
        {"anarchie", "énorme"}, {"anarchie", "cloche"},
        {"griffe", "fleur"}, {"griffe", "ombre"}, {"griffe", "poésie"}, 
        {"griffe", "énorme"}, {"griffe", "cloche"},
        {"civil", "fleur"}, {"civil", "ombre"}, {"civil", "poésie"}, 
        {"civil", "énorme"}, {"civil", "cloche"},
        {"étrange", "fleur"}, {"étrange", "ombre"}, {"étrange", "poésie"}, 
        {"étrange", "énorme"}, {"étrange", "cloche"}
    };
    
    std::vector<std::string> block22_24 = {"open", "always", "staff"};
    
    std::vector<std::string> target_words = {
        "alien", "detect", "flip", "gas", "organ", "peasant", "trigger", "staff"
    };
    
    // Convertir en indices
    std::vector<uint16_t> h_block1_14;
    for (const auto& p : phrases_1_14) {
        h_block1_14.insert(h_block1_14.end(), p.begin(), p.end());
    }
    
    std::vector<uint16_t> h_block15_16;
    for (const auto& p : block15_16) {
        h_block15_16.push_back(word_to_index(p.first, wordlist));
        h_block15_16.push_back(word_to_index(p.second, wordlist));
    }
    
    std::vector<uint16_t> h_block17;
    for (const auto& w : block17) {
        h_block17.push_back(word_to_index(w, wordlist));
    }
    
    std::vector<uint16_t> h_block18_19;
    for (const auto& p : block18_19) {
        h_block18_19.push_back(word_to_index(p.first, wordlist));
        h_block18_19.push_back(word_to_index(p.second, wordlist));
    }
    
    std::vector<uint16_t> h_block20_21;
    for (const auto& p : block20_21) {
        h_block20_21.push_back(word_to_index(p.first, wordlist));
        h_block20_21.push_back(word_to_index(p.second, wordlist));
    }
    
    std::vector<uint16_t> h_block22_24;
    for (const auto& w : block22_24) {
        h_block22_24.push_back(word_to_index(w, wordlist));
    }
    
    std::vector<uint16_t> h_targets;
    for (const auto& w : target_words) {
        h_targets.push_back(word_to_index(w, wordlist));
    }
    
    // Allocation GPU
    uint16_t *d_block1_14, *d_block15_16, *d_block17, *d_block18_19;
    uint16_t *d_block20_21, *d_block22_24, *d_targets, *d_result;
    bool *d_found;
    
    cudaMalloc(&d_block1_14, h_block1_14.size() * sizeof(uint16_t));
    cudaMalloc(&d_block15_16, h_block15_16.size() * sizeof(uint16_t));
    cudaMalloc(&d_block17, h_block17.size() * sizeof(uint16_t));
    cudaMalloc(&d_block18_19, h_block18_19.size() * sizeof(uint16_t));
    cudaMalloc(&d_block20_21, h_block20_21.size() * sizeof(uint16_t));
    cudaMalloc(&d_block22_24, h_block22_24.size() * sizeof(uint16_t));
    cudaMalloc(&d_targets, h_targets.size() * sizeof(uint16_t));
    cudaMalloc(&d_result, 24 * sizeof(uint16_t));
    cudaMalloc(&d_found, sizeof(bool));
    
    // Copie vers GPU
    cudaMemcpy(d_block1_14, h_block1_14.data(), h_block1_14.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_block15_16, h_block15_16.data(), h_block15_16.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_block17, h_block17.data(), h_block17.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_block18_19, h_block18_19.data(), h_block18_19.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_block20_21, h_block20_21.data(), h_block20_21.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_block22_24, h_block22_24.data(), h_block22_24.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_targets, h_targets.data(), h_targets.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
    
    bool h_found = false;
    cudaMemcpy(d_found, &h_found, sizeof(bool), cudaMemcpyHostToDevice);
    
    // Configuration kernel (optimisé pour RTX 4090)
    int threads = 256;
    unsigned long long total = (unsigned long long)phrases_1_14.size() * 4 * 3 * 3 * 25;
    int blocks = (total + threads - 1) / threads;
    
    std::cout << "Combinaisons totales: " << total << std::endl;
    std::cout << "Lancement: " << blocks << " blocks x " << threads << " threads" << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Lancement kernel
    test_combinations_kernel<<<blocks, threads>>>(
        d_block1_14, d_block15_16, d_block17, d_block18_19,
        d_block20_21, d_block22_24, d_targets,
        phrases_1_14.size(), d_found, d_result
    );
    
    cudaDeviceSynchronize();
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // Récupération résultat
    cudaMemcpy(&h_found, d_found, sizeof(bool), cudaMemcpyDeviceToHost);
    
    if (h_found) {
        std::vector<uint16_t> result(24);
        cudaMemcpy(result.data(), d_result, 24 * sizeof(uint16_t), cudaMemcpyDeviceToHost);
        
        std::cout << "\n=== TROUVÉ ===" << std::endl;
        for (int i = 0; i < 24; ++i) {
            std::cout << wordlist[result[i]] << " ";
        }
        std::cout << std::endl;
    } else {
        std::cout << "\nAucune solution trouvée." << std::endl;
    }
    
    double speed = (double)total / (duration.count() / 1000.0);
    std::cout << "\nTemps: " << duration.count() << " ms" << std::endl;
    std::cout << "Vitesse: " << speed / 1e9 << " GH/s" << std::endl;
    
    // Libération mémoire
    cudaFree(d_block1_14);
    cudaFree(d_block15_16);
    cudaFree(d_block17);
    cudaFree(d_block18_19);
    cudaFree(d_block20_21);
    cudaFree(d_block22_24);
    cudaFree(d_targets);
    cudaFree(d_result);
    cudaFree(d_found);
    
    return 0;
}
