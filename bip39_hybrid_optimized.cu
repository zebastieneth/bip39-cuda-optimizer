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
#include <iomanip>

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
// BIP39 CHECKSUM VALIDATION - OPTIMIZED
// ============================================================================

__device__ bool validate_checksum(const uint16_t* indices) {
    // Convert indices to entropy bytes
    uint8_t entropy[33]; // 24 words * 11 bits = 264 bits = 33 bytes
    memset(entropy, 0, 33);

    // Pack 11-bit indices into entropy
    int bit_pos = 0;
    #pragma unroll
    for (int i = 0; i < 24; ++i) {
        uint16_t idx = indices[i];
        #pragma unroll
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
// KERNEL: TEST ALL 8 CHECKSUMS FOR EACH COMBINATION
// ============================================================================

__global__ void test_combinations_kernel(
    const uint16_t* block1_14,    // Words 1-14 from file
    const uint16_t* block15_16,   // Words 15-16 (pairs)
    const uint16_t* block17,      // Word 17
    const uint16_t* block18_19,   // Words 18-19
    const uint16_t* block20_21,   // Words 20-21
    uint16_t word22,              // FIXED: "open"
    uint16_t word23,              // FIXED: "always"
    const uint16_t* word24_candidates, // 8 candidate words for position 24
    int num_block1_14,
    int num_block15_16,
    int num_block17,
    int num_block18_19,
    int num_block20_21,
    bool* found,
    uint16_t* result,
    unsigned long long* checksum_counter,  // counter for actual checksums computed
    unsigned long long batch_offset  // offset for batching
) {
    // Shared memory for word 24 candidates (optimization)
    __shared__ uint16_t s_word24[8];
    if (threadIdx.x < 8) {
        s_word24[threadIdx.x] = word24_candidates[threadIdx.x];
    }
    __syncthreads();

    // Calculate global index with batch offset
    unsigned long long idx = batch_offset + (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;

    // Early exit if already found
    if (*found) return;

    // Calculate total combinations
    unsigned long long total_combinations =
        (unsigned long long)num_block1_14 * num_block15_16 * num_block17 * num_block18_19 * num_block20_21;

    if (idx >= total_combinations) return;

    // Decompose index into block indices
    int i1_14 = idx % num_block1_14;
    unsigned long long temp = idx / num_block1_14;

    int i15_16 = temp % num_block15_16;
    temp /= num_block15_16;

    int i17 = temp % num_block17;
    temp /= num_block17;

    int i18_19 = temp % num_block18_19;
    temp /= num_block18_19;

    int i20_21 = temp % num_block20_21;

    // Build the phrase (words 1-23 are fixed for this combination)
    uint16_t phrase[24];

    // Words 1-14
    #pragma unroll
    for (int i = 0; i < 14; ++i) {
        phrase[i] = block1_14[i1_14 * 14 + i];
    }

    // Words 15-16
    phrase[14] = block15_16[i15_16 * 2];
    phrase[15] = block15_16[i15_16 * 2 + 1];

    // Word 17
    phrase[16] = block17[i17];

    // Words 18-19
    phrase[17] = block18_19[i18_19 * 2];
    phrase[18] = block18_19[i18_19 * 2 + 1];

    // Words 20-21
    phrase[19] = block20_21[i20_21 * 2];
    phrase[20] = block20_21[i20_21 * 2 + 1];

    // Word 22-23 (FIXED)
    phrase[21] = word22;
    phrase[22] = word23;

    // NOW TEST ALL 8 POSSIBLE WORD 24 VALUES
    // We need ALL 8 to have valid checksums!
    bool all_valid = true;

    #pragma unroll
    for (int test_idx = 0; test_idx < 8; ++test_idx) {
        // Set word 24 to this candidate
        phrase[23] = s_word24[test_idx];

        // Validate checksum
        atomicAdd(checksum_counter, 1ULL);  // ADDED: Count each checksum
        if (!validate_checksum(phrase)) {
            all_valid = false;
            break; // Early exit - if one fails, no need to test the rest
        }
    }

    // If ALL 8 checksums are valid, we found the winner!
    if (all_valid) {
        *found = true;
        // Store the result with the first valid word 24 (they're all valid)
        #pragma unroll
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
        return std::distance(wordlist.begin(), it);
    }
    std::cerr << "ERROR: Word not found in wordlist: " << word << std::endl;
    exit(1);
}

std::vector<std::vector<uint16_t>> load_phrases_file(const std::string& filename, const std::vector<std::string>& wordlist) {
    std::vector<std::vector<uint16_t>> phrases;
    std::ifstream file(filename);
    std::string line;

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::vector<uint16_t> phrase;
        std::string word;

        while (iss >> word) {
            phrase.push_back(word_to_index(word, wordlist));
        }

        if (phrase.size() == 14) {
            phrases.push_back(phrase);
        }
    }

    return phrases;
}

int main() {
    std::cout << "=== BIP39 CUDA OPTIMIZER - MULTI-GPU ===" << std::endl;

    // Detect GPUs
    int num_gpus;
    cudaGetDeviceCount(&num_gpus);
    std::cout << "GPUs détectés: " << num_gpus << std::endl;

    for (int i = 0; i < num_gpus; ++i) {
        cudaDeviceProp prop;
        cudaGetDeviceProperties(&prop, i);
        std::cout << "GPU " << i << ": " << prop.name
                  << " (" << prop.multiProcessorCount << " SMs, "
                  << prop.totalGlobalMem / (1024 * 1024 * 1024) << " GB)" << std::endl;
    }

    // Load wordlists
    std::vector<std::string> wordlist = load_wordlist("english.txt");
    std::vector<std::string> french_wordlist = load_wordlist("french.txt");

    if (wordlist.empty()) {
        std::cout << "Wordlist anglaise chargée: " << wordlist.size() << " mots" << std::endl;
    } else {
        std::cout << "Wordlist anglaise chargée: " << wordlist.size() << " mots" << std::endl;
    }

    // Load phrases 1-14 (mots français, indices français)
std::vector<std::vector<uint16_t>> phrases_1_14 = load_phrases_file("phrases_14_mots.txt", french_wordlist);
std::cout << "Phrases 1-14 chargées: " << phrases_1_14.size() << std::endl;

// BLOC 15-16: Toutes les paires A-B et B-A (pas AA ou BB)
std::vector<std::string> words_15_16 = {
    "utopie", "vacarme", "vaccin", "vagabond", "vague", "vaillant", "vaincre", "vaisseau",
    "valable", "valise", "vallon", "valve", "vampire", "vanille", "vapeur", "varier",
    "vaseux", "vassal", "vaste", "vecteur", "vedette", "végétal", "véhicule", "veinard",
    "véloce", "vendredi", "vénérer", "venger", "venimeux", "ventouse", "verdure", "vérin",
    "vernir", "verrou", "verser", "vertu", "veston", "vétéran", "vétuste", "vexant",
    "vexer", "viaduc", "viande", "victoire", "vidange", "vidéo", "vignette", "vigueur",
    "vilain", "village", "vinaigre", "violon", "vipère", "virement", "virtuose", "virus",
    "visage", "viseur", "vision", "visqueux", "visuel", "vital", "vitesse", "viticole", "vitrine"
};

std::vector<std::pair<std::string, std::string>> block15_16;
for (const auto& w1 : words_15_16) {
    for (const auto& w2 : words_15_16) {
        if (w1 != w2) {
            block15_16.push_back({w1, w2});
        }
    }
}
std::cout << "Paires générées pour mots 15-16: " << block15_16.size() << std::endl;

// BLOC 17: Tous les 2048 mots de la wordlist française
std::vector<std::string> block17 = french_wordlist;
std::cout << "Mots pour position 17: " << block17.size() << std::endl;

// BLOC 18-19: Toutes les paires A-B et B-A (pas AA ou BB)
std::vector<std::string> words_18_19 = {
    "énergie", "monnaie", "économie", "progrès", "amour", "bonheur", "science"
};

std::vector<std::pair<std::string, std::string>> block18_19;
for (const auto& w1 : words_18_19) {
    for (const auto& w2 : words_18_19) {
        if (w1 != w2) {
            block18_19.push_back({w1, w2});
        }
    }
}
std::cout << "Paires générées pour mots 18-19: " << block18_19.size() << std::endl;

// BLOC 20-21: Paires au sein de chaque groupe
std::vector<std::pair<std::string, std::string>> block20_21;

// Groupe 1
std::vector<std::string> groupe_1 = {"énergie", "physique", "relatif", "source"};
for (const auto& w1 : groupe_1) {
    for (const auto& w2 : groupe_1) {
        if (w1 != w2) {
            block20_21.push_back({w1, w2});
        }
    }
}

// Groupe 2
std::vector<std::string> groupe_2 = {"explorer", "énergie", "mesure", "partager", "parvenir", "source", "système"};
for (const auto& w1 : groupe_2) {
    for (const auto& w2 : groupe_2) {
        if (w1 != w2) {
            block20_21.push_back({w1, w2});
        }
    }
}

// Groupe 3
std::vector<std::string> groupe_3 = {"énergie", "libérer", "lumière", "mesure", "système", "titre", "varier", "vitesse"};
for (const auto& w1 : groupe_3) {
    for (const auto& w2 : groupe_3) {
        if (w1 != w2) {
            block20_21.push_back({w1, w2});
        }
    }
}

// Groupe 4
std::vector<std::string> groupe_4 = {"anarchie", "critère", "exemple", "janvier", "limite", "monnaie", "octobre", "pouvoir", "social", "système"};
for (const auto& w1 : groupe_4) {
    for (const auto& w2 : groupe_4) {
        if (w1 != w2) {
            block20_21.push_back({w1, w2});
        }
    }
}

// Groupe 5
std::vector<std::string> groupe_5 = {"argent", "cuivre", "dépenser", "épargne", "financer", "légal", "mesure", "métal", "monnaie", "papier", "pièce", "précieux", "social", "usage"};
for (const auto& w1 : groupe_5) {
    for (const auto& w2 : groupe_5) {
        if (w1 != w2) {
            block20_21.push_back({w1, w2});
        }
    }
}

std::cout << "Paires générées pour mots 20-21: " << block20_21.size() << std::endl;

// MOTS 22-23 (fixes)
std::string word22 = "open";
std::string word23 = "always";

// 8 CANDIDATES FOR WORD 24 (all must produce valid checksums!)
    std::vector<std::string> word24_candidates = {
        "alien", "detect", "flip", "gas", "organ", "peasant", "staff", "trigger"
    };

    std::cout << "\n🎯 Mode: Recherche de phrase où TOUS les 8 mots en position 24 produisent des checksums valides!" << std::endl;
    std::cout << "Mots 22-23 fixes: " << word22 << " " << word23 << std::endl;
    std::cout << "Candidats pour mot 24 (tous doivent valider): ";
    for (const auto& w : word24_candidates) {
        std::cout << w << " ";
    }
    std::cout << std::endl;

    // Convert to indices
    std::vector<uint16_t> h_block1_14;
    for (const auto& p : phrases_1_14) {
        h_block1_14.insert(h_block1_14.end(), p.begin(), p.end());
    }

    std::vector<uint16_t> h_block15_16;
    for (const auto& p : block15_16) {
        h_block15_16.push_back(word_to_index(p.first, french_wordlist));
        h_block15_16.push_back(word_to_index(p.second, french_wordlist));
    }

    std::vector<uint16_t> h_block17;
    for (const auto& w : block17) {
        h_block17.push_back(word_to_index(w, french_wordlist));
    }

    std::vector<uint16_t> h_block18_19;
    for (const auto& p : block18_19) {
        h_block18_19.push_back(word_to_index(p.first, french_wordlist));
        h_block18_19.push_back(word_to_index(p.second, french_wordlist));
    }

    std::vector<uint16_t> h_block20_21;
    for (const auto& p : block20_21) {
        h_block20_21.push_back(word_to_index(p.first, french_wordlist));
        h_block20_21.push_back(word_to_index(p.second, french_wordlist));
    }

    uint16_t h_word22 = word_to_index(word22, wordlist);
    uint16_t h_word23 = word_to_index(word23, wordlist);

    std::vector<uint16_t> h_word24_candidates;
    for (const auto& w : word24_candidates) {
        h_word24_candidates.push_back(word_to_index(w, wordlist));
    }

    // Calculate total combinations
    unsigned long long total_combinations = (unsigned long long)phrases_1_14.size() *
                                            block15_16.size() *
                                            block17.size() *
                                            block18_19.size() *
                                            block20_21.size();

    std::cout << "\n📊 Combinaisons de phrases à tester: " << total_combinations << std::endl;
    std::cout << "\nRépartition sur " << num_gpus << " GPU(s)" << std::endl << std::endl;

    // Multi-GPU configuration
    int threads = 256;
    int phrases_per_gpu = (phrases_1_14.size() + num_gpus - 1) / num_gpus;

    // Storage for GPU pointers
    std::vector<uint16_t*> d_block1_14_vec(num_gpus);
    std::vector<uint16_t*> d_block15_16_vec(num_gpus);
    std::vector<uint16_t*> d_block17_vec(num_gpus);
    std::vector<uint16_t*> d_block18_19_vec(num_gpus);
    std::vector<uint16_t*> d_block20_21_vec(num_gpus);
    std::vector<uint16_t*> d_word24_candidates_vec(num_gpus);
    std::vector<uint16_t*> d_result_vec(num_gpus);
    std::vector<bool*> d_found_vec(num_gpus);
    std::vector<unsigned long long*> d_counter_vec(num_gpus);  // ADDED: counter

    auto start = std::chrono::high_resolution_clock::now();

    // Calculate combinations per GPU and allocate memory
    std::vector<unsigned long long> total_per_gpu(num_gpus);
    std::vector<int> num_phrases_per_gpu(num_gpus);

    for (int gpu = 0; gpu < num_gpus; ++gpu) {
        cudaSetDevice(gpu);

        int start_phrase = gpu * phrases_per_gpu;
        int end_phrase = std::min(start_phrase + phrases_per_gpu, (int)phrases_1_14.size());
        num_phrases_per_gpu[gpu] = end_phrase - start_phrase;

        if (num_phrases_per_gpu[gpu] <= 0) continue;

        // Calculate total combinations for this GPU
        total_per_gpu[gpu] = (unsigned long long)num_phrases_per_gpu[gpu] *
                             block15_16.size() *
                             block17.size() *
                             block18_19.size() *
                             block20_21.size();

        std::cout << "GPU " << gpu << ": " << num_phrases_per_gpu[gpu] << " phrases, "
                  << total_per_gpu[gpu] << " combinaisons" << std::endl;

        // Extract phrases for this GPU
        std::vector<uint16_t> h_block1_14_gpu;
        for (int i = start_phrase; i < end_phrase; ++i) {
            h_block1_14_gpu.insert(h_block1_14_gpu.end(),
                                   h_block1_14.begin() + i * 14,
                                   h_block1_14.begin() + (i + 1) * 14);
        }

        // Allocate GPU memory
        cudaMalloc(&d_block1_14_vec[gpu], h_block1_14_gpu.size() * sizeof(uint16_t));
        cudaMalloc(&d_block15_16_vec[gpu], h_block15_16.size() * sizeof(uint16_t));
        cudaMalloc(&d_block17_vec[gpu], h_block17.size() * sizeof(uint16_t));
        cudaMalloc(&d_block18_19_vec[gpu], h_block18_19.size() * sizeof(uint16_t));
        cudaMalloc(&d_block20_21_vec[gpu], h_block20_21.size() * sizeof(uint16_t));
        cudaMalloc(&d_word24_candidates_vec[gpu], h_word24_candidates.size() * sizeof(uint16_t));
        cudaMalloc(&d_result_vec[gpu], 24 * sizeof(uint16_t));
        cudaMalloc(&d_found_vec[gpu], sizeof(bool));
        cudaMalloc(&d_counter_vec[gpu], sizeof(unsigned long long));

        // Copy to GPU
        cudaMemcpy(d_block1_14_vec[gpu], h_block1_14_gpu.data(), h_block1_14_gpu.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_block15_16_vec[gpu], h_block15_16.data(), h_block15_16.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_block17_vec[gpu], h_block17.data(), h_block17.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_block18_19_vec[gpu], h_block18_19.data(), h_block18_19.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_block20_21_vec[gpu], h_block20_21.data(), h_block20_21.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_word24_candidates_vec[gpu], h_word24_candidates.data(), h_word24_candidates.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);

        bool h_found = false;
        cudaMemcpy(d_found_vec[gpu], &h_found, sizeof(bool), cudaMemcpyHostToDevice);

        unsigned long long h_counter = 0;
        cudaMemcpy(d_counter_vec[gpu], &h_counter, sizeof(unsigned long long), cudaMemcpyHostToDevice);
    }

    std::cout << "\n🚀 Calcul en cours sur " << num_gpus << " GPU(s)..." << std::endl;

    // Batching parameters - max blocks per kernel launch (stay under CUDA limit)
    const unsigned long long MAX_BLOCKS_PER_LAUNCH = 1000000000ULL;  // 1 billion blocks per batch
    const unsigned long long THREADS_PER_BLOCK = threads;
    const unsigned long long COMBINATIONS_PER_BATCH = MAX_BLOCKS_PER_LAUNCH * THREADS_PER_BLOCK;

    bool found = false;
    int gpu_found = -1;
    std::vector<uint16_t> result(24);

    // Process each GPU with batching
    for (int gpu = 0; gpu < num_gpus && !found; ++gpu) {
        if (num_phrases_per_gpu[gpu] <= 0) continue;

        cudaSetDevice(gpu);
        unsigned long long total_this_gpu = total_per_gpu[gpu];
        unsigned long long processed = 0;
        unsigned long long batch_num = 0;
        unsigned long long total_batches = (total_this_gpu + COMBINATIONS_PER_BATCH - 1) / COMBINATIONS_PER_BATCH;

        while (processed < total_this_gpu && !found) {
            unsigned long long remaining = total_this_gpu - processed;
            unsigned long long this_batch = std::min(remaining, COMBINATIONS_PER_BATCH);
            int blocks = (this_batch + threads - 1) / threads;

            // Launch kernel for this batch
            test_combinations_kernel<<<blocks, threads>>>(
                d_block1_14_vec[gpu], d_block15_16_vec[gpu], d_block17_vec[gpu], d_block18_19_vec[gpu],
                d_block20_21_vec[gpu], h_word22, h_word23, d_word24_candidates_vec[gpu],
                num_phrases_per_gpu[gpu],
                block15_16.size(),
                block17.size(),
                block18_19.size(),
                block20_21.size(),
                d_found_vec[gpu], d_result_vec[gpu], d_counter_vec[gpu],
                processed  // batch offset
            );

            cudaDeviceSynchronize();

            // Check if found
            bool h_found;
            cudaMemcpy(&h_found, d_found_vec[gpu], sizeof(bool), cudaMemcpyDeviceToHost);
            if (h_found) {
                found = true;
                gpu_found = gpu;
                cudaMemcpy(result.data(), d_result_vec[gpu], 24 * sizeof(uint16_t), cudaMemcpyDeviceToHost);
                break;
            }

            processed += this_batch;
            batch_num++;

            // Progress update every 10 batches
            if (batch_num % 10 == 0 || processed >= total_this_gpu) {
                double progress = (double)processed / total_this_gpu * 100.0;
                std::cout << "\rGPU " << gpu << ": " << std::fixed << std::setprecision(2)
                          << progress << "% (" << batch_num << "/" << total_batches << " batches)" << std::flush;
            }
        }
        std::cout << std::endl;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Collect checksum counters from all GPUs
    unsigned long long total_checksums_computed = 0;

    for (int gpu = 0; gpu < num_gpus; ++gpu) {
        cudaSetDevice(gpu);
        unsigned long long h_counter;
        cudaMemcpy(&h_counter, d_counter_vec[gpu], sizeof(unsigned long long), cudaMemcpyDeviceToHost);
        total_checksums_computed += h_counter;
    }

    if (found) {
        std::cout << "\n🎉🎉🎉 === TROUVÉ sur GPU " << gpu_found << " === 🎉🎉🎉" << std::endl;
        std::cout << "Phrase gagnante: " << std::endl;
        for (int i = 0; i < 24; ++i) {
            std::cout << wordlist[result[i]] << " ";
            if ((i + 1) % 6 == 0) std::cout << std::endl;
        }
        std::cout << std::endl;
        std::cout << "\n✅ Cette phrase produit des checksums VALIDES pour les 8 mots:" << std::endl;
        for (const auto& w : word24_candidates) {
            std::cout << "  - " << w << std::endl;
        }
    } else {
        std::cout << "\n❌ Aucune solution trouvée dans cet espace de recherche." << std::endl;
    }

    // Performance metrics
    unsigned long long total_checksum_tests = total_combinations * 8;
    double speed_combinations = (double)total_combinations / (duration.count() / 1000.0);
    double speed_checksums = (double)total_checksum_tests / (duration.count() / 1000.0);
    
    // ADDED: Real speed based on actual computed checksums
    double real_speed_checksums = (double)total_checksums_computed / (duration.count() / 1000.0);

    std::cout << "\n⏱️  Temps total: " << duration.count() / 1000.0 << " secondes" << std::endl;
    std::cout << "\n📊 STATISTIQUES:" << std::endl;
    std::cout << "   Combinaisons testées: " << total_combinations << std::endl;
    std::cout << "   Checksums calculés: " << total_checksums_computed << std::endl;
    std::cout << "   Moyenne par combinaison: " << (double)total_checksums_computed / total_combinations << std::endl;
    std::cout << "\n🚀 PERFORMANCES:" << std::endl;
    std::cout << "   Vitesse: " << real_speed_checksums / 1e6 << " M checksums/s" << std::endl;
    std::cout << "   Par GPU: " << (real_speed_checksums / num_gpus) / 1e6 << " M checksums/s" << std::endl;

    // Free memory
    for (int gpu = 0; gpu < num_gpus; ++gpu) {
        cudaSetDevice(gpu);
        cudaFree(d_block1_14_vec[gpu]);
        cudaFree(d_block15_16_vec[gpu]);
        cudaFree(d_block17_vec[gpu]);
        cudaFree(d_block18_19_vec[gpu]);
        cudaFree(d_block20_21_vec[gpu]);
        cudaFree(d_word24_candidates_vec[gpu]);
        cudaFree(d_result_vec[gpu]);
        cudaFree(d_found_vec[gpu]);
        cudaFree(d_counter_vec[gpu]);  // ADDED
    }

    return 0;
}