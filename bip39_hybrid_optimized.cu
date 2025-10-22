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
    const uint16_t* block15_16,   // Mots 15-16 (paires)
    const uint16_t* block17,      // Mot 17
    const uint16_t* block18_19,   // Mots 18-19
    const uint16_t* block20_21,   // Mots 20-21
    const uint16_t* block22_24,   // Mots 22-24 fixes
    const uint16_t* target_words, // 8 mots cibles
    int num_block1_14,
    int num_block15_16,
    int num_block17,
    int num_block18_19,
    int num_block20_21,
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
    
    // Calcul des indices pour chaque bloc (dynamique)
    unsigned long long total_combinations = 
        (unsigned long long)num_block1_14 * num_block15_16 * num_block17 * num_block18_19 * num_block20_21;
    
    if (idx >= total_combinations) return;
    
    // Décomposition de l'index
    int i1_14 = idx % num_block1_14;
    unsigned long long temp = idx / num_block1_14;
    
    int i15_16 = temp % num_block15_16;
    temp /= num_block15_16;
    
    int i17 = temp % num_block17;
    temp /= num_block17;
    
    int i18_19 = temp % num_block18_19;
    temp /= num_block18_19;
    
    int i20_21 = temp % num_block20_21;
    
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
    std::cout << "=== BIP39 CUDA OPTIMIZER - MULTI-GPU ===" << std::endl;
    
    // Détecter le nombre de GPUs disponibles
    int num_gpus;
    cudaGetDeviceCount(&num_gpus);
    std::cout << "GPUs détectés: " << num_gpus << std::endl;
    
    if (num_gpus == 0) {
        std::cerr << "Erreur: Aucun GPU CUDA détecté!" << std::endl;
        return 1;
    }
    
    // Afficher les infos de chaque GPU
    for (int i = 0; i < num_gpus; ++i) {
        cudaDeviceProp prop;
        cudaGetDeviceProperties(&prop, i);
        std::cout << "GPU " << i << ": " << prop.name 
                  << " (" << prop.multiProcessorCount << " SMs, "
                  << prop.totalGlobalMem / (1024*1024*1024) << " GB)" << std::endl;
    }
    std::cout << std::endl;
    
    // Charger la wordlist BIP39 anglaise (pour les mots cibles)
    std::vector<std::string> wordlist = load_wordlist("english.txt");
    if (wordlist.size() != 2048) {
        std::cerr << "Erreur: wordlist anglaise invalide" << std::endl;
        return 1;
    }
    
    // Charger la wordlist BIP39 française (pour le mot 17)
    std::vector<std::string> french_wordlist = load_wordlist("french.txt");
    if (french_wordlist.size() != 2048) {
        std::cerr << "Erreur: wordlist française invalide (attendu 2048 mots, obtenu " 
                  << french_wordlist.size() << ")" << std::endl;
        return 1;
    }
    std::cout << "Wordlist française chargée: " << french_wordlist.size() << " mots" << std::endl;
    
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
    // Block 15-16: Liste des mots à combiner
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
    
    // Générer toutes les paires (A,B) où A != B
    // A-B et B-A comptent comme deux paires différentes
    std::vector<std::pair<std::string, std::string>> block15_16;
    for (size_t i = 0; i < words_15_16.size(); ++i) {
        for (size_t j = 0; j < words_15_16.size(); ++j) {
            if (i != j) {  // Pas de paires avec le même mot deux fois
                block15_16.push_back({words_15_16[i], words_15_16[j]});
            }
        }
    }
    
    std::cout << "Paires générées pour mots 15-16: " << block15_16.size() << std::endl;
    
    // Block 17: Tous les 2048 mots de la wordlist française
    std::vector<std::string> block17 = french_wordlist;
    std::cout << "Mots pour position 17: " << block17.size() << std::endl;
    
    // Block 18-19: Liste des mots à combiner
    std::vector<std::string> words_18_19 = {
        "énergie", "monnaie", "économie", "progrès", "amour", "bonheur", "science"
    };
    
    // Générer toutes les paires (A,B) où A != B
    std::vector<std::pair<std::string, std::string>> block18_19;
    for (size_t i = 0; i < words_18_19.size(); ++i) {
        for (size_t j = 0; j < words_18_19.size(); ++j) {
            if (i != j) {
                block18_19.push_back({words_18_19[i], words_18_19[j]});
            }
        }
    }
    
    std::cout << "Paires générées pour mots 18-19: " << block18_19.size() << std::endl;
    
    // Block 20-21: 5 groupes de mots, paires générées dans chaque groupe
    std::vector<std::vector<std::string>> groups_20_21 = {
        // Groupe 1 (4 mots)
        {"énergie", "physique", "relatif", "source"},
        
        // Groupe 2 (7 mots)
        {"explorer", "énergie", "mesure", "partager", "parvenir", "source", "système"},
        
        // Groupe 3 (8 mots)
        {"énergie", "libérer", "lumière", "mesure", "système", "titre", "varier", "vitesse"},
        
        // Groupe 4 (10 mots)
        {"anarchie", "critère", "exemple", "janvier", "limite", "monnaie", "octobre", "pouvoir", "social", "système"},
        
        // Groupe 5 (14 mots)
        {"argent", "cuivre", "dépenser", "épargne", "financer", "légal", "mesure", "métal", "monnaie", "papier", "pièce", "précieux", "social", "usage"}
    };
    
    // Générer toutes les paires dans chaque groupe (A,B) où A != B
    std::vector<std::pair<std::string, std::string>> block20_21;
    for (const auto& group : groups_20_21) {
        for (size_t i = 0; i < group.size(); ++i) {
            for (size_t j = 0; j < group.size(); ++j) {
                if (i != j) {
                    block20_21.push_back({group[i], group[j]});
                }
            }
        }
    }
    
    std::cout << "Paires générées pour mots 20-21: " << block20_21.size() << std::endl;
    
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
        h_block17.push_back(word_to_index(w, french_wordlist));
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
    
    // Configuration pour multi-GPU
    int threads = 256;
    unsigned long long total_combinations = (unsigned long long)phrases_1_14.size() * 
                                            block15_16.size() * 
                                            block17.size() * 
                                            block18_19.size() * 
                                            block20_21.size();
    
    std::cout << "Combinaisons totales: " << total_combinations << std::endl;
    std::cout << "Répartition sur " << num_gpus << " GPU(s)" << std::endl << std::endl;
    
    // Diviser le travail entre les GPUs (par phrases)
    int phrases_per_gpu = (phrases_1_14.size() + num_gpus - 1) / num_gpus;
    
    // Variables pour stocker les pointeurs de chaque GPU
    std::vector<uint16_t*> d_block1_14_vec(num_gpus);
    std::vector<uint16_t*> d_block15_16_vec(num_gpus);
    std::vector<uint16_t*> d_block17_vec(num_gpus);
    std::vector<uint16_t*> d_block18_19_vec(num_gpus);
    std::vector<uint16_t*> d_block20_21_vec(num_gpus);
    std::vector<uint16_t*> d_block22_24_vec(num_gpus);
    std::vector<uint16_t*> d_targets_vec(num_gpus);
    std::vector<uint16_t*> d_result_vec(num_gpus);
    std::vector<bool*> d_found_vec(num_gpus);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Lancer sur chaque GPU
    for (int gpu = 0; gpu < num_gpus; ++gpu) {
        cudaSetDevice(gpu);
        
        // Calculer la portion de phrases pour ce GPU
        int start_phrase = gpu * phrases_per_gpu;
        int end_phrase = std::min(start_phrase + phrases_per_gpu, (int)phrases_1_14.size());
        int num_phrases_this_gpu = end_phrase - start_phrase;
        
        if (num_phrases_this_gpu <= 0) continue;
        
        std::cout << "GPU " << gpu << ": phrases " << start_phrase << " à " << end_phrase-1 
                  << " (" << num_phrases_this_gpu << " phrases)" << std::endl;
        
        // Extraire les phrases pour ce GPU
        std::vector<uint16_t> h_block1_14_gpu;
        for (int i = start_phrase; i < end_phrase; ++i) {
            h_block1_14_gpu.insert(h_block1_14_gpu.end(), 
                                   h_block1_14.begin() + i * 14, 
                                   h_block1_14.begin() + (i + 1) * 14);
        }
        
        // Allocation GPU
        cudaMalloc(&d_block1_14_vec[gpu], h_block1_14_gpu.size() * sizeof(uint16_t));
        cudaMalloc(&d_block15_16_vec[gpu], h_block15_16.size() * sizeof(uint16_t));
        cudaMalloc(&d_block17_vec[gpu], h_block17.size() * sizeof(uint16_t));
        cudaMalloc(&d_block18_19_vec[gpu], h_block18_19.size() * sizeof(uint16_t));
        cudaMalloc(&d_block20_21_vec[gpu], h_block20_21.size() * sizeof(uint16_t));
        cudaMalloc(&d_block22_24_vec[gpu], h_block22_24.size() * sizeof(uint16_t));
        cudaMalloc(&d_targets_vec[gpu], h_targets.size() * sizeof(uint16_t));
        cudaMalloc(&d_result_vec[gpu], 24 * sizeof(uint16_t));
        cudaMalloc(&d_found_vec[gpu], sizeof(bool));
        
        // Copie vers GPU
        cudaMemcpy(d_block1_14_vec[gpu], h_block1_14_gpu.data(), h_block1_14_gpu.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_block15_16_vec[gpu], h_block15_16.data(), h_block15_16.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_block17_vec[gpu], h_block17.data(), h_block17.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_block18_19_vec[gpu], h_block18_19.data(), h_block18_19.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_block20_21_vec[gpu], h_block20_21.data(), h_block20_21.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_block22_24_vec[gpu], h_block22_24.data(), h_block22_24.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
        cudaMemcpy(d_targets_vec[gpu], h_targets.data(), h_targets.size() * sizeof(uint16_t), cudaMemcpyHostToDevice);
        
        bool h_found = false;
        cudaMemcpy(d_found_vec[gpu], &h_found, sizeof(bool), cudaMemcpyHostToDevice);
        
        // Calculer le nombre de blocks pour ce GPU
        unsigned long long total_this_gpu = (unsigned long long)num_phrases_this_gpu * 
                                            block15_16.size() * 
                                            block17.size() * 
                                            block18_19.size() * 
                                            block20_21.size();
        int blocks = (total_this_gpu + threads - 1) / threads;
        
        std::cout << "  Combinaisons: " << total_this_gpu << " (" << blocks << " blocks)" << std::endl;
        
        // Lancement kernel sur ce GPU
        test_combinations_kernel<<<blocks, threads>>>(
            d_block1_14_vec[gpu], d_block15_16_vec[gpu], d_block17_vec[gpu], d_block18_19_vec[gpu],
            d_block20_21_vec[gpu], d_block22_24_vec[gpu], d_targets_vec[gpu],
            num_phrases_this_gpu, 
            block15_16.size(),
            block17.size(),
            block18_19.size(),
            block20_21.size(),
            d_found_vec[gpu], d_result_vec[gpu]
        );
    }
    
    std::cout << "\n🚀 Calcul en cours sur " << num_gpus << " GPU(s)..." << std::endl;
    
    // Attendre que tous les GPUs finissent
    for (int gpu = 0; gpu < num_gpus; ++gpu) {
        cudaSetDevice(gpu);
        cudaDeviceSynchronize();
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // Vérifier les résultats de chaque GPU
    bool found = false;
    std::vector<uint16_t> result(24);
    int gpu_found = -1;
    
    for (int gpu = 0; gpu < num_gpus; ++gpu) {
        cudaSetDevice(gpu);
        bool h_found;
        cudaMemcpy(&h_found, d_found_vec[gpu], sizeof(bool), cudaMemcpyDeviceToHost);
        
        if (h_found) {
            found = true;
            gpu_found = gpu;
            cudaMemcpy(result.data(), d_result_vec[gpu], 24 * sizeof(uint16_t), cudaMemcpyDeviceToHost);
            break;
        }
    }
    
    if (found) {
        std::cout << "\n🎉 === TROUVÉ sur GPU " << gpu_found << " ===" << std::endl;
        for (int i = 0; i < 24; ++i) {
            std::cout << wordlist[result[i]] << " ";
        }
        std::cout << std::endl;
    } else {
        std::cout << "\n❌ Aucune solution trouvée." << std::endl;
    }
    
    double speed = (double)total_combinations / (duration.count() / 1000.0);
    std::cout << "\n⏱️  Temps total: " << duration.count() / 1000.0 << " secondes" << std::endl;
    std::cout << "⚡ Vitesse globale: " << speed / 1e9 << " GH/s" << std::endl;
    std::cout << "🚀 Vitesse par GPU: " << (speed / num_gpus) / 1e9 << " GH/s" << std::endl;
    
    // Libération mémoire de tous les GPUs
    for (int gpu = 0; gpu < num_gpus; ++gpu) {
        cudaSetDevice(gpu);
        cudaFree(d_block1_14_vec[gpu]);
        cudaFree(d_block15_16_vec[gpu]);
        cudaFree(d_block17_vec[gpu]);
        cudaFree(d_block18_19_vec[gpu]);
        cudaFree(d_block20_21_vec[gpu]);
        cudaFree(d_block22_24_vec[gpu]);
        cudaFree(d_targets_vec[gpu]);
        cudaFree(d_result_vec[gpu]);
        cudaFree(d_found_vec[gpu]);
    }
    
    return 0;
}
