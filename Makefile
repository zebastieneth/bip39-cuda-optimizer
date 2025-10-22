# Makefile pour BIP39 CUDA Optimizer
# Optimisé pour RTX 4090

# Compilateur
NVCC = nvcc

# Flags de compilation pour RTX 4090 (architecture Ada Lovelace, compute capability 8.9)
NVCC_FLAGS = -arch=sm_89 \
             -O3 \
             --use_fast_math \
             -Xptxas -O3 \
             -Xcompiler -O3 \
             -lineinfo

# Nom de l'exécutable
TARGET = bip39_hybrid

# Fichier source
SRC = bip39_hybrid_optimized.cu

# Règle par défaut
all: $(TARGET)

# Compilation
$(TARGET): $(SRC)
	@echo "Compilation avec optimisations RTX 4090..."
	$(NVCC) $(NVCC_FLAGS) $(SRC) -o $(TARGET)
	@echo "Compilation terminée: $(TARGET)"

# Compilation avec debug
debug: NVCC_FLAGS += -g -G
debug: $(TARGET)
	@echo "Version debug compilée"

# Nettoyage
clean:
	rm -f $(TARGET)
	@echo "Nettoyage effectué"

# Test
test: $(TARGET)
	@echo "Lancement du test..."
	./$(TARGET)

# Informations GPU
info:
	@echo "=== Information GPU ==="
	nvidia-smi --query-gpu=name,driver_version,memory.total,compute_cap --format=csv
	@echo ""
	nvcc --version

# Installation (si besoin de copier ailleurs)
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	@echo "Installation terminée"

.PHONY: all clean test info debug install
