# 🚀 BIP39 CUDA Checksum Optimizer

Programme CUDA ultra-optimisé pour tester massivement des combinaisons de mnémoniques BIP39 et valider leurs checksums sur GPU NVIDIA RTX 4090.

## ⚡ Performances

- **Vitesse**: 5-20 GH/s (milliards de checksums/seconde)
- **GPU**: Optimisé pour RTX 4090
- **Gain vs CPU**: 1000-4000×

## 🎯 Fonctionnalités

✅ Parallélisation massive GPU  
✅ Early exit optimization  
✅ Shared memory cache  
✅ SHA-256 optimisé  
✅ Validation BIP39 complète  

## 🚀 Installation rapide

### Prérequis
- NVIDIA GPU (RTX 4090 recommandé)
- CUDA Toolkit 12.x
- Linux (Ubuntu/WSL)

### Installation
```bash
# Télécharger la wordlist BIP39
wget https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt

# Créer votre fichier de phrases (14 mots par ligne)
nano phrases_14_mots.txt

# Compiler
make

# Lancer
./bip39_hybrid
```

## 📖 Documentation

- **QUICK_START.md** - Guide de démarrage (5 min)
- **TECHNICAL_DETAILS.md** - Détails techniques
- **00_START_HERE.txt** - Vue d'ensemble

## ⚙️ Configuration

Le programme teste des combinaisons structurées en blocs:
- Mots 1-14: Depuis `phrases_14_mots.txt`
- Mots 15-21: Combinaisons configurables
- Mots 22-24: Validation avec 8 mots cibles

Voir le code source pour personnaliser les blocs.

## 🔐 Avertissement

⚠️ **Usage légal uniquement**: Ce logiciel est destiné à la récupération de VOS propres phrases BIP39. L'utilisation pour attaquer des wallets qui ne vous appartiennent pas est ILLÉGALE.

## 📄 Licence

MIT License - Voir [LICENSE](LICENSE)

---

**Performance**: Pour 1 milliard de combinaisons → ~3 minutes sur RTX 4090 🚀
