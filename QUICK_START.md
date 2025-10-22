# 🚀 GUIDE DE DÉMARRAGE RAPIDE - BIP39 CUDA OPTIMIZER

## ⚡ Installation en 5 minutes

### 1️⃣ Prérequis

Vérifiez que vous avez CUDA installé:
```bash
nvcc --version
nvidia-smi
```

Si CUDA n'est pas installé, installez-le:
```bash
# Ubuntu/Debian
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt-get update
sudo apt-get install -y cuda-toolkit-12-3

# Ajouter au PATH
echo 'export PATH=/usr/local/cuda/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

### 2️⃣ Préparation des fichiers

Vous avez besoin de 2 fichiers dans le même dossier que le programme:

**A) english.txt** - La wordlist BIP39 officielle
```bash
wget https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
```

**B) phrases_14_mots.txt** - Votre fichier de phrases (format: 14 mots par ligne)
```
abandon ability able about above absent absorb abstract absurd abuse access accident
ability able about above absent absorb abstract absurd abuse access accident account
...
```

### 3️⃣ Compilation

```bash
make
```

C'est tout! Le Makefile est déjà configuré pour RTX 4090.

### 4️⃣ Exécution

```bash
./bip39_hybrid
```

---

## 📊 Ce que vous allez voir

```
=== BIP39 CUDA OPTIMIZER - RTX 4090 ===
Phrases 1-14 chargées: 1000
Combinaisons totales: 900000
Lancement: 3516 blocks x 256 threads

=== TROUVÉ ===
abandon ability able about above absent absorb abstract absurd abuse access accident account across ...

Temps: 156 ms
Vitesse: 5.77 GH/s
```

---

## 🎯 Configuration des blocs de mots

Le programme utilise VOS valeurs exactes définies dans le code:

### Blocs configurés:
- **Mots 1-14**: Depuis `phrases_14_mots.txt`
- **Mots 15-16**: laitue/peser, laitue/pouvoir, prairie/peser, prairie/pouvoir
- **Mot 17**: motif, peintre, sécher
- **Mots 18-19**: écrire/histoire, écrire/mérite, histoire/mérite
- **Mots 20-21**: 25 combinaisons (énergie, anarchie, griffe, civil, étrange × fleur, ombre, poésie, énorme, cloche)
- **Mots 22-24**: open, always, staff

### Mots de test (checksums):
alien, detect, flip, gas, organ, peasant, trigger, staff

---

## ⚙️ Personnalisation

Pour modifier les blocs de mots, éditez le fichier `bip39_hybrid_optimized.cu`:

```cpp
// Ligne ~485 - Bloc 15-16
std::vector<std::pair<std::string, std::string>> block15_16 = {
    {"laitue", "peser"}, {"laitue", "pouvoir"},
    {"prairie", "peser"}, {"prairie", "pouvoir"}
};

// Ligne ~490 - Bloc 17
std::vector<std::string> block17 = {"motif", "peintre", "sécher"};

// etc...
```

Puis recompilez:
```bash
make clean
make
```

---

## 🔍 Dépannage rapide

### Erreur: "nvcc: command not found"
```bash
export PATH=/usr/local/cuda/bin:$PATH
```

### Erreur: "english.txt not found"
```bash
wget https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
```

### Erreur: "phrases_14_mots.txt not found"
Créez votre fichier avec 14 mots par ligne (séparés par des espaces)

### Performance faible
Vérifiez que vous utilisez bien une RTX 4090:
```bash
nvidia-smi
```

---

## 📈 Performances attendues

| Combinaisons | Temps estimé (RTX 4090) |
|--------------|-------------------------|
| 1 million | < 1 seconde |
| 100 millions | ~20 secondes |
| 1 milliard | ~3 minutes |
| 1 trillion | ~3 heures |

---

## 📚 Fichiers du projet

- `bip39_hybrid_optimized.cu` - Code source principal
- `Makefile` - Configuration de compilation
- `QUICK_START.md` - Ce fichier
- `README.md` - Documentation complète
- `TECHNICAL_DETAILS.md` - Détails techniques

---

## ✅ Checklist avant exécution

- [ ] CUDA installé (nvcc --version)
- [ ] english.txt téléchargé
- [ ] phrases_14_mots.txt créé
- [ ] Programme compilé (make)
- [ ] GPU RTX 4090 détecté

---

## 🆘 Besoin d'aide?

1. Vérifiez les logs d'erreur
2. Consultez TECHNICAL_DETAILS.md
3. Testez avec moins de combinaisons d'abord

---

**C'est parti! 🚀**
