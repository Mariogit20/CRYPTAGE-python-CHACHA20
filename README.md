# CRYPTAGE-python-CHACHA20

# 🔒 SecureFolder - Streaming Edition (ChaCha20)

Un logiciel de chiffrement de dossiers open-source, rapide et ultra-sécurisé, développé en Python avec une interface graphique **PyQt6**. 

Ce projet a été conçu avec un objectif principal : **pouvoir chiffrer et déchiffrer des fichiers massifs (vidéos, archives de plus de 256 Go) sans jamais saturer la mémoire RAM (MemoryError)** et sans imposer les limites de taille inhérentes à certains algorithmes authentifiés.

## ✨ Fonctionnalités Principales

* 🚀 **Support des fichiers géants :** Utilisation de l'algorithme **ChaCha20 pur** en mode "streaming" (traitement par blocs de 64 Ko). Aucun fichier n'est trop lourd pour ce logiciel.
* 🛡️ **Sécurité Anti-Crash (Remplacement Atomique) :** Vos fichiers originaux sont protégés. En cas de coupure de courant, de plantage ou de disque dur plein en plein milieu de l'opération, le fichier original n'est jamais supprimé ou corrompu. Le système utilise des fichiers temporaires (`.tmp`).
* 🔑 **Gestion centralisée de la clé :** Le logiciel génère une clé de sécurité locale (`ma_cle_chacha20.key`). Un bouton dédié permet de la sauvegarder facilement sur une clé USB externe.
* ⚡ **Interface Fluide (Multithreading) :** Le chiffrement s'exécute en arrière-plan via un `QThread`, permettant à l'interface de rester réactive tout en affichant une barre de progression précise.

## 🚀 Utilisation Rapide (Version Exécutable Windows)

Si vous êtes sur Windows et ne souhaitez pas installer Python, vous pouvez utiliser la version compilée prête à l'emploi :
1. Allez dans le dossier `CRYPTAGE DOSSIER/chiffrement symétrique Fernet ChaCha20/dist/`
2. Double-cliquez sur l'exécutable `.exe`.
3. Cliquez sur **"Parcourir les dossiers"** pour choisir le dossier à sécuriser.
4. Cliquez sur **"Chiffrer le dossier"** (les fichiers obtiendront l'extension `.enc`).

⚠️ **ATTENTION :** Dès la première exécution, cliquez sur **"Sauvegarder la clé de sécurité (USB)"**. Sans ce fichier `.key`, **vos données chiffrées seront définitivement illisibles**.

## 💻 Installation pour les Développeurs

Si vous souhaitez exécuter le code source ou le modifier, voici la marche à suivre :

### Prérequis
* Python 3.9 ou supérieur.
* Git.

### Étapes d'installation

1. **Cloner le dépôt :**
   ```bash
   git clone [https://github.com/Mariogit20/CRYPTAGE-python-CHACHA20.git](https://github.com/Mariogit20/CRYPTAGE-python-CHACHA20.git)
   cd CRYPTAGE-python-CHACHA20/"CRYPTAGE DOSSIER/chiffrement symétrique Fernet ChaCha20"
