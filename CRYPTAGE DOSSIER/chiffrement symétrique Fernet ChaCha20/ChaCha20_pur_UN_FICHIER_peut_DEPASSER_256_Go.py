# =====================================================================
# IMPORTATIONS DES MODULES NÉCESSAIRES
# =====================================================================
import sys      # Permet de manipuler l'environnement du système (nécessaire pour démarrer et quitter l'app PyQt)
import os       # Permet d'interagir avec le système d'exploitation (lire/écrire des fichiers, lister des dossiers, renommer)
import shutil   # Fournit des fonctions de haut niveau pour copier des fichiers (utilisé ici pour sauvegarder la clé)

# Importation des composants visuels de PyQt6 pour construire l'interface graphique
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QFileDialog, QLabel, QMessageBox, 
                             QFrame, QSizePolicy, QSpacerItem, QProgressBar)

# Importation des outils de gestion du temps et des Threads (processus en arrière-plan)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# Importation de la bibliothèque de cryptographie pour utiliser l'algorithme ChaCha20
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


# =====================================================================
# 1. CRÉATION DU WORKER (Le "travailleur" de l'ombre)
# =====================================================================
# Dans PyQt, l'interface graphique tourne sur le "Thread principal". 
# Si on fait un gros calcul (comme chiffrer 50 Go) sur ce thread, la fenêtre va figer (Ne répond pas).
# On crée donc un QThread séparé pour faire le travail lourd en arrière-plan.
class WorkerCryptage(QThread):
    
    # DÉCLARATION DES SIGNAUX : Les threads ne peuvent pas modifier l'interface directement.
    # Ils doivent envoyer des "signaux" à la fenêtre principale pour qu'elle se mette à jour.
    progression = pyqtSignal(int)      # Enverra un nombre entier (le % de progression) à la barre
    info_fichier = pyqtSignal(str)     # Enverra du texte (le nom du fichier en cours) au label
    termine = pyqtSignal(int, int)     # Enverra deux entiers à la fin : (nombre de fichiers réussis, nombre d'erreurs)

    def __init__(self, chemin_cible, cle, taille_chunk, action):
        # Initialisation de la classe parente QThread
        super().__init__()
        
        # On sauvegarde les paramètres reçus depuis l'interface dans les variables du Worker
        self.chemin_cible = chemin_cible  # Le dossier choisi par l'utilisateur
        self.cle = cle                    # La clé secrète de 32 octets
        self.taille_chunk = taille_chunk  # La taille des morceaux à lire (ici 64 Ko)
        self.action = action              # L'action choisie : 'chiffrer' ou 'dechiffrer'

    # La méthode run() est le "cœur" du thread. Elle s'exécute automatiquement quand on lance worker.start()
    def run(self):
        # --- ÉTAPE 1 : INVENTAIRE DES FICHIERS ---
        fichiers_a_traiter = [] # Liste vide qui contiendra les chemins de tous les fichiers à traiter
        
        # os.walk() explore le dossier racine et tous ses sous-dossiers automatiquement
        for racine, sous_dossiers, fichiers in os.walk(self.chemin_cible):
            for nom_fichier in fichiers:
                # Si l'utilisateur a cliqué sur "Chiffrer"
                if self.action == 'chiffrer':
                    # On ne chiffre pas les fichiers déjà chiffrés (.enc) ni notre propre clé de sécurité !
                    if not nom_fichier.endswith(".enc") and nom_fichier != "ma_cle_chacha20.key":
                        # On assemble le chemin complet du fichier et on l'ajoute à la liste
                        fichiers_a_traiter.append(os.path.join(racine, nom_fichier))
                
                # Si l'utilisateur a cliqué sur "Déchiffrer"
                elif self.action == 'dechiffrer':
                    # On ne traite QUE les fichiers qui se terminent par ".enc"
                    if nom_fichier.endswith(".enc"):
                        fichiers_a_traiter.append(os.path.join(racine, nom_fichier))

        # On compte combien de fichiers on a trouvé au total pour calculer les pourcentages
        total_fichiers = len(fichiers_a_traiter)
        
        # Si la liste est vide, on signale immédiatement que c'est fini et on arrête la fonction (return)
        if total_fichiers == 0:
            self.termine.emit(0, 0)
            return

        # Compteurs pour le rapport de fin
        fichiers_traites = 0
        erreurs = 0

        # --- ÉTAPE 2 : TRAITEMENT DE CHAQUE FICHIER ---
        # enumerate() permet de parcourir la liste tout en gardant le compte (index 0, 1, 2...)
        for index, chemin_complet in enumerate(fichiers_a_traiter):
            
            # On extrait juste le nom du fichier (sans le chemin) pour l'afficher proprement
            nom_fichier = os.path.basename(chemin_complet)
            
            # On envoie un signal à l'interface pour afficher : "Traitement : nom_du_fichier.mp4"
            self.info_fichier.emit(f"Traitement : {nom_fichier}")
            
            # Utilisation d'un bloc try/except : si un fichier pose problème, le programme ne crashe pas,
            # il passe simplement au fichier suivant.
            try:
                # ==========================
                # LOGIQUE DE CHIFFREMENT
                # ==========================
                if self.action == 'chiffrer':
                    # On définit le nom du fichier final : "fichier.mp4.enc"
                    chemin_final = chemin_complet + ".enc"
                    # On définit le nom du fichier temporaire sécurisé : "fichier.mp4.enc.tmp"
                    chemin_tmp = chemin_final + ".tmp"
                    
                    # Génération d'un "nonce" (Number Used Once) aléatoire de 16 octets. Indispensable pour ChaCha20.
                    nonce = os.urandom(16)
                    # Initialisation de l'algorithme ChaCha20 avec la clé secrète et le nonce
                    cipher = Cipher(algorithms.ChaCha20(self.cle, nonce), mode=None)
                    # Création de l'objet qui va effectuer le chiffrement
                    encryptor = cipher.encryptor()
                    
                    # On ouvre le fichier original en lecture binaire ("rb") 
                    # et le fichier temporaire en écriture binaire ("wb")
                    with open(chemin_complet, "rb") as f_in, open(chemin_tmp, "wb") as f_out:
                        # On écrit le nonce tout au début du fichier chiffré (il sera nécessaire pour déchiffrer)
                        f_out.write(nonce)
                        
                        # Boucle de lecture par "morceaux" (chunks) pour ne pas saturer la RAM avec de gros fichiers
                        while True:
                            # On lit 64 Ko (taille_chunk) du fichier original
                            chunk = f_in.read(self.taille_chunk)
                            # Si chunk est vide, on a atteint la fin du fichier, on casse la boucle (break)
                            if not chunk: 
                                break
                            # On chiffre le morceau lu et on l'écrit immédiatement dans le fichier temporaire
                            f_out.write(encryptor.update(chunk))
                        
                        # Finalise proprement l'opération cryptographique (vide les tampons internes de l'algo)
                        f_out.write(encryptor.finalize())
                        
                    # L'écriture est terminée à 100%. Il est maintenant SÛR de remplacer le fichier.
                    # On renomme le fichier ".tmp" en ".enc" (opération atomique par l'OS)
                    os.replace(chemin_tmp, chemin_final)
                    # On supprime le fichier original en clair
                    os.remove(chemin_complet)

                # ==========================
                # LOGIQUE DE DÉCHIFFREMENT
                # ==========================
                elif self.action == 'dechiffrer':
                    # On enlève les 4 derniers caractères (".enc") pour retrouver le nom original
                    chemin_final = chemin_complet[:-4]
                    # Fichier temporaire pour protéger les données en cas de crash
                    chemin_tmp = chemin_final + ".tmp"
                    
                    with open(chemin_complet, "rb") as f_in, open(chemin_tmp, "wb") as f_out:
                        # On lit les 16 premiers octets du fichier .enc : c'est notre nonce !
                        nonce = f_in.read(16)
                        # On initialise l'algorithme ChaCha20 avec notre clé et le nonce qu'on vient de lire
                        cipher = Cipher(algorithms.ChaCha20(self.cle, nonce), mode=None)
                        # Création de l'objet qui va effectuer le déchiffrement
                        decryptor = cipher.decryptor()
                        
                        # Lecture et déchiffrement par morceaux
                        while True:
                            chunk = f_in.read(self.taille_chunk)
                            if not chunk: 
                                break
                            f_out.write(decryptor.update(chunk))
                        
                        f_out.write(decryptor.finalize()) # Clôture
                        
                    # Si tout s'est bien passé, on renomme le .tmp pour lui rendre son extension originale
                    os.replace(chemin_tmp, chemin_final)
                    # On supprime le fichier chiffré ".enc"
                    os.remove(chemin_complet)

                # Si on arrive ici sans erreur, on incrémente le compteur de succès
                fichiers_traites += 1
                
            except Exception as e:
                # Si n'importe quelle erreur survient (disque plein, permission refusée, etc.)
                erreurs += 1
                print(f"Erreur sur {nom_fichier} : {e}")
                
                # NETTOYAGE : Si le fichier .tmp a eu le temps d'être créé avant le crash, on le supprime.
                # On utilise locals() pour vérifier que la variable chemin_tmp a bien été définie dans ce cycle.
                if 'chemin_tmp' in locals() and os.path.exists(chemin_tmp):
                    os.remove(chemin_tmp)

            # Calcul mathématique du pourcentage de progression global
            pourcentage = int(((index + 1) / total_fichiers) * 100)
            # Envoi du signal à l'interface pour faire avancer la barre bleue
            self.progression.emit(pourcentage)

        # Fin de la boucle : on signale à l'interface que tout est fini, avec le bilan.
        self.termine.emit(fichiers_traites, erreurs)


# =====================================================================
# 2. L'INTERFACE GRAPHIQUE (La Fenêtre Principale)
# =====================================================================
class LogicielCryptage(QWidget):
    def __init__(self):
        # Initialisation de la classe de base QWidget
        super().__init__()
        
        # Configuration des paramètres de la fenêtre
        self.setWindowTitle("SecureFolder - Streaming Edition - Version 2") # Titre de la fenêtre
        self.resize(550, 480)                                   # Taille par défaut (largeur, hauteur)
        self.setMinimumSize(450, 400)                           # Taille minimum (impossible de réduire plus)
        
        # Initialisation des variables globales de l'application
        self.chemin_cible = None                  # Stockera le chemin du dossier choisi
        self.cle = None                           # Stockera la clé chargée en mémoire
        self.fichier_cle = "ma_cle_chacha20.key"  # Le nom du fichier contenant la clé
        self.taille_chunk = 64 * 1024             # 64 Ko de lecture à la fois (idéal pour les disques durs)
        
        # Appel des fonctions pour construire la fenêtre, la décorer et charger la clé
        self.initUI()
        self.appliquer_style()
        self.charger_ou_generer_cle()

    def initUI(self):
        # Création du "Layout Principal" (Boîte verticale qui empile les éléments de haut en bas)
        layout_principal = QVBoxLayout()
        layout_principal.setContentsMargins(30, 30, 30, 30) # Marges intérieures (G, H, D, B)
        layout_principal.setSpacing(20)                     # Espace entre chaque élément

        # 1. Titre d'information
        texte_titre = (
            "Avec le ChaCha20 pur, un fichier individuel à l'intérieur\n"
            "du dossier peut parfaitement dépasser 256 Go.\n"
            "Aucun Message d'Erreur si un Fichier dépasse 256 Go !"
        )
        titre = QLabel(texte_titre)             
        titre.setObjectName("titre")                     # On donne un ID pour pouvoir le styliser en CSS plus tard
        titre.setAlignment(Qt.AlignmentFlag.AlignCenter) # Centrer le texte
        titre.setWordWrap(True)                          # Autoriser le retour à la ligne si la fenêtre est petite
        layout_principal.addWidget(titre)                # On ajoute ce texte au layout principal

        # 2. Cadre pointillé pour la sélection du dossier
        frame_fichier = QFrame()
        frame_fichier.setObjectName("frameFichier")
        layout_fichier = QVBoxLayout(frame_fichier) # Un mini-layout vertical à l'intérieur du cadre
        
        # Label affichant le dossier sélectionné
        self.label_info = QLabel("Aucun dossier sélectionné")
        self.label_info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label_info.setWordWrap(True)
        
        # Bouton Parcourir
        self.btn_choisir = QPushButton("📂 Parcourir les dossiers...")
        self.btn_choisir.setObjectName("btnChoisir")
        self.btn_choisir.setCursor(Qt.CursorShape.PointingHandCursor) # Change la souris en "petite main"
        self.btn_choisir.clicked.connect(self.choisir_dossier)        # Lier le clic à la fonction choisir_dossier
        
        # Bouton Sauvegarder Clé
        self.btn_sauvegarder_cle = QPushButton("💾 Sauvegarder la clé de sécurité (USB)")
        self.btn_sauvegarder_cle.setObjectName("btnSauvegarder")
        self.btn_sauvegarder_cle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_sauvegarder_cle.clicked.connect(self.sauvegarder_cle) # Lier le clic à la fonction de sauvegarde

        # On ajoute ces éléments dans le cadre
        layout_fichier.addWidget(self.label_info)
        layout_fichier.addWidget(self.btn_choisir, alignment=Qt.AlignmentFlag.AlignCenter)
        layout_fichier.addWidget(self.btn_sauvegarder_cle, alignment=Qt.AlignmentFlag.AlignCenter)
        
        # On ajoute le cadre au layout principal
        layout_principal.addWidget(frame_fichier)

        # 3. Label textuel de progression (ex: "Traitement : video.mp4")
        self.label_progression = QLabel("")
        self.label_progression.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label_progression.setStyleSheet("font-size: 12px; color: #7f8c8d;")
        layout_principal.addWidget(self.label_progression)

        # 4. Barre de progression visuelle (de 0 à 100%)
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)     # Affiche le pourcentage au centre de la barre
        self.progress_bar.setFixedHeight(20)
        layout_principal.addWidget(self.progress_bar)

        # Ajout d'un ressort (Spacer) invisible pour pousser les boutons tout en bas de la fenêtre
        layout_principal.addSpacerItem(QSpacerItem(20, 10, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # 5. Boîte horizontale pour mettre les boutons Chiffrer/Déchiffrer côte à côte
        layout_boutons = QHBoxLayout()
        layout_boutons.setSpacing(15)

        # Bouton Chiffrer
        self.btn_chiffrer = QPushButton("🔒 Chiffrer le dossier")
        self.btn_chiffrer.setObjectName("btnAction")
        # Quand on clique, on appelle la fonction lancer_travail en lui envoyant le mot 'chiffrer' (grâce à lambda)
        self.btn_chiffrer.clicked.connect(lambda: self.lancer_travail('chiffrer'))
        
        # Bouton Déchiffrer
        self.btn_dechiffrer = QPushButton("🔓 Déchiffrer le dossier")
        self.btn_dechiffrer.setObjectName("btnAction")
        self.btn_dechiffrer.clicked.connect(lambda: self.lancer_travail('dechiffrer'))

        # Demande aux boutons de s'étirer horizontalement pour prendre toute la place disponible
        self.btn_chiffrer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.btn_dechiffrer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        layout_boutons.addWidget(self.btn_chiffrer)
        layout_boutons.addWidget(self.btn_dechiffrer)

        layout_principal.addLayout(layout_boutons)
        
        # On dit à la fenêtre principale d'utiliser ce "layout_principal" comme structure globale
        self.setLayout(layout_principal)

    def appliquer_style(self):
        # PyQt permet d'utiliser une syntaxe très proche du CSS web pour faire un joli design
        style = """
            QWidget { background-color: #f4f5f7; font-family: 'Segoe UI', Arial, sans-serif; color: #333333; }
            QLabel#titre { font-size: 16px; font-weight: bold; color: #2980b9; margin-bottom: 10px; }
            QFrame#frameFichier { background-color: #ffffff; border: 2px dashed #bdc3c7; border-radius: 10px; padding: 20px; }
            QLabel { font-size: 14px; color: #7f8c8d; }
            QPushButton { font-size: 14px; font-weight: bold; padding: 10px 20px; border-radius: 6px; border: none; color: white; }
            
            QPushButton#btnChoisir { background-color: #e74c3c; margin-top: 10px; }
            QPushButton#btnChoisir:hover { background-color: #c0392b; }
            QPushButton#btnChoisir:pressed { background-color: #922b21; }
            
            QPushButton#btnSauvegarder { background-color: #3498db; margin-top: 5px; }
            QPushButton#btnSauvegarder:hover { background-color: #2980b9; }
            QPushButton#btnSauvegarder:pressed { background-color: #1f618d; }
            
            QPushButton#btnAction { background-color: #2ecc71; padding: 12px; font-size: 15px; }
            QPushButton#btnAction:hover { background-color: #27ae60; }
            QPushButton#btnAction:pressed { background-color: #1e8449; }
            
            QPushButton:disabled { background-color: #bdc3c7; color: #7f8c8d; } /* Style des boutons grisés */
            
            QProgressBar { border: 1px solid #bdc3c7; border-radius: 5px; text-align: center; color: black; font-weight: bold; background-color: #ecf0f1; }
            QProgressBar::chunk { background-color: #3498db; border-radius: 4px; }
        """
        self.setStyleSheet(style)

    def charger_ou_generer_cle(self):
        # On vérifie si le fichier clé existe déjà sur l'ordinateur
        if not os.path.exists(self.fichier_cle):
            # S'il n'existe pas, on génère une nouvelle suite aléatoire de 32 octets (256 bits)
            self.cle = os.urandom(32) 
            # Et on crée le fichier pour l'y écrire ("wb" = write binary)
            with open(self.fichier_cle, "wb") as f_cle:
                f_cle.write(self.cle)
        else:
            # Si le fichier existe, on se contente de le lire ("rb" = read binary) et de stocker la clé en mémoire
            with open(self.fichier_cle, "rb") as f_cle:
                self.cle = f_cle.read()

    def sauvegarder_cle(self):
        """Permet à l'utilisateur de copier sa clé vers une clé USB ou un autre dossier sécurisé."""
        # Sécurité basique : on vérifie d'abord que le fichier clé a bien été généré localement
        if not os.path.exists(self.fichier_cle):
            QMessageBox.warning(self, "Erreur", "La clé n'existe pas encore.")
            return
            
        # Ouvre l'explorateur de fichiers de Windows pour demander OÙ enregistrer la copie
        chemin_destination, _ = QFileDialog.getSaveFileName(
            self, 
            "Sauvegarder la clé de chiffrement", 
            "ma_cle_chacha20_secours.key",                # Nom par défaut proposé à l'utilisateur
            "Fichiers Clé (*.key);;Tous les fichiers (*)" # Filtres de type de fichier
        )
        
        # Si l'utilisateur n'a pas cliqué sur "Annuler" dans l'explorateur de fichiers
        if chemin_destination:
            try:
                # shutil.copy2 copie le fichier ET préserve ses métadonnées (date de création, etc.)
                shutil.copy2(self.fichier_cle, chemin_destination)
                # Affichage d'une fenêtre popup de confirmation
                QMessageBox.information(self, "Succès", "La clé a été sauvegardée avec succès.\n\nGardez-la précieusement, sans elle vous ne pourrez plus déchiffrer vos fichiers !")
            except Exception as e:
                # Si la clé USB est débranchée en cours de copie par exemple
                QMessageBox.critical(self, "Erreur", f"Impossible de sauvegarder la clé : {e}")

    def choisir_dossier(self):
        # Ouvre une boite de dialogue pour sélectionner un répertoire
        chemin = QFileDialog.getExistingDirectory(self, "Sélectionner un dossier")
        
        # Si un dossier a été choisi (si l'utilisateur n'a pas annulé)
        if chemin:
            self.chemin_cible = chemin
            nom_dossier = os.path.basename(chemin) # Récupère juste "Vacances" au lieu de "C:/Users/Mario/Vacances"
            
            # Mise à jour des textes sur l'interface
            self.label_info.setText(f"<b>Dossier prêt :</b> {nom_dossier}")
            self.label_info.setStyleSheet("color: #2c3e50;")
            
            # Remise à zéro de la barre de progression pour un nouveau traitement
            self.progress_bar.setValue(0)
            self.label_progression.setText("")

    def lancer_travail(self, action):
        # Vérification qu'un dossier a bien été sélectionné via le bouton "Parcourir"
        if not self.chemin_cible:
            QMessageBox.warning(self, "Erreur", "Veuillez d'abord choisir un dossier.")
            return

        # SÉCURITÉ D'INTERFACE : On "grise" les boutons pour empêcher l'utilisateur
        # de cliquer 5 fois sur "Chiffrer" pendant que le traitement est en cours.
        self.btn_chiffrer.setEnabled(False)
        self.btn_dechiffrer.setEnabled(False)
        self.btn_choisir.setEnabled(False)
        self.btn_sauvegarder_cle.setEnabled(False)
        self.progress_bar.setValue(0)
        
        # On "invoque" notre travailleur (le Thread) défini tout en haut du script, en lui donnant le matériel
        self.worker = WorkerCryptage(self.chemin_cible, self.cle, self.taille_chunk, action)
        
        # CONNEXIONS FONDAMENTALES : On relie les "câbles" entre le Thread et la Fenêtre (GUI)
        # Quand le Thread émet "progression", la barre de progression met à jour sa valeur
        self.worker.progression.connect(self.progress_bar.setValue)
        # Quand le Thread émet "info_fichier", le label met à jour son texte
        self.worker.info_fichier.connect(self.label_progression.setText)
        # Quand le Thread émet "termine", l'interface déclenche la fonction "travail_termine" ci-dessous
        self.worker.termine.connect(self.travail_termine)
        
        # Démarrage effectif du Thread parallèle (appelle la méthode run() du Worker)
        self.worker.start()

    def travail_termine(self, fichiers_traites, erreurs):
        # Le travail est fini : On réactive tous les boutons pour que l'utilisateur puisse s'en resservir
        self.btn_chiffrer.setEnabled(True)
        self.btn_dechiffrer.setEnabled(True)
        self.btn_choisir.setEnabled(True)
        self.btn_sauvegarder_cle.setEnabled(True)
        self.label_progression.setText("Opération terminée.")
        
        # Nettoyage de la mémoire : on détruit le Thread qui a fini son travail
        self.worker.deleteLater()
        
        # Bilan : S'il y a eu des erreurs, on affiche un avertissement, sinon on affiche un message de succès
        if erreurs > 0:
            QMessageBox.warning(self, "Terminé avec des erreurs", f"{fichiers_traites} fichiers traités avec succès.\n{erreurs} erreurs rencontrées.")
        else:
            QMessageBox.information(self, "Terminé", f"Succès total !\n{fichiers_traites} fichiers traités.")


# =====================================================================
# BLOC DE LANCEMENT PRINCIPAL
# =====================================================================
# C'est ici que l'exécution de Python commence réellement
if __name__ == "__main__":
    # QApplication gère la boucle d'événements (clics, affichage, etc.) de l'OS. Il n'en faut qu'une par script.
    app = QApplication(sys.argv)
    
    # On instancie (crée) notre objet fenêtre
    fenetre = LogicielCryptage()
    
    # On la rend visible à l'écran
    fenetre.show()
    
    # app.exec() démarre la boucle d'événements qui maintient la fenêtre ouverte.
    # sys.exit() s'assure de fermer proprement Python quand on clique sur la croix rouge de la fenêtre.
    sys.exit(app.exec())
    
    
    
    