import sys
import os
import shutil
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QFileDialog, QLabel, QMessageBox, 
                             QFrame, QSizePolicy, QSpacerItem, QProgressBar)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

# =====================================================================
# 1. CRÉATION DU WORKER (Le thread qui fait le travail lourd en arrière-plan)
# =====================================================================
class WorkerCryptage(QThread):
    # Définition des signaux pour communiquer avec l'interface graphique
    progression = pyqtSignal(int)
    info_fichier = pyqtSignal(str)
    termine = pyqtSignal(int, int) # (fichiers_traites, erreurs)

    def __init__(self, chemin_cible, cle, taille_chunk, action):
        super().__init__()
        self.chemin_cible = chemin_cible
        self.cle = cle
        self.taille_chunk = taille_chunk
        self.action = action # 'chiffrer' ou 'dechiffrer'

    def run(self):
        # Étape 1 : Lister tous les fichiers valides pour calculer le total
        fichiers_a_traiter = []
        for racine, sous_dossiers, fichiers in os.walk(self.chemin_cible):
            for nom_fichier in fichiers:
                if self.action == 'chiffrer':
                    if not nom_fichier.endswith(".enc") and nom_fichier != "ma_cle_chacha20.key":
                        fichiers_a_traiter.append(os.path.join(racine, nom_fichier))
                elif self.action == 'dechiffrer':
                    if nom_fichier.endswith(".enc"):
                        fichiers_a_traiter.append(os.path.join(racine, nom_fichier))

        total_fichiers = len(fichiers_a_traiter)
        if total_fichiers == 0:
            self.termine.emit(0, 0)
            return

        fichiers_traites = 0
        erreurs = 0

        # Étape 2 : Traitement des fichiers
        for index, chemin_complet in enumerate(fichiers_a_traiter):
            nom_fichier = os.path.basename(chemin_complet)
            self.info_fichier.emit(f"Traitement : {nom_fichier}")
            
            try:
                if self.action == 'chiffrer':
                    chemin_final = chemin_complet + ".enc"
                    chemin_tmp = chemin_final + ".tmp" # Fichier temporaire de sécurité
                    
                    nonce = os.urandom(16)
                    cipher = Cipher(algorithms.ChaCha20(self.cle, nonce), mode=None)
                    encryptor = cipher.encryptor()
                    
                    with open(chemin_complet, "rb") as f_in, open(chemin_tmp, "wb") as f_out:
                        f_out.write(nonce)
                        while True:
                            chunk = f_in.read(self.taille_chunk)
                            if not chunk: 
                                break
                            f_out.write(encryptor.update(chunk))
                        f_out.write(encryptor.finalize()) # Clôture cryptographique propre
                        
                    # Remplacement atomique et suppression uniquement si le succès est total
                    os.replace(chemin_tmp, chemin_final)
                    os.remove(chemin_complet)

                elif self.action == 'dechiffrer':
                    chemin_final = chemin_complet[:-4]
                    chemin_tmp = chemin_final + ".tmp" # Fichier temporaire de sécurité
                    
                    with open(chemin_complet, "rb") as f_in, open(chemin_tmp, "wb") as f_out:
                        nonce = f_in.read(16)
                        cipher = Cipher(algorithms.ChaCha20(self.cle, nonce), mode=None)
                        decryptor = cipher.decryptor()
                        
                        while True:
                            chunk = f_in.read(self.taille_chunk)
                            if not chunk: 
                                break
                            f_out.write(decryptor.update(chunk))
                        f_out.write(decryptor.finalize()) # Clôture cryptographique propre
                        
                    # Remplacement atomique et suppression uniquement si le succès est total
                    os.replace(chemin_tmp, chemin_final)
                    os.remove(chemin_complet)

                fichiers_traites += 1
                
            except Exception as e:
                erreurs += 1
                print(f"Erreur sur {nom_fichier} : {e}")
                # Nettoyage du fichier temporaire en cas d'erreur/plantage
                if 'chemin_tmp' in locals() and os.path.exists(chemin_tmp):
                    os.remove(chemin_tmp)

            # Calcul et envoi du pourcentage de progression
            pourcentage = int(((index + 1) / total_fichiers) * 100)
            self.progression.emit(pourcentage)

        self.termine.emit(fichiers_traites, erreurs)


# =====================================================================
# 2. L'INTERFACE GRAPHIQUE
# =====================================================================
class LogicielCryptage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureFolder - Streaming Edition")
        self.resize(550, 480) # Légèrement agrandi pour le nouveau bouton
        self.setMinimumSize(450, 400)
        
        self.chemin_cible = None
        self.cle = None
        self.fichier_cle = "ma_cle_chacha20.key"
        self.taille_chunk = 64 * 1024
        
        self.initUI()
        self.appliquer_style()
        self.charger_ou_generer_cle()

    def initUI(self):
        layout_principal = QVBoxLayout()
        layout_principal.setContentsMargins(30, 30, 30, 30)
        layout_principal.setSpacing(20)

        texte_titre = (
            "Avec le ChaCha20 pur, un fichier individuel à l'intérieur\n"
            "du dossier peut parfaitement dépasser 256 Go.\n"
            "Aucun Message d'Erreur si un Fichier dépasse 256 Go !"
        )
        titre = QLabel(texte_titre)             
        titre.setObjectName("titre")
        titre.setAlignment(Qt.AlignmentFlag.AlignCenter)
        titre.setWordWrap(True)
        layout_principal.addWidget(titre)

        frame_fichier = QFrame()
        frame_fichier.setObjectName("frameFichier")
        layout_fichier = QVBoxLayout(frame_fichier)
        
        self.label_info = QLabel("Aucun dossier sélectionné")
        self.label_info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label_info.setWordWrap(True)
        
        self.btn_choisir = QPushButton("📂 Parcourir les dossiers...")
        self.btn_choisir.setObjectName("btnChoisir")
        self.btn_choisir.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_choisir.clicked.connect(self.choisir_dossier)

        # NOUVEAU : Bouton pour sauvegarder la clé
        self.btn_sauvegarder_cle = QPushButton("💾 Sauvegarder la clé de sécurité (USB)")
        self.btn_sauvegarder_cle.setObjectName("btnSauvegarder")
        self.btn_sauvegarder_cle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_sauvegarder_cle.clicked.connect(self.sauvegarder_cle)
        
        layout_fichier.addWidget(self.label_info)
        layout_fichier.addWidget(self.btn_choisir, alignment=Qt.AlignmentFlag.AlignCenter)
        layout_fichier.addWidget(self.btn_sauvegarder_cle, alignment=Qt.AlignmentFlag.AlignCenter)
        layout_principal.addWidget(frame_fichier)

        # Barre de progression et label d'information en temps réel
        self.label_progression = QLabel("")
        self.label_progression.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label_progression.setStyleSheet("font-size: 12px; color: #7f8c8d;")
        layout_principal.addWidget(self.label_progression)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFixedHeight(20)
        layout_principal.addWidget(self.progress_bar)

        layout_principal.addSpacerItem(QSpacerItem(20, 10, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        layout_boutons = QHBoxLayout()
        layout_boutons.setSpacing(15)

        self.btn_chiffrer = QPushButton("🔒 Chiffrer le dossier")
        self.btn_chiffrer.setObjectName("btnAction")
        self.btn_chiffrer.clicked.connect(lambda: self.lancer_travail('chiffrer'))
        
        self.btn_dechiffrer = QPushButton("🔓 Déchiffrer le dossier")
        self.btn_dechiffrer.setObjectName("btnAction")
        self.btn_dechiffrer.clicked.connect(lambda: self.lancer_travail('dechiffrer'))

        self.btn_chiffrer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.btn_dechiffrer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        layout_boutons.addWidget(self.btn_chiffrer)
        layout_boutons.addWidget(self.btn_dechiffrer)

        layout_principal.addLayout(layout_boutons)
        self.setLayout(layout_principal)

    def appliquer_style(self):
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
            
            QPushButton:disabled { background-color: #bdc3c7; color: #7f8c8d; }
            QProgressBar { border: 1px solid #bdc3c7; border-radius: 5px; text-align: center; color: black; font-weight: bold; background-color: #ecf0f1; }
            QProgressBar::chunk { background-color: #3498db; border-radius: 4px; }
        """
        self.setStyleSheet(style)

    def charger_ou_generer_cle(self):
        if not os.path.exists(self.fichier_cle):
            self.cle = os.urandom(32) 
            with open(self.fichier_cle, "wb") as f_cle:
                f_cle.write(self.cle)
        else:
            with open(self.fichier_cle, "rb") as f_cle:
                self.cle = f_cle.read()

    def sauvegarder_cle(self):
        """Permet à l'utilisateur de copier sa clé vers une clé USB ou un autre dossier sécurisé."""
        if not os.path.exists(self.fichier_cle):
            QMessageBox.warning(self, "Erreur", "La clé n'existe pas encore.")
            return
            
        chemin_destination, _ = QFileDialog.getSaveFileName(
            self, 
            "Sauvegarder la clé de chiffrement", 
            "ma_cle_chacha20_secours.key", 
            "Fichiers Clé (*.key);;Tous les fichiers (*)"
        )
        
        if chemin_destination:
            try:
                shutil.copy2(self.fichier_cle, chemin_destination)
                QMessageBox.information(self, "Succès", "La clé a été sauvegardée avec succès.\n\nGardez-la précieusement, sans elle vous ne pourrez plus déchiffrer vos fichiers !")
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Impossible de sauvegarder la clé : {e}")

    def choisir_dossier(self):
        chemin = QFileDialog.getExistingDirectory(self, "Sélectionner un dossier")
        if chemin:
            self.chemin_cible = chemin
            nom_dossier = os.path.basename(chemin)
            self.label_info.setText(f"<b>Dossier prêt :</b> {nom_dossier}")
            self.label_info.setStyleSheet("color: #2c3e50;")
            self.progress_bar.setValue(0)
            self.label_progression.setText("")

    def lancer_travail(self, action):
        if not self.chemin_cible:
            QMessageBox.warning(self, "Erreur", "Veuillez d'abord choisir un dossier.")
            return

        # On verrouille l'interface pendant le travail
        self.btn_chiffrer.setEnabled(False)
        self.btn_dechiffrer.setEnabled(False)
        self.btn_choisir.setEnabled(False)
        self.btn_sauvegarder_cle.setEnabled(False)
        self.progress_bar.setValue(0)
        
        # Création et configuration du Thread
        self.worker = WorkerCryptage(self.chemin_cible, self.cle, self.taille_chunk, action)
        
        # Connexion des signaux du Thread vers l'interface graphique
        self.worker.progression.connect(self.progress_bar.setValue)
        self.worker.info_fichier.connect(self.label_progression.setText)
        self.worker.termine.connect(self.travail_termine)
        
        # Lancement du Thread
        self.worker.start()

    def travail_termine(self, fichiers_traites, erreurs):
        # On déverrouille l'interface
        self.btn_chiffrer.setEnabled(True)
        self.btn_dechiffrer.setEnabled(True)
        self.btn_choisir.setEnabled(True)
        self.btn_sauvegarder_cle.setEnabled(True)
        self.label_progression.setText("Opération terminée.")
        
        # On nettoie le thread
        self.worker.deleteLater()
        
        if erreurs > 0:
            QMessageBox.warning(self, "Terminé avec des erreurs", f"{fichiers_traites} fichiers traités avec succès.\n{erreurs} erreurs rencontrées.")
        else:
            QMessageBox.information(self, "Terminé", f"Succès total !\n{fichiers_traites} fichiers traités.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    fenetre = LogicielCryptage()
    fenetre.show()
    sys.exit(app.exec())
    
    
    