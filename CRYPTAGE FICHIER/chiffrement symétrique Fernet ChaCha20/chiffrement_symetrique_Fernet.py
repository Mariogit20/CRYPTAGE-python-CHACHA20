import sys
import os
from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QFileDialog, QLabel, QMessageBox, 
                             QFrame, QSizePolicy, QSpacerItem)
from PyQt6.QtCore import Qt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class LogicielCryptage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureFile - ChaCha20 Edition")
        self.resize(500, 350)
        self.setMinimumSize(400, 250)
        
        self.chemin_fichier = None
        self.cle = None
        self.fichier_cle = "ma_cle_chacha20.key"
        
        # Définition de la limite de 256 Go en octets
        self.limite_taille = 256 * (1024 ** 3)
        
        self.initUI()
        self.appliquer_style()
        self.charger_ou_generer_cle()

    def initUI(self):
        # Layout principal
        layout_principal = QVBoxLayout()
        layout_principal.setContentsMargins(30, 30, 30, 30)
        layout_principal.setSpacing(20)

        # Titre avec retour à la ligne automatique (WordWrap)
        titre = QLabel("Avec le Cryptage ChaCha20Poly1305 Aucun Fichier individuel ne doit dépasser 256 Go. Affichage d'un Message d'Erreur si un Fichier dépasse 256 Go !")              
        titre.setObjectName("titre")
        titre.setAlignment(Qt.AlignmentFlag.AlignCenter)
        titre.setWordWrap(True) # <- Permet au texte de s'adapter à la fenêtre
        layout_principal.addWidget(titre)

        # Zone de sélection
        frame_fichier = QFrame()
        frame_fichier.setObjectName("frameFichier")
        layout_fichier = QVBoxLayout(frame_fichier)
        
        self.label_info = QLabel("Aucun fichier sélectionné")
        self.label_info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label_info.setWordWrap(True)
        
        self.btn_choisir = QPushButton("Parcourir les fichiers...")
        self.btn_choisir.setObjectName("btnChoisir")
        self.btn_choisir.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_choisir.clicked.connect(self.choisir_fichier)
        
        layout_fichier.addWidget(self.label_info)
        layout_fichier.addWidget(self.btn_choisir, alignment=Qt.AlignmentFlag.AlignCenter)
        layout_principal.addWidget(frame_fichier)

        layout_principal.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        # Boutons d'action
        layout_boutons = QHBoxLayout()
        layout_boutons.setSpacing(15)

        self.btn_chiffrer = QPushButton("🔒 Chiffrer")
        self.btn_chiffrer.setObjectName("btnAction")
        self.btn_chiffrer.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_chiffrer.clicked.connect(self.chiffrer_fichier)
        
        self.btn_dechiffrer = QPushButton("🔓 Déchiffrer")
        self.btn_dechiffrer.setObjectName("btnAction")
        self.btn_dechiffrer.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_dechiffrer.clicked.connect(self.dechiffrer_fichier)

        self.btn_chiffrer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.btn_dechiffrer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        layout_boutons.addWidget(self.btn_chiffrer)
        layout_boutons.addWidget(self.btn_dechiffrer)

        layout_principal.addLayout(layout_boutons)
        self.setLayout(layout_principal)

    def appliquer_style(self):
        style = """
            QWidget { background-color: #f4f5f7; font-family: 'Segoe UI', Arial, sans-serif; color: #333333; }
            QLabel#titre { font-size: 16px; font-weight: bold; color: #8e44ad; margin-bottom: 10px; }
            QFrame#frameFichier { background-color: #ffffff; border: 2px dashed #bdc3c7; border-radius: 10px; padding: 20px; }
            QLabel { font-size: 14px; color: #7f8c8d; }
            QPushButton { font-size: 14px; font-weight: bold; padding: 10px 20px; border-radius: 6px; border: none; color: white; }
            QPushButton#btnChoisir { background-color: #9b59b6; margin-top: 10px; }
            QPushButton#btnChoisir:hover { background-color: #8e44ad; }
            QPushButton#btnChoisir:pressed { background-color: #732d91; }
            QPushButton#btnAction { background-color: #2ecc71; padding: 12px; font-size: 15px; }
            QPushButton#btnAction:hover { background-color: #27ae60; }
            QPushButton#btnAction:pressed { background-color: #1e8449; }
        """
        self.setStyleSheet(style)

    def charger_ou_generer_cle(self):
        """Génère une clé ChaCha20 de 256 bits (32 octets)"""
        if not os.path.exists(self.fichier_cle):
            self.cle = ChaCha20Poly1305.generate_key()
            with open(self.fichier_cle, "wb") as f_cle:
                f_cle.write(self.cle)
        else:
            with open(self.fichier_cle, "rb") as f_cle:
                self.cle = f_cle.read()

    def choisir_fichier(self):
        chemin, _ = QFileDialog.getOpenFileName(self, "Sélectionner un fichier")
        if chemin:
            self.chemin_fichier = chemin
            nom_fichier = os.path.basename(chemin)
            self.label_info.setText(f"<b>Fichier prêt :</b> {nom_fichier}")
            self.label_info.setStyleSheet("color: #2c3e50;")

    def verifier_taille_fichier(self):
        """Vérifie si le fichier dépasse la limite de 256 Go."""
        taille = os.path.getsize(self.chemin_fichier)
        if taille > self.limite_taille:
            QMessageBox.critical(self, "Erreur de Taille", 
                                 "Le fichier dépasse la limite maximale autorisée de 256 Go.")
            return False
        return True

    def chiffrer_fichier(self):
        if not self.chemin_fichier:
            QMessageBox.warning(self, "Erreur", "Veuillez d'abord choisir un fichier.")
            return
            
        if not self.verifier_taille_fichier():
            return

        try:
            chacha = ChaCha20Poly1305(self.cle)
            # Génération d'un Nonce aléatoire de 12 octets
            nonce = os.urandom(12) 
            
            with open(self.chemin_fichier, "rb") as f:
                donnees_originales = f.read()
                
            # Chiffrement
            donnees_chiffrees = chacha.encrypt(nonce, donnees_originales, None)
            
            fichier_chiffre = self.chemin_fichier + ".enc"
            with open(fichier_chiffre, "wb") as f:
                # On sauvegarde le Nonce suivi des données chiffrées
                f.write(nonce + donnees_chiffrees)
                
            QMessageBox.information(self, "Succès", f"Fichier chiffré avec ChaCha20 :\n{fichier_chiffre}")
        except MemoryError:
            QMessageBox.critical(self, "Erreur Mémoire", "Le fichier est trop volumineux pour la mémoire vive (RAM) de votre ordinateur.")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Erreur de chiffrement :\n{str(e)}")

    def dechiffrer_fichier(self):
        if not self.chemin_fichier:
            QMessageBox.warning(self, "Erreur", "Veuillez d'abord choisir un fichier.")
            return
            
        if not self.verifier_taille_fichier():
            return

        try:
            chacha = ChaCha20Poly1305(self.cle)
            
            with open(self.chemin_fichier, "rb") as f:
                contenu_complet = f.read()
                
            # Extraction du Nonce (les 12 premiers octets) et du message chiffré (le reste)
            nonce = contenu_complet[:12]
            donnees_chiffrees = contenu_complet[12:]
            
            # Déchiffrement
            donnees_dechiffrees = chacha.decrypt(nonce, donnees_chiffrees, None)
            
            if self.chemin_fichier.endswith(".enc"):
                fichier_dechiffre = self.chemin_fichier[:-4] 
            else:
                fichier_dechiffre = self.chemin_fichier + ".dec"
                
            with open(fichier_dechiffre, "wb") as f:
                f.write(donnees_dechiffrees)
                
            QMessageBox.information(self, "Succès", f"Fichier déchiffré :\n{fichier_dechiffre}")
        except MemoryError:
            QMessageBox.critical(self, "Erreur Mémoire", "Le fichier est trop volumineux pour la mémoire vive (RAM) de votre ordinateur.")
        except Exception as e:
            QMessageBox.critical(self, "Erreur", "Clé incorrecte, fichier corrompu ou Nonce invalide.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    fenetre = LogicielCryptage()
    fenetre.show()
    sys.exit(app.exec())