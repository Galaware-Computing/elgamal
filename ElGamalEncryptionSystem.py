"""
Ce code a pour but la création d'un logiciel de chiffrement et de déchiffrement
basé sur l'algorithme de ElGamal.
"""
import sys
import random
import os

from PyQt5.QtCore import QRect
from PyQt5.QtCore import Qt

from PyQt5.QtWidgets import QApplication
from PyQt5.QtWidgets import QTextEdit
from PyQt5.QtWidgets import QMainWindow
from PyQt5.QtWidgets import QVBoxLayout
from PyQt5.QtWidgets import QFrame
from PyQt5.QtWidgets import QPushButton
from PyQt5.QtWidgets import QLabel

__version__ = '0.1'
__author__ = 'Nzie N. Charles & Pete K. Esdras'

# Nous créeons une classe qui héritera de la classe QMainWindow
# Cettesous classe fera office d'interface graphique et nous servira
# De view dans notre approche MVC

class ElGamalApplication(QMainWindow):
    """
    Cette classe hérite de la classe QMainWindow
    Elle fera office d'interface principale de notre logiciel
    """

    def __init__(self):
        """
        Cette fonction fait office de constructeur de la classe ElGamalView
        """
        super().__init__()

        # Ici nous definissons les propriétés de la fenetre principale
        self.setWindowTitle("ElGamal Cipher")
        self._dimension = QRect(400, 100, 400, 500)
        self.setGeometry(self._dimension)

        # Ici on s'occupe du contenu de l'application
        self.generalLayout = QVBoxLayout()
        self.generalLayout.setSpacing(10)

        self._centralWidget = QFrame(self)
        self.setCentralWidget(self._centralWidget)
        self._centralWidget.setLayout(self.generalLayout)

        # self._fichierNombrePremier = 'ElGamal_Project' + os.path.sep + 'liste_nombre_premier.txt'
        self._listNombrePremier = [
            8803, 8807, 8819, 8821, 8831, 8837, 8839, 8849, 8861, 8863,
            8867, 8887, 8893, 8923, 8929, 8933, 8941, 8951, 8963, 8969,
            8971, 8999, 9001, 9007, 9011, 9013, 9029, 9041, 9043, 9049,
            9059, 9067, 9091, 9103, 9109, 9127, 9133, 9137, 9151, 9157,
            9161, 9173, 9181, 9187, 9199, 9203, 9209, 9221, 9227, 9239,
            9241, 9257, 9277, 9281, 9283, 9293, 9311, 9319, 9323, 9337,
            9341, 9343, 9349, 9371, 9377, 9391, 9397, 9403, 9413, 9419,
            9421, 9431, 9433, 9437, 9439, 9461, 9463, 9467, 9473, 9479,
            9491, 9497, 9511, 9521, 9533, 9539, 9547, 9551, 9587, 9601,
            9613, 9619, 9623, 9629, 9631, 9643, 9649, 9661, 9677, 9679
        ]

        self._createApptitle()
        self._createEncryptionZone()
        self._connectSignals()

        # ///////////////////////////////////////////////////////////////////////////////
        # ///////////////////////////////////////////////////////////////////////////////
        # ///////////////////////////////////////////////////////////////////////////////
        # ///////////////////////////////////////////////////////////////////////////////
        # ///////////////////////////////////////////////////////////////////////////////


    def _createApptitle(self):
        """
        Cette fonction a pour rôle de creer une zone dans laquelle
        le nom de l'application sera afficher en gras italique
        """

        self.appTitleLabel = QLabel("<h1><i>ElGamal Encryption System</i><:h1>")
        self.appTitleLabel.setAlignment(Qt.AlignCenter)

        self.generalLayout.addWidget(self.appTitleLabel)

        # ///////////////////////////////////////////////////////////////////////////////
        # ///////////////////////////////////////////////////////////////////////////////

    def _createEncryptionZone(self):
        """
        Cette fonction a pour rôle de creer une zone dans laquelle
        nous pourrons réaliser le chiffrement d'un message
        """

        # Ici nous avons le titre separateur de la partie
        # Encryption
        self.encryptTitleLabel1 = QLabel("<h3><i>___________ZONE DE CHIFFREMENT / DÉCHIFFREMENT___________</i></h3>")
        self.encryptTitleLabel1.setAlignment(Qt.AlignCenter)

        self.generalLayout.addWidget(self.encryptTitleLabel1)

        self.encryptionZone = QVBoxLayout()

        self._lineL01 = QTextEdit()
        self._lineL01.setPlaceholderText("Veillez saisir le texte à chiffrer ici")

        self._lineL02 = QTextEdit()
        self._lineL02.setPlaceholderText("Inserer le texte à déchiffrer ici")

        self._btnB01 = QPushButton('Chiffrer le texte')
        self._btnB01.setFixedWidth(120)
        self._btnB01.setFixedHeight(30)

        self._btnB02 = QPushButton('Déchiffrer le texte')
        self._btnB02.setFixedWidth(120)
        self._btnB02.setFixedHeight(30)

        self.encryptionZone.addWidget(self._lineL01)
        self.encryptionZone.addWidget(self._btnB01)
        self.encryptionZone.addWidget(self._lineL02)
        self.encryptionZone.addWidget(self._btnB02)

        # Le conteneur principal
        self.generalLayout.addLayout(self.encryptionZone)

   

# ///////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////

    def _placerMessageChiffrer(self):
        self._nombrePremier = self.gen_nbr_premier()
        self._alpha = self.primitiv_root()
        self._skey = self.skey_generator()
        self._pkey = self.pkey_generator()
        self._kparam = self.skey_generator()

        test = self._setMessageCypher()
        self._lineL02.setText(test)
        self._lineL01.setText("")

    def _getMessageClair(self, messageContener):
        """
        Cette fonction permet de recuperer le texte à chiffrer
        """
        _textClair = messageContener.toPlainText()
        return _textClair

    def _setMessageCypher(self):
        """
        Cette fonction permet d'inserer le message chiffrer
        dans la zone de chiffrement
        """
        self._messageChiffrerTab = self.encrytion(self._getMessageClair(self._lineL01))
        messageChiffrer = ''
        for i in range(len(self._messageChiffrerTab[1])):
            messageChiffrer = messageChiffrer + str(self._messageChiffrerTab[1][i]) + ' '
        
        return messageChiffrer

# ///////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////

    def _setMessageClair(self):
        """
        Cette fonction permet de recuperer le texte à chiffrer
        """
        _textDechiffrer = self.decryption(self._messageChiffrerTab)
        self._lineL01.setText(_textDechiffrer)
        self._lineL02.setText("")

# ///////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////
    
    def _connectSignals(self):
        """
        Cette fonction a pour but de connecter les signaux capter par l'interface
        aux actions qui serons réaliser
        """
        self._btnB01.clicked.connect(self._placerMessageChiffrer)
        self._btnB02.clicked.connect(self._setMessageClair)

# ///////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////
# ///////////////////////////////////////////////////////////////////////////////////////////////

    """
    Ce code a pour objectif d'implémenter l'algorithme de chiffrement de AlGamal
    """

    # Modulation Exponentielle
    def power_mod(self, a, b, c):
        """
        Cette fonction a pour but de calculer l'exponentielle modulaire
        a à la puissance b modulo c
        """
        x = 1
        y = a

        while b > 0:
            if b % 2 != 0:
                x = (x * y) % c
            y = (y * y) % c
            b = int(b / 2)

        return x % c

    # Générer un nombre premier
    def gen_nbr_premier(self):
        """
        Cette fonction a pour but de rechercher un nombre premier dans la
        liste prédefinie de nombre premier que nous avons choisi.

        file: indique l'emplacement du fichier contenant la liste des nombres 
        premiers dans l'ordinateur
        """

        liste = self._listNombrePremier
        # with open(self._fichierNombrePremier, 'r') as fichier:
        #     liste = fichier.readlines()
        
        nbre_hasard = random.randint(0, len(liste)-1)
        nbre_premier = liste[nbre_hasard]

        return nbre_premier

    # Calcul de la racine primitive d'un nombre premier
    def primitiv_root(self):
        """
        Cette fonction a pour but de trouver la plus grande racine primitive du nombre
        premier choisi
        """

        # Creons un tableau contenant toute les valeurs entieres inférieures à nbre_premier
        valeursEntieres = []
        for j in range(1, self._nombrePremier):
            valeursEntieres.append(j)

        tabTemp = None
        

        for i in range(1, self._nombrePremier):
            tabTemp = valeursEntieres[:]
            alpha = self._nombrePremier - i

            for k in range(1, self._nombrePremier):

                reste = self.power_mod(alpha, k, self._nombrePremier)

                if (reste in tabTemp):
                    tabTemp.remove(reste)
                
                if len(tabTemp) == 0:
                    return alpha
    
    # Calcul de la clé privée
    def skey_generator(self):
        """Cette fonction aura pour but de générer la clef secrète"""

        skey = random.randint(2, self._nombrePremier)

        return skey

    # Calcul de beta
    def calcul_beta(self):
        """
        Cette fonction calcule la troisieme valeur de la cle publique en fonction de la
        racine primitive et de la cle privée générer à l'aide de la fonction skey_generator
        """

        beta = self.power_mod(self._alpha, self._skey, self._nombrePremier)
        return beta

    # Calcul de la clé publique
    def pkey_generator(self):
        """Cette fonction aura pour but de générer la clef publique"""

        pkey = []
        pkey.append(self._nombrePremier)
        pkey.append(self._alpha)
        pkey.append(self.calcul_beta())

        return pkey

    def encrytion(self, message):
        """
        Cette fonction aura pour but de chiffrer le message que l'on souhaite
        transmettre
        """
        
        encrypt_msg = []
        r = self.power_mod(self._alpha, self._kparam, self._nombrePremier)

        for i in range(0, len(message)):
            encrypt_msg.append(ord(message[i]))

        for i in range(0, len(message)):
            encrypt_msg[i] = encrypt_msg[i] *self.power_mod(self._pkey[2], self._kparam, self._pkey[0])

        encrypt_msg_final = []
        encrypt_msg_final.append(r)
        encrypt_msg_final.append(encrypt_msg)

        return encrypt_msg_final

    def decryption(self, en_msg):
        """
        Cette fonction aura pour but de déchiffrer le message que l'on a
        reçu
        """

        decrypt_msg = []
        t = en_msg[1]
        r = en_msg[0]

        for j in range(0, len(t)):
            decrypt_msg.append(chr(int(t[j] / self.power_mod(r, self._skey, self._pkey[0]))))

        msg_decrypt = ""

        for i in range(0, len(decrypt_msg)):
            msg_decrypt = msg_decrypt + str(decrypt_msg[i])

        return msg_decrypt
# ////////////////////////////////////////////////////////////////////////////////////////////////
# ////////////////////////////////////////////////////////////////////////////////////////////////
# ////////////////////////////////////////////////////////////////////////////////////////////////
# ////////////////////////////////////////////////////////////////////////////////////////////////
# ////////////////////////////////////////////////////////////////////////////////////////////////
# ////////////////////////////////////////////////////////////////////////////////////////////////
# Fonction principale
def main():
    """
    La fonction principale
    """

    # Creer une instance de QApplication
    elGamalApp = QApplication(sys.argv)

    # Création d'une instance de l'objet ElGamalView
    view = ElGamalApplication()
    view.show()


    # Création de la boucle evenementielle infini
    sys.exit(elGamalApp.exec_())


if __name__ == "__main__":
    main()