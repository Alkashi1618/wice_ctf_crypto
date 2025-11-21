import sys
import subprocess
import base64
import os

def install_package(package):
    """Tente d'installer un package manquant"""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"✅ {package} installé avec succès!")
        return True
    except subprocess.CalledProcessError:
        print(f"❌ Échec de l'installation de {package}")
        return False

# Vérifier et installer pycryptodome si nécessaire
try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
except ImportError:
    print("📦 Installation de pycryptodome...")
    if install_package("pycryptodome"):
        # Réimporter après installation
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.Signature import pkcs1_15
        from Crypto.Hash import SHA256
    else:
        print("❌ Impossible de continuer sans pycryptodome")
        sys.exit(1)

"""
RSA (Rivest-Shamir-Adleman)
Chiffrement asymétrique - 2048 bits
Utilise une paire de clés: publique et privée
"""

class RSACipher:
    def __init__(self):
        self.key_size = 2048  # Taille de la clé en bits
        self.private_key = None
        self.public_key = None
    
    def generer_paire_cles(self):
        """
        Génère une paire de clés RSA (publique et privée)
        
        Propriétés:
        - Clé publique: peut être partagée avec tout le monde
        - Clé privée: doit rester secrète
        """
        print("\n" + "="*60)
        print("🔑 GÉNÉRATION DE PAIRE DE CLÉS RSA-2048")
        print("="*60)
        print("Génération en cours... (peut prendre quelques secondes)")
        
        # Génération de la clé privée
        key = RSA.generate(self.key_size)
        self.private_key = key
        self.public_key = key.publickey()
        
        print(f"✅ Paire de clés générée!")
        print(f"Taille: {self.key_size} bits")
        print(f"\nClé publique (n, e):")
        print(f"  n = {self.public_key.n}")
        print(f"  e = {self.public_key.e}")
        print(f"\nClé privée (n, d):")
        print(f"  d = {self.private_key.d}")
        print("="*60)
        
        # Sauvegarde des clés
        self.sauvegarder_cles()
        
        return self.private_key, self.public_key
    
    def sauvegarder_cles(self):
        """Sauvegarde les clés dans des fichiers PEM"""
        # Sauvegarde de la clé privée
        private_pem = self.private_key.export_key()
        with open("Priv_Key.pem", 'wb') as f:
            f.write(private_pem)
        print(f"✅ Clé privée sauvegardée: Priv_Key.pem")
        
        # Sauvegarde de la clé publique
        public_pem = self.public_key.export_key()
        with open("Pub_Key.pem", 'wb') as f:
            f.write(public_pem)
        print(f"✅ Clé publique sauvegardée: Pub_Key.pem")
    
    def charger_cle_privee(self, filename="Priv_Key.pem"):
        """Charge une clé privée depuis un fichier"""
        try:
            with open(filename, 'rb') as f:
                key_data = f.read()
                self.private_key = RSA.import_key(key_data)
            print(f"✅ Clé privée chargée depuis: {filename}")
            return self.private_key
        except FileNotFoundError:
            print(f"❌ Fichier {filename} non trouvé!")
            return None
    
    def charger_cle_publique(self, filename="Pub_Key.pem"):
        """Charge une clé publique depuis un fichier"""
        try:
            with open(filename, 'rb') as f:
                key_data = f.read()
                self.public_key = RSA.import_key(key_data)
            print(f"✅ Clé publique chargée depuis: {filename}")
            return self.public_key
        except FileNotFoundError:
            print(f"❌ Fichier {filename} non trouvé!")
            return None
    
    def chiffrer(self, message, public_key=None):
        """
        Chiffre un message avec la clé publique RSA
        
        Principe:
        - Utilise la clé PUBLIQUE du destinataire
        - Seul le destinataire (avec sa clé privée) peut déchiffrer
        """
        if public_key is None:
            public_key = self.public_key
        
        if public_key is None:
            print("❌ Aucune clé publique disponible!")
            return None
        
        try:
            # Création du cipher RSA
            cipher = PKCS1_OAEP.new(public_key)
            
            # Chiffrement
            message_bytes = message.encode('utf-8')
            ciphertext = cipher.encrypt(message_bytes)
            
            # Encodage en Base64 pour affichage
            encrypted_b64 = base64.b64encode(ciphertext).decode('utf-8')
            
            print("\n" + "="*60)
            print("🔐 CHIFFREMENT RSA")
            print("="*60)
            print(f"Message original: {message}")
            print(f"Taille du message: {len(message)} caractères")
            print(f"Message chiffré (Base64): {encrypted_b64}")
            print(f"Taille chiffrée: {len(encrypted_b64)} caractères")
            print("\n💡 Ce message ne peut être déchiffré qu'avec la clé privée correspondante")
            print("="*60)
            
            return encrypted_b64
            
        except Exception as e:
            print(f"❌ Erreur lors du chiffrement: {str(e)}")
            print("Le message est peut-être trop long pour RSA.")
            return None
    
    def dechiffrer(self, encrypted_b64, private_key=None):
        """
        Déchiffre un message avec la clé privée RSA
        
        Principe:
        - Utilise la clé PRIVÉE (secrète)
        - Seul le propriétaire de la clé privée peut déchiffrer
        """
        if private_key is None:
            private_key = self.private_key
        
        if private_key is None:
            print("❌ Aucune clé privée disponible!")
            return None
        
        try:
            # Décodage Base64
            ciphertext = base64.b64decode(encrypted_b64)
            
            # Création du cipher et déchiffrement
            cipher = PKCS1_OAEP.new(private_key)
            decrypted_bytes = cipher.decrypt(ciphertext)
            message = decrypted_bytes.decode('utf-8')
            
            print("\n" + "="*60)
            print("🔓 DÉCHIFFREMENT RSA")
            print("="*60)
            print(f"Message chiffré (Base64): {encrypted_b64[:50]}...")
            print(f"Message déchiffré: {message}")
            print(f"Taille du message: {len(message)} caractères")
            print("="*60)
            
            return message
            
        except Exception as e:
            print(f"❌ Erreur lors du déchiffrement: {str(e)}")
            print("Vérifiez que la clé privée est correcte.")
            return None
    
    def signer(self, message, private_key=None):
        """
        Signe un message avec la clé privée
        
        Principe:
        - Crée une "empreinte" du message avec la clé privée
        - Prouve que c'est bien l'auteur qui a signé
        - N'importe qui peut vérifier avec la clé publique
        """
        if private_key is None:
            private_key = self.private_key
        
        if private_key is None:
            print("❌ Aucune clé privée disponible!")
            return None
        
        # Création du hash du message
        message_bytes = message.encode('utf-8')
        hash_obj = SHA256.new(message_bytes)
        
        # Signature
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        print("\n" + "="*60)
        print("✍️  SIGNATURE NUMÉRIQUE RSA")
        print("="*60)
        print(f"Message signé: {message}")
        print(f"Hash SHA-256: {hash_obj.hexdigest()}")
        print(f"Signature (Base64): {signature_b64}")
        print("\n💡 Cette signature prouve l'authenticité et l'intégrité du message")
        print("="*60)
        
        return signature_b64
    
    def verifier_signature(self, message, signature_b64, public_key=None):
        """
        Vérifie la signature d'un message avec la clé publique
        
        Principe:
        - Utilise la clé PUBLIQUE de l'auteur
        - Vérifie que le message n'a pas été modifié
        - Vérifie l'identité de l'auteur
        """
        if public_key is None:
            public_key = self.public_key
        
        if public_key is None:
            print("❌ Aucune clé publique disponible!")
            return False
        
        try:
            # Décodage de la signature
            signature = base64.b64decode(signature_b64)
            
            # Création du hash du message
            message_bytes = message.encode('utf-8')
            hash_obj = SHA256.new(message_bytes)
            
            # Vérification
            pkcs1_15.new(public_key).verify(hash_obj, signature)
            
            print("\n" + "="*60)
            print("✅ SIGNATURE VALIDE")
            print("="*60)
            print(f"Message: {message}")
            print(f"Hash: {hash_obj.hexdigest()}")
            print("\n💡 Le message est authentique et n'a pas été modifié!")
            print("="*60)
            
            return True
            
        except (ValueError, TypeError) as e:
            print("\n" + "="*60)
            print("❌ SIGNATURE INVALIDE")
            print("="*60)
            print("Le message a été modifié ou la signature est incorrecte!")
            print("="*60)
            return False


def menu_principal():
    """Menu interactif pour tester RSA"""
    rsa = RSACipher()
    
    while True:
        print("\n" + "="*60)
        print("🔐 RSA-2048 - CHIFFREMENT ASYMÉTRIQUE")
        print("="*60)
        print("1. Générer une paire de clés RSA")
        print("2. Charger une clé privée")
        print("3. Charger une clé publique")
        print("4. Chiffrer un message (avec clé publique)")
        print("5. Déchiffrer un message (avec clé privée)")
        print("6. Signer un message (avec clé privée)")
        print("7. Vérifier une signature (avec clé publique)")
        print("8. Quitter")
        print("="*60)
        
        choix = input("\nVotre choix: ")
        
        if choix == "1":
            rsa.generer_paire_cles()
            
        elif choix == "2":
            filename = input("Nom du fichier (par défaut: Priv_Key.pem): ").strip()
            if not filename:
                filename = "Priv_Key.pem"
            rsa.charger_cle_privee(filename)
            
        elif choix == "3":
            filename = input("Nom du fichier (par défaut: Pub_Key.pem): ").strip()
            if not filename:
                filename = "Pub_Key.pem"
            rsa.charger_cle_publique(filename)
            
        elif choix == "4":
            if rsa.public_key is None:
                print("\n❌ Veuillez d'abord charger une clé publique!")
                continue
            message = input("\nEntrez le message à chiffrer: ")
            encrypted = rsa.chiffrer(message)
            
        elif choix == "5":
            if rsa.private_key is None:
                print("\n❌ Veuillez d'abord charger une clé privée!")
                continue
            encrypted = input("\nEntrez le message chiffré (Base64): ")
            decrypted = rsa.dechiffrer(encrypted)
            
        elif choix == "6":
            if rsa.private_key is None:
                print("\n❌ Veuillez d'abord charger une clé privée!")
                continue
            message = input("\nEntrez le message à signer: ")
            signature = rsa.signer(message)
            
        elif choix == "7":
            if rsa.public_key is None:
                print("\n❌ Veuillez d'abord charger une clé publique!")
                continue
            message = input("\nEntrez le message: ")
            signature = input("Entrez la signature (Base64): ")
            rsa.verifier_signature(message, signature)
            
        elif choix == "8":
            print("\n👋 Au revoir!")
            break
            
        else:
            print("\n❌ Choix invalide!")


# Programme principal
if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║           RSA-2048 - CHIFFREMENT ASYMÉTRIQUE              ║
    ║         Rivest-Shamir-Adleman (2048 bits)                 ║
    ║                                                           ║
    ║  Propriétés:                                              ║
    ║  • Deux clés: publique (partageable) et privée (secrète) ║
    ║  • Clé publique: chiffrement et vérification signature    ║
    ║  • Clé privée: déchiffrement et création signature        ║
    ║  • Permet l'échange sécurisé sans partager de secret      ║
    ║  • Base de la cryptographie moderne (HTTPS, SSH, etc.)    ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Installation requise: pip install pycryptodome
    menu_principal()