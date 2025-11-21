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
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("📦 Installation de pycryptodome...")
    if install_package("pycryptodome"):
        # Réimporter après installation
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        from Crypto.Util.Padding import pad, unpad
    else:
        print("❌ Impossible de continuer sans pycryptodome")
        sys.exit(1)

# Le reste du code AES reste identique...
"""
AES (Advanced Encryption Standard)
Chiffrement symétrique moderne - 256 bits
Mode CBC (Cipher Block Chaining)
"""

class AESCipher:
    def __init__(self):
        self.key_size = 32  # 256 bits
        self.block_size = AES.block_size  # 16 bytes

    def generer_cle(self):
        """
        Génère une clé AES aléatoire de 256 bits
        Retourne la clé encodée en base64 pour affichage
        """
        key = get_random_bytes(self.key_size)
        key_b64 = base64.b64encode(key).decode('utf-8')

        print("\n" + "="*60)
        print("🔑 GÉNÉRATION DE CLÉ AES-256")
        print("="*60)
        print(f"Taille de la clé: {self.key_size * 8} bits")
        print(f"Clé générée (Base64): {key_b64}")
        print(f"Longueur: {len(key_b64)} caractères")
        print("="*60)

        # Sauvegarder la clé dans un fichier
        self.sauvegarder_cle(key, "AES_Key.txt")

        return key, key_b64

    def sauvegarder_cle(self, key, filename):
        """Sauvegarde la clé dans un fichier"""
        key_b64 = base64.b64encode(key).decode('utf-8')
        with open(filename, 'w') as f:
            f.write(key_b64)
        print(f"✅ Clé sauvegardée dans: {filename}")

    def charger_cle(self, filename):
        """Charge une clé depuis un fichier"""
        try:
            with open(filename, 'r') as f:
                key_b64 = f.read().strip()
                key = base64.b64decode(key_b64)
            print(f"✅ Clé chargée depuis: {filename}")
            return key
        except FileNotFoundError:
            print(f"❌ Fichier {filename} non trouvé!")
            return None

    def chiffrer(self, message, key):
        """
        Chiffre un message avec AES-256 en mode CBC

        Étapes:
        1. Génération d'un IV (Initialization Vector) aléatoire
        2. Padding du message (ajout de bytes pour atteindre la taille de bloc)
        3. Chiffrement avec AES
        4. Concaténation IV + message chiffré
        """
        # Génération d'un IV aléatoire
        iv = get_random_bytes(self.block_size)

        # Création du cipher AES en mode CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Padding du message et chiffrement
        message_bytes = message.encode('utf-8')
        padded_message = pad(message_bytes, self.block_size)
        ciphertext = cipher.encrypt(padded_message)

        # Combinaison IV + ciphertext
        encrypted_data = iv + ciphertext
        encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')

        print("\n" + "="*60)
        print("🔐 CHIFFREMENT AES-256")
        print("="*60)
        print(f"Message original: {message}")
        print(f"Taille du message: {len(message)} caractères")
        print(f"IV (Base64): {base64.b64encode(iv).decode('utf-8')}")
        print(f"Message chiffré (Base64): {encrypted_b64}")
        print(f"Taille chiffrée: {len(encrypted_b64)} caractères")
        print("="*60)

        return encrypted_b64

    def dechiffrer(self, encrypted_b64, key):
        """
        Déchiffre un message AES-256

        Étapes:
        1. Décodage Base64
        2. Extraction de l'IV (premiers 16 bytes)
        3. Extraction du ciphertext
        4. Déchiffrement
        5. Retrait du padding
        """
        try:
            # Décodage Base64
            encrypted_data = base64.b64decode(encrypted_b64)

            # Extraction de l'IV
            iv = encrypted_data[:self.block_size]
            ciphertext = encrypted_data[self.block_size:]

            # Création du cipher et déchiffrement
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(ciphertext)

            # Retrait du padding
            decrypted_message = unpad(decrypted_padded, self.block_size)
            message = decrypted_message.decode('utf-8')

            print("\n" + "="*60)
            print("🔓 DÉCHIFFREMENT AES-256")
            print("="*60)
            print(f"Message chiffré (Base64): {encrypted_b64[:50]}...")
            print(f"IV extrait (Base64): {base64.b64encode(iv).decode('utf-8')}")
            print(f"Message déchiffré: {message}")
            print(f"Taille du message: {len(message)} caractères")
            print("="*60)

            return message

        except Exception as e:
            print(f"\n❌ Erreur lors du déchiffrement: {str(e)}")
            print("Vérifiez que la clé utilisée est correcte.")
            return None


def menu_principal():
    """Menu interactif pour tester AES"""
    aes = AESCipher()
    key = None

    while True:
        print("\n" + "="*60)
        print("🔐 AES-256 - CHIFFREMENT SYMÉTRIQUE MODERNE")
        print("="*60)
        print("1. Générer une nouvelle clé AES")
        print("2. Charger une clé existante")
        print("3. Chiffrer un message")
        print("4. Déchiffrer un message")
        print("5. Quitter")
        print("="*60)

        choix = input("\nVotre choix: ")

        if choix == "1":
            key, key_b64 = aes.generer_cle()

        elif choix == "2":
            filename = input("Nom du fichier de clé (par défaut: AES_Key.txt): ").strip()
            if not filename:
                filename = "AES_Key.txt"
            key = aes.charger_cle(filename)

        elif choix == "3":
            if key is None:
                print("\n❌ Veuillez d'abord générer ou charger une clé!")
                continue
            message = input("\nEntrez le message à chiffrer: ")
            encrypted = aes.chiffrer(message, key)

        elif choix == "4":
            if key is None:
                print("\n❌ Veuillez d'abord générer ou charger une clé!")
                continue
            encrypted = input("\nEntrez le message chiffré (Base64): ")
            decrypted = aes.dechiffrer(encrypted, key)

        elif choix == "5":
            print("\n👋 Au revoir!")
            break

        else:
            print("\n❌ Choix invalide!")


# Programme principal
if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║            AES-256 - CHIFFREMENT SYMÉTRIQUE               ║
    ║          Advanced Encryption Standard (256 bits)          ║
    ║                                                           ║
    ║  Propriétés:                                              ║
    ║  • Même clé pour chiffrer et déchiffrer                   ║
    ║  • Très rapide et efficace                                ║
    ║  • Standard actuel de l'industrie                         ║
    ║  • Mode CBC avec IV pour plus de sécurité                 ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    # Installation requise: pip install pycryptodome
    menu_principal()