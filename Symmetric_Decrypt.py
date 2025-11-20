import string

lettre = string.ascii_letters

# Fonction pour calculer l'inverse modulaire
def inverse_modulaire(a, m):
    """
    Calcule l'inverse modulaire de a modulo m
    a * a_inv ≡ 1 (mod m)
    """
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

# Fonction de déchiffrement César
def dechiffrement_Cesar(cypher_text):
    tableau_decrypt = ""
    cypher_number = ""
    cypher_key = ""
    plain_number = ""
    for i in range(len(cypher_text)):
        cypher_number += str(lettre.find(cypher_text[i]))+'|'
        dechiffre = (lettre.find(cypher_text[i]) + 26) - cle_Cesar
        tableau_decrypt += lettre[dechiffre]
        cypher_key += str(cle_Cesar) + '|'
        plain_number += str(dechiffre) + '|'
    
    print("    Text chiffré: ", '|'.join(cypher_text))
    print("  Indice chiffré: ", cypher_number)
    print("      Cypher Key: ", cypher_key)
    print("      Text clair: ", '|'.join(tableau_decrypt))
    print("    Indice clair: ", plain_number)

# Fonction de déchiffrement Vigenère
def dechiffrement_Vigenere(cypher_text):
    tableau_decrypt = ""
    cypher_number = ""
    cypher_key = ""
    plain_number = ""
    j = 0
    for i in range(len(cypher_text)):
        cypher_number += str(lettre.find(cypher_text[i]))+'|'
        dechiffre = (lettre.find(cypher_text[i]) + 26) - lettre.find(cle_Vigenere[j])
        j = (j+1)%len(cle_Vigenere)
        tableau_decrypt += lettre[dechiffre]
        cypher_key += str(cle_Vigenere) + '|'
        plain_number += str(dechiffre) + '|'
    
    print("    Text chiffré: ", '|'.join(cypher_text))
    print("  Indice chiffré: ", cypher_number)
    print("      Cypher Key: ", cypher_key)
    print("      Text clair: ", '|'.join(tableau_decrypt))
    print("    Indice clair: ", plain_number)

# Fonction de déchiffrement Affine
def dechiffrement_Affine(cypher_text, a, b):
    """
    Déchiffre un texte avec le chiffrement affine
    Formule: P = a_inv * (C - b) mod 26
    """
    tableau_decrypt = ""
    cypher_number = ""
    plain_number = ""
    
    # Calcul de l'inverse modulaire de 'a'
    a_inv = inverse_modulaire(a, 26)
    
    if a_inv is None:
        print(f"\n❌ Erreur: {a} n'a pas d'inverse modulaire modulo 26")
        print("La valeur 'a' doit être première avec 26 (pgcd(a, 26) = 1)")
        print("Valeurs valides pour 'a': 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25\n")
        return None
    
    for i in range(len(cypher_text)):
        cypher_index = lettre.find(cypher_text[i])
        
        if cypher_index != -1:
            # Formule de déchiffrement: P = a_inv * (C - b) mod 26
            plain_index = (a_inv * (cypher_index - b)) % 26
            tableau_decrypt += lettre[plain_index]
            
            cypher_number += str(cypher_index) + '|'
            plain_number += str(plain_index) + '|'
        else:
            # Caractère non alphabétique
            tableau_decrypt += cypher_text[i]
            cypher_number += '?|'
            plain_number += '?|'
    
    print("    Text chiffré: ", '|'.join(cypher_text))
    print("  Indice chiffré: ", cypher_number)
    print(f"      Clé (a, b): ({a}, {b})")
    print(f"  Inverse de a  : {a_inv}")
    print("      Text clair: ", '|'.join(tableau_decrypt))
    print("    Indice clair: ", plain_number)
    
    return tableau_decrypt


Continue = "O"
while Continue == "O":
    print("\n" + "="*60)
    # Entrée de l'algorithme choisi
    chif_choice = int(input("Quel algorithme voulez-vous utiliser:\n1- Cesar\n2- Vigenère\n3- Chiffrement affine\n"))
    print("="*60)
    
    # Déchiffrement César
    if chif_choice == 1:
        cypher_text = input("Donnez le message chiffré: \n")
        cle_Cesar = int(input("Entrer une clé César: \n"))
        print("-"*60)
        dechiffrement_Cesar(cypher_text)
        print("-"*60)
    
    # Déchiffrement Vigenère
    elif chif_choice == 2:
        cypher_text = input("Donnez le message chiffré: \n")
        cle_Vigenere = input("Entrer une clé Vigenère: \n")
        print("-"*60)
        dechiffrement_Vigenere(cypher_text)
        print("-"*60)
    
    # Déchiffrement Affine
    elif chif_choice == 3:
        cypher_text = input("Donnez le message chiffré: \n")
        a = int(input("Entrer la première valeur de la clé affine 'a': \n"))
        b = int(input("Entrer la deuxième valeur de la clé affine 'b': \n"))
        print("-"*60)
        resultat = dechiffrement_Affine(cypher_text, a, b)
        print("-"*60)
        if resultat:
            print(f"✅ Message déchiffré: {resultat}")
    
    # Choix indisponible
    else:
        print("Choisissez entre 1, 2 et 3 svp!")
    
    Continue = input("\nVoulez-vous faire un nouveau déchiffrement? (O/N)\n")
    if Continue != "O":
        print("Bye!")