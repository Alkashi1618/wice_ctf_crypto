import string
lettre = string.ascii_letters
#Fonction pour le chiffrement de César
def chiffrement_Cesar(plain_text):
    tableau_cypher = ""
    tableau_number = ""
    plain_number = ""
    cypher_key = ""
    for i in range(len(plain_text)):
        plain_number += str(lettre.find(plain_text[i]))+'|'
        chiffre = (lettre.find(plain_text[i]) + cle_Cesar) % 26
        tableau_cypher += lettre[chiffre]
        tableau_number += str(chiffre)+'|'
        cypher_key += str(cle_Cesar)+'|'
    print("    Text clair: ", '|'.join(plain_text))
    print("Indice chiffré: ", plain_number)
    print("    cypher key: ", cypher_key)
    print("  Text Chiffré: ", '|'.join(tableau_cypher))
    print("Indice Chiffré: ", tableau_number)

#Fonction pour le chiffrement de Vigenère
def chiffrement_Vigenere(plain_text):
    tableau_cypher = ""
    tableau_number = ""
    plain_number = ""
    cypher_key = ""
    j = 0
    for i in range(len(plain_text)):
        plain_number += str(lettre.find(plain_text[i])) + '|'
        chiffre = (lettre.find(plain_text[i]) + lettre.find(cle_Vigenere[j])) % 26
        j = (j+1) % len(cle_Vigenere)
        tableau_cypher += lettre[chiffre]
        tableau_number += str(chiffre)+'|'
        cypher_key += str(cle_Vigenere)+'|'
    print("    Text clair: ", '|'.join(plain_text))
    print("Indice chiffré: ", plain_number)
    print("    cypher key: ", cypher_key)
    print("  Text Chiffré: ", '|'.join(tableau_cypher))
    print("Indice Chiffré: ", tableau_number)


def chiffrement_Affine(plain_text):
    tableau_cypher = ""
    tableau_number = ""
    plain_number = ""
    cypher_key = ""
    for i in range(len(plain_text)):
        plain_number += str(lettre.find(plain_text[i])) + '|'
        chiffre = (a * lettre.find(plain_text[i]) + b) % 26
        tableau_cypher += lettre[chiffre]
        tableau_number += str(chiffre)+'|'
    print("    Text clair: ", '|'.join(plain_text))
    print("Indice chiffré: ", plain_number)
    print("  Text Chiffré: ", '|'.join(tableau_cypher))
    print("Indice Chiffré: ", tableau_number)

Continue = "O"
while Continue == "O":
    #Choix de chiffrement
    # Entrée de l'algorithme choisi
    chif_choice = int(input("Quel algorithme voulez-vous utiliser:\n1- Cesar\n2- Vigenère\n3- Chiffrement affine\n"))
    # chiffrement_Cesar()
    if chif_choice == 1:
        plain_text = input("Donnez le message claire: \n")
        cle_Cesar = int(input("entrer une cle César: \n"))
        chiffrement_Cesar(plain_text)
    # chiffrement_Vigenere()
    elif chif_choice == 2:
        plain_text = input("Donnez le message claire: \n")
        cle_Vigenere = input("entrer une cle Vigenère: \n")
        chiffrement_Vigenere(plain_text)
    # chiffrement_Affine()
    elif chif_choice == 3:
        plain_text = input("Donnez le message claire: \n")
        a = int(input("Entrer la première valeur de la clé affine 'a': \n "))
        b = int(input("Entrer la première valeur de la clé affine 'b': \n  "))
        chiffrement_Affine(plain_text)
    # choix indisponible
    else:
        print("Choisissez entre 1, 2 et 3 svp!")

    
    Continue = input("Voulez-vous faire un nouveau chiffrement? (O/N)\n")
    if Continue != "O":
        print ("Bye!")