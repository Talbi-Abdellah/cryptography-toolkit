# CryptoSuite

CryptoSuite est un projet universitaire de cryptographie appliquée qui regroupe plusieurs travaux pratiques allant de la cryptographie classique aux communications sécurisées modernes. Le projet est volontairement pédagogique : il illustre les principes, les algorithmes et les protocoles de base dans une structure claire, modulaire et facile a executer.

L'objectif est de proposer une base de TP complete qui montre comment la cryptographie peut etre utilisee pour chiffrer des messages, proteger leur integrite, verifier leur authenticite, securiser des echanges reseau et realiser un vote electronique simplifie avec chiffrement homomorphe.

## Vue d'ensemble

Le projet est organise en modules independants, chacun correspondant a une famille de techniques cryptographiques. Cette separation permet de tester chaque TP de facon autonome tout en gardant une architecture coherente.

- `classical/` : cryptographie classique
- `symmetric/` : cryptographie symetrique
- `asymmetric/` : cryptographie asymetrique
- `hashing/` : fonctions de hachage et d'integrite
- `signatures/` : signatures numeriques
- `secure_app/` : communications securisees et vote electronique
- `utils/` : fonctions utilitaires et journalisation
- `logs/` : fichiers de logs generes par l'application

## Structure des TPs

### TP1 - Cryptographie classique

Le dossier `classical/` regroupe les chiffrements historiques et pedagogiques.

- César : substitution mono-alphabetique avec deplacement fixe.
- Vigenere : chiffrement polyalphabetique base sur un mot-cle.
- Hill : chiffrement matriciel sur des blocs de caracteres.
- OTP : one-time pad, exemple theorique de securite parfaite si la cle est vraiment aleatoire, secrete et utilisee une seule fois.

Ce TP sert a comprendre les limites des chiffrements simples et les notions de substitution, transposition et gestion de cle.

### TP2 - Cryptographie symetrique

Le dossier `symmetric/` montre le chiffrement avec une meme cle pour chiffrer et dechiffrer.

- RC4 : algorithme de flux historique, presente a des fins pedagogiques.
- DES : ancien standard a bloc, utile pour l'etude historique.
- AES : standard moderne de chiffrement symetrique, utilise dans les TP de communication securisee.

Ce TP illustre la notion de chiffrement par blocs, d'IV, de mode de fonctionnement et de performances.

### TP3 - Cryptographie asymetrique

Le dossier `asymmetric/` presente les algorithmes a cle publique.

- RSA : chiffrement et gestion de cle publique/privee.
- Diffie-Hellman : echange de cle partagee sur canal non sur.
- ElGamal : chiffrement asymetrique et demonstration de malléabilité.
- ECC : operations sur courbes elliptiques et echange ECDH.

Ce TP explique comment la cryptographie asymetrique resout le probleme du partage de cle et ouvre la voie aux signatures et aux protocoles hybrides.

### TP4 - Hachage et integrite

Le dossier `hashing/` presente les fonctions de hachage et les mecanismes de verification d'integrite.

- MD5 : fonction ancienne, presente pour comparaison historique.
- SHA-256 : fonction moderne largement utilisee.
- SHA-512 : variante 512 bits.
- HMAC : code d'authentification base sur une cle secrete et une fonction de hachage.

Ce TP montre comment detecter les modifications de donnees et verifier qu'un message n'a pas ete altere.

### TP5 - Signatures numeriques

Le dossier `signatures/` traite de l'authenticite et de la non-repudiation.

- RSA-PSS : signature RSA moderne avec remplissage PSS.
- DSA : signature basee sur le probleme du logarithme discret.
- ECDSA : signature sur courbes elliptiques.

Ce TP montre comment prouver l'origine d'un message et verifier qu'il provient bien du detenteur de la cle privee.

### TP6 - Communications et applications securisees

Le dossier `secure_app/` regroupe les applications securisees de communication et de vote.

- `server.py` / `client.py` : chat securise TCP.
- `bt_server.py` / `bt_client.py` : chat securise Bluetooth RFCOMM.
- `udp_server.py` / `udp_client.py` : chat securise UDP pour Wi-Fi / LAN.
- `vote/` : vote electronique securise avec chiffrement homomorphe de Paillier.

Ce TP combine plusieurs mecanismes cryptographiques pour proteger la confidentialite, l'integrite et l'authenticite des echanges.

## Fonctionnalites principales

- Chat securise TCP avec echange de cle, chiffrement AES, hachage SHA-256 et signature RSA.
- Chat Bluetooth RFCOMM securise avec gestion de l'indisponibilite de PyBluez.
- Chat UDP securise avec timeout et gestion simple des pertes de paquets.
- Vote electronique pedagogique avec Paillier et addition homomorphe des votes chiffrés.
- Interface CLI claire pour les clients interactifs.
- Journalisation centralisee dans `logs/cryptosuite.log`.

## Technologies utilisees

- Python 3.13+
- `socket` pour les communications reseau TCP et UDP
- `pycryptodome` pour AES, RSA, OAEP, hachage et signatures
- `pybluez` en option pour Bluetooth RFCOMM
- Modules standard : `json`, `argparse`, `threading`, `logging`, `os`, `socket`
- Architecture modulaire avec paquets Python

## Concepts cryptographiques utilises

- AES-256-CBC : chiffrement symetrique des messages.
- RSA-OAEP : echange de cle AES de facon sure.
- SHA-256 : calcul d'empreinte pour verifier l'integrite.
- Signature RSA : authentification de l'emetteur d'un message.
- Paillier : chiffrement homomorphe additif pour le vote electronique.
- Homomorphisme : possibilite d'effectuer une addition sur des donnees chiffrees sans les dechiffrer.

## Installation

Installez d'abord les dependances principales :

```powershell
pip install pycryptodome
```

Bluetooth est optionnel et depend du systeme d'exploitation et du support materiel :

```powershell
pip install pybluez
```

Remarque : sous Windows, Bluetooth RFCOMM peut ne pas fonctionner selon la pile Bluetooth disponible. Dans ce cas, utilisez les versions TCP, UDP ou vote.

## Commandes d'execution

### TCP securise

Serveur :

```powershell
py -m secure_app.server
```

Client :

```powershell
py -m secure_app.client
```

### Bluetooth RFCOMM securise

Serveur :

```powershell
py -m secure_app.bt_server
```

Client :

```powershell
py -m secure_app.bt_client
```

### UDP securise pour Wi-Fi / LAN

Serveur :

```powershell
py -m secure_app.udp_server
```

Client :

```powershell
py -m secure_app.udp_client
```

### Vote electronique securise

Serveur de vote :

```powershell
py -m secure_app.vote.vote_server
```

Client electeur :

```powershell
py -m secure_app.vote.vote_client
```

## Fonctionnement des principales applications

### Exemple TCP securise

Le fonctionnement suit les etapes suivantes :

1. Le serveur genere une paire de cles RSA pour l'echange et une paire de cles RSA pour la signature.
2. Le client recoit les cles publiques du serveur.
3. Le client genere une cle AES-256 aleatoire.
4. Cette cle AES est chiffree avec RSA-OAEP et envoyee au serveur.
5. Les messages suivants sont chiffres en AES-256-CBC.
6. Chaque message est accompagne de son hash SHA-256 et de sa signature RSA.
7. Le recepteur dechiffre, recalcule le hash, verifie la signature et affiche l'etat de securite.

Cette architecture associe la rapidite de l'AES et la securite du couple RSA + signature.

### Exemple vote electronique

Le vote repose sur le chiffrement homomorphe de Paillier :

1. Le serveur genere une cle publique Paillier et une cle privee.
2. Chaque electeur choisit `0` pour Non ou `1` pour Oui.
3. Le client chiffre son vote avec la cle publique.
4. Le serveur multiplie les votes chiffres entre eux modulo `n^2`.
5. Grace a la propriete homomorphe de Paillier, le produit des ciphertexts correspond a la somme des votes clairs.
6. Le serveur ne dechiffre que le resultat final, pas les bulletins individuels.

Cette approche protege la confidentialite du vote individuel tout en permettant le depouillement du total.

## Logs

Les journaux de l'application sont centralises dans :

```text
logs/cryptosuite.log
```

Les logs contiennent notamment :

- les connexions et deconnexions,
- les etapes de handshake,
- les resultats de verification du hash,
- les resultats de verification des signatures,
- les erreurs reseau ou de protocoles,
- les evenements relatifs au vote.

Les messages secrets ne doivent pas etre enregistres en clair dans les logs.

## Limitations

- Bluetooth RFCOMM peut ne pas fonctionner sous Windows selon la pile Bluetooth disponible et l'installation de PyBluez.
- UDP ne garantit ni la livraison, ni l'ordre, ni l'unicite des paquets. L'exemple inclut un timeout simple, mais pas de vraie retransmission fiable.
- Le vote Paillier est une version pedagogique simplifiee, sans authentification forte des electeurs, sans anonymat complet et sans gestion avancee des attaques applicatives.
- Le projet est concu pour l'apprentissage et la demonstration, pas pour un deploiement de production.

## Organisation du projet

```text
cryptography-toolkit/
├── classical/
├── symmetric/
├── asymmetric/
├── hashing/
├── signatures/
├── secure_app/
│   ├── server.py
│   ├── client.py
│   ├── bt_server.py
│   ├── bt_client.py
│   ├── udp_server.py
│   ├── udp_client.py
│   └── vote/
├── utils/
├── logs/
└── README.md
```

## Conclusion

CryptoSuite presente une vue d'ensemble progressive de la cryptographie appliquee : des chiffrements classiques aux communications securisees et au vote electronique homomorphe. Le projet est structure pour faciliter la lecture, les demonstrations en cours, et les adaptations futures dans le cadre d'un TP universitaire.

## Auteurs

- Nom : Aouina soheib
        OGGAD abdellah
        Talbi abdellah
- Classe / Groupe : 3 A

