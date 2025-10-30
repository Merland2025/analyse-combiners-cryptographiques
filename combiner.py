
"""
Etude des Combiners Cryptographiques
Par Merland BAFOUETILA - M2  Mathématique de l'information Spécialité Arithmétique, Codage et Cryptologie
"""

import hashlib
import time

#Analyse simple des méthodes pour combiner algorithmes classiques et post-quantiques

class CombinerAnalyse:
    
    def __init__(self):
        self.resultats = []
    
#Combine avec XOR

    def combiner_xor(self, data1, data2):
        taille = min(len(data1), len(data2))
        resultat = bytes(a ^ b for a, b in zip(data1[:taille], data2[:taille]))
        return resultat


#  Combine par concaténation 

    def combiner_concat(self, data1, data2):

        return data1 + data2
    
#Combine avec SHA-256

    def combiner_hash(self, data1, data2):
        combine = data1 + data2
        return hashlib.sha256(combine).digest()
    
#Simule une clé post-quantique

    def generer_cle_pqc(self, message):
        return hashlib.shake_128(message).digest(32)
    
#Simule une clé classique

    def generer_cle_classique(self, message):
    
        return hashlib.sha256(message).digest()
    
# Teste un combiner et mesure ses performances
    
    def tester_combiner(self, nom, fonction, pq_key, classic_key):
        
        # Mesure du temps
        debut = time.time()
        for _ in range(1000):
            resultat = fonction(pq_key, classic_key)
        temps = (time.time() - debut) * 1000  # en ms
        
        # Taille du résultat
        taille = len(resultat)
        
        # Test de sécurité basique
        # Si une clé est compromise
        cle_nulle = b'\x00' * 32
        test1 = fonction(cle_nulle, classic_key) != resultat
        test2 = fonction(pq_key, cle_nulle) != resultat
        
        secure = test1 and test2
        
        return {
            'nom': nom,
            'temps_ms': temps,
            'taille_bytes': taille,
            'secure': secure
        }
    
    def lancer_analyse(self):
        """Lance l'analyse complète"""
        print("Analyse des Combiners Cryptographiques")
        print("=" * 40)
        
        # Génération des clés de test
        
        message = b"test_combiner_hybride"
        pq_key = self.generer_cle_pqc(message)
        classic_key = self.generer_cle_classique(message)
        
        print(f"Clé PQC:    {pq_key.hex()[:20]}...")
        print(f"Clé Classique: {classic_key.hex()[:20]}...")
        print()
        
        # Liste des combiners à tester
        combiners = [
            ("XOR", self.combiner_xor),
            ("Concaténation", self.combiner_concat),
            ("Hachage SHA-256", self.combiner_hash)
        ]
        
        # Test de chaque combiner
        for nom, fonction in combiners:
            resultat = self.tester_combiner(nom, fonction, pq_key, classic_key)
            self.resultats.append(resultat)
            
            print(f"Combiner: {nom}")
            print(f"  Temps: {resultat['temps_ms']:.3f} ms")
            print(f"  Taille: {resultat['taille_bytes']} octets")
            print(f"  Sécurisé: {'OUI' if resultat['secure'] else 'NON'}")
            print()
    
    def afficher_conclusion(self):
        """Affiche les conclusions"""
        print("Conclusions:")
        print("=" * 30)
        
        # Trouve le plus rapide
        plus_rapide = min(self.resultats, key=lambda x: x['temps_ms'])
        print(f"Plus rapide: {plus_rapide['nom']} ({plus_rapide['temps_ms']:.3f} ms)")
        
        # Trouve le plus compact
        plus_petit = min(self.resultats, key=lambda x: x['taille_bytes'])
        print(f"Plus compact: {plus_petit['nom']} ({plus_petit['taille_bytes']} octets)")
        
        # Vérifie la sécurité
        tous_secures = all(r['secure'] for r in self.resultats)
        print(f"Tous sécurisés: {'OUI' if tous_secures else 'NON'}")

def demo_tls_simple():
    """Démonstration simple pour TLS"""
    print("\nApplication à TLS:")
    print("=" * 20)
    
    analyseur = CombinerAnalyse()
    
    # Simulation handshake TLS
    print("1. Client propose algorithmes")
    print("2. Serveur choisit Kyber + ECDH") 
    print("3. Échange de clés hybride")
    
    # Génération des secrets
    secret_pqc = analyseur.generer_cle_pqc(b"client_key")
    secret_classic = analyseur.generer_cle_classique(b"server_key")
    
    # Application du combiner
    secret_final = analyseur.combiner_hash(secret_pqc, secret_classic)
    
    print(f"4. Secret final: {secret_final.hex()[:30]}...")
    print("5. Session TLS établie!")

if __name__ == "__main__":
    print("Projet étudiant - Combiners Hybrides")
    print("Par Merland BAFOUETILA - M2 Cryptologie Paris 8\n")
    
    # Analyse principale
    analyseur = CombinerAnalyse()
    analyseur.lancer_analyse()
    
    # Démonstration TLS
    demo_tls_simple()
    
    # Conclusions
    print("\n" + "=" * 50)
    analyseur.afficher_conclusion()