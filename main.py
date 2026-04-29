import os
import sys
import requests
import socket
import whois
from PIL import Image
from PIL.ExifTags import TAGS
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track

console = Console()

def banner():
    ascii_art = """
     ██████╗██╗██╗     ███████╗███╗   ██╗████████╗███████╗
    ██╔════╝██║██║     ██╔════╝████╗  ██║╚══██╔══╝╚══███╔╝
    ╚█████╗ ██║██║     █████╗  ██╔██╗ ██║   ██║     ███╔╝ 
     ╚═══██╗██║██║     ██╔══╝  ██║╚██╗██║   ██║    ███╔╝  
    ██████╔╝██║███████╗███████╗██║ ╚████║   ██║   ███████╗
    ╚═════╝ ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝
              [ OSINT TOOL ]
    """
    console.print(Panel(ascii_art, style="bold magenta", expand=False))

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def osint_user():
    username = console.input("[bold yellow]Entrez le pseudo : [/bold yellow]")
    platforms = {
        "GitHub": f"https://github.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}"
    }
    
    table = Table(title=f"Résultats pour {username}")
    table.add_column("Plateforme", style="cyan")
    table.add_column("Statut", style="bold")
    table.add_column("Lien", style="blue")

    for name, url in track(platforms.items(), description="Recherche..."):
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                table.add_row(name, "[green]TROUVÉ[/green]", url)
            else:
                table.add_row(name, "[red]NON TROUVÉ[/red]", "-")
        except:
            table.add_row(name, "[yellow]ERREUR[/yellow]", "-")
    
    console.print(table)

def osint_ip_domain():
    target = console.input("[bold yellow]Entrez IP ou Domaine : [/bold yellow]")
    try:
        data = whois.whois(target)
        ip_addr = socket.gethostbyname(target)
        geo = requests.get(f"http://ip-api.com/json/{ip_addr}").json()

        table = Table(title=f"Analyse de {target}")
        table.add_column("Type", style="magenta")
        table.add_column("Donnée", style="white")

        table.add_row("IP Réelle", ip_addr)
        table.add_row("Registrar", str(data.registrar))
        table.add_row("Pays", geo.get("country", "N/A"))
        table.add_row("Ville", geo.get("city", "N/A"))
        table.add_row("ISP", geo.get("isp", "N/A"))
        table.add_row("Organisation", str(data.org))
        
        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Erreur : {e}[/bold red]")

def osint_email():
    email = console.input("[bold yellow]Entrez l'email : [/bold yellow]")
    domain = email.split('@')[-1]
    
    table = Table(title=f"Vérification Email : {email}")
    table.add_column("Test", style="cyan")
    table.add_column("Résultat", style="white")

    try:
        mx_records = socket.getaddrinfo(domain, 25)
        table.add_row("Serveur MX", "[green]VALIDE[/green]")
    except:
        table.add_row("Serveur MX", "[red]INVALIDE[/red]")
    
    table.add_row("Format", "[green]OK[/green]" if "@" in email and "." in domain else "[red]KO[/red]")
    table.add_row("Recherche Leaks", f"https://haveibeenpwned.com/unifiedsearch/{email}")
    
    console.print(table)

def osint_image():
    path = console.input("[bold yellow]Chemin de l'image : [/bold yellow]")
    try:
        img = Image.open(path)
        exif_data = img._getexif()
        
        if not exif_data:
            console.print("[yellow]Aucune métadonnée EXIF trouvée.[/yellow]")
            return

        table = Table(title="Métadonnées Image")
        table.add_column("Tag", style="cyan")
        table.add_column("Valeur", style="white")

        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            table.add_row(str(tag), str(value))
        
        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Erreur : {e}[/bold red]")

def main():
    while True:
        clear_screen()
        banner()
        console.print("[1] Recherche Usernames")
        console.print("[2] IP & Domaine Lookup")
        console.print("[3] Email Validator")
        console.print("[4] Image EXIF Analyzer")
        console.print("[0] Quitter")
        
        choice = console.input("\n[bold magenta]Silentz > [/bold magenta]")

        if choice == "1":
            osint_user()
        elif choice == "2":
            osint_ip_domain()
        elif choice == "3":
            osint_email()
        elif choice == "4":
            osint_image()
        elif choice == "0":
            break
        
        console.input("\n[Appuyez sur Entrée pour continuer]")

if __name__ == "__main__":
    main()
