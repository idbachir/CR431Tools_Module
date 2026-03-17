# CR431Tools_Module
Outils d’analyse des logs firewall. Ce module permet de traiter et d’analyser des journaux de coupe-feux. 
Il inclut des fonctions pour lire et structurer les fichiers de logs, appliquer différents filtres 
(IP source, IP destination, port de destination, utilisateur, nom de règle) et afficher les résultats correspondants. 
Le module offre également une fonctionnalité d’association entre les adresses IP de destination 
et leur FQDN en utilisant les données du journal Pi‑Hole fourni.

# Télécharger et installer le module.
- Télécharger les deux fichiers "CR431Tools.psm1" et "CR431Tools.psd1"
- Céréer un répertoire au nom de "CR431Tools" et y déplacer les deux fichiers téléchargés
- Déplacer le répertoires dans "C:\Program Files\PowerShell\7\Modules" (PowerShell 7 doit être déjà installé)
- Ajouter le path "C:\Program Files\PowerShell\7\Modules\CR431Tools"
  * Ouvrir PowerShell avec les privilèges administrateur :
  * Exécuter la commande : notepad $PROFILE , notepad s'affiche à l'écran.
  * Ajouter la ligne suivante puis enregistrer et fermer Notepad : $env:PSModulePath += ";C:\Program Files\PowerShell\7\Modules\CR431Tools"
  * vérifier si le path est ajouter, exécuter la commande suivante : $env:PSModulePath -split ';'
- Si tout est correct, fermer powershell puis l'ouvrir à nouveau.
  * Exécuter la commande : Import-Module CR431Tools, un message d'erreur apparait, revérifier les étapes précédentes.
  * Exécuter la commande : Show-ModuleParameters, pour afficher les différentes commandes et leurs paramètres respectifs.

# Premier essai du module.
- Placer les deux fichiers "fw.log" et "pihole.log" dans le répertoire "C:\CR431-Logs" (CR431-Logs doit être créé s'il n'existe pas).
- exécuter la commande : Invoke-FwFullProcess pour lancer le traitement complet.
- Il est possible d'exécuter le traitement par parties séparées, les commandes sont les suivantes :
  * Convert-FwLogToTable -Avec ou sans paramètres.
  * Get-FwDataCols -Avec ou sans paramètres.
  * Find-FwIpFqdn -Avec ou sans paramètres.
- Les fichiers CSV générés seront déposés au fur et à mesure dans "C:\CR431-Logs".
  
# Bonus
**Le fichier CSV dans lequel figure les adresses IP avec leurs FQDN correspondants possède une colonne supplémentaire énumérant le nombre d'occurence 
d'une adresse IP et le fichier est classé par ordre décroissant du nombre d'occurences**
