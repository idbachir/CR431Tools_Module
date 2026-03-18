**CR431Tools – Module PowerShell d’analyse de logs Firewall & Pi hole**
CR431Tools est un module PowerShell conçu pour automatiser l’analyse des journaux firewall et enrichir les données avec les résolutions DNS issues de Pi hole.
Il permet de :
•	Lire et structurer un fichier fw.log
•	Extraire les colonnes pertinentes
•	Associer les IP de destination à leur FQDN via pihole.log
•	Générer automatiquement plusieurs fichiers CSV d’analyse
•	Exécuter tout le pipeline en une seule commande

**Installation du module**
**1. Télécharger les fichiers**
Récupérez les deux fichiers suivants :
•	CR431Tools.psm1
•	CR431Tools.psd1
**2. Créer le dossier du module**
Dans un emplacement de modules PowerShell :
C:\Program Files\PowerShell\7\Modules\CR431Tools
Placez-y les deux fichiers téléchargés.
**3. Ajouter le chemin au PSModulePath**
Ouvrez PowerShell en administrateur, puis taper la commande suivante :
notepad $PROFILE
Ajoutez la ligne suivante :
$env:PSModulePath += ";C:\Program Files\PowerShell\7\Modules\CR431Tools"
Enregistrez, fermez, puis redémarrez PowerShell.
**4. Vérifier que le module est détecté**
$env:PSModulePath -split ';'
Import-Module CR431Tools
Si aucune erreur n’apparaît, le module est chargé.
Pour afficher les fonctions exportées :
Show-ModuleParameters

**Premier essai du module**
**1. Préparer les fichiers de logs**
Placez les fichiers suivants dans :
C:\CR431-Logs
•	fw.log
•	pihole.log
Créez le dossier s’il n’existe pas.
**2. Lancer le traitement complet**
dans la même session PowerShell où le module a été importé, taper la commande suivante:
Invoke-FwFullProcess
**Le module va automatiquement :**
1.	Lire et structurer fw.log
2.	Extraire les colonnes pertinentes
3.	Associer les IP aux FQDN via Pi hole
4.	Générer les fichiers CSV suivants :
1_fw_parsed.csv
2_fw_parsed_filtered.csv
3_fw_ip_fqdn_stats.csv
Tous seront déposés dans C:\CR431-Logs.

**Exécuter les étapes séparément**
Vous pouvez aussi exécuter chaque étape manuellement :
Convert-FwLogToTable
Get-FwDataCols
Find-FwIpFqdn
Chaque fonction accepte des paramètres personnalisables.

**Bonus : Statistiques enrichies**
Le fichier final 3_fw_ip_fqdn_stats.csv contient :
•	L’adresse IP de destination
•	Le FQDN correspondant (si trouvé dans Pi hole)
•	Le nombre d’occurrences de chaque IP
•	Un tri automatique par nombre d’occurrences décroissant
Cela permet d’identifier rapidement :
•	Les destinations les plus fréquentes
•	Les domaines associés
•	Les comportements réseau suspects ou inhabituels
