# ============================
# Module : CR431Tools
# ============================

<#  
    Module Name : CR431Tools
    Description : Outils d’analyse des logs firewall. Ce module permet de traiter et d’analyser des journaux de coupe-feux. 
	              Il inclut des fonctions pour lire et structurer les fichiers de logs, appliquer différents filtres 
				  (IP source, IP destination, port de destination, utilisateur, nom de règle) et afficher les résultats correspondants. 
				  Le module offre également une fonctionnalité d’association entre les adresses IP de destination 
				  et leur FQDN en utilisant les données du journal Pi‑Hole fourni.
    Notes       : (Fonctions)
                  - Convert-FwLogToTable : Convertit un log brut en CSV structuré.
                  - Get-FwDataCols    : Extrait les colonnes pertinentes.
                  - Find-FwIpFqdn        : Associe IP → FQDN via Pi-hole.
				  - Invoke-FwFullProcess    : Exécuter tout le processus au complet.
	Auteurs     : Malika Saidani, Idir Ait Bachir
	Date 		: 2026-03-25
#>

# -------------------------------------------------------------------
# 1. Convert-FwLogToTable
#    Convertit un fichier de logs firewall en CSV structuré.
# -------------------------------------------------------------------
function Convert-FwLogToTable {

    [CmdletBinding()]
    param(
        # Chemin du fichier log source
        [string]$SrcPath = "C:\CR431-Logs\fw.log",

        # Chemin du fichier CSV généré
        [string]$OutputCsv = "C:\CR431-Logs\1_fw_parsed.csv",

    )
	
	# Vérifier si le fichier log existe
	if (-not (Test-Path $SrcPath)) {
		Write-Host "Le fichier '$SrcPath' n'existe pas. Arrêt de traitement" -ForegroundColor Red
		exit 1 # Message de sortie avec code d'erreur pour éviter à ce que le terminal ferme
	}
	else {
    Write-Host "Début de traitement..." -ForegroundColor Green
	Write-Host "Lecture du fichier : '$SrcPath'..." -ForegroundColor Cyan
	}
	
    # ---------------------------------------------------------------
    # DO / WHILE : attendre que le fichier soit lisible et non vide
    # ---------------------------------------------------------------
    do {
    try {
        $lines = Get-Content -Path $SrcPath -ErrorAction Stop
    }
    catch {
        Write-Host "Impossible de lire le fichier '$SrcPath'. Arrêt du traitement." -ForegroundColor Magenta
        exit 1 # quitte le script avec un code d’erreur pour éviter la fermeture du terminal
    }

    if (-not $lines -or $lines.Count -eq 0) {
        Write-Host "Fichier '$SrcPath' vide. Arrêt du traitement." -ForegroundColor Magenta
        exit 1 # quitte le script avec un code d’erreur pour éviter la fermeture du terminal
    }

} while ($false)  # boucle exécutée une seule fois

    # ---------------------------------------------------------------
    # Parsing ligne par ligne
    # Utilisation d'une boucle FOR pour illustrer l’indexation
    # ---------------------------------------------------------------
    $objects = for ($i = 0; $i -lt $lines.Count; $i++) {

        $line = $lines[$i]

        # Ignore les lignes vides
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        # Dictionnaire pour stocker les champs extraits
        $entry = @{}

        # -----------------------------------------------------------
        # FOREACH : extraction des paires clé="valeur"
        # -----------------------------------------------------------
        foreach ($match in [regex]::Matches($line, '(\w+)=["]([^"]+)["]')) {
            $entry[$match.Groups[1].Value] = $match.Groups[2].Value
        }

        # -----------------------------------------------------------
        # FOREACH : extraction des paires clé=valeur (non-quotées)
        # -----------------------------------------------------------
        foreach ($match in [regex]::Matches($line, '(\w+)=([^\s"]+)')) {
            if (-not $entry.ContainsKey($match.Groups[1].Value)) {
                $entry[$match.Groups[1].Value] = $match.Groups[2].Value
            }
        }

        # Ignore les lignes sans données exploitables
        if ($entry.Count -eq 0) { continue }

        # Retourne un objet PowerShell
        [PSCustomObject]$entry
    }

    # ---------------------------------------------------------------
    # TRY/CATCH : export CSV avec gestion d’erreur personnalisée
    # ---------------------------------------------------------------
    try {
        $objects | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "CSV généré : $OutputCsv" -ForegroundColor Yellow
    }
    catch {
        Write-Host "Erreur lors de l'export CSV : $($_.Exception.Message)" -ForegroundColor Red
    }
}	

# -------------------------------------------------------------------
# 2. Get-FwDataCols
#    Extrait uniquement les colonnes pertinentes du CSV firewall généré par la fonction : 1. Convert-FwLogToTable.
# -------------------------------------------------------------------
function Get-FwDataCols {

    [CmdletBinding()]
    param(
        # CSV source complet généré par la fonction précédente
        [string]$InputPath = "C:\CR431-Logs\1_fw_parsed.csv",

        # CSV filtré à générer
        [string]$OutputPath = "C:\CR431-Logs\2_fw_parsed_filtered.csv"
    )

    # Vérifie l’existence du fichier
    if (-Not (Test-Path $InputPath)) {
		Write-Host "Le fichier '$InputPath' est introuvable." -ForegroundColor Red
		exit 1   # quitte le script avec un code d’erreur pour éviter la fermeture du terminal
	}
	else {
		Write-Host "Le traitement se poursuit..." -ForegroundColor Green
	}

    # ---------------------------------------------------------------
    # TRY/CATCH : lecture du CSV généré par la fonction précédente
    # ---------------------------------------------------------------
    try {
        $data = Import-Csv -Path $InputPath -ErrorAction Stop
    }
    catch {
        Write-Host "Erreur de lecture CSV : $($_.Exception.Message)" -ForegroundColor Red
        exit 1   # quitte le script avec un code d’erreur pour éviter la fermeture du terminal
    }

    # Vérifie la présence des colonnes attendues
    $requiredCols = "src_ip","dst_ip","dst_port","user_name","fw_rule_name"
    foreach ($col in $requiredCols) {
        if (-not ($data | Get-Member -Name $col)) {
            Write-Host "Colonne manquante : $col" -ForegroundColor Magenta
        }
    }

    # ---------------------------------------------------------------
    # TRY/CATCH : export du CSV filtré
    # ---------------------------------------------------------------
    try {
        $data |
            Select-Object src_ip, dst_ip, dst_port, user_name, fw_rule_name |
            Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

        Write-Host "Fichier généré : '$OutputPath'" -ForegroundColor Yellow
    }
    catch {
        Write-Host "Erreur lors de l'export : $($_.Exception.Message)" -ForegroundColor Red
		exit 1   # quitte le script avec un code d’erreur pour éviter la fermeture du terminal
    }
}

# -------------------------------------------------------------------
# 3. Find-FwIpFqdn
#    Associe les IP firewall, du fichier csv généré par la fonction : 
#    2. Get-FwDataCols, aux FQDN trouvés dans Pi-hole.
# -------------------------------------------------------------------
function Find-FwIpFqdn {

    [CmdletBinding()]
    param(
        # CSV firewall filtré généré par la seconde fonction
        [string]$FilteredCsv = "C:\CR431-Logs\2_fw_parsed_filtered.csv",

        # Log Pi-hole
        [string]$PiholeLog   = "C:\CR431-Logs\pihole.log",

        # CSV final à générer
        [string]$FinalCsv   = "C:\CR431-Logs\3_fw_ip_fqdn_stats.csv"
    )
	
	# Vérifier l'existence des deux fichiers
	if (-not (Test-Path $FilteredCsv)) {
		Write-Host "Le fichier '$FilteredCsv' est introuvable." -ForegroundColor Red
		exit 1   # quitte le script avec un code d’erreur pour éviter la fermeture du terminal
	}
	elseif (-not (Test-Path $PiholeLog)) {
		Write-Host "Le fichier '$PiholeLog' est introuvable." -ForegroundColor Red
		exit 1   # quitte le script avec un code d’erreur pour éviter la fermeture du terminal
	}
	else {
		Write-Host "Le traitement se poursuit..." -ForegroundColor Green
	}

    Write-Host "Lecture du fichier : '$PiholeLog'..." -ForegroundColor Cyan

    # Table de correspondance IP → FQDN
    $dnsMap = @{}

    # ---------------------------------------------------------------
    # TRY/CATCH : lecture du log Pi-hole
    # ---------------------------------------------------------------
    try {
        $piholeLines = Get-Content $PiholeLog -ErrorAction Stop
    }
    catch {
        Write-Host "Impossible de lire le log Pi-hole : $($_.Exception.Message)" -ForegroundColor Red
        exit 1 # quitte le script avec un code d’erreur
    }

    # Extraction des correspondances reply FQDN is IP
    foreach ($line in $piholeLines) {
        if ($line -match "reply\s+([^\s]+)\s+is\s+([0-9A-Fa-f:\.]+)") {
            $dnsMap[$matches[2]] = $matches[1]
        }
    }

    # ---------------------------------------------------------------
    # TRY/CATCH : lecture du CSV firewall généré par la seconde fonction
    # ---------------------------------------------------------------
    try {
        $fwData = Import-Csv $FilteredCsv -ErrorAction Stop
    }
    catch {
        Write-Host "Impossible de lire le CSV firewall : $($_.Exception.Message)" -ForegroundColor Red
        exit 1 # quitte le script avec un code d’erreur
    }

    # Groupement par IP destination
    $grouped = $fwData | Group-Object -Property dst_ip

    # Construction du tableau final
    $output = foreach ($g in $grouped) {
        [PSCustomObject]@{
            dst_ip    = $g.Name
            nbr_occur = $g.Count
            fqdn      = $dnsMap[$g.Name]
        }
    }

    # ---------------------------------------------------------------
    # TRY/CATCH : export final
    # ---------------------------------------------------------------
    try {
        $output |
            Sort-Object -Property nbr_occur -Descending |
            Export-Csv $FinalCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

        Write-Host "Fichier généré : '$FinalCsv'" -ForegroundColor Yellow
    }
    catch {
        Write-Host "Erreur lors de l'export final : $($_.Exception.Message)" -ForegroundColor Red
		exit 1 # quitte le script avec un code d’erreur
    }
}

# -------------------------------------------------------------------
# 4. Invoke-FwFullProcess
#    Exécute automatiquement les 3 étapes :
#    1. Convert-FwLogToTable
#    2. Get-FwDataCols
#    3. Find-FwIpFqdn
# -------------------------------------------------------------------
function Invoke-FwFullProcess {

    [CmdletBinding()]
    param(
        # Dossiers et fichiers utilisés dans le traitement
        [string]$InPath  = "C:\CR431-Logs",
        [string]$OutPath = "C:\CR431-Logs",

    )

    Write-Host "=== DÉMARRAGE DU TRAITEMENT COMPLET ===" -ForegroundColor Cyan

	# Construction des chemins
    $FwLogPath      = Join-Path $InPath "fw.log"
    $PiholeLog      = Join-Path $InPath "pihole.log"

    $ParsedCsv      = Join-Path $OutPath "1_fw_parsed.csv"
    $FilteredCsv    = Join-Path $OutPath "2_fw_parsed_filtered.csv"
    $FinalOutputCsv = Join-Path $OutPath "3_fw_ip_fqdn_stats.csv"

    # 1. Conversion du log firewall → CSV structuré
    Convert-FwLogToTable -SrcPath $FwLogPath -OutputCsv $ParsedCsv -VerboseOutput:$VerboseOutput

    # 2. Extraction des colonnes pertinentes
    Get-FwDataCols -InputPath $ParsedCsv -OutputPath $FilteredCsv

    # 3. Association IP → FQDN via Pi-hole
    Find-FwIpFqdn -FilteredCsv $FilteredCsv -PiholeLog $PiholeLog -FinalCsv $FinalOutputCsv

    Write-Host "=== TRAITEMENT TERMINÉ ===" -ForegroundColor Cyan
}

# -------------------------------------------------------------------
# 5. Show-ModuleParameters
#    Liste les paramètres de chaque fonction exportée par le module.
#    Cette fonction est utile pour documenter rapidement le module
#    ou vérifier les paramètres disponibles sans ouvrir le code.
# -------------------------------------------------------------------
function Show-ModuleParameters {
    param(
        # Nom du module à analyser (par défaut : CR431Tools)
        [string]$ModuleName = "CR431Tools"
    )

    # Récupère toutes les commandes (fonctions) appartenant au module
    Get-Command -Module $ModuleName |
        
        # Pour chaque commande trouvée, on construit un objet personnalisé
        ForEach-Object {
            [PSCustomObject]@{
                # Nom de la fonction
                Fonction   = $_.Name

                # Liste des paramètres disponibles, séparés par des virgules
                Parametres = ($_.Parameters.Keys -join ", ")
            }
        }
}

# -------------------------------------------------------------------
# 6. Export des fonctions du module
# -------------------------------------------------------------------
Export-ModuleMember -Function Convert-FwLogToTable, Get-FwDataCols, Find-FwIpFqdn, Invoke-FwFullProcess, Show-ModuleParameters
