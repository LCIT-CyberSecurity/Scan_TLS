# Découverte SNMPv3 / LLDP

La découverte est une action volontaire d'un opérateur dans **Cartographie**. Elle
ne se lance jamais lors d'un scan TLS et n'interroge aucun sous-réseau arbitraire.
Le formulaire ne propose que les cibles IP déjà enregistrées. Les noms DNS et CIDR
doivent d'abord être résolus ou découpés dans le périmètre autorisé, puis ajoutés
comme cibles individuelles.

La requête est placée dans la file existante et exécutée par le worker de scan sur
son réseau de sortie dédié. L'API reste sur le réseau interne de gestion ; elle ne
sonde pas directement le réseau des cibles.

## Configuration administrateur

Monter les deux secrets SNMPv3 dans l'API à l'aide de variables d'environnement ou
de fichiers Docker Secrets protégés :

```text
ORION_SNMP_SECRETS_DIR=/chemin/protege/vers/les-secrets-snmp
ORION_SNMP_V3_USERNAME=<utilisateur en lecture seule>
ORION_SNMP_V3_AUTH_KEY_FILE=/run/secrets/snmp_auth_key
ORION_SNMP_V3_PRIV_KEY_FILE=/run/secrets/snmp_priv_key
```

L'utilisateur SNMP doit avoir uniquement `authPriv` et les droits MIB en lecture.
Les secrets ne sont ni renvoyés par l'API, ni persistés en base, ni transmis au
navigateur. La configuration répond seulement si le service est activé. En
l'absence d'un des trois paramètres, l'API refuse la découverte.
Le répertoire de secrets est monté en lecture seule dans l'API et le worker ; les
fichiers doivent être lisibles uniquement par l'UID du conteneur (`10001`).

## Données collectées

Le collecteur utilise PySNMP asynchrone en SNMPv3 avec HMAC-SHA-2-256 et AES-128.
Il lit `sysDescr`, `sysObjectID`, `sysName`, IF-MIB (`ifName`, `ifDescr`, `ifSpeed`,
`ifOperStatus`) et LLDP-MIB (identifiants du châssis/port distant, nom système et
description du port local). Les OID numériques sont utilisés pour tolérer les
équipements où les fichiers MIB ne sont pas installés. Les champs absents restent
absents ; une absence de réponse ou de LLDP est indéterminée et ne prouve pas
l'absence d'équipement ou de connexion.

La charge est bornée à 100 cibles, 10 requêtes simultanées, un timeout par requête
réglable de 1 à 5 secondes (2 secondes par défaut), zéro retransmission et 90 secondes
de durée globale. Les équipements qui répondent sont enregistrés comme
`OBSERVED` avec source et date. Les liens LLDP sont conservés séparément des liens
déclarés et inférés. Seule une prévisualisation explicitement confirmée modifie la
cartographie. Les cibles, leur classification SI et les zones ne sont pas modifiées.

SNMPv2c n'est pas activé. Cette version collecte une seule adresse IP à la fois
depuis des entrées d'inventaire ; les découvertes de groupes, les profils d'accès
multiples et la planification restent à venir.
