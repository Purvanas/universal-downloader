# Universal Downloader

Universal Downloader rassemble dans une interface unique l’analyse, le téléchargement et l’extraction audio de médias pris en charge par `yt-dlp` et `gallery-dl`. Je l’utilise comme passerelle entre une URL, le format souhaité et, si besoin, mon convertisseur web.

**Démo : [dl.purvanas.fr](https://dl.purvanas.fr)**

## Du lien au fichier

L’application commence par analyser l’URL. Elle privilégie `yt-dlp`, puis utilise des stratégies ciblées pour les publications contenant plusieurs médias, les fichiers directs et les pages HTML classiques. Un téléchargement devient ensuite un job suivi en temps réel par Server-Sent Events.

- vidéo avec choix de qualité et fusion audio/vidéo ;
- extraction audio en MP3, M4A, Opus, WAV, FLAC ou AAC ;
- images et carrousels via `gallery-dl` ;
- listes de médias téléchargées élément par élément ;
- fichiers temporaires supprimés automatiquement ;
- limite partagée d’analyses et de jobs concurrents, arrêt des processus trop longs ;
- plafond de taille appliqué aux transferts directs et aux sorties d’extracteurs ;
- transfert direct en flux, avec taille maximale et backpressure.

La compatibilité exacte dépend des extracteurs installés, du site source et de leurs évolutions. L’interface ne promet donc pas qu’une URL arbitraire fonctionnera toujours.

## Architecture

```text
URL ──> validation réseau ──> relais HTTP(S) local ──> yt-dlp / gallery-dl
                                      │
                                      └── job + progression SSE
                                               │
                                               └── fichier temporaire
```

Le serveur Express garde l’état des jobs en mémoire. Les résultats sont écrits dans `downloads/`, disponibles quelques minutes, puis supprimés. Le frontend est écrit en HTML, CSS et JavaScript sans framework.

Les requêtes HTTP(S) des extracteurs passent par un relais lié à `127.0.0.1`. À chaque requête ou redirection, il refuse les identifiants dans l’URL, les ports autres que 80/443 et toute réponse DNS contenant une adresse privée ou réservée, puis ouvre la connexion vers l’adresse validée plutôt que de résoudre le nom une seconde fois. Les requêtes HTTP(S) effectuées directement par Node utilisent le même principe d’épinglage DNS.

Les miniatures ne sont jamais chargées directement par le navigateur depuis un tiers. Le frontend reçoit un chemin local opaque ; le serveur récupère uniquement des images JPEG, PNG, WebP ou GIF, avec un timeout, une limite de 3 Mio et la même validation réseau.

Le scan Chromium a été retiré : le service n’exécute pas le JavaScript des pages tierces. Le relais protège les chemins HTTP(S) qui le prennent en charge ; il ne constitue ni une sandbox de processus ni une politique réseau globale pour la machine. Une instance publique doit donc conserver un filtrage sortant et des limites système indépendants.

## Installation

Prérequis :

- **Node.js 22 ou 24** ;
- [`yt-dlp`](https://github.com/yt-dlp/yt-dlp) dans le `PATH` ;
- `ffmpeg` pour les fusions et extractions audio ;
- [`gallery-dl`](https://github.com/mikf/gallery-dl) dans le `PATH` pour les images et carrousels.

```bash
git clone https://github.com/Purvanas/universal-downloader.git
cd universal-downloader
YOUTUBE_DL_SKIP_DOWNLOAD=true npm ci
cp .env.example .env
node --env-file=.env server.js
```

La variable d’installation évite le téléchargement automatique d’un binaire pendant `npm ci`. Indiquez ensuite le binaire maintenu par l’hôte avec `YTDLP_BIN` ; cela rend l’installation reproductible et évite de dépendre d’un téléchargement GitHub au postinstall.

Le serveur écoute par défaut sur `127.0.0.1:3600`. Placez-le derrière un reverse proxy HTTPS. [.env.example](.env.example) documente le répertoire temporaire, les chemins d’outils, la limite de taille, la concurrence et l’origine autorisée pour le convertisseur.

Un fichier de cookies Netscape peut être indiqué par `COOKIE_FILE` pour les sources qui exigent une session. Il reste local, est ignoré par Git et ne doit jamais être partagé. Sans fichier, l’application fonctionne avec les contenus publics accessibles aux extracteurs.

`ERRORS_TOKEN` protège le journal technique. Sans valeur, la route d’administration reste invisible.

## Sécurité et périmètre

L’application télécharge du contenu depuis Internet et lance des outils externes. Le relais ne remplace pas une sandbox du système d’exploitation et ne garantit pas qu’un autre processus de la machine ne puisse accéder au réseau. Pour une instance publique, exécutez-la avec un utilisateur non privilégié, un système de fichiers borné, des limites CPU/mémoire/processus et un filtrage réseau sortant. Mettez régulièrement à jour `yt-dlp` et `gallery-dl` : les sites changent souvent leur lecteur et leurs protections.

Utilisez l’outil uniquement pour des contenus que vous êtes autorisé à récupérer et dans le respect des règles du service source. Le projet ne contourne pas les DRM.

## Vérification

La CI exécute les contrôles et tests sur Node.js 22 et 24 sans télécharger `yt-dlp`. Les tests réseau utilisent des doubles locaux : ils vérifient les plages privées et NAT64, les ports, les réponses DNS multiples, l’épinglage de l’adresse, le refus d’une redirection interne et les limites des aperçus sans contacter de site réel.

## Licence

Le code de ce dépôt est distribué sous licence [MIT](LICENSE). `yt-dlp`, `gallery-dl`, FFmpeg et les autres dépendances conservent leurs propres licences.
