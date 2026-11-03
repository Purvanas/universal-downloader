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
URL ──> validation réseau ──> analyse yt-dlp / gallery-dl
                                  │
                                  └── job + progression SSE
                                           │
                                           └── fichier temporaire
```

Le serveur Express garde l’état des jobs en mémoire. Les résultats sont écrits dans `downloads/`, disponibles quelques minutes, puis supprimés. Le frontend est écrit en HTML, CSS et JavaScript sans framework.

Les URL fournies par les utilisateurs et chaque redirection HTTP sont contrôlées pour bloquer les adresses locales, privées et de lien local. Le scan par navigateur headless est désactivé par défaut : il exécute du contenu tiers et élargit fortement la surface réseau. Si vous l’activez, isolez aussi le processus et filtrez les sorties réseau au niveau du système ou du conteneur ; la protection applicative ne remplace pas une politique d’egress.

## Installation

Prérequis :

- **Node.js 22 ou 24** ;
- [`yt-dlp`](https://github.com/yt-dlp/yt-dlp) dans le `PATH` ;
- `ffmpeg` pour les fusions et extractions audio ;
- [`gallery-dl`](https://github.com/mikf/gallery-dl) dans le `PATH` pour les images et carrousels ;
- un navigateur compatible avec Puppeteer uniquement si le scan profond est activé.

```bash
git clone https://github.com/Purvanas/universal-downloader.git
cd universal-downloader
PUPPETEER_SKIP_DOWNLOAD=true npm ci
cp .env.example .env
node --env-file=.env server.js
```

La variable d’installation évite de télécharger Chromium lorsque le scan profond reste désactivé. Si vous activez cette fonction, installez un navigateur compatible avec Puppeteer dans l’environnement isolé prévu pour lui.

Le serveur écoute par défaut sur `127.0.0.1:3600`. Placez-le derrière un reverse proxy HTTPS. [.env.example](.env.example) documente le répertoire temporaire, les chemins d’outils, la limite de taille, la concurrence et l’origine autorisée pour le convertisseur.

Un fichier de cookies Netscape peut être indiqué par `COOKIE_FILE` pour les sources qui exigent une session. Il reste local, est ignoré par Git et ne doit jamais être partagé. Sans fichier, l’application fonctionne avec les contenus publics accessibles aux extracteurs.

`ERRORS_TOKEN` protège le journal technique. Sans valeur, la route d’administration reste invisible.

## Sécurité et périmètre

L’application télécharge du contenu depuis Internet et lance des outils externes. Pour une instance publique, exécutez-la avec un utilisateur non privilégié, un système de fichiers borné, des limites CPU/mémoire/processus et un filtrage réseau sortant. Mettez régulièrement à jour `yt-dlp` et `gallery-dl` : les sites changent souvent leur lecteur et leurs protections.

Utilisez l’outil uniquement pour des contenus que vous êtes autorisé à récupérer et dans le respect des règles du service source. Le projet ne contourne pas les DRM.

## Vérification

La CI exécute les contrôles et tests sur Node.js 22 et 24. Les tests réseau utilisent des doubles locaux : ils vérifient les plages privées, les réponses DNS multiples et les redirections sans contacter de site réel.

## Licence

Le code de ce dépôt est distribué sous licence [MIT](LICENSE). `yt-dlp`, `gallery-dl`, FFmpeg, Puppeteer et les autres dépendances conservent leurs propres licences.
