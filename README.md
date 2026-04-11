# Universal Downloader

**Free online video downloader** — Download videos, audio, and photos from YouTube, Twitter/X, Instagram, TikTok, Facebook, Reddit, and 1000+ other sites.

**[Use it now → dl.purvanas.fr](https://dl.purvanas.fr)**

## Features

- **YouTube Downloader** — MP4 up to 4K, age-restricted videos supported
- **Twitter/X Downloader** — Save tweets with videos and images
- **Instagram Downloader** — Reels, stories, posts in HD
- **TikTok Downloader** — Videos without watermark
- **Facebook Downloader** — Public videos in HD
- **Reddit Downloader** — Videos and direct image links
- **SoundCloud Downloader** — Music in MP3
- **Audio extraction** — Convert any video to MP3, M4A, OPUS, WAV
- **1000+ sites** supported via yt-dlp

## How it works

1. Paste a URL
2. Click "Analyze"
3. Choose quality/format
4. Download

No account, no installation, no tracking. Everything runs on a self-hosted server.

## Tech Stack

- **Backend**: Node.js, Express
- **Download engine**: [yt-dlp](https://github.com/yt-dlp/yt-dlp), [gallery-dl](https://github.com/mikf/gallery-dl)
- **Frontend**: Vanilla HTML/CSS/JS (single file, no framework)
- **Hosting**: Self-hosted on Ubuntu Server, behind Cloudflare Tunnel

## Self-hosting

```bash
git clone https://github.com/Purvanas/universal-downloader.git
cd universal-downloader
npm install
# Make sure yt-dlp and ffmpeg are installed on your system
node server.js
```

Runs on port 3600 by default.

## Supported platforms

| Platform | Video | Audio | Images |
|----------|-------|-------|--------|
| YouTube | 4K | MP3/M4A/WAV | Thumbnails |
| Twitter/X | HD | - | Photos |
| Instagram | HD | - | Photos |
| TikTok | HD | MP3 | - |
| Facebook | HD | - | - |
| Reddit | HD | - | Direct links |
| SoundCloud | - | MP3 | - |
| Twitch | Clips/VODs | - | - |
| Vimeo | HD | MP3 | - |
| Dailymotion | HD | MP3 | - |
| Pinterest | - | - | HD |
| + 1000 more | via yt-dlp | via yt-dlp | via gallery-dl |

## License

MIT

## Links

- **Live demo**: [dl.purvanas.fr](https://dl.purvanas.fr)
- **Author**: [Purvanas](https://purvanas.fr)
- **Other tools**: [QR Generator](https://qr.purvanas.fr) · [FileDrop](https://drop.purvanas.fr) · [Converter](https://convert.purvanas.fr) · [Photo Editor](https://edit.purvanas.fr)
