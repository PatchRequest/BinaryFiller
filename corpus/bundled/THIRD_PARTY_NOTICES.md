# Third-party goodware bundled for corpus extraction

These binaries are **unmodified upstream releases**, redistributed solely to
seed a goodware feature corpus for authorized red-team / security research
tooling. Licenses below govern the original works; binary-filler itself does
not claim ownership.

| File | Project | License | Source |
|------|---------|---------|--------|
| `putty-x64.exe` | PuTTY | MIT | https://www.chiark.greenend.org.uk/~sgtatham/putty/ |
| `puttygen-x64.exe` | PuTTY | MIT | same |
| `pageant-x64.exe` | PuTTY | MIT | same |
| `rufus-4.15.exe` | Rufus | GPLv3 | https://github.com/pbatard/rufus |
| `busybox-w32.exe` | busybox-w32 | GPL-2.0 | https://frippery.org/busybox/ |
| `7zr.exe` | 7-Zip | LGPL / unRAR restriction on codecs (7zr is reduced) | https://www.7-zip.org/ |
| `SumatraPDF-3.6.1-64.exe` | SumatraPDF | GPLv3 | https://www.sumatrapdfreader.org/ |
| `notepadpp-x64.exe` | Notepad++ | GPLv3 | https://github.com/notepad-plus-plus/notepad-plus-plus |
| `jq-windows-amd64.exe` | jq | MIT | https://github.com/jqlang/jq |
| `rg.exe` | ripgrep | MIT / Apache-2.0 | https://github.com/BurntSushi/ripgrep |

## Obligations (summary — read upstream licenses)

- **MIT / Apache-2.0**: preserve copyright and license notices.
- **GPL / LGPL**: source is available from upstream; redistributing modified
  versions of those programs requires complying with GPL/LGPL. We ship
  **unmodified** upstream binaries.
- Do not remove this notice when redistributing the `corpus/bundled/` tree.

## Not included (intentionally)

- Proprietary freeware that forbids redistribution (many “free tools”, Sysinternals
  EULAs, etc.).
- Large installers / Electron apps (size and license noise).

## Refresh

```bash
./scripts/fetch-bundled-goodware.sh
./scripts/rebuild-bundled-corpus.sh
```
