#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -f .env ]; then echo '.env exists; edit it directly.'; exit 1; fi
umask 077
python3 - <<'PYTHON'
from pathlib import Path
import secrets
text=Path('.env.example').read_text()
password=secrets.token_hex(24)
text=text.replace('replaceWithRandom32Chars',password)
for name in ['SERVICE_TOKEN','OWNER_PASSWORD','SESSION_SECRET']:
 text=text.replace(name+'='+password,name+'='+secrets.token_hex(24))
Path('.env').write_text(text)
print('Created .env. Read OWNER_PASSWORD locally to log in.')
PYTHON
