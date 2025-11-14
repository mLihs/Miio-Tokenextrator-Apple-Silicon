# Xiaomi Cloud Token Extractor for macOS

Desktop GUI for listing Xiaomi Cloud device tokens without touching the command line.

## Disclaimer

- This project is for personal use only; you are responsible for complying with Xiaomi’s terms of service and local laws.
- Credentials are entered directly into the app and forwarded only to Xiaomi’s endpoints; nonetheless, use a dedicated account if possible.
- The maintainers provide no warranty—use at your own risk.

## Based On

- Built on top of [Piotr Machowski’s Xiaomi Cloud Tokens Extractor](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor); their Python logic and assets underpin the GUI bridge layer.
- GUI implemented with PySide6 (Qt for Python) and packaged via PyInstaller.

## Install & Run

```bash
cd /Users/martinlihs/Documents/Works/TokenExtraktor/V1
python3 -m venv .venv
source .venv/bin/activate
pip install .
python -m token_extractor_gui
```

## Build the macOS `.app`

```bash
cd /Users/martinlihs/Documents/Works/TokenExtraktor/V1
source .venv/bin/activate
pip install pyinstaller
pyinstaller \
  --distpath dist \
  --workpath build \
  --windowed \
  --name "XiaomiTokenExtractor" \
  --icon Xiaomi-cloud-tokens-extractor/icon.ico \
  --add-data "Xiaomi-cloud-tokens-extractor/icon.ico:." \
  --hidden-import PySide6.QtCore \
  --hidden-import PySide6.QtGui \
  --hidden-import PySide6.QtWidgets \
  --hidden-import PySide6.QtNetwork \
  src/token_extractor_gui/app.py
open dist/XiaomiTokenExtractor.app
```

To distribute: sign with your Apple Developer ID and submit for notarization before sharing the bundle.

## License

- Distributed under the MIT License; see `LICENSE`.
- Includes and adapts code from Piotr Machowski’s Xiaomi Cloud Tokens Extractor (MIT).
