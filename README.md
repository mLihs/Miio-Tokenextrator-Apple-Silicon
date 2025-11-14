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


## Disclaimer

This software is provided "as is" without any express or implied warranties, 
including but not limited to the warranties of merchantability, fitness for a 
particular purpose, and non-infringement. In no event shall the author or 
contributors be liable for any claim, damages, or other liability arising from, 
out of, or in connection with the software or the use or other dealings in the 
software.

⚠️ **Hardware / Firmware Notice**
This project interacts with physical hardware, embedded devices, 
network services, and/or firmware components. Incorrect configuration, 
installation, or usage may lead to device malfunction, connection issues, 
network instability, data loss, or irreversible damage. Proceed only if you 
fully understand the risks.

⚠️ **Reverse Engineering Notice**
This project may use or interact with undocumented, proprietary, or reverse-engineered 
protocols (e.g., miIO, Matter implementations, BLE characteristics, 3MF internals).  
Behavior may change at any time due to vendor updates.

⚠️ **Brand Independence**
This project is not affiliated with, associated with, or endorsed by any of the 
mentioned manufacturers, brands, or companies (including but not limited to Xiaomi, 
SmartMi, Aqara, Bambu Lab, Synology, Matter, ESP32, or Deutsche Bahn).
All trademarks and product names belong to their respective owners.

Use entirely at your own risk.
