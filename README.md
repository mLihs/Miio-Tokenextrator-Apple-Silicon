# Xiaomi Cloud Token Extractor for macOS

A powerful desktop GUI application for extracting Xiaomi Cloud device tokens without command-line complexity. Built for macOS with Apple Silicon support.

![macOS](https://img.shields.io/badge/macOS-Apple%20Silicon-000000?style=flat&logo=apple)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## ✨ Features

### Authentication
- 🔐 **Password Login** with 2FA email verification support
- 📱 **QR Code Login** - scan with your Xiaomi Home app
- 🤖 **CAPTCHA Handling** - automatic image display and verification
- 🔄 **Network Retry** - automatic retry with exponential backoff (3 attempts)
- ⚡ **Smart Error Messages** - user-friendly errors with actionable suggestions

### Device Management
- 🌍 **Multi-Region Support** - 8 server regions (CN, DE, US, RU, TW, SG, IN, I2)
- 🔍 **Real-time Search** - filter devices by name, IP, token, MAC, or model
- 📊 **Sortable Columns** - click any header to sort devices
- 🔑 **BLE Encryption Keys** - automatic retrieval for Bluetooth devices
- 🏠 **Hierarchical View** - organized by Server → Home → Device

### Copy & Export
- 📋 **Smart Copy/Paste**:
  - Right-click context menu for individual fields
  - Copy entire rows or multiple devices
  - Keyboard shortcut support (⌘+C / Ctrl+C)
  - Tab-separated format for spreadsheets
  
- 💾 **Multiple Export Formats**:
  - **CSV** - perfect for Excel/Google Sheets
  - **JSON** - structured data with full details
  - **YAML** - human-readable configuration format

### User Experience
- 💫 **Progress Indicators** - visual feedback during operations
- 💾 **Settings Persistence** - remembers window size, server selection, preferences
- 🎨 **Auto-resize Columns** - optimal readability
- 📝 **Integrated Log Viewer** - track operations and debug issues
- 🛡️ **Graceful Shutdown** - saves state and cancels operations cleanly

## 🚀 Quick Start

### Download & Run (Easiest)
1. Download the latest `XiaomiTokenExtractor.app` from releases
2. Right-click the app and select **"Open"** (first time only - macOS security)
3. Grant permission when prompted
4. Start extracting tokens!

### Build from Source

```bash
# Clone repository
git clone <repository-url>
cd Mac-Silicon-Miio-Tokenextrator

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install .

# Run directly
python -m token_extractor_gui

# Or build the app
pip install pyinstaller
pyinstaller XiaomiTokenExtractor.spec
open dist/XiaomiTokenExtractor.app
```

## 📖 How to Use

### 1. **Authentication**
Choose your preferred method:
- **Password Tab**: Enter Xiaomi account credentials
- **QR Tab**: Scan QR code with Xiaomi Home app

### 2. **Select Server Region**
- Choose your region (or "All regions" to search everywhere)
- Most devices are in: CN (China), DE (Germany), US (United States)

### 3. **Fetch Devices**
- Click "Fetch devices" or "Fetch devices via QR login"
- Wait for the progress bar to complete
- Devices appear organized by server and home

### 4. **Find & Copy Tokens**
- **Search**: Type in the search bar to filter devices
- **Copy**: Right-click any device to copy specific fields
- **Export**: Use export buttons for CSV/JSON/YAML formats

## 🔧 Advanced Features

### Search & Filter
```
Type in search bar:
- Device name: "vacuum"
- IP address: "192.168"
- Token: "abc123"
- Model: "roborock"
```

### Copy Options
- **Individual field**: Right-click → Copy Token/IP/MAC/etc.
- **Entire row**: Right-click → Copy Row
- **Multiple devices**: Select with ⌘+Click, press ⌘+C
- **All devices**: Select multiple → Copy All Selected Devices

### Export Formats

**CSV** - Tab-separated values
```csv
Server,Home ID,Device Name,Device ID,Token,IP,MAC,Model,BLE Key
DE,123456,Living Room Vacuum,device_id,token123,192.168.1.10,...
```

**JSON** - Full structured data
```json
{
  "server": "de",
  "homes": [
    {
      "home_id": 123456,
      "devices": [...]
    }
  ]
}
```

**YAML** - Human-readable format
```yaml
server: de
homes:
  - home_id: 123456
    devices:
      - name: Living Room Vacuum
        token: abc123...
```

## 🛡️ Robustness & Stability

- **Network Retry Logic**: Automatic retry on connection failures (3 attempts)
- **User-Friendly Errors**: Clear error messages with troubleshooting steps
- **Graceful Shutdown**: Properly cancels operations and saves state
- **Settings Persistence**: All preferences saved between sessions
- **Thread Safety**: Proper cleanup and resource management

## 🔒 Security & Privacy

- ✅ Credentials sent **only** to official Xiaomi servers
- ✅ No third-party data collection
- ✅ Local storage only (no cloud sync)
- ✅ Open source - verify the code yourself

**Recommendations:**
- Use a dedicated Xiaomi account if concerned
- Enable 2FA on your Xiaomi account
- Keep tokens secure - they provide device access

## 📝 Requirements

- **macOS**: 11.0+ (Big Sur or later)
- **Architecture**: Apple Silicon (M1/M2/M3) or Intel
- **Python**: 3.10+ (for building from source)
- **Network**: Active internet connection

## 🐛 Troubleshooting

### App won't open (prohibition icon)
```bash
# Remove quarantine flag
xattr -cr /path/to/XiaomiTokenExtractor.app

# Or right-click → Open (first time only)
```

### Connection fails
- ✅ Check internet connection
- ✅ Try different server region
- ✅ Disable VPN temporarily
- ✅ Check firewall settings

### Authentication fails
- ✅ Verify credentials (not Roborock account!)
- ✅ Use QR code login instead
- ✅ Check spam folder for 2FA emails
- ✅ Wait if hitting rate limits (3-5 requests/day limit)

### No devices found
- ✅ Try "All regions" instead of specific server
- ✅ Verify devices are in Xiaomi Home app
- ✅ Check BLE checkbox for Bluetooth devices

## 🏗️ Built With

- **[PySide6](https://wiki.qt.io/Qt_for_Python)** - Qt bindings for Python
- **[PyInstaller](https://pyinstaller.org/)** - Package to standalone app
- **[Requests](https://requests.readthedocs.io/)** - HTTP library
- **[PyCryptodome](https://pycryptodome.readthedocs.io/)** - Encryption (RC4)

## 👏 Credits

Built on top of [Piotr Machowski's Xiaomi Cloud Tokens Extractor](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor). The core authentication and API logic comes from this excellent project.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

Includes and adapts code from Piotr Machowski's Xiaomi Cloud Tokens Extractor (MIT).

## ⚠️ Disclaimers

**General Use**
This software is provided "as is" without warranties. The authors are not liable for any damages or issues arising from use.

**Personal Use Only**
You are responsible for complying with Xiaomi's terms of service and local laws. Use at your own risk.

**Hardware / Firmware Notice**
This project interacts with physical devices and network services. Incorrect usage may lead to device malfunction, connection issues, or data loss.

**Reverse Engineering Notice**
Uses reverse-engineered protocols (miIO). Behavior may change due to vendor updates.

**Brand Independence**
Not affiliated with or endorsed by Xiaomi, SmartMi, Aqara, or any mentioned brands. All trademarks belong to their respective owners.

---

## 🤝 Contributing

Contributions welcome! Please feel free to submit issues or pull requests.

## 📮 Support

- 🐛 **Bug Reports**: [GitHub Issues](../../issues)
- 💡 **Feature Requests**: [GitHub Discussions](../../discussions)
- 📖 **Documentation**: This README and inline code comments

---

**Made with ❤️ for the smart home community**
