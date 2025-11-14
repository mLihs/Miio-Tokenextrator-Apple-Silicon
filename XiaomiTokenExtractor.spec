# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['src/token_extractor_gui/app.py'],
    pathex=[],
    binaries=[],
    datas=[('Xiaomi-cloud-tokens-extractor/icon.ico', '.')],
    hiddenimports=['PySide6.QtCore', 'PySide6.QtGui', 'PySide6.QtWidgets', 'PySide6.QtNetwork'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='XiaomiTokenExtractor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['Xiaomi-cloud-tokens-extractor/icon.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='XiaomiTokenExtractor',
)
app = BUNDLE(
    coll,
    name='XiaomiTokenExtractor.app',
    icon='Xiaomi-cloud-tokens-extractor/icon.ico',
    bundle_identifier=None,
)
