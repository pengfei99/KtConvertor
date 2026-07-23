# Building a Windows executable with PyInstaller

## Prerequisites

- Windows (required — `get_tgt.py` uses Windows-only APIs)
- Python 3.11+
- `pip install pyinstaller`

## Build

```powershell
pyinstaller --onefile --name convert-tgt --hidden-import=minikerberos --hidden-import=minikerberos.common.ccache --hidden-import=asn1crypto src/ktconvertor/main.py
```

You should find the output of the pyinstaller inside `dist/`:

- standalone executable: `dist/convert-tgt.exe`
- source file:
- wheel file:

## Troubleshooting

If the exe crashes with `ModuleNotFoundError` at runtime, rebuild with explicit hidden imports:


