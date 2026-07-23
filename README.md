# KtConvertor

Extracts a Kerberos TGT from a Windows logon session (raw kirbi / `KRB-CRED`)
and converts it to MIT ccache format for use with native Kerberos stacks,
Hadoop/HDFS clients, and tools like `klist`.

## Modules

- **`kirbi2ccache.py`** — Zero-dependency kirbi→ccache converter (stdlib only, cross-platform).
  Can be copied out of the repo and used standalone.
- **`get_tgt.py`** — Windows-only TGT extraction via SSPI (`secur32.dll`) and LSA APIs (ctypes).
  Raises `ImportError` on non-Windows.
- **`main.py`** — CLI entry point that combines extraction and conversion.

## Usage

```powershell
# Install
uv sync

# Run (after install)
get-tgt

# With options
get-tgt --target cifs/dc.domain.local -o ticket.ccache --debug
```

You can also run directly: `python -m ktconvertor.main`

## Build standalone executable (Windows)

Requires PyInstaller on Windows:

```powershell
pip install pyinstaller
pyinstaller --onefile --name convert-tgt --hidden-import=minikerberos --hidden-import=minikerberos.common.ccache --hidden-import=asn1crypto src/ktconvertor/main.py
```

Output: `dist/convert-tgt.exe`


## Requirements

- Python >=3.11
- Dependencies: `minikerberos`, `asn1crypto`
- TGT extraction requires Windows; conversion runs on any platform

## Test

```powershell
pytest
```

Test data (`.kirbi` files) must be placed in `tests/testdata/kirbi/`.

## Reference: Existing tools

There are existing tools:

- https://github.com/ParrotSec/mimikatz: a tool in C to test Windows security.
- https://github.com/skelsec/pypykatz: Mimikatz implementation in pure Python
- https://github.com/ghostpack/rubeus: C# toolset for raw Kerberos interaction
- https://github.com/skelsec/minikerberos: python implementation for kerberos ticket management
- https://github.com/fortra/impacket: python implementation for kerberos ticket management `impacket` is considered as a
  virus by `Windows defender`


## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.





