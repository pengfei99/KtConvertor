# KtConvertor

The objective of this project is to get a kerberos TGT ticket from a windows logon session in raw kirbi format,
then convert it to MIT Kerberos cache file.

## Existing tools

There are existing tools:

- https://github.com/ParrotSec/mimikatz: a tool in C to test Windows security.
- https://github.com/skelsec/pypykatz: Mimikatz implementation in pure Python
- https://github.com/ghostpack/rubeus: C# toolset for raw Kerberos interaction
- https://github.com/skelsec/minikerberos: python implementation for kerberos ticket management
- https://github.com/fortra/impacket: python implementation for kerberos ticket management `impacket` is considered as a
  virus by `Windows defender`

## 🚀 Key Features

* **Smart Pathing:** Automatically detects the correct Kerberos cache path for you (Only for windows)
* **Safe I/O:** Atomic kerberos ccache file writes and overwrites.
* **Developer Friendly:** Fully type-hinted and optimized for use with `uv`.

## 🚀 Quick Start

This tool is released as a python package and executable. To install it as a python package, you need to have 
`python virtual env` and `pip` to install it.

If you want to use it as an executable, you only need to download the `convert-tgt.exe`

### Build your python virtual environment with conda

For example, you can create a virtual environment for python 3.11 with conda.

```powershell
conda create --name my_test python=3.11
```

### Build your python virtual environment with uv

```powershell
# clone the repo git

# use uv to create virtual env
uv sync
```


## Basic Usage

After installation, you can view all available options of the tool with `convert-tgt.exe --help`

```powershell

```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.





