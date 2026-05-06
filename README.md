# KtConvertor

The objective of this project is to convert a kerberos ticket from format `.kirbi` to MIT Kerberos cache file. 


We use the `ccache.py` of the project [minikerberos](https://github.com/skelsec/minikerberos/blob/main/minikerberos/common/ccache.py)

## 🚀 Key Features

*   **Smart Pathing:** Automatically detects the correct Kerberos cache path for your OS (following XDG standards on Linux).
*   **Safe I/O:** Atomic file writes and automatic directory creation.
*   **Modern CLI:** Built with `Typer` and `Rich` for beautiful, informative terminal output.
*   **Developer Friendly:** Fully type-hinted and optimized for use with `uv`.

## 🚀 Quick Start

This tool is released as a python package and executable. You need to have `python` and `pip` to install it.

### Build your local environment

As we mentioned before, this tool may build locally the `.whl` files. So if the `OS, CPU architecture or python 
version` of your build environment are not compatible with the target machine, the downloaded or generated `.whl` will 
not be compatible in the target machine. The python version which you use to run the tool will define the downloaded installed

Before build your local environment, check the below things:
- What is the `OS` of your target machine? (e.g. Windows, Linux, MacOS)
- What is the `CPU architecture` of your target machine? (e.g. x86, ARM, etc.)
- What is the `python version` of your target python environment (e.g. 3.11, 3.12, etc.)

For example if you target environment is a `Windows Server 2019` with `x86` CPU and `python 3.11`. Your local environment
should also be `Windows, x86, and python 3.11`.

> We recommend you to use a virtual environment to run the tool.
> Your local environment must have internet access.

For example, you can create a virtual environment for python 3.11 with conda.

```powershell
conda create --name my_test python=3.11
```

### Installation

Here we suppose you already have the required `python`, `pip` and `virtual environment`.

```powershell
pip install ktconvertor
```

### Basic Usage

After installation, you can view all available options of the tool with `convert-tgt.exe --help` 

```powershell
> convert-tgt.exe --help

 Usage: convert-tgt [OPTIONS] KIRBI_PATH

 Convert a Kerberos .kirbi ticket to .ccache format.

┌─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ *    kirbi_path      FILE  Path to the input .kirbi ticket file. [required]                                         │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ --output              -o      PATH  Path for the output .ccache file. If omitted, uses the default OS cache path.   │
│ --install-completion                Install completion for the current shell.                                       │
│ --show-completion                   Show completion for the current shell, to copy it or customize the              │
│                                     installation.                                                                   │
│ --help                              Show this message and exit.                                                     │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘


> convert-tgt.exe tgt.kirbi
```


## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.



