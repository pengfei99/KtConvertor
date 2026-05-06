import typer
from pathlib import Path
from typing import Optional
from rich.console import Console

# Adjust the import to match your package structure
from ktconvertor.convertor import convert_kirbi

# Initialize console for professional-looking output
console = Console()

app = typer.Typer(
    name="krbconvertor",
    help="CLI tool to convert Kerberos .kirbi tickets to MIT CCACHE format.",
    rich_markup_mode="rich"
)


@app.command()
def convert(
        kirbi_path: Path = typer.Argument(
            ...,
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
            help="Path to the input .kirbi ticket file."
        ),
        ccache_path: Optional[Path] = typer.Option(
            None,
            "--output", "-o",
            writable=True,
            help="Path for the output .ccache file. If omitted, uses the default OS cache path."
        ),
):
    """
    Convert a Kerberos .kirbi ticket to .ccache format.
    """
    try:
        # Convert Path object back to string if your core function requires it,
        # though it's better if convert_kirbi handles Path objects.
        final_path = convert_kirbi(str(kirbi_path), str(ccache_path) if ccache_path else None)

        console.print(f"[bold green]✓ Success:[/bold green] Ticket converted to [cyan]{final_path}[/cyan]")

    except Exception as e:
        console.print(f"[bold red]✗ Error:[/bold red] {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()