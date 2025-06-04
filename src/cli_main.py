import typer
from rich.console import Console
from src.core.scanner import PortScanner
import asyncio

app = typer.Typer()
console = Console()

@app.command()
def scan(target: str, ports: str = "1-1000"):
    """Scan a target for open ports."""
    scanner = PortScanner()
    try:
        result = asyncio.run(scanner.scan_target(target, ports))
        console.print(f"[bold green]Scan results for {result.target}:[/bold green]")
        for port in result.ports:
            console.print(f"Port {port}: {result.services[port]}")
        console.print(f"Scan completed at: {result.timestamp}")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

if __name__ == "__main__":
    app() 