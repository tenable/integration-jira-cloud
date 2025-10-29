import logging
from pathlib import Path

import tomlkit
import typer
from rich.columns import Columns
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from . import validator
from .jira.jira import Jira
from .processor import Processor

console = Console()
app = typer.Typer(add_completion=False)


def setup_logging(verbose: bool = False):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)],
    )


def tenable_table(config: dict) -> Table:
    """
    Builds the Tenable configuration table for the CLI.
    """
    platform = config["tenable"]["platform"]
    akey = config["tenable"]["access_key"]
    skey = config["tenable"]["secret_key"]
    table = Table(title="Tenable Parameters")
    table.add_column("Parameter", style="bold")
    table.add_column("Value", style="cyan")
    table.add_row("Platform", platform)
    table.add_row("Severities", ",".join(config["tenable"]["severities"]))
    table.add_row("Vulnerability Age", str(config["tenable"]["vuln_age"]))
    table.add_row("Last Run", str(config["tenable"].get("last_run")))
    table.add_row("Access key", f"{akey[:4]}...{akey[-4:]}")
    table.add_row("Secret key", f"{skey[:4]}...{skey[-4:]}")
    if platform == "tsc":
        table.add_row("Security Center URL", config["tenable"]["url"])
        table.add_row("Page Size", str(config["tenable"]["tsc_page_size"]))
    elif platform == "tvm":
        table.add_row("TVM URL", config["tenable"]["url"])
        table.add_row("Export Chunk Size", str(config["tenable"]["tvm_chunk_size"]))
    return table


def jira_table(config: dict) -> Table:
    """
    Builds the Jira configuration table for the CLI.
    """
    table = Table(title="Jira Parameters")
    table.add_column("Parameter", style="bold")
    table.add_column("Value", style="magenta")
    table.add_row("Application URL", config["jira"]["url"])
    table.add_row("Username", config["jira"]["api_username"])
    table.add_row("API Token", f"{config['jira']['api_token'][:4]}...")
    table.add_row("Closed Transition", config["jira"]["closed"])
    table.add_row("Severity Map", str(config["jira"]["severity_map"]))
    table.add_row(
        "Use VPR for Severity?", str(config["jira"].get("use_vpr_severity_map", False))
    )
    table.add_row(
        "VPR Sev Map",
        "\n".join(
            [
                f"* {i['lower_bound']} -> {i['priority']}"
                for i in config["jira"].get("vpr_sev_map", [])
            ]
        ),
    )
    table.add_row("State Map", str(config["jira"]["state_map"]))
    table.add_row("Max Workers", str(config["jira"]["max_workers"]))
    table.add_row("Project Key", config["jira"]["project"]["key"])
    table.add_row("Task Name", config["jira"]["task"]["name"])
    table.add_row("Task ID", str(config["jira"]["task"]["id"]))
    table.add_row("Task Closed ID", str(config["jira"]["task"].get("closed_id")))
    table.add_row("Sub-Task Name", config["jira"]["subtask"]["name"])
    table.add_row("Sub-Task ID", str(config["jira"]["subtask"]["id"]))
    table.add_row("Sub-Task Closed ID", str(config["jira"]["subtask"].get("closed_id")))
    return table


def field_definition_table(jira: Jira) -> Table:
    """
    Returns the field mapping table for the CLI.
    """
    table = Table(title="Jira Fields")
    table.add_column("Field Name")
    table.add_column("Jira Id", style="magenta")
    table.add_column("Tenable Mapping", style="cyan")
    for field in jira.fields:
        table.add_row(field.name, field.id, field.attr)
    return table


@app.command()
def validate(configfile: Path):
    """
    Validates the configuration file
    """
    with open(configfile, "r", encoding="utf-8") as f:
        config = tomlkit.load(f)
    errors = validator.validate(config)
    if errors:
        for error in errors:
            location = ".".join([str(e) for e in error.get("loc", [])])
            data = tomlkit.dumps(error.get("input"))
            console.print(f"{location}: {error.get('msg')}")
            console.print(data)
        raise typer.Exit(code=1)
    console.print("Configuration loaded: OK")


@app.command()
def build(
    configfile: Path,
    update: bool = True,
    verbose: bool = False,
):
    """
    Runs the initial configuration for the Jira project.
    """
    setup_logging(verbose)
    validate(configfile)
    with open(configfile, "r", encoding="utf-8") as f:
        config = tomlkit.load(f)
    jira = Jira(config)
    jira.setup()
    if update:
        with open(configfile, "w", encoding="utf-8") as f:
            tomlkit.dump(config, f)
    console.print(Columns([tenable_table(config), jira_table(config)]))
    console.print(field_definition_table(jira))


@app.command()
def sync(
    configfile: Path,
    update: bool = True,
    verbose: bool = False,
    cleanup: bool = True,
    ignore_last_run: bool = False,
    debug: bool = False,
):
    """
    Perform the sync between Tenable & Jira
    """
    with configfile.open("r", encoding="utf-8") as fobj:
        config = tomlkit.load(fobj)

    if debug:
        verbose = True
        cleanup = False
        config["jira"]["max_workers"] = 1

    setup_logging(verbose)

    dbfile = Path(config["mapping_database"]["path"])
    if dbfile.exists():
        console.print("WARNING :: Mapping Cache discovered.  We will be removing it.")
        dbfile.unlink()

    processor = Processor(config, ignore_last_run=ignore_last_run)
    console.print(Columns([tenable_table(config), jira_table(config)]))
    console.print(field_definition_table(processor.jira))
    processor.sync(cleanup=cleanup)
    if update:
        with open(configfile, "w", encoding="utf-8") as f:
            tomlkit.dump(config, f)
