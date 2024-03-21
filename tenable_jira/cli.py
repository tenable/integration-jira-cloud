from pathlib import Path
from rich.columns import Columns
from rich.panel import Panel
from rich.console import Console
from rich.table import Table
import tomlkit
import typer

from .jira.jira import Jira
from . import validator

console = Console()
app = typer.Typer()


@app.command()
def validate(configfile: Path):
    """
    Validates the configuration file
    """
    with open(configfile, 'r', encoding='utf-8') as f:
        config = tomlkit.load(f)
    errors = validator.validate(config)
    if errors:
        for error in errors:
            location = '.'.join(error.get('loc', []))
            data = tomlkit.dumps(error.get('input'))
            console.print(f'{location}: {error.get("msg")}')
            console.print(data)
        raise typer.Exit(code=1)
    console.print('Configuration loaded: OK')


@app.command()
def build(configfile: Path,
          update: bool = True,
          verbose: bool = True
          ):
    """
    Runs the initial configuration for the Jira project.
    """
    validate(configfile)
    with open(configfile, 'r', encoding='utf-8') as f:
        config = tomlkit.load(f)
    jira = Jira(config)
    jira.setup()

    if update:
        with open(configfile, 'w', encoding='utf-8') as f:
            tomlkit.dump(config, f)

    if verbose:
        platform = config['tenable']['platform']
        akey = config['tenable']['access_key']
        skey = config['tenable']['secret_key']
        ten_table = Table('Tenable Parameters')
        ten_table.add_column('Parameter', style='bold')
        ten_table.add_column('Value', style='cyan')
        ten_table.add_row('Platform', config['tenable'][platform])
        ten_table.add_row('Severities',
                          ','.join(config['tenable']['severities']))
        ten_table.add_row('Vulnerability Age', config['tenable']['vuln_age'])
        ten_table.add_row('Access key', f'{akey[:4]}...{akey[-4:]}')
        ten_table.add_row('Secret key', f'{skey[:4]}...{skey[-4:]}')
        if platform == 'tsc':
            ten_table.add_row('Security Center URL', config['tenable']['url'])
            ten_table.add_row('Page Size', config['tenable']['tsc_page_size'])
        elif platform == 'tvm':
            ten_table.add_row('TVM URL', config['tenable']['url'])
            ten_table.add_row('Export Chunk Size',
                              config['tenable']['tvm_chunk_size'])

        jira_table = Table('Jira Parameters')
        jira_table.add_column('Parameter', style='bold')
        jira_table.add_column('Value', style='magenta')
        jira_table.add_row('Application URL', config['jira']['url'])
        jira_table.add_row('Username', config['jira']['api_username'])
        jira_table.add_row('API Token',
                           f'{config["jira"]["api_token"][:4]}...')
        jira_table.add_row('Closed Transition', config['jira']['closed'])
        jira_table.add_row('Severity Map', config['jira']['severity_map'])
        jira_table.add_row('State Map', config['jira']['state_map'])
        jira_table.add_row('Project Key', config['jira']['project']['key'])
        jira_table.add_row('Task Name',
                           config['jira']['project']['task']['name'])
        jira_table.add_row('Task ID',
                           config['jira']['project']['task']['id'])
        jira_table.add_row('Sub-Task Name',
                           config['jira']['project']['subtask']['name'])
        jira_table.add_row('Sub-Task ID',
                           config['jira']['project']['subtask']['id'])

        fields_table = Table(title='Jira Fields')
        fields_table.add_column('Field Name')
        fields_table.add_column('Jira Id', style='magenta')
        fields_table.add_column('Tenable Mapping', style='cyan')
        for field in config['jira']['fields']:
            fields_table.add_row(field['name'],
                                 field['id'],
                                 field['attr'][platform]
                                 )
        console.print(Columns([Panel(ten_table), Panel(jira_table)]))
        console.print(fields_table)
