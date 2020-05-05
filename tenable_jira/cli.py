#!/usr/bin/env python
'''
MIT License

Copyright (c) 2019 Tenable Network Security, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''
import click, logging, time, yaml, json, platform, sys, os
from tenable.io import TenableIO
from tenable.sc import TenableSC
from .config import base_config
from restfly.utils import dict_merge
from .jira import Jira
from .transform import Tio2Jira
from . import __version__

troubleshooting = '''
### Configuration File:
```yaml
{configfile}
```

### Debug Logs
```
{logging}
```

### Available IssueTypes
```yaml
{issuetypes}
```
'''

@click.command()
@click.option('--observed-since', '-s', envvar='SINCE', default=0,
    type=click.INT, help='The unix timestamp of the age threshold')
@click.option('--setup-only', is_flag=True,
    help='Performs setup tasks and generates a config file.')
@click.option('--troubleshoot', is_flag=True,
    help='Outputs some basic troubleshooting data to file as an issue.')
@click.argument('configfile', default='config.yaml', type=click.File('r'))
def cli(configfile, observed_since, setup_only=False, troubleshoot=False):
    '''
    Tenable.io -> Jira Cloud Transformer & Ingester
    '''
    config_from_file = yaml.load(configfile, Loader=yaml.Loader)
    config = dict_merge(base_config(), config_from_file)

    # Get the logging definition and define any defaults as need be.
    log = config.get('log', {})
    log_lvls = {'debug': 10, 'info': 20, 'warn': 30, 'error': 40}
    log['level'] = log_lvls[log.get('level', 'warn')]
    log['format'] = log.get('format',
        '%(asctime)-15s %(name)s %(levelname)s %(message)s')

    # Configure the root logging facility
    if troubleshoot:
        logging.basicConfig(
            level=logging.DEBUG,
            format=log['format'],
            filename='tenable_debug.log'
        )
    else:
        logging.basicConfig(**log)

    # Output some basic information detailing the config file used and the
    # python version & system arch.
    logging.info('Tenable2JiraCloud Version {}'.format(__version__))
    logging.info('Using configuration file {}'.format(configfile.name))
    uname = platform.uname()
    logging.info('Running on Python {} {}/{}'.format(
        '.'.join([str(i) for i in sys.version_info][0:3]),
        uname[0], uname[-2]))

    # instantiate the Jira object
    jira = Jira(
        'https://{}/rest/api/3'.format(config['jira']['address']),
        config['jira']['api_username'],
        config['jira']['api_token']
    )

    # Initiate the Tenable.io API model, the Ingester model, and start the
    # ingestion and data transformation.
    if config['tenable'].get('platform') == 'tenable.io':
        source = TenableIO(
            access_key=config['tenable'].get('access_key'),
            secret_key=config['tenable'].get('secret_key'),
            vendor='Tenable',
            product='JiraCloud',
            build=__version__
        )
        if int(source.session.details().get('permissions')) < 64:
            logging.error('API Keys tie to non-admin user.')
    elif config['tenable'].get('platform') == 'tenable.sc':
        source = TenableSC(
            config['tenable'].get('address'),
            port=int(config['tenable'].get('port', 443)),
            username=config['tenable'].get('username'),
            password=config['tenable'].get('password'),
            access_key=config['tenable'].get('access_key'),
            secret_key=config['tenable'].get('secret_key'),
            vendor='Tenable',
            product='JiraCloud',
            build=__version__
        )
    else:
        logging.error('No valid Tenable platform configuration defined.')
        exit(1)
    ingest = Tio2Jira(source, jira, config)

    if troubleshoot:
        # if the troubleshooting flag is set, then we will be collecting some
        # basic information and outputting it to the screen in a format that
        # Github issues would expect to format it all pretty.  This should help
        # reduce the amount of time that is spent with back-and-forth debugging.
        try:
            ingest.ingest(observed_since)
        except:
            logging.exception('Caught the following Exception')

        # Some basic redaction of sensitive data, such as API Keys, Usernames,
        # Passwords, and hostnames.
        addr = config_from_file['jira']['address']
        sc_addr = 'NOTHING_TO_SEE_HERE_AT_ALL'
        config_from_file['jira']['address'] = '<REDACTED>'
        config_from_file['jira']['api_token'] = '<REDACTED>'
        config_from_file['jira']['api_username'] = '<REDACTED>'
        config_from_file['project']['leadAccountId'] = '<REDACTED>'
        if config_from_file['tenable'].get('address'):
            sc_addr = config_from_file['tenable']['address']
            config_from_file['tenable']['address'] = '<REDACTED>'
        if config_from_file['tenable'].get('access_key'):
            config_from_file['tenable']['access_key'] = '<REDACTED>'
        if config_from_file['tenable'].get('secret_key'):
            config_from_file['tenable']['secret_key'] = '<REDACTED>'
        if config_from_file['tenable'].get('username'):
            config_from_file['tenable']['username'] = '<REDACTED>'
        if config_from_file['tenable'].get('password'):
            config_from_file['tenable']['password'] = '<REDACTED>'

        output = troubleshooting.format(
            configfile=yaml.dump(config_from_file, default_flow_style=False),
            logging=open('tenable_debug.log').read() \
                .replace(addr, '<JIRA_CLOUD_HOST>') \
                .replace(sc_addr, '<TENABLE_SC_HOST>'),
            issuetypes='\n'.join(
                [
                    '{id}: {name}'.format(**a)
                    for a in jira.issue_types.list()
                    if a.get('name').lower() in ['task', 'subtask', 'sub-task']
                ]
            )
        )
        print(output)
        print('\n'.join([
            '/-------------------------------NOTICE-----------------------------------\\',
            '| The output above is helpful for us to troubleshoot exactly what is     |',
            '| happening within the code and offer a diagnosis for how to correct.    |',
            '| Please note that while some basic redaction has already been performed |',
            '| that we ask you to review the information you\'re about to send and     |',
            '| ensure that nothing deemed sensitive is transmitted.                   |',
            '| ---------------------------------------------------------------------- |',
            '| -- Copy of output saved to "issue_debug.md"                            |',
            '\\------------------------------------------------------------------------/'
        ]))
        with open('issue_debug.md', 'w') as reportfile:
            print(output, file=reportfile)
        os.remove('tenable_debug.log')
    elif not setup_only:
        ingest.ingest(observed_since)

        # If we are expected to continually re-run the transformer, then we will
        # need to track the passage of time and run every X hours, where X is
        # defined by the user in the configuration.
        if config.get('service', {}).get('interval', 0) > 0:
            sleeper = int(config['service']['interval']) * 3600
            while True:
                last_run = int(time.time())
                logging.info(
                    'Sleeping for {}h'.format(sleeper/3600))
                time.sleep(sleeper)
                logging.info(
                    'Initiating ingest with observed_since={}'.format(last_run))
                ingest.ingest(last_run)
    elif setup_only:
        # In setup-only mode, the ingest will not run, and instead a config file
        # will be generated that will have all of the JIRA identifiers baked in
        # and will also inform the integration to ignore the screen builder.
        # When using this config, if there are any changes to the code, then
        # this config will need to be re-generated.
        config['screen']['no_create'] = True
        logging.info('Set to setup-only.  Will not run ingest.')
        logging.info('The following is the updated config file from the setup.')
        with open('generated_config.yaml', 'w') as outfile:
            outfile.write(yaml.dump(config, Dumper=yaml.Dumper))
        logging.info('Generated "generated_config.yaml" config file.')
        logging.info('This config file should be updated for every new version of this integration.')
