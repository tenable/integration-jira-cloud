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
import click, logging, time, yaml, json, platform, sys
from tenable.io import TenableIO
from .config import base_config
from restfly.utils import dict_merge
from .jira import Jira
from .transform import Tio2Jira
from . import __version__

@click.command()
@click.option('--observed-since', '-s', envvar='SINCE', default=0,
    type=click.INT, help='The unix timestamp of the age threshold')
@click.argument('configfile', default='config.yaml', type=click.File('r'))
def cli(configfile, observed_since):
    '''
    Tenable.io -> Jira Cloud Transformer & Ingester
    '''
    config = dict_merge(
        base_config(),
        yaml.load(configfile, Loader=yaml.CLoader)
    )

    # Get the logging definition and define any defaults as need be.
    log = config.get('log', {})
    log_lvls = {'debug': 10, 'info': 20, 'warn': 30, 'error': 40}
    log['level'] = log_lvls[log.get('level', 'warn')]
    log['format'] = log.get('format',
        '%(asctime)-15s %(name)s %(levelname)s %(message)s')

    # Configure the root logging facility
    logging.basicConfig(**log)

    # Output some basic information detailing the config file used and the
    # python version & system arch.
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
    elif config['tenable'].get('platform') == 'tenable.sc':
        logging.error('Tenable.sc ingest is not yet implimented.')
        exit(1)
    else:
        logging.error('No valid Tenable platform configuration defined.')
        exit(1)
    ingest = Tio2Jira(source, jira, config)
    ingest.ingest(observed_since)

    # If we are expected to continually re-run the transformer, then we will
    # need to track the passage of time and run every X hours, where X is
    # defined by the user in the configuration.
    if config.get('service', {}).get('interval', 0) > 0:
        sleeper = int(config['service']['interval']) * 3600
        while True:
            last_run = int(time.time())
            logging.info(
                'Sleeping for {}h before next iteration'.format(sleeper/3600))
            time.sleep(sleeper)
            logging.info(
                'Initiating ingest with observed_since={}'.format(last_run))
            ingest.ingest(last_run)