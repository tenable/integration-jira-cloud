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
import click, logging, time, yaml
from tenable.io import TenableIO
from .config import base_config
from restfly.utils import dict_merge
from .jira import Jira
from .transform import Tio2Jira
from . import __version__

@click.command()
@click.option('--verbose', '-v', envvar='VERBOSITY', default=0,
    count=True, help='Logging Verbosity')
@click.option('--observed-since', '-s', envvar='SINCE', default=0,
    type=click.INT, help='The unix timestamp of the age threshold')
@click.option('--run-every', '-r', envvar='RUN_EVERY',
    type=click.INT, help='How many hours between recurring imports')
@click.argument('configfile', default='config.yaml', type=click.File('r'))
def cli(configfile, verbose, observed_since, run_every):
    '''
    Tenable.io -> IBM CloudPak for Security Transformer & Ingester
    '''
    # Setup the logging verbosity.
    if verbose == 0:
        logging.basicConfig(level=logging.WARNING)
    if verbose == 1:
        logging.basicConfig(level=logging.INFO)
    if verbose > 1:
        logging.basicConfig(level=logging.DEBUG)

    logging.debug('Using configuration file {}'.format(configfile.name))

    config = dict_merge(
        base_config(),
        yaml.load(configfile, Loader=yaml.CLoader)
    )

    jira = Jira(
        config['jira']['url'],
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
    # defined by the user.
    if run_every and run_every > 0:
        while True:
            sleeper = run_every * 3600
            last_run = int(time.time())
            logging.info(
                'Sleeping for {}s before next iteration'.format(sleeper))
            time.sleep(sleeper)
            logging.info(
                'Initiating ingest with observed_since={}'.format(last_run))
            ingest.ingest(last_run)