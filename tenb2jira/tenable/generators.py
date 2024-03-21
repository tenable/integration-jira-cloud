import typing
import arrow
from restfly.utils import dict_flatten, dict_merge
import uuid

if typing.TYPE_CHECKING:
    from tenable.io.exports.iterator import ExportsIterator
    from tenable.sc.analysis import AnalysisResultsIterator


def tvm_asset_cleanup(*assets_iters: 'ExportsIterator') -> dict:
    """
    A simple wrapper to coalesce the multiple terminated asset states within
    TVM.

    Args:
        *assets_iters (ExportsIterator): An asset export iterator

    Returns:
        dict:
            Returns the individual closed assets
    """
    for assets_iter in assets_iters:
        yield from assets_iter


def tvm_merged_data(assets_iter: 'ExportsIterator',
                    vulns_iter: 'ExportsIterator',
                    asset_fields: list[str] = None
                    ) -> dict:
    """
    Merges the asset and vulnerability finding data together into a single
    object and adds in a computed finding id based on the following attributes:

        * asset.id
        * plugin.id
        * port.port
        * port.protocol

    This field is stored as ``integration_finding_id``.

    Args:
        assets_iter (ExportsIterator): The asset iterator
        vulns_iter (ExportsIterator): The vulnerability iterator

    Returns:
        dict:
            Returns the individual findings, flattened and merged with the
            asset data.
    """
    # Yes this is expensive on memory, however it's the only way to get the
    # other asset attributes available within the finding for the Jira ticket
    # without build a database to match everything up into.
    assets = {}
    for asset in assets_iter:
        assets[asset['id']] = {
            'tags': [f'{t["key"]}:{t["value"]}' for t in asset['tags']],
            'ipv4': asset['ipv4s'],
            'ipv6': asset['ipv6s'],
        }
        if asset_fields:
            for field in asset_fields:
                assets[asset['id']][field] = asset[field]

    for finding in vulns_iter:
        # Merge the relevant asset's data into the finding object.
        finding['asset'] = dict_merge(finding['asset'],
                                      assets[finding['asset']['uuid']]
                                      )

        # Flatten the data structure into a flat dictionary.
        f = dict_flatten(finding)

        # Compute the finding id based on the asset id, plugin id, port, and
        # protocol.  We will be generating a UUID based off this data for easy
        # lookup in the mapping database.
        istr = (f'{f["asset.uuid"]}:{f["plugin.id"]}:'
                f'{f["port.port"]}:{f["port.protocol"]}')
        f['integration_finding_id'] = uuid.uuid3(uuid.NAMESPACE_DNS, istr)

        pid = arrow.get(f.get('plugin.vpr.updated',
                              f.get('plugin.modification_date')
                              ))
        f['integration_pid_updated'] = pid

        # Return the augmented finding to the caller.
        yield f


def tsc_merged_data(*vuln_iters: 'AnalysisResultsIterator') -> dict:
    """
    Flattens and extends the vulnerability results returned from the
    Security Center analysis API.  The following fields are added to the
    finding in order to make processing easier:

        * ``integration_finding_id``: comprised of the fields in vulnUniqueness
        * ``integration_state``: derrived from the source and previously
                                 mitigated fields.

    Args:
        *vuln_iters (AnalysisResultsIterator):
            Iterators for each source from Security Center

    Returns:
        dict:
            Returns the individual findings, flattened and enhanced with the
            relevent attributes.
    """
    # This state map tracks the sourcetype and converts it into the TVM base
    # state names.
    state_map = {'cumulative': 'open', 'patched': 'fixed'}

    for vuln_iter in vuln_iters:
        # For this iterator, pull the sourcetpye from the embedded query and
        # store the state mapping.
        state = state_map[vuln_iter._query['sourceType']]
        for finding in vuln_iter:
            # Flatten the data structure into a flat dictionary.
            f = dict_flatten(finding)

            # If the hasBeenMitigated flag was flipped, then the finding isn't
            # open, but is reopened.  We want to confer state accurately so we
            # will check that here.
            if f['hasBeenMitigated'] == '1' and state == 'open':
                f['integration_state'] = 'reopened'
            else:
                f['integration_state'] = state

            # Compute the finding ID and asset IDs based on the fields
            # returned in the vulnUniqueness and hostUniqueness fields.
            # We will then store that field as a UUID
            # in the integration_finding_id attribute.
            uniqf = f['vulnUniqueness'].replace('repositoryID',
                                                'repository.id')\
                                       .split(',')
            uniqa = f['hostUniqueness'].replace('repositoryID',
                                                'repository.id')\
                                       .split(',')
            fstr = ':'.join([f'{f[i]}' for i in uniqf])
            astr = ':'.join([f'{f[i]}' for i in uniqa])
            f['asset.uuid'] = uuid.uuid3(uuid.NAMESPACE_DNS, astr)
            f['integration_finding_id'] = uuid.uuid3(uuid.NAMESPACE_DNS, fstr)
            f['integration_pid_updated'] = arrow.get(int(f.get('pluginModDate')))

            # Return the augmented finding to the caller.
            yield f
