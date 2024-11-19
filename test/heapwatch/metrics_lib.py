#!/usr/bin/env python3
# Copyright (C) 2019-2024 Algorand, Inc.
# This file is part of go-algorand
#
# go-algorand is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# go-algorand is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.
#
###
#
# Common functions for processing /metrics data captured by heapWatch.py
#
import configparser
from datetime import datetime
from enum import Enum
import logging
import os
import re
import sys
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse


from client_ram_report import dapp


logger = logging.getLogger(__name__)
metric_line_re = re.compile(r'(\S+\{[^}]*\})\s+(.*)')

def num(x):
    if '.' in x:
        return float(x)
    return int(x)

def hunum(x):
    if x >= 10000000000:
        return '{:.1f}G'.format(x / 1000000000.0)
    if x >= 1000000000:
        return '{:.2f}G'.format(x / 1000000000.0)
    if x >= 10000000:
        return '{:.1f}M'.format(x / 1000000.0)
    if x >= 1000000:
        return '{:.2f}M'.format(x / 1000000.0)
    if x >= 10000:
        return '{:.1f}k'.format(x / 1000.0)
    if x >= 1000:
        return '{:.2f}k'.format(x / 1000.0)
    return '{:.2f}'.format(x)


def test_metric_line_re():
    testlines = (
        ('algod_network_connections_dropped_total{reason="write err"} 1', 1),
        #('algod_network_sent_bytes_MS 274992', 274992), # handled by split
    )
    for line, n in testlines:
        try:
            m = metric_line_re.match(line)
            assert int(m.group(2)) == n
        except:
            print('failed on line %r', line)
            raise

def terraform_inventory_ip_not_names(tf_inventory_path):
    """return ip to nickname mapping"""
    tf_inventory = configparser.ConfigParser(allow_no_value=True)
    tf_inventory.read(tf_inventory_path)
    ip_to_name = {}
    for k, sub in tf_inventory.items():
        if k.startswith('name_'):
            for ip in sub:
                if ip in ip_to_name:
                    logger.warning('ip %r already named %r, also got %r', ip, ip_to_name[ip], k)
                ip_to_name[ip] = k
    #logger.debug('names: %r', sorted(ip_to_name.values()))
    #logger.debug('ip to name %r', ip_to_name)
    return ip_to_name

metrics_fname_re = re.compile(r'(.*?)\.(\d+_\d+)\.metrics')

def gather_metrics_files_by_nick(
    metrics_files: Iterable[str], nick_res: List[str], nick_lres: List[str]
) -> Dict[str, Dict[datetime, str]]:
    """return {"node nickname": {datetime: path, ...}, ...}}
    after resolving ip addresses into nodes nick names and applying nick_re and nick_lre filters.
    """
    filesByNick = {}
    tf_inventory_path = None
    for path in metrics_files:
        fname = os.path.basename(path)
        if fname == 'terraform-inventory.host':
            tf_inventory_path = path
            continue
        m = metrics_fname_re.match(fname)
        if not m:
            continue
        nick = m.group(1)
        timestamp = m.group(2)
        timestamp = datetime.strptime(timestamp, '%Y%m%d_%H%M%S')
        dapp(filesByNick, nick, timestamp, path)

    if tf_inventory_path:
        # remap ip addresses to node names
        ip_to_name = terraform_inventory_ip_not_names(tf_inventory_path)
        filesByNick2 = {}
        for nick in filesByNick.keys():
            parsed = urlparse('//' + nick)
            name: str = ip_to_name.get(parsed.hostname)
            val = filesByNick[nick]
            filesByNick2[name] = val

        filesByNick = filesByNick2
        filesByNick2 = {}

        for nick in filesByNick.keys():
            if nick_res or not nick_res and not nick_lres:
                # filter by regexp or apply default renaming
                for nick_re in nick_res:
                    if re.match(nick_re, nick):
                        break
                else:
                    if nick_res:
                        # regex is given but not matched, continue to the next node
                        continue

                # apply default renaming
                name = nick
                idx = name.find('_')
                if idx != -1:
                    name = name[idx+1:]
                val = filesByNick[nick]
                filesByNick2[name] = val

            elif nick_lres:
                # filter by label:regexp
                label = None
                for nick_lre in nick_lres:
                    label, nick_re = nick_lre.split(':')
                    if re.match(nick_re, nick):
                        break
                else:
                    if nick_lres:
                        # regex is given but not matched, continue to the next node
                        continue

                val = filesByNick[nick]
                filesByNick2[label] = val
            else:
                raise RuntimeError('unexpected options combination')

        if filesByNick2:
            filesByNick = filesByNick2

    return filesByNick

class MetricType(Enum):
    GAUGE = 0
    COUNTER = 1

    def __str__(self):
        return self.name.lower()

class Metric:
    """Metric with tags"""
    def __init__(self, metric_name: str, type: MetricType, desc: str, value: Union[int, float]):
        full_name = metric_name.strip()
        self.name = full_name
        self.value = value
        self.type = type
        self.desc = desc
        self.tags: Dict[str, str] = {}
        self.tag_keys: set = set()

        det_idx = self.name.find('{')
        if det_idx != -1:
            self.name = self.name[:det_idx]
            # ensure that the last character is '}'
            idx = full_name.index('}')
            if idx != len(full_name) - 1:
                raise ValueError(f'Invalid metric name: {full_name}')
            raw_tags = full_name[full_name.find('{')+1:full_name.find('}')]
            tags = raw_tags.split(',')
            for tag in tags:
                key, value = tag.split('=')
                if not value:
                    continue
                if value[0] == '"' and value[-1] == '"':
                    value = value[1:-1]
                self.tags[key] = value
                self.tag_keys.add(key)

    def short_name(self):
        return self.name

    def __str__(self):
        return self.string()

    def string(self, tags: Optional[set[str]]=None, with_role=False, quote=False) -> str:
        result = self.name

        if with_role:
            node = self.tags.get('n')
            if node:
                role = 'relay' if node.startswith('r') else 'npn' if node.startswith('npn') else 'node'
                self.add_tag('role', role)

        if self.tags or tags:
            if not tags:
                tags = self.tags
            esc = '"' if quote else ''
            result += '{' + ','.join([f'{k}={esc}{v}{esc}' for k, v in sorted(self.tags.items()) if k in tags]) + '}'
        return result

    def add_tag(self, key: str, value: str):
        self.tags[key] = value
        self.tag_keys.add(key)

    def has_tags(self, tags: Dict[str, Tuple[str, ...]], tag_keys: Set[str] | None) -> bool:
        """return True if all tags are present in the metric tags
        tag_keys are not strictly needed but used as an optimization
        """
        if tag_keys is not None and self.tag_keys.intersection(tag_keys) != tag_keys:
            return False
        for k, vals in tags.items():
            v = self.tags.get(k)
            if v not in vals:
                return False
        return True

def parse_metrics(
    fin: Iterable[str], nick: str, metrics_names: set=None, diff: bool=None
) -> Dict[str, List[Metric]]:
    """Parse metrics file and return dicts of metric names (no tags) and list of Metric objects
    each containing the metric name, value and tags.
    """
    out = {}
    try:
        last_type = None
        last_desc = None
        for line in fin:
            if not line:
                continue
            line = line.strip()
            if not line:
                continue
            if line[0] == '#':
                if line.startswith('# TYPE'):
                    tpe = line.split()[-1]
                    if tpe == 'gauge':
                        last_type = MetricType.GAUGE
                    elif tpe == 'counter':
                        last_type = MetricType.COUNTER
                elif line.startswith('# HELP'):
                    last_desc = line.split(None, 3)[-1]  # skip first 3 words (#, HELP, metric name)
                continue
            m = metric_line_re.match(line)
            if m:
                name = m.group(1)
                value = num(m.group(2))
            else:
                ab = line.split()
                name = ab[0]
                value = num(ab[1])

            metric = Metric(name, last_type, last_desc, value)
            metric.add_tag('n', nick)
            if not metrics_names or metric.name in metrics_names:
                if metric.name not in out:
                    out[metric.name] = [metric]
                else:
                    out[metric.name].append(metric)
    except:
        print(f'An exception occurred in parse_metrics: {sys.exc_info()}')
        pass
    if diff and metrics_names and len(metrics_names) == 2 and len(out) == 2:
        m = list(out.keys())
        name = f'{m[0]}_-_{m[1]}'
        metric = Metric(name, MetricType.GAUGE, f'Diff of {m[0]} and {m[1]}', out[m[0]][0].value - out[m[1]][0].value)
        out = {name: [metric]}

    return out

def parse_tags(tag_pairs: List[str]) -> Tuple[Dict[str, Tuple[str, ...]], Set[str]]:
    tags = {}
    keys = set()
    if not tag_pairs:
        return tags, keys

    for tag in tag_pairs:
        if '=' not in tag:
            raise ValueError(f'Invalid tag: {tag}')
        k, v = tag.split('=', 1)
        val = tags.get(k)
        if val is None:
            tags[k] = (v,)
        else:
            tags[k] = val + (v,)
        keys.add(k)

    return tags, keys