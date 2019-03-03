#!/usr/bin/env python3
#
# auceps.py: a tool for analysing log files and checking, who is up to
# nefarious things.


import argparse
import collections
import geolite2
import time
import re


class LogEntry:
    '''
    Represents a log entry. This is just for convenience purposes.
    '''

    def __init__(self, timestamp, process, message):
        self.timestamp = timestamp
        self.process = process
        self.message = message

    def __repr__(self):
        return f'{self.timestamp}: {self.process}: {self.message}'


def parse_process(process):
    '''
    Parses the process field, which is of the form 'name[PID]'. We are
    not interested in any PIDs, though.
    '''

    return process[:process.find('[')]


def parse_log(filename):
    '''
    Performs simple log parsing. Returns a time stamp entry, a program
    type, and a message for each entry.

    :param filename: Input filename
    :return: List of parsed tuples
    '''

    entries = []

    with open(filename) as f:
        for line in f:
            fields = line.split(' ')

            timestamp = ' '.join(fields[:3])
            hostname = fields[3]  # we ignore this, but at least all fields
                                  # are accounted for now
            process = parse_process(fields[4])
            message = ' '.join(fields[5:])
            entry = LogEntry(timestamp, process, message)

            entries.append(entry)

    return entries


def might_be_nefarious(entry):
    '''
    Checks whether a log entry might be nefarious. A nefarious entry is
    an entry that comes from `ssh`, and contains *either* invalid login
    names, or an invalid password.
    '''

    failed_password = entry.message.startswith('Failed password')
    return entry.process == 'sshd' and failed_password


def get_ip_addresses(entries):
    '''
    Collects IP addresses that are involved in potentially nefarious
    things. This functions returns a `collections.Counter()` object,
    which permits further statistical insights.
    '''

    addresses = collections.Counter()
    re_addr = '.*from\s+([0-9\.]+)\s+.*'

    for entry in entries:
        message = entry.message
        match = re.match(re_addr, message)

        if match:
            address = match.group(1)
            addresses[address] += 1

    return addresses


def get_countries(addresses):
    '''
    Given a collection with IP addresses, looks up their countries and
    creates a new counter object.
    '''

    reader = geolite2.geolite2.reader()
    countries = collections.Counter()

    for address in addresses:
        data = reader.get(address)
        if data:
            if 'registered_country' in data.keys():
                country = data['registered_country']
            elif 'country' in data.keys():
                country = data['country']
            else:
                print(f'Unable to query IP address {address}')
                continue
            name = country['names']['en']
            iso_code = country['iso_code']
            country = f'{name} ({iso_code})'

            countries[country] += addresses[address]

    return countries


def get_names(entries):
    '''
    Gets user names for valid and invalid users and returns two
    counters.
    '''

    valid_users = collections.Counter()
    invalid_users = collections.Counter()

    for entry in entries:
        if 'invalid user' in entry.message:
            username = entry.message.replace(
                'Failed password for invalid user ', ''
            )
            username = username.split(' ')[0]

            invalid_users[username] += 1
        else:
            username = entry.message.replace(
                'Failed password for ', ''
            )
            username = username.split(' ')[0]

            valid_users[username] += 1

    return valid_users, invalid_users


def print_names(title, counter, n):

    print(title, '\n')

    m = sum(counter.values())
    for name, count in counter.most_common(n):
        print('- {} ({:2.2f})'.format(name, 100 * count / m))

    print('')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('INPUT', nargs='+', help='Input files')

    args = parser.parse_args()
    entries = []

    for filename in args.INPUT:
        entries.extend(parse_log(filename))

    print(f'Processed {len(entries)} log entries')

    entries = list(filter(might_be_nefarious, entries))

    print(f'After filtering, {len(entries)} log entries remain')

    addresses = get_ip_addresses(entries)
    countries = get_countries(addresses)
    valid_users, invalid_users = get_names(entries)

    print_names('Persistent addresses', addresses, 10)

    # FIXME: make output path configurable
    with open('/tmp/countries.csv', 'w') as f:
        print('name,code,count', file=f)
        for country in countries:
            re_country = r'(.*)\s+\((.*)\)$'
            match = re.match(re_country, country)

            assert match

            name = match.group(1)
            code = match.group(2)
            count = countries[country]

            print(f'{name},{code},{count}', file=f)

    print_names('Valid users', valid_users, 10)
    print_names('Invalid users', invalid_users, 10)
