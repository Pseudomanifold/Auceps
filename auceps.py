#!/usr/bin/env python3
#
# auceps.py: a tool for analysing log files and checking, who is up to
# nefarious things.


import argparse
import time


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
