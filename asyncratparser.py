#!/usr/bin/env python3
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from logging import getLogger, basicConfig, DEBUG, WARNING, ERROR, INFO, Formatter, StreamHandler
from sys import stderr,stdout, version_info, exit

from asyncrat_cfg_parser import AsyncRATConfigParser

logger = getLogger('asyncratparser')

if __name__ == '__main__':
    argp = ArgumentParser(prog='asyncratparser.py',
      formatter_class=RawDescriptionHelpFormatter,
      description='Parses configuration of AsyncRAT malware client as JSON.')
    argp.add_argument('filepath', nargs='+', help='one or more AsyncRAT payload filepaths')
    argp.add_argument('-c', '--parse-cert', action='store_true', help='return parsed certificate instead of base64 string')
    argp.add_argument('-d', '--debug', action='store_true', help='enable debug logging')   
    args = argp.parse_args()

    basicConfig(format='%(created)f:%(levelname)s:%(name)s:%(module)s: %(message)s',level=DEBUG if args.debug else WARNING)

    this_python = version_info[:2]
    min_version = (3, 8)
    if this_python < min_version:
        message_parts = [
                'This script does not work on Python {}.{}.'.format(*this_python),
                'Please upgrade to the minimum supported version {}.{}.'.format(*min_version),
        ]
        logger.error(' '.join(message_parts))
        exit(1)
    
    for filepath in args.filepath:
        try:
            parser = AsyncRATConfigParser(filepath)
            result = parser.report(args.parse_cert)
            if result: 
                print(result)
        except:
            logger.exception(f'Exception for {filepath}', exc_info=True)
            continue
    
