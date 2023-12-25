#!/usr/bin/env python3
import sys
from socket import inet_aton
import argparse
import enum
import v2ray.config_pb2 as config_pb2


class OutputType(enum.Enum):
    GeoSite = 'geosite'
    GeoIP = 'geoip'


def process_ip_input(geoiplist, input_file, country_code):
    geoip = geoiplist.entry.add()
    geoip.country_code = country_code
    data_processed = False
    for line in input_file:
        line = line.strip()
        if line.startswith('#'):
            continue
        network, prefix = line.split('/')
        cidr = geoip.cidr.add()
        cidr.prefix = int(prefix)
        cidr.ip = inet_aton(network)
        data_processed = True
    if not data_processed:
        raise RuntimeError('empty input')


def process_site_input(geositelist, input_file, country_code):
    geosite = geositelist.entry.add()
    geosite.country_code = country_code
    data_processed = False
    for line in input_file:
        line = line.strip()
        if line.startswith('#'):
            continue
        domain = geosite.domain.add()
        if ':' not in line:
            domain.type = 0    # substring
            domain.value = line
        else:
            type, value = line.split(':', 1)
            if type == 'regexp':
                domain.type = 1
            elif type == 'domain':
                domain.type = 2
            else:
                raise RuntimeError('Unknwon domain format: {} in file {}'.format(type, input_file))
            domain.value = value
        data_processed = True
    if not data_processed:
        raise RuntimeError('empty input')
        

def main():
    parser = argparse.ArgumentParser(description='Generate V2Ray\'s geoip.dat and geosite.dat file.')
    parser.add_argument('-i', '--input', nargs=2, action='append', metavar=('input_file', 'country_code'), help='input file and country code')
    parser.add_argument('type', help='output file type (geosite or geoip)')
    parser.add_argument('output', help='output file path')
    args = parser.parse_args()

    output_type = OutputType(args.type)
    if not args.input:
        raise RuntimeError('You need to specify at least 1 input.')
    if output_type == OutputType.GeoSite:
        geolist = config_pb2.GeoSiteList()
        process_input = process_site_input
    elif output_type == OutputType.GeoIP:
        geolist = config_pb2.GeoIPList()
        process_input = process_ip_input

    for input_file, country_code in args.input:
        if input_file == '-':
            input_file = sys.stdin
        else:
            input_file = open(input_file, 'r')
        process_input(geolist, input_file, country_code)
    if args.output == '-':
        output_file = sys.stdout.buffer
    else:
        output_file = open(args.output, 'wb')
    output_file.write(geolist.SerializeToString())


if __name__ == '__main__':
    main()

