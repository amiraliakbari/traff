import datetime
import sys

import pytz
from django.core.management.base import BaseCommand

from traff.data.models import Protocol, Device, TrafficSummary


def process_packet(timestamp, device, dst, protocol=None, is_tx=False, packet_size=0, icmp_type=None, dns_query=None, http_host=None, http_url=None):
    # Traffic summary
    protocol = Protocol.parse(protocol)
    summary = TrafficSummary.get(timestamp, device=device, dst=dst, protocol=protocol)
    if is_tx:
        summary.tx_packets += 1
        summary.tx_bytes += packet_size
    else:
        summary.rx_packets += 1
        summary.rx_bytes += packet_size

    # Update details
    detail1 = icmp_type or dns_query or http_host
    if detail1:
        summary.add_detail(1, detail1)
    detail2 = http_url
    if detail2:
        summary.add_detail(2, detail2)
    summary.save()


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        n_ok = 0
        n_exp = 0
        n_old = 0
        devices = set()
        try:
            for l in sys.stdin:
                a = l.strip().split(',')
                if len(a) < 12:
                    print('-', end='')
                    continue
                try:
                    timestamp = datetime.datetime.fromtimestamp(float(a[0]), pytz.utc)
                    packet_size = int(a[1])
                    protocol = a[2]
                    src = a[3] or '0.0.0.0'
                    dst = a[4] or '0.0.0.0'
                    icmp_type = a[7]
                    dns_query = a[10]
                    http_host = a[11]
                    http_url = a[12]

                    # Handle download/upload
                    src_is_local = src.startswith('10.')
                    dst_is_local = dst.startswith('10.')
                    if src_is_local and dst_is_local:
                        if src == '10.42.0.1':
                            device = Device.parse(dst)
                            dst = src
                            is_tx = False
                        else:
                            device = Device.parse(src)
                            is_tx = True
                    elif src_is_local:
                        device = Device.parse(src)
                        is_tx = True
                    elif dst_is_local:
                        device = Device.parse(dst)
                        dst = src
                        is_tx = False

                    # Check for already processed packets
                    if device.last_packet and timestamp < device.last_packet:
                        n_old += 1
                        print('_', end='')
                        continue
                    device.update_last_packet_time(timestamp)
                    devices.add(device)

                    # Process packet
                    process_packet(timestamp, device, dst, protocol=protocol, is_tx=is_tx, packet_size=packet_size, icmp_type=icmp_type, dns_query=dns_query, http_host=http_host, http_url=http_url)
                    n_ok += 1
                    print('.', end='')
                except Exception as e:
                    if isinstance(e, KeyboardInterrupt):
                        raise
                    print('!', end='')
                    n_exp += 1
        except KeyboardInterrupt:
            print('$')
        for device in devices:
            device.save(update_fields=['last_packet'])
        print('Done! Processed {} packets with {} errors and {} old packets.'.format(n_ok, n_exp, n_old))
