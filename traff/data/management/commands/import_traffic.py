import datetime
import sys

import pytz
from django.core.management.base import BaseCommand

from traff.data.models import Protocol, Device, TrafficSummary


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
                    continue
                try:
                    timestamp = float(a[0])
                    packet_size = int(a[1])
                    protocol = a[2]
                    src = a[3] or '0.0.0.0'
                    dst = a[4] or '0.0.0.0'
                    icmp_type = a[7]
                    dns_query = a[10]
                    http_host = a[11]
                    http_url = a[12]

                    timestamp = datetime.datetime.fromtimestamp(timestamp, pytz.utc)
                    device = Device.parse(src)

                    # Check for already processed packets
                    if device.last_packet and timestamp < device.last_packet:
                        n_old += 1
                        continue
                    device.update_last_packet_time(timestamp)
                    devices.add(device)

                    # Traffic summary
                    protocol = Protocol.parse(protocol)
                    summary = TrafficSummary.get(timestamp, device=device, dst=dst, protocol=protocol)
                    summary.packets_count += 1
                    summary.packets_size += packet_size

                    # Update details
                    detail1 = icmp_type or dns_query or http_host
                    if detail1:
                        summary.add_detail(1, detail1)
                    detail2 = http_url
                    if detail2:
                        summary.add_detail(2, detail2)
                    summary.save()
                    n_ok += 1
                except:
                    print('!', a)
                    n_exp += 1
        except KeyboardInterrupt:
            pass
        for device in devices:
            device.save(update_fields=['last_packet'])
        print('Done! Processed {} packets with {} errors and {} old packets.'.format(n_ok, n_exp, n_old))
