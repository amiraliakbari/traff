import pytz
from django.db import models


class Protocol(models.Model):
    code = models.CharField(max_length=255, db_index=True)
    name = models.CharField(max_length=255)

    _protocol_cache = {}

    def __str__(self):
        return self.name

    @property
    def is_dns(self):
        return self.code == 'dns'

    @property
    def is_http(self):
        return self.code == 'http'

    @classmethod
    def parse(cls, proto):
        # Normalize
        if ':ip:tcp:http:' in proto or proto.endswith(':ip:tcp:http'):
            proto = 'http'
        elif proto.endswith(':ip:tcp'):
            proto = 'tcp'
        elif ':ip:tcp:ssl:' in proto or proto.endswith(':ip:tcp:ssl'):
            proto = 'ssl'
        elif proto.endswith(':arp'):
            proto = 'arp'
        elif proto.endswith(':ip:udp'):
            proto = 'udp'
        elif ':ip:udp:dns:' in proto or proto.endswith(':ip:udp:dns'):
            proto = 'dns'
        # Get
        if proto not in cls._protocol_cache:
            try:
                protocol = cls.objects.get(code=proto)
            except cls.DoesNotExist:
                protocol = cls.objects.create(code=proto, name=proto)
            cls._protocol_cache[proto] = protocol
        return cls._protocol_cache[proto]


class Device(models.Model):
    name = models.CharField(max_length=255)
    ip = models.GenericIPAddressField(protocol='IPv4', db_index=True)
    last_packet = models.DateTimeField(blank=True, null=True)

    _device_cache = {}

    def __str__(self):
        return self.name

    def update_last_packet_time(self, timestamp):
        if not self.last_packet or self.last_packet < timestamp:
            self.last_packet = timestamp

    @classmethod
    def parse(cls, ip):
        if ip not in cls._device_cache:
            try:
                device = cls.objects.get(ip=ip)
            except cls.DoesNotExist:
                device = cls.objects.create(ip=ip, name=ip)
            cls._device_cache[ip] = device
        return cls._device_cache[ip]


class TrafficSummary(models.Model):
    timestamp = models.DateTimeField(db_index=True)
    device = models.ForeignKey(Device, on_delete=models.CASCADE, db_index=True)
    dst = models.GenericIPAddressField(protocol='IPv4')
    protocol = models.ForeignKey(Protocol, on_delete=models.CASCADE, db_index=True)
    # Stats
    packets_count = models.BigIntegerField(default=0)
    packets_size = models.BigIntegerField(default=0)
    # Details
    proto_details1 = models.TextField(blank=True, null=True)
    proto_details2 = models.TextField(blank=True, null=True)
    proto_details3 = models.TextField(blank=True, null=True)

    def get_detail(self, level):
        field = 'proto_details' + str(int(level))
        detail = getattr(self, field)
        if not detail:
            return set()
        return set(detail.split('\n'))

    def add_detail(self, level, detail):
        field = 'proto_details' + str(int(level))
        details = self.get_detail(level)
        if not isinstance(detail, list):
            detail = [detail]
        for dt in detail:
            dt = dt.replace('\n', '\t')
            if not dt:
                continue
            details.add(dt)
        setattr(self, field, '\n'.join(details).strip())

    @classmethod
    def get(cls, timestamp, device, dst, protocol):
        timestamp = timestamp.astimezone(pytz.timezone('Asia/Tehran')).replace(minute=0, second=0, microsecond=0)
        return cls.objects.get_or_create(
            timestamp=timestamp,
            device=device,
            dst=dst,
            protocol=protocol,
        )[0]


class TrafficTest(models.Model):
    name = models.CharField(max_length=255)
    device = models.ForeignKey(Device, on_delete=models.CASCADE, db_index=True)
    timestamp_start = models.DateTimeField(db_index=True)
    timestamp_end = models.DateTimeField(db_index=True)
    # Stats
    packets_count = models.BigIntegerField(default=0)
    packets_size = models.BigIntegerField(default=0)
    # Details
    dst_ips = models.TextField(blank=True, null=True)
    dns_queries = models.TextField(blank=True, null=True)
    http_hosts = models.TextField(blank=True, null=True)
    http_urls = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.name

    def calculate(self):
        summaries = TrafficSummary.objects.filter(timestamp__gte=self.timestamp_start, timestamp__lt=self.timestamp_end, device=self.device).select_related('protocol')
        packets_count = 0
        packets_size = 0
        dst_ips = set()
        dns_queries = set()
        http_hosts = set()
        http_urls = set()
        for s in summaries:
            packets_count += s.packets_count
            packets_size += s.packets_size
            dst_ips.add(s.dst)
            if s.protocol.is_dns:
                dns_queries |= s.get_detail(1)
            elif s.protocol.is_http:
                http_hosts |= s.get_detail(1)
                http_urls |= s.get_detail(2)
        self.packets_count = packets_count
        self.packets_size = packets_size
        self.dst_ips = '\n'.join(dst_ips)
        self.dns_queries = '\n'.join(dns_queries)
        self.http_hosts = '\n'.join(http_hosts)
        self.http_urls = '\n'.join(http_urls)
        self.save()
