from django.contrib import admin, messages

from .models import Protocol, Device, TrafficSummary, TrafficTest


class ProtocolAdmin(admin.ModelAdmin):
    list_display = ['code', 'name']


class DeviceAdmin(admin.ModelAdmin):
    list_display = ['name', 'ip']


class TrafficSummaryAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'device', 'dst', 'protocol', 'rx_packets', 'rx_bytes', 'tx_packets', 'tx_bytes']
    list_filter = ['device', 'protocol']
    date_hierarchy = 'timestamp'


class TrafficTestAdmin(admin.ModelAdmin):
    list_display = ['name', 'device', 'timestamp_start', 'timestamp_end', 'rx_packets', 'rx_bytes', 'tx_packets', 'tx_bytes', 'dst_ips_count', 'dns_queries_count', 'http_hosts_count', 'https_hosts_count']
    list_filter = ['device']
    date_hierarchy = 'timestamp_start'
    actions = ['do_calculate']

    def dst_ips_count(self, obj):
        return (obj.dst_ips).count('\n')

    def dns_queries_count(self, obj):
        return (obj.dns_queries).count('\n')

    def http_hosts_count(self, obj):
        return (obj.http_hosts).count('\n')

    def https_hosts_count(self, obj):
        return (obj.https_hosts).count('\n')

    def do_calculate(self, request, queryset):
        affected = 0
        for t in queryset:
            t.calculate()
            affected += 1
        self.message_user(
            request,
            '{} Traffic Test Results Calculated!'.format(affected),
            level=messages.SUCCESS,
        )

    do_calculate.short_description = 'Calculate Results'


admin.site.register(Protocol, ProtocolAdmin)
admin.site.register(Device, DeviceAdmin)
admin.site.register(TrafficSummary, TrafficSummaryAdmin)
admin.site.register(TrafficTest, TrafficTestAdmin)
