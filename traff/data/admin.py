from django.contrib import admin, messages

from .models import Protocol, Device, TrafficSummary, TrafficTest


class ProtocolAdmin(admin.ModelAdmin):
    list_display = ['code', 'name']


class DeviceAdmin(admin.ModelAdmin):
    list_display = ['name', 'ip']


class TrafficSummaryAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'device', 'dst', 'protocol', 'packets_count', 'packets_size']
    list_filter = ['device', 'protocol']
    date_hierarchy = 'timestamp'


class TrafficTestAdmin(admin.ModelAdmin):
    list_display = ['name', 'device', 'timestamp_start', 'timestamp_end', 'packets_count', 'packets_size']
    list_filter = ['device']
    date_hierarchy = 'timestamp_start'
    actions = ['do_calculate']

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
