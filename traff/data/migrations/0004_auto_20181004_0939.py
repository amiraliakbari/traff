# Generated by Django 2.1.2 on 2018-10-04 06:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('data', '0003_traffictest'),
    ]

    operations = [
        migrations.RenameField(
            model_name='trafficsummary',
            old_name='packets_count',
            new_name='rx_bytes',
        ),
        migrations.RenameField(
            model_name='trafficsummary',
            old_name='packets_size',
            new_name='rx_packets',
        ),
        migrations.RenameField(
            model_name='traffictest',
            old_name='packets_count',
            new_name='rx_bytes',
        ),
        migrations.RenameField(
            model_name='traffictest',
            old_name='packets_size',
            new_name='rx_packets',
        ),
        migrations.AddField(
            model_name='trafficsummary',
            name='tx_bytes',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='trafficsummary',
            name='tx_packets',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='traffictest',
            name='tx_bytes',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='traffictest',
            name='tx_packets',
            field=models.BigIntegerField(default=0),
        ),
    ]
