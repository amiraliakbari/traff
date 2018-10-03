# Generated by Django 2.1.2 on 2018-10-03 08:05

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Device',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('ip', models.GenericIPAddressField(db_index=True, protocol='IPv4')),
            ],
        ),
        migrations.CreateModel(
            name='Protocol',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.CharField(db_index=True, max_length=255)),
                ('name', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='TrafficSummary',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(db_index=True)),
                ('dst', models.GenericIPAddressField(protocol='IPv4')),
                ('packets_count', models.BigIntegerField(default=0)),
                ('packets_size', models.BigIntegerField(default=0)),
                ('proto_details1', models.TextField(blank=True, null=True)),
                ('proto_details2', models.TextField(blank=True, null=True)),
                ('proto_details3', models.TextField(blank=True, null=True)),
                ('device', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='data.Device')),
                ('protocol', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='data.Protocol')),
            ],
        ),
    ]
