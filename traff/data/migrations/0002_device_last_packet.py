# Generated by Django 2.1.2 on 2018-10-03 09:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('data', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='last_packet',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
