# Generated by Django 3.1.6 on 2021-02-10 07:22

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('User', '0005_auto_20210210_1250'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otp',
            name='expiry_date',
            field=models.DateTimeField(default=datetime.datetime(2021, 2, 10, 7, 24, 34, 333192, tzinfo=utc)),
        ),
    ]
