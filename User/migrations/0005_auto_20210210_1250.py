# Generated by Django 3.1.6 on 2021-02-10 07:20

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('User', '0004_auto_20210210_1248'),
    ]

    operations = [
        migrations.AlterField(
            model_name='otp',
            name='expiry_date',
            field=models.DateTimeField(default=datetime.datetime(2021, 2, 10, 10, 20, 19, 264288, tzinfo=utc)),
        ),
        migrations.AlterField(
            model_name='otp',
            name='id',
            field=models.CharField(max_length=500, primary_key=True, serialize=False),
        ),
    ]
