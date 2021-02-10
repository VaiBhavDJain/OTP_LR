# Generated by Django 3.1.6 on 2021-02-10 07:04

import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
from django.utils.timezone import utc


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='OTP',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('transaction', models.CharField(max_length=200)),
                ('amount', models.IntegerField(default=0)),
                ('recipient', models.CharField(default='08012345678', max_length=15)),
                ('description', models.CharField(default='Order', max_length=100)),
                ('status', models.CharField(default='Pending', max_length=100)),
                ('date', models.DateTimeField(auto_now_add=True)),
                ('expiry_date', models.DateTimeField(default=datetime.datetime(2021, 2, 10, 10, 4, 54, 61974, tzinfo=utc))),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
