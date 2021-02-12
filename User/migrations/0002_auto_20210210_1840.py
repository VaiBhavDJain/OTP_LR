# Generated by Django 3.1.6 on 2021-02-10 13:10

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('User', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='first_name',
            field=models.CharField(max_length=15),
        ),
        migrations.AlterField(
            model_name='user',
            name='last_name',
            field=models.CharField(max_length=15),
        ),
        migrations.AlterField(
            model_name='user',
            name='password',
            field=models.CharField(max_length=100, validators=[django.core.validators.RegexValidator('[A-Za-z0-9@#$%^&+=]{8,}', message='The password must contain at least one in  A-Z and a-z, 0-9 and special character.')]),
        ),
    ]
