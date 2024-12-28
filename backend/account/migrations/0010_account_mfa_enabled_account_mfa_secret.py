# Generated by Django 5.1.2 on 2024-12-11 14:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0009_account_avatar'),
    ]

    operations = [
        migrations.AddField(
            model_name='account',
            name='mfa_enabled',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='account',
            name='mfa_secret',
            field=models.CharField(blank=True, max_length=16, null=True),
        ),
    ]
