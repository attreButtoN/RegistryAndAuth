# Generated by Django 3.2.9 on 2021-11-24 11:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0003_remove_user_login_field'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='login',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]