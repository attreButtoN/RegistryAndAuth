# Generated by Django 3.2.9 on 2021-12-01 12:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0009_auto_20211130_1543'),
    ]

    operations = [
        migrations.AlterField(
            model_name='modelforcodes',
            name='tries',
            field=models.IntegerField(default=0),
        ),
    ]