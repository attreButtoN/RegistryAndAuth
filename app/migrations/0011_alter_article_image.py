# Generated by Django 3.2.9 on 2021-12-02 08:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0010_alter_modelforcodes_tries'),
    ]

    operations = [
        migrations.AlterField(
            model_name='article',
            name='image',
            field=models.FileField(blank=True, upload_to='image/%Y/%m/%d', verbose_name='Изображение'),
        ),
    ]
