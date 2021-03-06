# Generated by Django 3.2.9 on 2021-11-30 15:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0008_unsuccessfultries'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserUnfreezeCode',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_id', models.CharField(max_length=255)),
                ('verify_code', models.CharField(max_length=100)),
            ],
        ),
        migrations.AddField(
            model_name='modelforcodes',
            name='tries',
            field=models.ImageField(default=0, upload_to=''),
        ),
    ]
