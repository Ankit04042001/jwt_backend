# Generated by Django 4.2 on 2023-04-20 04:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0004_alter_user_managers'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='first_name',
            field=models.CharField(default='rahul', max_length=50),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='user',
            name='last_name',
            field=models.CharField(default='singh', max_length=50),
            preserve_default=False,
        ),
    ]
