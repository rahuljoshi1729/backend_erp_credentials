# Generated by Django 4.2.6 on 2023-11-27 21:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0019_timetabledata'),
    ]

    operations = [
        migrations.AlterField(
            model_name='timetabledata',
            name='time_table_url',
            field=models.URLField(blank=True, null=True),
        ),
    ]
