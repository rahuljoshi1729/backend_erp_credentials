# Generated by Django 4.2.6 on 2023-11-27 17:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0015_examdataadmitresult_date'),
    ]

    operations = [
        migrations.CreateModel(
            name='eventsdata',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('event_name', models.CharField(max_length=100)),
                ('date', models.DateField(blank=True, null=True)),
                ('poster', models.URLField(blank=True, null=True)),
            ],
        ),
    ]
