# Generated by Django 4.2.6 on 2023-11-27 08:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0014_examdataadmitresult_exam_name'),
    ]

    operations = [
        migrations.AddField(
            model_name='examdataadmitresult',
            name='date',
            field=models.DateField(blank=True, null=True),
        ),
    ]