# Generated by Django 4.2.6 on 2023-11-26 10:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0013_examdataadmitresult_remove_exam_result'),
    ]

    operations = [
        migrations.AddField(
            model_name='examdataadmitresult',
            name='exam_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]