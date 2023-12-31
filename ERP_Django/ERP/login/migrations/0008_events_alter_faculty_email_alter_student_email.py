# Generated by Django 4.2.6 on 2023-11-26 09:02

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0007_alter_attendance_student_id'),
    ]

    operations = [
        migrations.CreateModel(
            name='events',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('exam_name', models.CharField(max_length=100)),
                ('total_marks', models.IntegerField()),
                ('date', models.DateField(blank=True, null=True)),
                ('admit_card', models.URLField(blank=True, null=True)),
                ('result', models.URLField(blank=True, null=True)),
            ],
        ),
        migrations.AlterField(
            model_name='faculty',
            name='email',
            field=models.EmailField(max_length=254, unique=True, validators=[django.core.validators.RegexValidator(message='Email must end with akgec.ac.in', regex='.*akgec\\.ac\\.in$')]),
        ),
        migrations.AlterField(
            model_name='student',
            name='email',
            field=models.EmailField(max_length=254, unique=True, validators=[django.core.validators.RegexValidator(message='Email must end with akgec.ac.in', regex='.*akgec\\.ac\\.in$')]),
        ),
    ]
