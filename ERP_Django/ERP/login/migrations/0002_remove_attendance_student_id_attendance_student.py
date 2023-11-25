# Generated by Django 4.2.7 on 2023-11-24 23:14

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='attendance',
            name='student_id',
        ),
        migrations.AddField(
            model_name='attendance',
            name='student',
            field=models.ForeignKey(default=None, on_delete=django.db.models.deletion.CASCADE, related_name='attendance', to='login.student'),
        ),
    ]