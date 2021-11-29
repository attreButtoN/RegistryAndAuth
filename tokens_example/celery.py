import os
from celery.schedules import crontab
from app import *
from celery import Celery
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tokens_example.settings')

app = Celery('app')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()


app.conf.beat_schedule = {
    'send-spam': {
        'task' : 'app.tasks.send_spam',
        'schedule': crontab(minute='*/1')
    },
}

