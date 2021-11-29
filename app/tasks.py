from .utils import Util
from tokens_example.celery import app


@app.task
def send_spam():
    email_body = "Hello"
    email = "denis.pivovarov.01@mail.ru"
    data = {'email_body': email_body, 'to_email':email,
            'email_subject': 'Receive that test message'}
    Util.send_email(data)
