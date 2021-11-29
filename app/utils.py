import string
from random import random
from django.core.mail import EmailMessage
import threading

from requests import Response
from rest_framework import status

from .smsc_api import SMSC
from .models import *
import random
import string


class EmailThread(threading.Thread):
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()


class Util:
    @staticmethod
    def send_email(data):
        print(data)
        email = EmailMessage(
            subject=data['email_subject'], body=data['email_body'], to=[data['to_email']])
        EmailThread(email).start()


class AccountUtils:
    @staticmethod
    def get_tokens_for_user(user):
        refresh = RefreshToken.for_user(user)

        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }


class PhoneUtil:
    @staticmethod
    def create_code(request, user):
        codes_model = ModelForCodes()
        SMS_CODE_LEN = 6
        code_m = ModelForCodes.objects.filter(user_id=user.id).first()
        if code_m is None:
            code = ''.join(random.choices(string.digits, k=SMS_CODE_LEN))
            codes_model.code = code
            codes_model.user_id = user.id
            codes_model.save()
        else:
            code = code_m.code

        return code

    # def create_code_recovery(request,user):
    #     codes_model = ModelForSMSRecovery()
    #     SMS_CODE_LEN = 9
    #     phone_number = user.phone_number
    #     code_m = ModelForSMSRecovery.objects.filter(phone_number = phone_number).first()
    #     if code_m is None:
    #         code = ''.join(random.choices(string.digits, k=SMS_CODE_LEN))
    #         codes_model.code = code
    #         codes_model.phone_number = phone_number
    #         codes_model.save()
    #     return code
    @staticmethod
    def send_verification_sms(request, code, user):
        user_by_phone = user
        user = request.user
        user = User.objects.get(id=user.pk)

        phone_number = request.POST.get("phone_number")
        sender = SMSC(SMSC.login, SMSC.password)
        sender.send_sms(f'7{phone_number}', f'Код подтверждения: {code} ,Nigger', sender='Sender')
        user.phone_number = phone_number
        user.save()
        return phone_number

    @staticmethod
    def delete_used_sms(request, code_model, user):
        code_model.delete()
        user.is_phone_verified = True
        user.save()

    @staticmethod
    def delete_used_recovery_sms(code_model):
        code_model.delete()
