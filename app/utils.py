import os
import string
import uuid
from random import random

from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
import threading

from requests import Response
from rest_framework import status

from .smsc_api import SMSC
from .models import *
import random
import string
DOMAIN = os.getenv('DOMAIN')


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
    @staticmethod
    def unfreeze_account(user):
        current_site = DOMAIN
        token = RefreshToken.for_user(user).access_token
        url_confirm = (
            f'http://{current_site}/unfreeze/?token={token}&id={user.pk}'
        )
        email_body = f"Use link to unfreeze \n {url_confirm}"

        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Account Freezed'}
        Util.send_email(data)
    @staticmethod
    def freeze_account(user_id):
        user = User.objects.filter(pk=user_id).first()
        user.is_active = False
        user.save()
        email_body = "Осторожно, ваш аккаунт был заморожен, было произведено более трех попыток ввода неправильного " \
                     "пароля" \
                     "\nДля разморозки аккаунта авторизуйтесь, после чего вам будет направлена инструкция для " \
                     "разморозки " \
                     "аккаунта"
        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Аккаунт был заморожен'}
        Util.send_email(data)

    @staticmethod
    def clear_unsuccessful_tries(user):
        model = UnsuccessfulTries.objects.filter(user_id=user.pk).first()
        model.tries = 0
        model.save()

    @staticmethod
    def check_unsuccessful_tries(user_id):
        model = UnsuccessfulTries.objects.filter(user_id=user_id).first()
        if model is None:
            print("In None")
            model_m = UnsuccessfulTries()
            model_m.user_id = user_id
            model_m.tries = 0
            model_m.save()
            model = UnsuccessfulTries.objects.filter(user_id=user_id).first()
            model.tries = model.tries + 1
            model.save()

        else:
            if model.tries >= 5:
                AccountUtils.freeze_account(user_id)
            else:
                model.tries = model.tries + 1
                print(model.tries)
                model.save()
                return model.tries


class PhoneUtil:
    @staticmethod
    def create_code(request, user):
        print(user)
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
        print(user)
        user = User.objects.filter(id=user.pk).first()
        print(user)
        phone_number = request.POST.get("phone_number")
        user = User.objects.filter(phone_number=phone_number).first()
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
