import uuid

import jwt
from django.conf import settings
from django.db.models import Q
from drf_yasg import openapi
from rest_framework.generics import GenericAPIView

from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from copy import deepcopy

from .filters import TagsFilter
from .serializer import *
from drf_yasg.utils import swagger_auto_schema
from rest_framework import generics, status, views, permissions
from django_filters.rest_framework import DjangoFilterBackend
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util, PhoneUtil, AccountUtils
from .watermark import image_watermark, text_watermark
from django.http import HttpResponsePermanentRedirect
import os
from .renderers import *
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

ALLOWED_ALGORITHMS = (
    'HS256',
    'HS384',
    'HS512',
    'RS256',
    'RS384',
    'RS512',
)


class CustomRedirect(HttpResponsePermanentRedirect):
    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer,)
    permission_classes = [AllowAny]

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify')
        absurl = 'http://' + current_site + relativeLink + "?token=" + str(token)
        email_body = 'Hello ' + user.username + \
                     'use that link to verify your account \n' + absurl
        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Verify your email'}

        Util.send_email(data)
        return Response(user_data, status=status.HTTP_201_CREATED)
    def get(self,requset):
        data = requset.data
        serializer = self.serializer_class(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        data = serializer.data
        return Response(data)



class UnFreeze(APIView):
    serializer_class = UnFreezeAccountSerializer
    permission_classes = [AllowAny]

    def get(self, request):
        token = request.GET.get(str('token'))
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms="HS256")
        user = User.objects.get(id=payload['user_id'])
        try:
            if not user.is_active:
                user.is_active = True
                user.save()
                AccountUtils.clear_unsuccessful_tries(user)
            else:
                return Response({"Аккаунт не заморожен"})
            return Response({'email': 'Аккаунт разморожен'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer
    permission_classes = [permissions.AllowAny]
    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get(str('token'))
        print(token)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms="HS256")
        user = User.objects.get(id=payload['user_id'])
        try:
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class EditUserAuthData(views.APIView):
    serializer_class = EditPhoneNumber
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):

        user = request.user
        if user.phone_number is not None:
            return Response(status=status.HTTP_400_BAD_REQUEST, data={"Error": "Данный функционал не готов"})
        else:
            user.phone_number = request.GET.get("phone_number")
            user.save()


class SendVerificationCode(views.APIView):
    serializer_class = PhoneVerifySerializer

    def put(self, request):
        user = request.user
        code = PhoneUtil.create_code(request, user)
        phone_number = PhoneUtil.send_verification_sms(request, code, user)

        return Response(f'Код был отправлен на номер: 7{phone_number}', status=status.HTTP_200_OK)


class VerifyPhone(views.APIView):
    serializer_class = CodeSerializer

    def post(self, request):
        user = request.user
        input_code = request.data.get("code_from_send_by_sms")
        try:
            code_model = ModelForCodes.objects.get(user_id=user.pk)
        except:
            return Response(status=status.HTTP_404_NOT_FOUND, data={"code error": "Код не найден"})
        if code_model is not None:
            if code_model.code == input_code:
                PhoneUtil.delete_used_sms(request, code_model, user)
                return Response({'number': 'Successfully activated'}, status=status.HTTP_200_OK)
            else:
                return Response(status=status.HTTP_400_BAD_REQUEST, data={"code error": "Неверный код"})


class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer

    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)


class SendMailForgotPasswordView(APIView):
    permission_classes = [AllowAny]
    serializer_class = SendResetPasswordEmailSerializer

    def post(self, request, *args, **kwargs):
        print(request.data)
        user = User.objects.filter(email=request.data.get("email")).first()
        if user is None:
            return Response(
                data={"error send mail": "user does not exist"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        current_site = get_current_site(
            request=request).domain
        verify_code = uuid.uuid4().hex
        UserResetPasswordCode.objects.create(user_id=user.pk, verify_code=verify_code)
        url_confirm = (
            f'http://{current_site}/email-reset-password/?verify_code={verify_code}&id={user.pk}'
        )
        email_body = f'{user.username}, \nПерейдите по ссылке ниже чтобы сбросить пароль  \n' + url_confirm
        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Сброс пароля'}
        Util.send_email(data)
        return Response(data={"status": f"Сообщение отправлено на почту: {user.email}"}, status=status.HTTP_200_OK)


class SendSmsForgotPasswordView(APIView):
    permission_classes = [AllowAny]
    serializer_class = SendResetPasswordSmsSerializer

    def post(self, request):
        user = User.objects.filter(phone_number=request.data.get("phone_number")).first()
        print(user)
        code = PhoneUtil.create_code(request, user)
        phone_number = PhoneUtil.send_verification_sms(request, code, user)

        return Response(f'Код был отправлен на номер: 7{phone_number}', status=status.HTTP_200_OK)


class ForgotPasswordRecoveryBySMSView(APIView):
    permission_classes = [AllowAny]
    serializer_class = ResetPasswordByPhoneSerializer

    def post(self, request):
        # input_code = request.data.get("code_from_send_by_sms")
        try:


            input_code = request.data.get("sms_code")
            # print(input_code)
            code_model = ModelForCodes.objects.get(code=input_code)
            print(code_model)

        except Exception as ex:
            phone_number = request.data.get("phone_number")
            user = User.objects.filter(phone_number = phone_number).first()
            AccountUtils.check_unsuccessful_tries(user.pk)
            code_model_true = ModelForCodes.objects.filter(user_id=user.pk).first()
            model = UnsuccessfulTries.objects.filter(user_id=user.pk).first()

            if model.tries >=3:
                AccountUtils.clear_unsuccessful_tries(user)
                PhoneUtil.delete_used_recovery_sms(code_model_true)
                return Response(data = {"Code deleated, try again"},status =status.HTTP_400_BAD_REQUEST)
            # code_model.save()
            return Response(status=status.HTTP_404_NOT_FOUND, data={"Error": f"You're invalid insert code correctly, you have {3-code_model_true.tries} chances until cod delete"})
        if code_model is not None:
            if code_model.code == input_code:
                new_password = request.data.get("new_password")
                new_password_repeat = request.data.get("new_password_repeat")
                if new_password == new_password_repeat:
                    PhoneUtil.delete_used_recovery_sms(code_model)
                    user = User.objects.filter(id=code_model.user_id).first()
                    user.set_password(new_password)
                    user.save()
                    return Response({'Success': 'Password Changed'}, status=status.HTTP_200_OK)
                else:
                    return Response({"Password Fields have differences"}, status=status.HTTP_400_BAD_REQUEST)
            else:
                if code_model.tries >=3:
                    PhoneUtil.delete_used_recovery_sms(code_model)
                    return Response(status=status.HTTP_403_FORBIDDEN,data={"Ошибка":"Превышен лимит неправильных вводов"})
                else:
                    code_model.tries+=1
                    code_model.save()
                return Response(status=status.HTTP_400_BAD_REQUEST, data={"code error": "Неверный код"})


class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]
    serializer_class = ResetPasswordEmailSerializer

    def post(self, request, *args, **kwargs):

        id_user = request.data.get("id")
        verify_code = request.data.get("verify_code")
        password = request.data.get("password")

        if id_user is None or verify_code is None or password is None:
            return Response(
                data={"confirmation error": "required id field is missing"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if str(id_user).isdigit() is False:
            return Response(
                data={"confirmation error": "required id field is missing"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        verify_object = UserResetPasswordCode.objects.filter(
            Q(user_id=id_user) & Q(verify_code=verify_code)
        ).first()

        if verify_object is None:
            return Response(
                data={"confirmation error": "id or verify_code is incorrect"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        else:
            verify_object.delete()
            user = User.objects.filter(pk=id_user).first()
            if user:
                user.set_password(password)
                user.save()
                tokens = AccountUtils.get_tokens_for_user(user)
                return Response(tokens, status=status.HTTP_200_OK)
            else:
                return Response(
                    data={"confirmation error": "required id field is missing"},
                    status=status.HTTP_400_BAD_REQUEST,
                )


class ChangePassword(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        user = request.user
        password = request.data.get("current_password")
        new_password = request.data.get("new_password")
        repeat_new_password = request.data.get("new_password_repeat")

        if not user.check_password(password):
            return Response(data={"Error": "Wrong password"}, status=status.HTTP_400_BAD_REQUEST)
        if new_password != repeat_new_password:
            return Response(data={"Error": "New Passwords fields have differences"})
        user.set_password(new_password)
        user.save()
        return Response({"Password changed"}, status=status.HTTP_200_OK)


class CreateTag(APIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = Tag.objects.all()
    serializer_class = TagSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def get(self, request):
        data = Tag.objects.all()
        tag = TagSerializer(data, many=True)
        return Response(tag.data)


class CreateRetrieveArticle(APIView):
    permission_classes = [permissions.IsAuthenticated]
    queryset = Article.objects.all()
    serializer_class = ArticleSerializer
    filter_backends = [DjangoFilterBackend]  # rest_filters.SearchFilter)
    filterset_class = TagsFilter

    def post(self, request):
        user = request.user
        data = request.data
        request.data._mutable = True
        # request.data  ["image"] = image_watermark(request)\
        url = request.data["url"]
        image = request.data["image"]
        # image_watermark(str(image))
        request.data['author'] = user.email
        print(request.data['author'])
        request.data._mutable = False
        serializer = ArticleSerializer(
            data=data)
        print(data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()

            text_watermark(image)

            return Response({"Success": "Article Created"}, status=status.HTTP_201_CREATED)
        else:
            return Response(data=serializer.data, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        data = Article.objects.all()
        print(data)
        articles = ArticleSerializer(data, many=True)
        return Response(articles.data)


class UserData(APIView):
    queryset = User.objects.all()
    serializer_class = UserSerialier

    def get(self, request):
        user_data = UserSerialier(
            User.objects.filter(pk=self.request.user.pk).first()
        )
        return Response(data=user_data.data, status=status.HTTP_200_OK)


class DestroyUpdateArticle(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ArticleSerializer

    def delete(self, request, pk, format=None):
        pk = self.kwargs['pk']
        user = request.user
        article = Article.objects.filter(pk=pk).first()

        if article.author != user.email:
            return Response(data={"Access denied"}, status=status.HTTP_403_FORBIDDEN)

        else:
            article.delete()
            return Response(data={"Deleted"}, status=status.HTTP_200_OK)

    def put(self, request, pk, format=None):
        pk = self.kwargs['pk']
        user = request.user
        article = Article.objects.filter(pk=pk).first()
        # article.tag = request.POST.get('tag', False)
        # article.tag.set(request.POST.get('tag'))

        if article.author != user.email:

            return Response(data={"Access denied"}, status=status.HTTP_403_FORBIDDEN)
        else:
            # article = ArticleSerializer(request.data)
            serializer = ArticleSerializer(
                article, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(data=serializer.data, status=status.HTTP_200_OK)
            else:
                return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, pk):
        pk = self.kwargs['pk']
        article_data = ArticleSerializer(
            Article.objects.filter(pk=pk).first()
        )
        return Response(data=article_data.data, status=status.HTTP_200_OK)

# class GoogleSocialAuthView(GenericAPIView):
#
#     serializer_class = GoogleSocialAuthSerializer
#
#     def post(self, request):
#         """
#         POST with "auth_token"
#         Send an idtoken as from google to get user information
#         """
#
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         data = ((serializer.validated_data)['auth_token'])
#         return Response(data, status=status.HTTP_200_OK)
