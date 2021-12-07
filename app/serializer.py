from rest_framework.response import Response
from rest_framework import serializers, status
from .models import *
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import serializers
# from . import google
# from .register_google import register_social_user as register_social_user
import os
from rest_framework.exceptions import AuthenticationFailed
from .utils import AccountUtils


class UserSerialier(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)

    default_error_messages = {
        'username': 'The username should only contain alphanumeric characters'}

    class Meta:
        model = User
        fields = ['email', 'username', 'password']

    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')
        # user_type = attrs.get('user_type', '')

        if not username.isalnum():
            raise serializers.ValidationError(
                self.default_error_messages)
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']


class UnFreezeAccountSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']


class PhoneVerifySerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["phone_number"]


class CodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["code_from_send_by_sms"]


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.CharField(max_length=255, min_length=3)
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(
        max_length=255, min_length=3, read_only=True)

    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        user = User.objects.get(email=obj['email'])

        return {
            'refresh': user.tokens()['refresh'],
            'access': user.tokens()['access']
        }

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        filtered_user_by_email = User.objects.filter(email=email)
        user = auth.authenticate(email=email, password=password)
        print(user)

        if user is None:
            filtered_user_by_email = User.objects.filter(phone_number=email).first()
            user = filtered_user_by_email
            if user is not None:
                if user.is_phone_verified == False:
                    raise AuthenticationFailed('Phone is not verified, verify your phone')
                email = filtered_user_by_email.email
                user = auth.authenticate(email=email, password=password)
                print(user)
                print(filtered_user_by_email)
        filtered_user_by_email = User.objects.filter(phone_number=email)

        if filtered_user_by_email.exists() and filtered_user_by_email[0].auth_provider != 'email':
            raise AuthenticationFailed(
                detail='Please continue your login using ' + filtered_user_by_email[0].auth_provider)

        if not user:
            user_id = User.objects.get(email=email).pk
            user = User.objects.get(email=email)
            if user.is_active == False:
                AccountUtils.unfreeze_account(user)
                raise AuthenticationFailed("Ваш аккаунт был заморожен, следуйте инструкциям отправленным на почту")

            AccountUtils.check_unsuccessful_tries(user_id)

            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')
        AccountUtils.clear_unsuccessful_tries(user)
        return {
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens
        }

        return super().validate(attrs)


class EditPhoneNumber(serializers.ModelSerializer):
    class Meta:
        model = User

        fields = ["phone_number"]


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):

        try:
            RefreshToken(self.token).blacklist()

        except TokenError:
            self.fail('bad_token')


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    # redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)


class ResetPasswordEmailSerializer(serializers.Serializer):
    # email = serializers.EmailField(required=True)
    id = serializers.IntegerField(required=True)
    verify_code = serializers.CharField(max_length=100, required=True)
    password = serializers.CharField(
        write_only=True,
        required=True,
        help_text="Leave empty if no change needed",
        style={"input_type": "password", "placeholder": "Password"},
    )
    # password = serializers.


class ResetPasswordByPhoneSerializer(serializers.Serializer):
    sms_code = serializers.CharField(
        required=True,
        help_text="Code from SMS",

    )
    phone_number = serializers.CharField(
        required=True,
        help_text="Hidden",

    )
    new_password = serializers.CharField(
        write_only=True,
        required=True,
        help_text="New Password",
        style={"input_type": "password", "placeholder": "Password"}
    )
    new_password_repeat = serializers.CharField(
        write_only=True,
        required=True,
        help_text="New Password",
        style={"input_type": "password", "placeholder": "Password"}
    )


class SendResetPasswordEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class SendResetPasswordSmsSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=11)


class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        help_text="Leave empty if no change needed",
        style={"input_type": "password", "placeholder": "Password"},
    )


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(
        write_only=True,
        required=True,
        help_text="Current Password",
        style={"input_type": "password", "placeholder": "Password"}
    )
    new_password = serializers.CharField(
        write_only=True,
        required=True,
        help_text="Current Password",
        style={"input_type": "password", "placeholder": "Password"}
    )
    new_password_repeat = serializers.CharField(
        write_only=True,
        required=True,
        help_text="Current Password",
        style={"input_type": "password", "placeholder": "Password"}
    )


class TagSerializer(serializers.ModelSerializer):
    tag = models.CharField(max_length=150, verbose_name="Теги")

    class Meta:
        model = Tag
        fields = (
            "id",
            "tag",
        )


class ArticleSerializer(serializers.ModelSerializer):
    # tag = TagSerializer(many=True)
    author = serializers.CharField()

    # title = serializers.CharField(max_length = 255)

    class Meta:
        model = Article
        fields = (
            "createdAt",
            "updatedAt",
            "id",
            "title",
            "description",
            "image",
            "author",
            "url",
            "tag",

        )

    # def save(self):
    #     user = CurrentUserDefault()  # <= magic!
    #     return user
    # filter_fields = "tag"

    # def create(self, validated_data):
    #     user = self.context.get('request').user
    #
    #
    #     print(user)
    #     user =user.email
    #     tag = validated_data.pop("tag")
    #
    #     new_data = Article.objects.create(**validated_data)
    #     new_data.tag.set(tag)
    #     new_data.author = user
    #     new_data.save()
    #     return new_data

# class GoogleSocialAuthSerializer(serializers.Serializer):
#     auth_token = serializers.CharField()
#
#     def validate_auth_token(self, auth_token):
#         user_data = google.Google.validate(auth_token)
#         try:
#             user_data['sub']
#         except:
#             raise serializers.ValidationError(
#                 'The token is invalid or expired. Please login again.'
#             )
#
#         if user_data['aud'] != os.environ.get('GOOGLE_CLIENT_ID'):
#
#             raise AuthenticationFailed('oops, who are you?')
#
#         user_id = user_data['sub']
#         email = user_data['email']
#         name = user_data['name']
#         provider = 'google'
#
#         return register_social_user(
#             provider=provider, user_id=user_id, email=email, name=name)
