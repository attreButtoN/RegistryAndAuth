from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin)

from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken


class UserManager(BaseUserManager):

    def create_user(self, username, email, password=None):
        if username is None:
            raise TypeError('Users should have a username')
        if email is None:
            raise TypeError('Users should have a Email')

        user = self.model(username=username, email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, email, password=None):
        if password is None:
            raise TypeError('Password should not be none')

        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


AUTH_PROVIDERS = {'email': 'email'}


class User(AbstractBaseUser, PermissionsMixin):
    # login = models.CharField(max_length=255,blank=True,null=True)
    username = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    phone_number = models.CharField(max_length=10)
    code_from_send_by_sms = models.CharField(max_length=6, help_text="6-и значный код подтверждения")
    is_verified = models.BooleanField(default=False)
    is_phone_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    auth_provider = models.CharField(
        max_length=255, blank=False,
        null=False, default=AUTH_PROVIDERS.get('email'))

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.email

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }


class ModelForCodes(models.Model):
    user_id = models.CharField(max_length=255)
    code = models.CharField(max_length=6)


class ModelForSMSRecovery(models.Model):
    phone_number = models.CharField(max_length=10)

    code_from_send_by_sms = models.CharField(max_length=6, help_text="6-и значный код подтверждения")


class UserResetPasswordCode(models.Model):
    user_id = models.CharField(max_length=255)
    verify_code = models.CharField(max_length=100)


class Tag(models.Model):
    tag = models.CharField(max_length=150, verbose_name="Теги")


    def __str__(self):
        return self.tag


class Article(models.Model):

    createdAt = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Дата создания",
        editable=False,

    )
    updatedAt = models.DateTimeField(
        auto_now=True,
        verbose_name="Дата обновления"
    )
    title = models.CharField(max_length=150, blank=False, verbose_name="Название")
    description = models.CharField(max_length=150, verbose_name="Описание")
    image = models.ImageField(
        upload_to="image/%Y/%m/%d", verbose_name="Изображение", blank=True
    )
    author = models.CharField(max_length=150, verbose_name="Автор")
    url = models.CharField(max_length=150, blank=False, verbose_name="Url")
    tag = models.ManyToManyField(Tag, verbose_name="Тег")

    class Meta:
        verbose_name = u"Блог"
        verbose_name_plural = u"Блог"

    def __str__(self):
        return self.title



