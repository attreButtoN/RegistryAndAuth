from django.conf.urls.static import static
from django.urls import path,include
from app.views import *
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from django.http import StreamingHttpResponse
from django.urls import path

from .camera import VideoCamera, gen


urlpatterns = [
    path('register/', RegisterView.as_view(), name="register"),
    path('login/', LoginAPIView.as_view(), name="login"),
    path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('phone-verify/', VerifyPhone.as_view()),
    path('send-code/',SendVerificationCode.as_view()),
    path("logout/",LogoutAPIView.as_view()),
    path("change_password",ChangePassword.as_view()),

    path("reset-password-sms/",ForgotPasswordRecoveryBySMSView.as_view()),
    path("send-sms-reset-password",SendSmsForgotPasswordView.as_view()),
    path("email-reset-password/", ForgotPasswordView.as_view()),
    path("send-reset/",SendMailForgotPasswordView.as_view()),

    path('tag/',CreateTag.as_view()),
    path('me/',UserData.as_view()),
    path("article/",CreateRetrieveArticle.as_view()),
    path("article/<int:pk>/",DestroyUpdateArticle.as_view()),



    path('monitor/', lambda r: StreamingHttpResponse(gen(VideoCamera()),
                                                     content_type='multipart/x-mixed-replace; boundary=frame')),
]
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)