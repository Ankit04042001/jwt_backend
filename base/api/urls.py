from django.urls import path
from . import views
from .views import *
from rest_framework_simplejwt.views import TokenBlacklistView


urlpatterns = [
    path('register/', RegisterUserAPIView.as_view(), name='register'),
    path('otp/', OtpValidationAPIView.as_view(), name='otp'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('get_user/', GetUserAPIView.as_view(), name='get_user'),
    path('password/', ChangePasswordAPIView.as_view(), name='password'),
    path('forget_password/', ForgetPasswordAPIView.as_view(), name='forget_password'),
    path('forget_otp/', ForgetOtpAPIView.as_view(), name='forget_otp'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('test/', views.test, name='test')

]


