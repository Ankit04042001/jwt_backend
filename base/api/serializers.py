from rest_framework import serializers
from base.models import *
from rest_framework.exceptions import ValidationError, AuthenticationFailed
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.hashers import make_password
from .custom_token import authenticate_custom_token
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
import jwt
from django.conf import settings


class RegisterSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(max_length=255, write_only=True, style={'input_type' : 'password'})
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password', 'confirm_password']
        extra_kwargs = {
            'password' : {'write_only' : True, 'style' : {'input_type' : 'password'}},
        }

    def validate(self, attrs):
        email = attrs.get('email')
        first_name = attrs.get('first_name')
        last_name = attrs.get('last_name')
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        otp = self.context['otp']
        
        user = User.objects.all().filter(email=email)

        if len(user) >= 1:
            raise ValidationError('User with this email id already Exists', code='user_exist')
        

        if password != confirm_password:
            raise ValidationError('Password and Confirm Password not matching.', code='not_matching')
        
        try:
            proxy_user = ProxyUser.objects.get(email=email)
            proxy_user.delete()
            proxy_user = ProxyUser(email=email, first_name=first_name, last_name=last_name, password=make_password(password), otp=otp)
            proxy_user.save()
        except:
            proxy_user = ProxyUser(email=email, first_name=first_name, last_name=last_name, password=make_password(password), otp=otp)
            proxy_user.save()
        return attrs


class OtpValidationSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)

    def validate(self, attrs):
        user_id = authenticate_custom_token(self.context['request'])
        proxy_user = ProxyUser.objects.get(id = user_id)
        proxy_user.otp_attempt = proxy_user.otp_attempt - 1
        proxy_user.save()

        if proxy_user.otp_attempt < 0:
            raise ValidationError('otp Attempts over.', code='attempt_over')

        try:
            otp = int(attrs.get('otp'))
        except:
            raise ValueError('Otp should contain digits only')



        if otp<100000 or otp>999999:
            raise ValidationError('Otp should be of 6 digits only.', code='invalid_otp')



        if otp != int(proxy_user.otp):
            raise ValidationError('Invalid Otp', code='invalid_otp')


        user = User(email=proxy_user.email, first_name=proxy_user.first_name, last_name=proxy_user.last_name, password=proxy_user.password)
        user.save()
        proxy_user.delete()

        return attrs


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(max_length=50, style={'input_type' : 'password'})
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        try:
            user = User.objects.get(email=email)
        except:
            raise ValidationError('User with this email id does not exist', code='invalid_user')

        if not check_password(password, user.password):
            raise ValidationError('Invalid password', code='invalid_password')
        return attrs


class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        refresh = attrs.get('refresh')
        try:
            payload = jwt.decode(refresh, settings.SECRET_KEY, algorithms=['HS256'])
            attrs['user'] = payload['user_id']
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Invalid or Expired Token')
        except jwt.DecodeError:
            raise AuthenticationFailed('Invalid Token')
        
        return attrs

class ChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=50, style={'input_type': 'password'}, required=True)
    new_password = serializers.CharField(max_length=50, style={'input_type': 'password'}, required=True)
    confirm_new_password = serializers.CharField(max_length=50, style={'input_type': 'password'}, required=True)

    def validate(self, attrs):
        old_password = attrs.get('password')
        password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_new_password')
        user_id = self.context['user_id']

        user = User.objects.get(id = user_id)

        if not check_password(old_password, user.password):
            raise ValidationError('Old password is not correct', 'not_correct')

        if password and confirm_password and (password != confirm_password):
            raise ValidationError('Password and Confirm Password not matching', code='not_matching')

        user.set_password(password)
        user.save()

        return attrs


class ForgetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    def validate(self, attrs):
        email = attrs.get('email')

        try:
            user = User.objects.get(email = email)
        except:
            raise ValidationError('User with this email id doest not exist' , code='not_exist')

        return  attrs

class ForgetOtpValidationSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6, required=True)
    password = serializers.CharField(max_length=50, style = {'input_type' : 'password'}, required=True)
    confirm_password = serializers.CharField(max_length=50, style = {'input_type' : 'password'}, required=True)

    def validate(self, attrs):
        otp = attrs.get('otp')
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')

        user_id = authenticate_custom_token(self.context['request'])
        proxy_user = ProxyUser.objects.get(id=user_id)
        proxy_user.otp_attempt = proxy_user.otp_attempt - 1
        proxy_user.save()


        if proxy_user.otp_attempt < 0:
            raise ValidationError('otp Attempts over.', code='attempt_over')

        try:
            otp = int(otp)
        except:
            raise ValueError('Otp should contain digits only')



        if otp<100000 or otp>999999:
            raise ValidationError('Otp should be of 6 digits only.', code='invalid_otp')



        if otp != int(proxy_user.otp):
            raise ValidationError('Invalid Otp.', code='invalid_otp')

        if password != confirm_password:
            raise ValidationError('Password and Confirm Password not matching', code = 'not_matching')

        user = User.objects.get(email=proxy_user.email)
        user.set_password(proxy_user.password)
        user.save()
        proxy_user.delete()

        return attrs