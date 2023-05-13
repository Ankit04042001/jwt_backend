from django.http import JsonResponse
from rest_framework.decorators import permission_classes, api_view
from rest_framework.permissions import IsAuthenticated, AllowAny
from .serializers import *
from rest_framework import generics
from rest_framework.response import  Response
from .custom_token import generate_custom_token
from rest_framework_simplejwt.tokens import RefreshToken
import uuid


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class RegisterUserAPIView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        otp = str(int(uuid.uuid1()))[:6]

        serializer = self.serializer_class(data = request.data, context={'otp' : otp})
        serializer.is_valid(raise_exception = True)
        email = serializer.data['email']

        user = ProxyUser.objects.get(email=email)
    
        context = {
            'user_id' : user.id
        }

        token = generate_custom_token(context)
        print(otp)

        return Response({
            "status" : True,
            "status_code" : 200, 
            "msg" : "otp sent successfully",
            "data" : {
                'register_token' : token
            }
        })


class OtpValidationAPIView(generics.GenericAPIView):
    serializer_class = OtpValidationSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request' : request})
        serializer.is_valid(raise_exception=True)
        return Response({
            'status' : True,
            'status_code' : 200,
            'msg' : 'Registeration successful',
            'data' : {

            }
        })


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data['email']

        user = User.objects.get(email=email)

        tokens = get_tokens_for_user(user)

        return Response({
            'status' : True,
            'status_code' : 200, 
            'msg' : 'Login Successful',
            'data' : {
                'first_name' : user.first_name,
                'access_token' : tokens['access'],
                'refresh_token' : tokens['refresh']
            } 
        })


class RefreshTokenAPIView(generics.GenericAPIView):
    serializer_class = RefreshTokenSerializer

    def post(self, request):
        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception=True)
        refresh = serializer.data['refresh']
        token = RefreshToken(refresh)
        token.blacklist()
        payload = jwt.decode(refresh, settings.SECRET_KEY, algorithms=['HS256'])
        tokens = get_tokens_for_user(User.objects.get(id=payload['user_id']))
        return Response({
            'status' : True,
            'status_code' : 200,
            'msg' : 'token refreshed successfully',
            'data' : {
                'access' : tokens['access'],
                'refresh' : tokens['refresh']
            }
        })

class GetUserAPIView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_id = request.user.id
        user = User.objects.get(id=user_id)

        return Response({
            'status' : True,
            'status_code' : 200,
            'msg' : 'User fetched successfully',
            'data' : {
                'first_name' : user.first_name
            }
        })

class ChangePasswordAPIView(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data = request.data, context = {'user_id' : request.user.id})
        serializer.is_valid(raise_exception=True)

        
        return Response({
            'status' : True,
            'status_code' : 200,
            'msg' : 'Password Changed Successfully', 
            'data' : {

            }
        })

class LogoutAPIView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        refresh_token = request.data['refresh']
        token = RefreshToken(refresh_token)
        token.blacklist()
            
        return Response({
            'status' : True,
            'status_code' : 200,
            'msg' : 'Logout Successfully',
            'data' : {

            }
        })

class ForgetPasswordAPIView(generics.GenericAPIView):
    serializer_class = ForgetPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data = request.data, context={'request' : request})
        serializer.is_valid(raise_exception = True)
        email = serializer.data['email']
        otp = str(int(uuid.uuid1()))[:6]
        print(otp)

        try:
            user = ProxyUser(email = email, otp = otp)
            user.save()
        except:
            user = ProxyUser.objects.get(email=email)
            user.delete()
            proxy_user = ProxyUser(email - email, otp = otp)
            proxy_user.save()

        token = generate_custom_token({'user_id' : user.id})
        

        return Response({
            'status' : True,
            'status_code' : 200,
            'msg' : 'Otp Sent Successfully',
            'data' : {
                'token' : token
            }
        })

class ForgetOtpAPIView(generics.GenericAPIView):
    serializer_class = ForgetOtpValidationSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request' : request})
        serializer.is_valid(raise_exception=True)

        return Response({
            'status' : True,
            'status_code' : 200,
            'msg' : 'Forget Password Successfully',
            'data' : {

            }
        })

# @permission_classes(IsAuthenticated)
@api_view(['Get'])
def test(request):

    return JsonResponse({'test' : 'test passed'})