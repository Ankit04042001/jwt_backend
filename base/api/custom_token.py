import jwt
import datetime
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed

def generate_custom_token(context):
    payload = context
    payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=5)
    payload['iat'] = datetime.datetime.utcnow()


    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    

    return token


def authenticate_custom_token(request):
    authorization_header = request.headers.get('Authorization')

    if not authorization_header:
        raise AuthenticationFailed('Token missing')

    try:
        register_token_prefix = authorization_header.split(' ')[0]
        if register_token_prefix != 'Token':
            raise AuthenticationFailed('Invalid prefix')
        register_token = authorization_header.split(' ')[1]
        payload = jwt.decode(register_token, settings.SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed('Otp Expired.')
    except IndexError:
        raise AuthenticationFailed('Token Prefix Mission.')

    return payload['user_id']
