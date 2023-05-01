from rest_framework.views import exception_handler
from rest_framework.response import Response


def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    hadndler = {
        'NotAuthenticated' : custom_authentication_handler,
        'AuthenticationFailed' : custom_authentication_failed_handler,
        'MethodNotAllowed' : custom_method_handler,
        'ValidationError' : custom_validation_handler,
        'UnsupportedMediaType' : custom_media_handler,
        'InvalidToken' : custom_token_handler,
    }
    if response is None:
        response = Response({
            'status' : False,
            'msg' : f'{exc.__class__.__name__} : {exc.args}'
        })
        return response

    exception_class = exc.__class__.__name__
    hadndler[exception_class](exc, context, response)

    return response



def custom_authentication_handler(exc, context, response):
    response.status_code = 200
    response.data = {
        'status' : False,
        'status_code' : exc.status_code,
        'msg' : 'Not Authenticated'
    }
    return response

def custom_authentication_failed_handler(exc, context, response):
    response.status_code = 200
    response.data = {
        'status' : False,
        'status_code' : exc.status_code,
        'msg' : response.data
    }
    return response

def custom_method_handler(exc, context, response):
    response.status_code = 200
    response.data = {
        'status' : False,
        'status_code' : exc.status_code,
        'msg' : 'Method Not Allowed'
    }
    return response

def custom_validation_handler(exc, context, response):
    response.status_code = 200
    errorList = []
    for key, value in response.data.items():
        errorList.append([key, value])
    
    key = errorList[0][0]
    key = normalize(key)
    error = (errorList[0][1])[0]

    if error.code == 'required':
        msg = f'{key} is required.'

    elif error.code == 'blank':
        msg = f'{key} can not be blank.'
    
    elif error.code == 'invalid':
        msg = f'Invalid {key}.'

    elif key == 'Otp' and error.code == 'max_length':
        msg = f'Otp should be of 6 digits only'    
    else:
        msg = error.title()
    

    response.data = {
        'status' : False,
        'status_code' : exc.status_code,
        'msg' : msg
    }    
    
    return response


def normalize(key):
    value = key.split('_')

    for i in range(len(value)):
        value[i] = value[i].capitalize()
    return " ".join(value)


def custom_media_handler(exc, context, response):
    response.status_code = 200
    response.data = {
        'status' : False,
        'status_code' : exc.status_code,
        'msg' : 'Send Data in Json Only'
    }
    return response

def custom_token_handler(exc, context, response):
    response.status_code = 200
    response.data = {
        'status' : False,
        'status_code' : exc.status_code,
        'msg' : 'Invalid or Expired Token.{ Token type = Access or Refresh}'
    }
    return response