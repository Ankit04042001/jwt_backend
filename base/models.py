from django.db import models
import datetime

from django.contrib.auth.models import AbstractBaseUser

from .managers import Manager

class User(AbstractBaseUser):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(
        verbose_name = "email address",
        max_length = 255,
        unique = True
    )
    is_active = models.BooleanField(default = True)
    is_admin = models.BooleanField(default = False)

    objects = Manager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']
    

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True


    def has_module_perms(self, app_label):
        return True
    

    @property 
    def is_staff(self):
        return self.is_admin



class ProxyUser(models.Model):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(
        verbose_name = 'email_address',
        max_length = 255,
        unique = True
    )
    password = models.CharField(max_length=255)
    otp = models.CharField(max_length=6)
    otp_attempt = models.SmallIntegerField(default=3)

    def __str__(self):
        return f'{self.email} with otp {self.otp}'
