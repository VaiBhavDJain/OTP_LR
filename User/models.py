from django.db import models
from django.utils import timezone
from django.core.validators import RegexValidator
# Create your models here.
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext as _

class User(AbstractUser):
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=100, null=False, blank=False, validators=[
        RegexValidator(r'[A-Za-z0-9@#$%^&+=]{8,}',
                       message='The password must contain at least one in  A-Z and a-z, 0-9 and special character.')])
    first_name = models.CharField(max_length=15)
    last_name = models.CharField(max_length=15)


class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.IntegerField(default=0)
  #  expiry_time = models.DateTimeField()
  #  time = models.DateTimeField(auto_now_add=True)



# User model Abstract class (email/password) username = none
# Login API
# Forget Password
