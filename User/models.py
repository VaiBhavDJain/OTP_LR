from django.db import models
from django.utils import timezone
# Create your models here.
from django.contrib.auth.models import User
from django.utils.translation import gettext as _
"""
class OTP(models.Model):
    id = models.ForeignKey(User, on_delete=models.CASCADE,unique=False)
    key = models.CharField(max_length=14)
    valid_from = models.DateTimeField(default=timezone.now)
    valid_to = models.DateTimeField()
    expired = models.BooleanField(default=False)
"""

class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    id = models.CharField(max_length=10, primary_key=True,blank=False)
    otp = models.IntegerField(default=0)
    date = models.DateTimeField(auto_now_add=True)
    expiry_date = models.DateTimeField(default=timezone.now() + timezone.timedelta(seconds=120))

    def is_expired(self):
        if timezone.now() >= self.expiry_date:
            return True
        else:
            return False

