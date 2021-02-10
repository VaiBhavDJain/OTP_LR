from django.contrib import admin
from .models import OTP
# Register your models here.
"""
class OTPAdmin(admin.ModelAdmin):
    list_display = ('id','user','otp','date', 'expiry_date')


admin.site.register(OTP, OTPAdmin)
"""
admin.site.register(OTP)

