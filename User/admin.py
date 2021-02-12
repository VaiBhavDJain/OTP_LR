from django.contrib import admin
from .models import User,OTP
# Register your models here.

class OTPSAdmin(admin.ModelAdmin):
    list_display = ('id','user','otp')

class UserAdmin(admin.ModelAdmin):
    list_display = ('id','username','email','password','first_name', 'last_name')


admin.site.register(User,UserAdmin)
admin.site.register(OTP,OTPSAdmin)


