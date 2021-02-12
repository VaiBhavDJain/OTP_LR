from rest_framework import serializers
# from rest_framework.permissions import IsAuthenticated
# from django.db import models
from .models import User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
# from django.contrib.auth import authenticate
# from django.contrib.auth.hashers import make_password
# Register serializer
from django.contrib.auth import password_validation
import random
import logging

# Get an instance of a logger
logger = logging.getLogger(__name__)


class AuthenticationSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        return token

    def validate(self, attrs):
        data = super().validate(attrs)

        refresh = self.get_token(self.user)

        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)
        data['id'] = self.user.id
        data['email'] = self.user.email
        data['username'] = self.user.username
        logger.info(f'User login successfully with this Credentials : {data}')
        return data


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'first_name', 'last_name')

    def validate_email(self, emails):
        if User.objects.filter(email=emails).exists():
            raise serializers.ValidationError('email already exist.')
        return emails

    def validate_password(self, value):
        password_validation.validate_password(value, self.instance)
        return value

    def create(self, validated_data):
        user = User.objects.create_user(validated_data['username'], validated_data['email'], validated_data['password'],
                                        first_name=validated_data['first_name'], last_name=validated_data['last_name'])

        return user


# User serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


# ---------------------------------------------------------------------------------------------------------------
# ==================== Reset Password =============================================================================

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from .models import OTP, User
from django.utils import timezone


class ResetPasswordEmailRequestSerializer(serializers.ModelSerializer):
    user = serializers.CharField(required=False)
    otp = serializers.CharField(required=False)

    class Meta:
        model = OTP
        fields = '__all__'

    def validate(self, attrs):
        attrs['user'] = self.context['user']
        otp = random.randint(100000, 999999)
        attrs['otp'] = otp
        return attrs


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8, max_length=68, write_only=True)
    otp = serializers.CharField(min_length=6, max_length=6)
    email = serializers.CharField(min_length=1, max_length=40)

    def validate_otp(self, otp):
        otp = OTP.objects.filter(otp=otp, user__email=self.initial_data.get('email'),
                                 expiry_time__gt=timezone.now()).first()
        if otp:
            return otp
        raise serializers.ValidationError('Invalid OTP.')


# -------------------------------------------------------------------------------------------------------------------
# ===================================================================================================================
# -------------------------------------------------------------------------------------------------------------------
# ==================================== Profile Update ===============================================================
from rest_framework.fields import CurrentUserDefault


class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'first_name', 'last_name')

    def validate_email(self, emails):
        if not User.objects.filter(email=emails).exists():
            raise serializers.ValidationError('email not exists in dtaabase.')
        return emails

    def validate_username(self, value):
        user = self.context['request'].user
        if User.objects.exclude(pk=user.pk).filter(username=value).exists():
            raise serializers.ValidationError({"username": "This username is already in use."})
        return value

    def update(self, instance, validated_data):
        user = self.context['request'].user
        if user.pk != instance.pk:
            raise serializers.ValidationError({"authorize": "You dont have permission for this user."})
        instance.username = validated_data['username']
        instance.first_name = validated_data['first_name']
        instance.last_name = validated_data['last_name']
        instance.save()
        return instance


# -------------------------------------------------------------------------------------------------------------------
# ===================================================================================================================
# -------------------------------------------------------------------------------------------------------------------
# ==================================== Update User Password ===============================================================
"""

class ChangePasswordSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('password', 'new_password', 'confirm_password')

        def validate(self, attrs):
            try:
                old_password = attrs.get('password')
                new_password = attrs.get('new_password')
                confirm_password = attrs.get('confirm_password')

                user = User.objects.get(password=old_password)

                if not (new_password == confirm_password):
                    raise AuthenticationFailed('Password does not match ')

                user.set_password(new_password)
                user.save()

                return (user)
            except Exception as e:
                raise AuthenticationFailed('Invalid', 401)

"""


class UpdatePasswordSerializer(serializers.Serializer):
    model = User

    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)
