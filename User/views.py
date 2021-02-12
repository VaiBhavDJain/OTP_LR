# from rest_framework import generics, permissions, mixins
from rest_framework.response import Response
from .serializer import RegisterSerializer, UserSerializer, AuthenticationSerializer

# Register API
from rest_framework.decorators import APIView, api_view
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView


class Authenticate(TokenObtainPairView):
    permission_classes = (AllowAny,)
    serializer_class = AuthenticationSerializer

@api_view(['GET', 'POST'])
def Registerapi(request):
    user_serializer = RegisterSerializer(data=request.data)
    if user_serializer.is_valid():
        user_serializer.save()
        return Response(user_serializer.data, status=status.HTTP_201_CREATED)
    return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class home(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        content = {'message': 'Hello, CubexO !'}
        return Response(content)


# --------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------------------------
# ------------------------------------ Reset Password ---------------------------------------------------------------

from rest_framework.views import APIView
from rest_framework import status, generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.views import TokenObtainPairView

# from .decorators import authorize
from .models import User
from .serializer import ResetPasswordEmailRequestSerializer, SetNewPasswordSerializer

from .email_services import sent_mail
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.hashers import make_password
from .models import OTP
import random
from django.utils import timezone


# -------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------------------
# ------------------------------ Forgot Password ----------------------------------------------------------------

class RequestPasswordReset(generics.GenericAPIView):

    def post(self, request):
        try:
            user = User.objects.get(email=request.data['email'])
        except User.DoesNotExist:
            return Response({'error': "We will send you the otp if the email exist on our database."})
        otp, created = OTP.objects.get_or_create(user=user)
        otp.otp = random.randint(100000, 999999)
        otp.expiry_time = timezone.now()  # add time delta
        otp.save()
        email_body = f'Hello,  this OTP to reset your password  {otp.otp}'
        data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Reset your passsword'}
        sent_mail(data)
        return Response({'success': 'We have sent you a OTP to reset your password', 'otp': otp.otp},
                        status=status.HTTP_200_OK)


class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def put(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.validated_data.get('otp').user.set_password(serializer.validated_data.get('password'))
        serializer.validated_data.get('otp').delete()
        # OTP.objects.filter(user=serializer.validated_data.get('otp').user).delete()
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


# -------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------------------
# ------------------------------ Profile Update ----------------------------------------------------------------


from .serializer import ProfileUpdateSerializer, UpdatePasswordSerializer
from django.http.response import JsonResponse
from rest_framework.parsers import JSONParser

"""

@api_view(['PUT'])
def ProfileUpdate(request, pk):
    profile = User.objects.get(pk=pk)

    if request.method == 'PUT':
        update_profile_data = JSONParser().parse(request)
        profile_update_serializer = ProfileUpdateSerializer(profile, data=update_profile_data)
        if profile_update_serializer.is_valid():
            profile_update_serializer.save()
            return JsonResponse(profile_update_serializer.data)
        return JsonResponse(profile_update_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
"""


class ProfileUpdate(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = ProfileUpdateSerializer


# -------------------------------------------------------------------------------------------------------------------
# ===================================================================================================================
# -------------------------------------------------------------------------------------------------------------------
# ========================================= User Update Password ====================================================
import logging

logger = logging.getLogger(__name__)


class UpdatePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = UpdatePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def update(self, request, *args, **kwargs):
        user = self.request.user
        serializer = UpdatePasswordSerializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not user.check_password(serializer.validated_data["old_password"]):
                logger.warning(f"Invalid Old password ")
                return Response({"error": "Invalid Old password"}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            new_pass = serializer.data.get("new_password")
            confirm_pass = serializer.data.get("confirm_password")
            if new_pass != confirm_pass:
                logger.warning(f"Password not matched")
                return Response({"error": "Password must matched"}, status=status.HTTP_400_BAD_REQUEST)

            user.set_password(serializer.data.get("new_password"))
            user.save()

            return Response({
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
            })

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# user add email
# check if email exist in database else through error
# if exist generate otp and store in db
# otp model -
# otp generation time
# otp
# email
# reset password otp password and confirm password
