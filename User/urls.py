from django.conf.urls import url
from . import views
from django.urls import path, include
from User.views import Registerapi, home
urlpatterns = [
      path('register/', Registerapi),
      path('login/', home.as_view()),
      path('request-reset-password/', views.RequestPasswordReset.as_view(), name="request-reset-email"),
   #   path('password-reset/<uidb64>/<token>', PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
      path('reset-password/', views.SetNewPasswordAPIView.as_view(), name='password-reset-complete'),
      path('profile-update/<int:pk>', views.ProfileUpdate.as_view()),
      path('update-password/', views.UpdatePasswordView.as_view(), name='update-password'),
      path('login-token/', views.Authenticate.as_view(), name="api_auth"),
]


