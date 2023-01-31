from django.urls import path,include
from django.contrib.auth import views  as auth_views
from my_app.views import UserPasswordResetView, SendPasswordResetEmailView, UserRegistrationView, UserLoginView, UserProfileView, SocialLoginView,UserChangePasswordView,UserEditUsernameEmailView,UserEditImageView

urlpatterns = [
    path('register', UserRegistrationView.as_view(), name='register'),
    path('login', UserLoginView.as_view(), name='login'),
    path('profile', UserProfileView.as_view(), name='profile'),
    path('SendResetPasswordEmail', SendPasswordResetEmailView.as_view(), name='SendResetPasswordEmail'),
    path('resetPassword/<uid>/<token>', UserPasswordResetView.as_view(), name = 'reset-password'),
    
    path('oauth/login', SocialLoginView.as_view()),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('changeusername/changeemail',UserEditUsernameEmailView.as_view(), name='changeusername-changeemail'),
    path('changeimage',UserEditImageView.as_view(),name='changeimage')
    
    
]
