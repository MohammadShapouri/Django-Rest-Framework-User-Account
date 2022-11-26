"""config URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from userAccount import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api-auth/', include('rest_framework.urls')),
    path('api/token/', views.CustomTokenObtainPairView.as_view(), name='TokenObtainPairView'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='TokenRefreshView'),
    path('api/', include('userAccount.urls')),
    path('api/password_reset/', views.PasswordResetView.as_view(), name="password_reset"),
    path('api/reset/<uidb64>/<token>/', views.PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
    # path('api/user/<int:pk>/change_password/', views.PasswordChangeView.as_view(), name='PasswordChange'),
    path('api/user/<int:pk>/change_password/', views.PasswordChangeView.as_view(), name='PasswordChange')
]
urlpatterns += static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)
