from django.urls import path, include
from . import views
from rest_framework import routers


router = routers.SimpleRouter()
router.register('user', views.UserAccountViewSet)


urlpatterns = [
    path('activate/<uidb64>/<token>',
        views.ActivateUserAccount.as_view(), name='Activate'),
    path('activate-email/<uidb64>/<token>', views.ActivateEmail.as_view(), name='ActivateEmail')
]

urlpatterns += router.urls