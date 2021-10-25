from django.urls import path
from rest_framework.routers import DefaultRouter
from knox import views as knox_views

from salon.views import *

router = DefaultRouter()
router.register(r'user', UserViewSet, basename='User')

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login')
]
