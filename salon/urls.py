from django.urls import path
from rest_framework.routers import DefaultRouter
from salon.views import *

router = DefaultRouter()
router.register(r'user', UserViewSet, basename='User')

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('services/', ServicesView.as_view(), name='services'),
    path('cart/', CartView.as_view({'get': 'list'}), name='cart'),
    path('addCart/<int:pk>/', AddCartView.as_view(), name='addCart'),
    path('createCart/', CreateCartView.as_view(), name='createCart')
]
