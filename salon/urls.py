from django.conf.urls import url
from django.urls import path
from rest_framework.routers import DefaultRouter
from salon.views import *
from knox import views as knox_views

router = DefaultRouter()
router.register(r'user', UserViewSet, basename='User')

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('services/', ServicesView.as_view(), name='services'),
    path('cart/', CartView.as_view({'get': 'list'}), name='cart'),
    path('deleteServiceCart/<int:pk>/', DeleteServiceFromCartView.as_view(), name='deleteService'),
    path('cart/<int:pk>/', AddServiceView.as_view(), name='addService'),
    path('orders/', OrderView.as_view({'get': 'list'}), name='order'),
    path('createOrder/', CreateOrderView.as_view(), name='createOrder'),
    path('logout/', knox_views.LogoutView.as_view(), name='knox_logout'),
    path('createService/', CreateServiceView.as_view(), name='createService'),
    path('updateService/<int:pk>/', UpdateServiceView.as_view(), name='updateService'),
    path('deleteService/<int:pk>/', DeleteServiceView.as_view(), name='deleteService')
]
