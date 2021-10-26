from knox.models import AuthToken
from rest_framework import generics, status, viewsets
from rest_framework.generics import ListCreateAPIView, RetrieveAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_jwt.settings import api_settings
from django.contrib.auth import login
from rest_framework import permissions
from rest_framework.authtoken.serializers import AuthTokenSerializer
from knox.views import LoginView as KnoxLoginView
from salon.models import User, Service, Cart
from salon.permissions import IsOwnerOrReadOnly
from salon.serializers import UserSerializer, RegisterSerializer, LoginSerializer, ServiceSerializer, CartSerializer, \
    AddCartSerializer, CreateCartSerializer
from rest_framework.authtoken.models import Token


class UserViewSet(ListCreateAPIView):
    serializer_class = UserSerializer
    queryset = User.objects.all()


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        user = User.objects.filter(**serializer.data).first()

        # payload = api_settings.JWT_PAYLOAD_HANDLER(user).decode('utf-8')
        # token = api_settings.JWT_ENCODE_HANDLER(payload).decode('utf-8')
        return Response({"token": AuthToken.objects.create(user)[1]}, status=status.HTTP_201_CREATED, headers=headers)


class LoginView(KnoxLoginView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request, format=None):
        serializer = AuthTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        return super(LoginView, self).post(request, format=None)

    def get_post_response_data(self, request, token, instance):
        UserSerializer = self.get_user_serializer_class()

        data = {
            'token': token
        }
        if UserSerializer is not None:
            data["user"] = UserSerializer(
                request.user,
                context=self.get_context()
            ).data
        return data


class ServicesView(APIView):
    def get(self, request):
        services = Service.objects.all()
        serializer = ServiceSerializer(services, many=True)
        return Response(serializer.data)


class CartView(viewsets.ModelViewSet):
    def get_queryset(self):
        return Cart.objects.filter(owner=self.request.user)

    serializer_class = CartSerializer


class CreateCartView(generics.CreateAPIView):
    queryset = Cart.objects.all()
    serializer_class = CreateCartSerializer

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response({"message": 'успешно создалась'}, status=status.HTTP_201_CREATED, headers=headers)


class AddCartView(generics.UpdateAPIView):
    permission_classes = [permissions.IsAuthenticatedOrReadOnly, IsOwnerOrReadOnly]
    queryset = Cart.objects.all()
    serializer_class = AddCartSerializer
    lookup_field = 'pk'

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Service add to card"})

        else:
            return Response({"message": "failed", "details": serializer.errors})


class DeleteServiceFromCartView(generics.DestroyAPIView):
    serializer_class = ServiceSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def get_queryset(self):
        cart = Cart.objects.filter(owner=self.request.user, is_active=True).first()
        return cart.services.all()

    def destroy(self, request, *args, **kwargs):
        cart = Cart.objects.filter(owner=self.request.user, is_active=True).first()
        cart.services.remove(self.get_object())
        return Response({"message": "Item removed from cart"}, status=status.HTTP_204_NO_CONTENT)


class AddServiceView(RetrieveAPIView):
    serializer_class = ServiceSerializer

    def get_queryset(self):
        return Service.objects.all()

    def retrieve(self, request, *args, **kwargs):
        cart = Cart.objects.filter(owner=self.request.user, is_active=True).first()
        cart.services.add(self.get_object())
        return Response({"message": "Service add to card"}, status=status.HTTP_201_CREATED)
