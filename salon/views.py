from rest_framework import generics, status
from rest_framework.generics import ListCreateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_jwt.settings import api_settings
from django.contrib.auth import login
from rest_framework import permissions
from rest_framework.authtoken.serializers import AuthTokenSerializer
from knox.views import LoginView as KnoxLoginView
from salon.models import User
from salon.renderers import UserJSONRenderer
from salon.serializers import UserSerializer, RegisterSerializer


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
        payload = api_settings.JWT_PAYLOAD_HANDLER(user)
        token = api_settings.JWT_ENCODE_HANDLER(payload)
        return Response({'token': token}, status=status.HTTP_201_CREATED, headers=headers)


# class LoginView(APIView):
#
#     serializer_class = LoginSerializer
#
#     def post(self, request):
#         user = request.data.get('user', {})
#         serializer = self.serializer_class(data=user)
#         serializer.is_valid(raise_exception=True)
#
#         return Response(serializer.data, status=status.HTTP_200_OK)

class LoginView(KnoxLoginView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        serializer = AuthTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        return super(LoginView, self).post(request, format=None)