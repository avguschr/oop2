from abc import ABC

from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from salon.models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            'id',
            'email',
            'password'
        )


class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True, validators=[UniqueValidator(queryset=User.objects.all())])
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password],
                                     style={'input_type': 'password'})
    fio = serializers.RegexField(regex=r'^[а-яА-ЯёЁ\s-]+$', max_length=264, required=True)

    class Meta:
        model = User
        fields = (
            'email',
            'fio',
            'password',

        )

    def create(self, validated_data):
        user = User.objects.create(
            email=validated_data['email'],
            fio=validated_data['fio'],
        )

        user.set_password(validated_data['password'])
        user.save()

        return user


# class LoginSerializer(serializers.Serializer):
#     email = serializers.EmailField(required=True, max_length=255)
#     password = serializers.CharField(max_length=128, write_only=True)
#     token = serializers.CharField(max_length=255, read_only=True)
#
#     def validate(self, data):
#         email = data.get('email', None)
#         password = data.get('password', None)
#         token = data.get('token', None)
#
#         if email is None:
#             raise serializers.ValidationError(
#                 'An email address is required!'
#             )
#         if password is None:
#             raise serializers.ValidationError(
#                 'A password is required!'
#             )
#         if token is None:
#             raise serializers.ValidationError(
#                 'A token is required!'
#             )
#         user = authenticate(username=email, password=password, token=token)
#         if user is None:
#             raise serializers.ValidationError(
#                 'A user with this email and password was not found!'
#             )
#         return {
#             'email': user.email,
#         }
