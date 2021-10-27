from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import RegexValidator


class User(AbstractUser):
    username = models.CharField(max_length=128, null=True, blank=True)
    fio = models.CharField(max_length=128, null=False, verbose_name='ФИО')
    email = models.EmailField('email address', unique=True, null=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

    class Meta:
        verbose_name = 'Пользователь'
        verbose_name_plural = 'Пользователи'


class Service(models.Model):
    name = models.CharField(max_length=128, null=False)
    description = models.TextField(null=False)
    cost = models.IntegerField(null=False)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Услуга'
        verbose_name_plural = 'Услуги'


class Cart(models.Model):
    owner = models.ForeignKey('User', on_delete=models.CASCADE, null=False)
    services = models.ManyToManyField(Service, blank=True, related_name='cart')
    is_active = models.BooleanField(default=True, null=False)

    class Meta:
        verbose_name = 'Корзина'
        verbose_name_plural = 'Корзины'



class Order(models.Model):
    phoneNumberRegex = RegexValidator(regex=r"^\+?1?\d{8,15}$")
    owner = models.ForeignKey('User', on_delete=models.CASCADE, null=False)
    services = models.ManyToManyField(Service, blank=False, null=False, related_name='order')
    phone = models.CharField(validators=[phoneNumberRegex], max_length=16, null=True)
    comment = models.TextField(null=True, blank=True)
    sum = models.IntegerField(null=False)
    class Meta:
        verbose_name = 'Заказ'
        verbose_name_plural = 'Заказы'