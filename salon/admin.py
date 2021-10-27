from django.contrib import admin

from salon.models import *

admin.site.register(User)
admin.site.register(Service)
admin.site.register(Cart)
admin.site.register(Order)