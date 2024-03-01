from django.contrib import admin
from .models import User
from django.contrib.auth.models import Group

# Register your models here.

class UserAdmin(admin.ModelAdmin):
    list_display = (
        'username',
        'name',
        'email',
        'date_joined',
    )
    search_fields = ('username','name','email')

admin.site.register(User, UserAdmin)
admin.site.unregister(Group)