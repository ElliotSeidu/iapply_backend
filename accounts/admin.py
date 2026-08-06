from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User

# Register your models here.
class CustomUserAdmin(UserAdmin):
    fieldsets = [("Personal details", {"fields": ["email", "first_name", "last_name", "password"]}), ("Others", {"fields":["is_active", "is_staff"]})]
    search_fields = ["email", "first_name", "last_name"]
    add_fieldsets = [(None, {"classes": ("wide",), "fields": ["email", "first_name", "last_name", "password1", "password2"]})]
    list_display = ["email", "first_name", "last_name"]
    ordering = ["first_name"]

admin.site.register(User, CustomUserAdmin)