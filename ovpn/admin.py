from django.contrib import admin
from ovpn.models import  *
# Register your models here.
class UserAdmin(admin.ModelAdmin):
    list_display = ('vpnuser', 'password')
    search_fields = ('vpnuser',)

