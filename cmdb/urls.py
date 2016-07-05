from django.conf.urls import patterns, include, url
from django.contrib import admin
admin.autodiscover()
from django.conf import settings

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'yusong.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

    url(r'^admin/', include(admin.site.urls)),
    (r'^$', 'jump.views.index'),
    (r'^searchU/$', 'jump.views.searchUser'),
    (r'^client_search_perm/$', 'jump.views.client_search_perm'),
    (r'^searchHost/$', 'jump.views.searchHost'),
    (r'^login/$', 'jump.views.login'),
    (r'^logout/$', 'jump.views.logout'),
    #(r'^chgPass/$', 'jump.views.chgPass'),
    (r'^user/$', 'jump.views.showUser'),
    (r'^addUser/$', 'jump.views.addUser'),
    (r'^host/$', 'jump.views.showHost'),
    (r'^addHost/$', 'jump.views.addHost'),
    (r'^showPerm/$', 'jump.views.showPerm'),
    (r'^addPerm/$', 'jump.views.addPerm'),
    (r'^modyfyhost/(\d{1,4})/$', 'jump.views.modyfyHost'),
    #(r'^ovpn/$', 'jump.views.ovpn'),
    #(r'^vpn/$', 'jump.views.vpn'),
    #(r'^addVpnUser/$', 'jump.views.addVpnUser'),
    (r'^ch_passwd/$','jump.views.ch_passwd'),
    (r'^ttt/$','jump.views.ttt')
)
