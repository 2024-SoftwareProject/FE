from django.urls import path
from . import views

urlpatterns=[
    
    path('login/', views.Login.as_view(), name='login'),
    path('logout/', views.Logout, name='logout'),

    path('agreement/', views.Agreement.as_view(), name='agreement'),
    path('signup/', views.Signup.as_view(), name='signup'),
    path('signupAuth/', views.Signup_success, name='signup_success'),
    path('activate/<str:uid64>/<str:token>/', views.activate, name='activate'),

    path('recovery/pw/', views.recoveryPW.as_view(), name='recovery_pw'),
    path('recovery/pw/find/', views.ajax_find_pw, name='ajax_pw'),
    path('recovery/pw/auth/', views.auth_confirm, name='recovery_auth'),
    path('recovery/pw/reset/', views.auth_pw_reset, name='recovery_pw_reset'),

    path('mypage/', views.Mypage, name='mypage'),
    path('mypage/editAccount/', views.editAccount, name='edit_account'),
    path('maypage/editPassword/', views.editPassword, name='edit_password'),
    path('mypage/deleteAccount/', views.deleteAccount , name='delete_account'),
    
]