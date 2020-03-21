from django.urls import path
from . import views

urlpatterns = [ 
    path('', views.CreatAndGetUser.as_view()),
    path('login', views.LoginUSer.as_view())
    # path('<int:pk>/',views.UpdateAndDeleteUser.as_view())
]