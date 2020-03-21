from django.shortcuts import render
from django.contrib.auth import get_user_model
from .serializers import CreateUserSerializer, UserSerializer, UserLoginSerializer
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from . models import User

# Create your views here.

# User = get_user_model()

class CreatAndGetUser(APIView):

    def get(self, request, format=None):
        user = User.objects.all()
        serializer = UserSerializer(user, many = True)

        return Response(serializer.data)
    
    def post(self, request, format=None):
        # return Response(request.data)
      
        serializer = CreateUserSerializer(data = request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginUSer(APIView):
    def get(self, request, format=None):
        user = User.objects.all()
        serializer = UserSerializer(user, many = True)

        return Response(serializer.data)
    
    def post(self, request, format=None):
        # return Response(request.data)
      
        serializer = UserLoginSerializer(data = request.data)
       
        if serializer.is_valid():
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)