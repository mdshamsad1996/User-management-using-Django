from rest_framework import serializers
# from . models import User
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.conf import settings
from django.db.models import Q

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
        class Meta:
            model = User
            fields = ['username', 'email', 'password']
            # fields = '__all__'
            # extra_kwargs = {'password': {'write_only': True}}



class CreateUserSerializer(serializers.ModelSerializer):

    email = serializers.EmailField(
        required=True,
        label="Email Address"
    )

    password = serializers.CharField(
        required=True,
        label="Password",
        style={'input_type': 'password'},
        write_only = True
    )

    password_2 = serializers.CharField(
        required=True,
        label="Confirm Password",
        style={'input_type': 'password'},
        write_only=True
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_2']
        extra_kwargs = {'password': {'write_only': True}}



    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value
    
    def validate_password(self, value):
        if len(value) < getattr(settings, 'PASSWORD_MIN_LENGTH', 8):
            raise serializers.ValidationError(
                "Password should be atleast %s characters long." % getattr(settings, 'PASSWORD_MIN_LENGTH', 8)
            )
        return value
    
    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value

    def validate_password_2(self, value):
        data = self.get_initial()
        password = data.get('password')

        if password != value:
            raise serializers.ValidationError("Passwords doesn't match.")
        return value

    
    def create(self, validated_data):
       password = self.validated_data['password']
       user = User.objects.create_user(
            email = self.validated_data['email'],
            username = self.validated_data['username'],
        )
       user.set_password(password)
       
       return user

        # user = User(user_data)
        # user.set_password(password)
        # user.save()
        # return user

    #     user = User.objects.create_user(            
    #         email = validated_data['email'],
    #         username = validated_data['username'],
    #         password= make_password(validated_data['password']),
    #     )

    

    # #     # hashed_pwd = make_password("plain_text")
    # #     # check_password("plain_text",hashed_pwd) 


    # #     # password = data.pop('password')
    # #     # user = User(**data)
    # #     # user.is_active = is_active
    # #     # user.set_password(password)
    # #     # user.save()

    # #     # password = validated_data.pop('password')
    # #     # user = self.Meta.model.objects.create(**validated_data)
    # #     user.set_password(password)
    # #     user.save()


class UserLoginSerializer(serializers.ModelSerializer):

    username = serializers.CharField(
        required = True,
        write_only = True,
        label = "Email Address"
    )
    email = serializers.EmailField(
        required = True,
        allow_blank = True,
        write_only = True,
        label ='Email Address'
    )

    password = serializers.CharField(
        required = True,
        write_only = True,
        style = {'input_type': 'password'}
    )

    class Meta(object):
        model = User
        fields = ['email', 'username', 'password']



    def validate(self, data):
        email  = data.get('email', None)
        username = data.get('username', None)
        password = data.get('password', None)


        user = authenticate(username=username, password=password)

        if user is not None:
            return user
        else:
            raise serializers.ValidationError("Invalid credentials.")



        # if not username:
        #     raise serializers.ValidationError("Please enter username or email to login.")

        # user = User.objects.filter(
        #     Q(email=email) | Q(username=username)
        # ).exclude(
        #     email__isnull=True
        # ).exclude(
        #     email__iexact=''
        # ).distinct()

        # if user.exists() and user.count() == 1:
        #     user_obj = user.first()
        # else:
        #     raise serializers.ValidationError("This username/email is not valid.")

        # if user_obj:
            
        #     if not self.user_obj.check_password(password):
        #         raise serializers.ValidationError("Invalid credentials.")

        # if not User.objects.filter(username=username).exists():
        #      raise serializers.ValidationError("This username/email is not valid.")

        # user = User.objects.filter(username=username).first()


        # if not user.check_password(password):
        #     raise serializers.ValidationError("Invalid Password")


        return user.first()
        
        


        # if user.exists():
        #     return user
        # return user


       

    #     if not email and not username:
    #         raise serializers.ValidationError("Please enter username or email to login.")

    #     user = User.objects.filter(
    #         Q(email = email) | Q(username=username)
    #     )

    #     if user.exists() and user.count() == 1:
    #         user_obj = user.first()
    #     else:
    #         raise serializers.ValidationError("This username/email is not valid.")



    #     # if user_obj:
    #     #     if not check_password(user_obj.password, password):
    #     #     # if user_obj.password != make_password(password):
    #     #         raise serializers.ValidationError("Invalid credentials.")

    #     return data
