from django.db import models
# Create your models here.
from django.core.validators import RegexValidator
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)

USERNAME_REGEX = '^[a-zA-Z0-9]*$'

class MyUSerManager(BaseUserManager):
    def create_user(self, username, email, password=None):
        if not email:
            raise ValueError('User must have an email address')

        user = self.model(
            username = username,
            email = self.normalize_email(email)
        )
        # user.set_password(make_password(password))
        user.save()
        return user

    
    def create_superuser(self, username, email, password=None):
        user = self.create_user(username, email, password)
        user.is_admin = True
        user.save()
        return user


class User(AbstractBaseUser):
    username = models.CharField(
        max_length = 300,
        validators = [
            RegexValidator(regex = USERNAME_REGEX,
                            message = 'username must be alphanumeric or contain number',
                            code = 'invalid user name'
            )],
        unique=True
    )
    email = models.EmailField(
        max_length = 255,
        unique = True,
        verbose_name = 'email address'
    )
    is_admin = models.BooleanField(default=False)

    # objects = MyUSerManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']
