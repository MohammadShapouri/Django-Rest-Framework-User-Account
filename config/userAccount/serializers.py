import re
from rest_framework import serializers
from django.core.validators import RegexValidator
from django.core import exceptions
import django.contrib.auth.password_validation as password_validators
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from extentions.emailVerification.EmailVerifier import EmailVerifier
from django.contrib.auth import authenticate
from rest_framework_simplejwt.settings import api_settings
from rest_framework import exceptions as rest_exceptions
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import update_last_login
from django.utils.translation import gettext_lazy as _
from django.http import JsonResponse
# For password reset option.
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template import loader
from django.core.mail import EmailMultiAlternatives
from django.contrib.auth.forms import _unicode_ci_compare
from rest_framework.response import Response




UserAccount = get_user_model()
UserModel = UserAccount
UsernameValidator = RegexValidator(regex = r"^[\w.+-]+\Z",
                                    message = (
                                                "Enter a valid username. This value may contain only English letters, "
                                                "numbers, and @/./+/-/_ characters."
                                                ),
                                    flags = re.ASCII)





class UserAccountRegisterSerializer(serializers.ModelSerializer, EmailVerifier):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.serializer_request = self.context.get('serializer_request')
        # self.admin_view = self.context.get('admin_view')

        if self.serializer_request.user.is_authenticated:
            if self.serializer_request.user.is_superuser or self.serializer_request.user.is_staff:
                fields = ['pk', 'first_name', 'last_name', 'username', 'email', 'password', 'confirm_password', 'profile_picture', 'is_active', 'is_staff', 'is_superuser', 'last_login', 'date_joined']
            else:
                fields = ['first_name', 'last_name', 'username', 'email', 'password', 'confirm_password']
        else:
            fields = ['first_name', 'last_name', 'username', 'email', 'password', 'confirm_password']

        allowed = set(fields)
        existing = set(self.fields.keys())
        for fieldname in existing - allowed:
            self.fields.pop(fieldname)
        print(self.fields.keys())


    password = serializers.CharField(style = {'input_type' : 'password'}, write_only=True)
    confirm_password = serializers.CharField(style = {'input_type' : 'password'}, write_only=True)

    class Meta:
        model = UserAccount
        fields = ['pk', 'first_name', 'last_name', 'username', 'email', 'password', 'confirm_password', 'is_active', 'profile_picture', 'is_active', 'is_staff', 'is_superuser', 'last_login', 'date_joined']

        extra_kwargs = {
            'username' : {
                'validators' : None
            },
            'email' : {
                'validators' : None
            },
        }


    def validate_username(self, value):
        username = value
        try:
            UsernameValidator(username)
        except:
            raise serializers.ValidationError({'username' : "Username is not valid."})
        
        try:
            user = UserAccount.objects.get(username__iexact = username)
        except UserAccount.DoesNotExist:
            return username
        else:
            raise serializers.ValidationError({'username' : "Username is already in use."})
            


    def validate_email(self, value):
        email = value

        users = UserAccount.objects.filter(email__iexact = email).count()
        if users == 0:
            return email
        else:
            raise serializers.ValidationError({'email' : "email is already in use."})


    
    def validate(self, attrs):  
        # Get the password from the data.
        password = attrs.get('password')
        confirm_password = attrs.pop('confirm_password')

        # confirm_password = data.get('confirm_password')
        # del data['confirm_password']

        if password != confirm_password:
            raise serializers.ValidationError({'password' : "Two passwords aren't equal."})

        # Here data has all the fields which have validated values.
        # So we can create a User instance out of it.
        user = UserAccount(**attrs)
        
        errors_dict = dict()

        try:
            # Validate the password and catch the exception
            password_validators.validate_password(password=password, user=user)

        # The exception raised here is different than serializers.ValidationError
        except exceptions.ValidationError as e:
            errors_dict['password'] = list(e.messages)

        if errors_dict:
            raise serializers.ValidationError(errors_dict)

        return super(UserAccountRegisterSerializer, self).validate(attrs)


    def save(self, **kwargs):
        self.validated_data['password'] = make_password(password=self.validated_data.get('password'))
        return super().save(**kwargs)

    # def create(self, validated_data):
    #     validated_data['password'] = make_password(password=validated_data.get('password'))
    #     return super().create(validated_data)







class UserAccountSerilalizer(serializers.ModelSerializer):

    def __init__(self, *args, **kwargs):
        super(UserAccountSerilalizer, self).__init__(*args, **kwargs)
        self.serializer_request = self.context.get('serializer_request')
        # self.admin_view = self.context.get('admin_view')
        self.pk = self.context.get('pk')

        if self.serializer_request.user.is_authenticated:
            if self.serializer_request.user.is_superuser or self.serializer_request.user.is_staff:
                fields = ['pk', 'first_name', 'last_name', 'username', 'email', 'profile_picture', 'new_email', 'is_active', 'is_staff', 'is_superuser', 'last_login', 'date_joined']
            elif self.serializer_request.user.pk == self.pk:
                fields = ['first_name', 'last_name', 'username', 'email', 'profile_picture']
            else:
                fields = ['first_name', 'last_name', 'username', 'profile_picture']
        else:
            fields = ['first_name', 'last_name', 'username', 'profile_picture']

        allowed = set(fields)
        existing = set(self.fields.keys())
        for fieldname in existing - allowed:
            self.fields.pop(fieldname)


    class Meta:
        model = UserAccount
        fields = ['pk', 'first_name', 'last_name', 'username', 'email', 'profile_picture', 'new_email', 'is_active', 'is_staff', 'is_superuser', 'last_login', 'date_joined']





class UserAccountUpdateSerilalizer(serializers.ModelSerializer):
    def __init__(self, *args, **kwargs):
        super(UserAccountUpdateSerilalizer, self).__init__(*args, **kwargs)
        self.serializer_request = self.context.get('serializer_request')
        # self.admin_view = self.context.get('admin_view')
        self.object = self.context.get('object')


        if self.serializer_request.user.is_authenticated:
            if self.serializer_request.user.is_superuser or self.serializer_request.user.is_staff:
                fields = ['first_name', 'last_name', 'username', 'email', 'profile_picture', 'new_email', 'is_active', 'is_staff', 'is_superuser', 'last_login', 'date_joined']
            elif str(self.serializer_request.user.pk) == str(self.instance.pk):
                fields = ['first_name', 'last_name', 'username', 'email', 'profile_picture']
        else:
            fields = []

        allowed = set(fields)
        existing = set(self.fields.keys())
        for fieldname in existing - allowed:
            self.fields.pop(fieldname)

        # self.fields['new_email'] = serializers.HiddenField(default=self.instance.new_email)

    class Meta:
        model = UserAccount
        fields = ['first_name', 'last_name', 'username', 'email', 'profile_picture', 'new_email', 'is_active', 'is_staff', 'is_superuser', 'last_login', 'date_joined']

        extra_kwargs = {
            'username' : {
                'validators' : None
            },
            'email' : {
                'validators' : None
            },
        }



    def validate_username(self, value):
        username = value
        try:
            UsernameValidator(username)
        except:
            raise serializers.ValidationError({'username' : "Username is not valid."})
        
        try:
            user = UserAccount.objects.get(username__iexact = username)
        except UserAccount.DoesNotExist:
            return username
        else:
            if user == self.serializer_request.user:
                return username
            else:
                raise serializers.ValidationError({'username' : "Username is already in use."})



    def validate_email(self, value):
        email = value

        users = UserAccount.objects.filter(email__iexact = email)
        users_count = users.count()
        if users_count == 0:
            return email
        elif users_count == 1:

            if users.get() == self.serializer_request.user:
                return email
            else:
                raise serializers.ValidationError({'email' : "email is already in use."})
        else:
            raise serializers.ValidationError({'email' : "email is already in use."})






class CustomTokenObtainPairSerializer(serializers.Serializer):

    default_error_messages = {
        "no_active_account": _("No active account found with the given credentials")
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # self.serializer_request = self.context.get('serializer_request')
        self.fields['email_username'] = serializers.CharField(label='Email or Username')
        self.fields['password'] = serializers.CharField(style = {'input_type' : 'password'}, write_only=True)


    def validate(self, attrs):
        email_username = attrs.get('email_username')
        authenticate_kwargs = dict()

        if str(email_username).__contains__('@'):
            try:
                email = UserAccount.objects.get(email__iexact=email_username).email
            except UserAccount.DoesNotExist:
                email = None

            authenticate_kwargs = {
                "email": email,
                "password": attrs.get('password'),
        }
        else:
            try:
                email = UserAccount.objects.get(username__iexact=email_username).email
            except UserAccount.DoesNotExist:
                email = None

            authenticate_kwargs = {
                "email": email,
                "password": attrs.get('password'),
        }
        
        try:
            authenticate_kwargs["request"] = self.context["request"]
        except KeyError:
            pass

        self.user = authenticate(**authenticate_kwargs)

        if not api_settings.USER_AUTHENTICATION_RULE(self.user):
            raise rest_exceptions.AuthenticationFailed(
                self.error_messages["no_active_account"],
                "no_active_account",
            )

        data = dict()
        refresh = RefreshToken.for_user(self.user)

        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        user_info = {
            "pk": self.user.pk,
            "first_name": self.user.first_name,
            "last_name": self.user.last_name,
            "username": self.user.username,
            "email": self.user.email,
            "profile_picture": self.user.profile_picture.url,
            "is_staff": self.user.is_staff,
            "is_superuser": self.user.is_superuser,
        }
        data["user_info"] = user_info
        return data





class PasswordResetSerializer(serializers.Serializer):
    def __init__(self,*args, **kwargs):
        super().__init__(*args, **kwargs)
        self.opts = self.context.get('opts')
        self.use_https = self.opts.get('use_https')
        self.token_generator = self.opts.get('token_generator')
        self.from_email = self.opts.get('from_email')
        self.email_template_name = self.opts.get('email_template_name')
        self.subject_template_name = self.opts.get('subject_template_name')
        self.request = self.opts.get('request')
        self.html_email_template_name = self.opts.get('html_email_template_name')
        self.extra_email_context = self.opts.get('extra_email_context')

        self.fields['email_username'] = serializers.CharField(required=True)


    def validate(self, attrs):
        email_username = attrs.get('email_username')
        if str(email_username).__contains__('@'):
            try:
                attrs['email_username'] = UserAccount.objects.get(email__iexact=email_username).email
            except UserAccount.DoesNotExist:
                attrs['email_username'] = email_username
        else:
            try:
                attrs['email_username'] = UserAccount.objects.get(username__iexact=email_username).email
            except UserAccount.DoesNotExist:
                attrs['email_username'] = email_username
        return super().validate(attrs)


    def send_mail(
        self,
        subject_template_name,
        email_template_name,
        context,
        from_email,
        to_email,
        html_email_template_name=None,
    ):
        """
        Send a django.core.mail.EmailMultiAlternatives to `to_email`.
        """
        subject = loader.render_to_string(subject_template_name, context)
        # Email subject *must not* contain newlines
        subject = "".join(subject.splitlines())
        body = loader.render_to_string(email_template_name, context)

        email_message = EmailMultiAlternatives(subject, body, from_email, [to_email])
        if html_email_template_name is not None:
            html_email = loader.render_to_string(html_email_template_name, context)
            email_message.attach_alternative(html_email, "text/html")

        email_message.send()


    def get_users(self, email):
        """Given an email, return matching user(s) who should receive a reset.

        This allows subclasses to more easily customize the default policies
        that prevent inactive users and users with unusable passwords from
        resetting their password.
        """
        email_field_name = UserModel.get_email_field_name()
        active_users = UserModel._default_manager.filter(
            **{
                "%s__iexact" % email_field_name: email,
                "is_active": True,
            }
        )
        return (
            u
            for u in active_users
            if u.has_usable_password()
            and _unicode_ci_compare(email, getattr(u, email_field_name))
        )

    def save(self, domain_override=None, **kwargs):
        """
        Generate a one-use only link for resetting password and send it to the
        user.
        """
        email = self.validated_data.get('email_username')

        if not domain_override:
            current_site = get_current_site(self.request)
            site_name = current_site.name
            domain = current_site.domain
        else:
            site_name = domain = domain_override
        # current_site = get_current_site(self.request)
        # site_name = current_site.name
        # domain = current_site.domain

        email_field_name = UserModel.get_email_field_name()
        for user in self.get_users(email):
            user_email = getattr(user, email_field_name)
            context = {
                "email": user_email,
                "domain": domain,
                "site_name": site_name,
                "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                "user": user,
                "token": self.token_generator.make_token(user),
                "protocol": "https" if self.use_https else "http",
                **(self.extra_email_context or {}),
            }
            self.send_mail(
                self.subject_template_name,
                self.email_template_name,
                context,
                self.from_email,
                user_email,
                html_email_template_name=self.html_email_template_name,
            )






class SetPasswordSerializer(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = self.context.get('user')

        self.fields['new_password1'] = serializers.CharField(style = {'input_type' : 'password'}, write_only=True, required=True)
        self.fields['new_password2'] = serializers.CharField(style = {'input_type' : 'password'}, write_only=True, required=True)

    def validate(self, attrs):
        new_password1 = attrs.get('new_password1')
        new_password2 = attrs.get('new_password2')


        if new_password1 != new_password2:
            raise serializers.ValidationError({'password' : "Two passwords aren't equal."})

        errors_dict = dict()

        try:
            password_validators.validate_password(password=new_password1, user=self.user)
        except exceptions.ValidationError as e:
            errors_dict['password'] = list(e.messages)

        if errors_dict:
            raise serializers.ValidationError(errors_dict)

        return super().validate(attrs)


    def save(self, **kwargs):
        password = self.validated_data.get('new_password1')
        self.user.set_password(password)
        self.user.save()
        return self.user



class PasswordChangeSerializer(serializers.Serializer):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['old_password'] = serializers.CharField(style = {'input_type' : 'password'}, write_only=True, required=True)
        self.fields['new_password1'] = serializers.CharField(style = {'input_type' : 'password'}, write_only=True, required=True)
        self.fields['new_password2'] = serializers.CharField(style = {'input_type' : 'password'}, write_only=True, required=True)


    def validate(self, attrs):
        old_password = attrs.get('old_password')
        new_password1 = attrs.get('new_password1')
        new_password2 = attrs.get('new_password2')

        errors_dict = dict()
        if old_password == None:
            errors_dict['old_password'] = "This field is required."

        if new_password1 == None:
            errors_dict['new_password1'] = "This field is required."

        if new_password2 == None:
            errors_dict['new_password2'] = "This field is required."
        
        if errors_dict:
            raise serializers.ValidationError(errors_dict)



        if not self.instance.check_password(old_password):
            raise serializers.ValidationError({'old_Password' : _("Your old password was entered incorrectly. Please enter it again.")})

        if new_password1 != new_password2:
            raise serializers.ValidationError({'New Password' : _("The two password fields didn’t match.")})

        errors_dict = dict()

        try:
            password_validators.validate_password(password=new_password1, user=self.instance)
        except exceptions.ValidationError as e:
            errors_dict['password'] = list(e.messages)

        if errors_dict:
            raise serializers.ValidationError(errors_dict)

        return super().validate(attrs)


    def save(self, **kwargs):
        new_password = self.validated_data.get('new_password1')
        self.instance.set_password(new_password)
        self.instance.save()
        return self.instance


class UserAccountDeleteSerilalizer(serializers.Serializer):
    def __init__(self, instance=None, data=..., **kwargs):
        super().__init__(instance, data, **kwargs)
        self.fields['password'] = serializers.CharField(style = {'input_type' : 'password'}, write_only=True)

    def validate(self, attrs):
        password = attrs.get('password')

        if not self.instance.check_password(password):
            raise serializers.ValidationError({'password' : "Password is not valid."})
        return super().validate(attrs)