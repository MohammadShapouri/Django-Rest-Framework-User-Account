from django.contrib.auth import get_user_model
# For password reset option.
from django.contrib.auth.tokens import default_token_generator
from extentions.emailVerification.EmailVerifier import (ActivateNewEmailView,
                                                        ActivateView,
                                                        EmailVerifier)
from rest_framework import status
from rest_framework.generics import GenericAPIView, UpdateAPIView
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.views import TokenViewBase
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser

from .serializers import (CustomTokenObtainPairSerializer,
                          PasswordResetSerializer,
                          UserAccountRegisterSerializer,
                          UserAccountSerilalizer, UserAccountUpdateSerilalizer,
                          SetPasswordSerializer,
                          PasswordChangeSerializer,
                          UserAccountDeleteSerilalizer)

from rest_framework.permissions import AllowAny, IsAuthenticated
from .permissions import AllowOwnersAdmins
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
import random
import string
# For Password Reset option.
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.utils.http import urlsafe_base64_decode
from django.http import HttpResponseRedirect
from rest_framework.exceptions import PermissionDenied
# Create your views here.



UserAccount = get_user_model()
UserModel = UserAccount

class UserAccountViewSet(ModelViewSet, EmailVerifier):

    parser_classes = [MultiPartParser, FormParser, JSONParser]
    queryset = UserAccount.objects.all()

    def get_serializer_class(self):
        request_method = self.request.method
        if request_method == 'POST':
            return UserAccountRegisterSerializer
        elif request_method == 'GET':
            return UserAccountSerilalizer
        elif request_method == 'PUT' or request_method == 'PATCH':
            return UserAccountUpdateSerilalizer
        elif request_method == 'DELETE':
            return UserAccountDeleteSerilalizer
        return super().get_serializer_class()


    def get_permissions(self):
        if self.request.method == 'POST' or self.request.method == 'GET':
            permission_classes = [AllowAny]
        else:
            # action is 'update' or 'partial_update' or 'destroy':
            permission_classes = [AllowOwnersAdmins]
        return [permission() for permission in permission_classes]


    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({'serializer_request' : self.request})
        # context.update({ 'admin_view' : False})
        # context.update({'object' : self.get_object()})
        return context



    def verification_token_generator(self):
        allowed_chars = string.ascii_letters + string.digits
        return ''.join(random.choices(allowed_chars, k=32))


    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.save(is_active=False, is_account_verified=False, verification_token=self.verification_token_generator())
        headers = self.get_success_headers(serializer.data)
        self.mail_subject = 'Activate Your Account.'
        self.verify_email_DRF_BASE(request, user)
        return Response({'User Account' : "Account added. Check your emails to verify your account.", 'Account Detail' : serializer.data}, status=status.HTTP_201_CREATED, headers=headers)




    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        
        validated_data = serializer.validated_data
        new_email = validated_data.get('email')
        if new_email != None:
            del validated_data['email']
        if instance.email != new_email:
            user = serializer.save(new_email=new_email, is_n_email_verified=False, verification_token=self.verification_token_generator())
            self.new_mail_subject = 'Verify Your New Email.'
            self.verify_new_email_DRF_BASE(request, user)
        else:
            serializer.save()

        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}
        return Response(serializer.data)




    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_destroy(instance)
        return Response(status.HTTP_204_NO_CONTENT)





class ActivateUserAccount(ActivateView):
    permission_classes = [AllowAny]
    pass


class ActivateEmail(ActivateNewEmailView):
    permission_classes = [AllowAny]
    pass


class CustomTokenObtainPairView(TokenViewBase):
    permission_classes = [AllowAny]
    serializer_class = CustomTokenObtainPairSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({ 'serializer_request' : self.request})
        return context



class PasswordResetView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetSerializer

    email_template_name = "userAccount/password_reset_email.html"
    extra_email_context = None
    from_email = None
    html_email_template_name = None
    subject_template_name = "userAccount/password_reset_subject.txt"
    token_generator = default_token_generator
    

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({'opts' : {
            "use_https": self.request.is_secure(),
            "token_generator": self.token_generator,
            "from_email": self.from_email,
            "email_template_name": self.email_template_name,
            "subject_template_name": self.subject_template_name,
            "request": self.request,
            "html_email_template_name": self.html_email_template_name,
            "extra_email_context": self.extra_email_context,
        }
        })
        return context


    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'Password Reset Email' : "Password reset email sent."}, status=status.HTTP_201_CREATED)



INTERNAL_RESET_SESSION_TOKEN = "_password_reset_token"
class PasswordResetConfirmView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = SetPasswordSerializer

    reset_url_token = "set-password"
    token_generator = default_token_generator

    
    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        if "uidb64" not in kwargs or "token" not in kwargs:
            raise ImproperlyConfigured(
                "The URL path must contain 'uidb64' and 'token' parameters."
            )

        self.validlink = False
        # self.user = self.get_user(kwargs["uidb64"])
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(kwargs["uidb64"]).decode()
            self.user = UserModel._default_manager.get(pk=uid)
        except (
            TypeError,
            ValueError,
            OverflowError,
            UserModel.DoesNotExist,
            ValidationError,
        ):
            self.user = None

        if self.user is not None:
            if self.token_generator.check_token(self.user, kwargs["token"]):
                self.validlink = True
                return super().dispatch(request, *args, **kwargs)
            # else:
            #     return PermissionDenied()

                
        # if self.user is not None:
        #     token = kwargs["token"]
        #     if token == self.reset_url_token:
        #         session_token = self.request.session.get(INTERNAL_RESET_SESSION_TOKEN)
        #         if self.token_generator.check_token(self.user, session_token):
        #             # If the token is valid, display the password reset form.
        #             self.validlink = True
        #             return super().dispatch(request, *args, **kwargs)
        #         else:
        #             if session_token != None:
        #                 del self.request.session[INTERNAL_RESET_SESSION_TOKEN]
        #     else:
        #         if self.token_generator.check_token(self.user, token):
        #             # Store the token in the session and redirect to the
        #             # password reset form at a URL without the token. That
        #             # avoids the possibility of leaking the token in the
        #             # HTTP Referer header.
        #             self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
        #             redirect_url = self.request.path.replace(
        #                 token, self.reset_url_token
        #             )
        #             return HttpResponseRedirect(redirect_url)
        #         else:
        #             self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
        #             redirect_url = self.request.path.replace(
        #                 token, self.reset_url_token
        #             )
        #             return HttpResponseRedirect(redirect_url)
        
        # Display the "Password reset unsuccessful" page.
        # return HttpResponseRedirect({'Password Reset' : "Password reset unsuccessful."}, status=status.HTTP_400_BAD_REQUEST)
        return super().dispatch(request, *args, **kwargs)




    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({'user' : self.user})
        return context

    def get(self, request, *args, **kwargs):
        if self.validlink:
            return Response(data='Link is valid for resetting password.', status=status.HTTP_200_OK)
        else:
            raise PermissionDenied(detail='This link is not valid for resetting password.', code=status.HTTP_403_FORBIDDEN)

    def post(self, request, *args, **kwargs):
        if self.validlink:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            # Delete the session.
            # del self.request.session[INTERNAL_RESET_SESSION_TOKEN]
            return Response({'Password' : "New password set."}, status=status.HTTP_200_OK)
        else:
            return Response(data='This link is not valid for resetting password.', status=status.HTTP_403_FORBIDDEN)




class PasswordChangeView(UpdateAPIView):
    permission_classes = [AllowOwnersAdmins]
    serializer_class = PasswordChangeSerializer

    def get_object(self):
        pk = self.kwargs.get('pk')
        return UserAccount.objects.get(pk=pk)
        
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}
        return Response({'Password' : "New password set."}, status=status.HTTP_200_OK)




# INTERNAL_RESET_SESSION_TOKEN = "_password_reset_token"
# class PasswordResetConfirmView(GenericAPIView):
#     serializer_class = SetPasswordSerializer

#     reset_url_token = "set-password"
#     token_generator = default_token_generator

    
#     @method_decorator(sensitive_post_parameters())
#     @method_decorator(never_cache)
#     def dispatch(self, request, *args, **kwargs):
#         if "uidb64" not in kwargs or "token" not in kwargs:
#             raise ImproperlyConfigured(
#                 "The URL path must contain 'uidb64' and 'token' parameters."
#             )

#         self.validlink = False
#         # self.user = self.get_user(kwargs["uidb64"])
#         try:
#             # urlsafe_base64_decode() decodes to bytestring
#             uid = urlsafe_base64_decode(kwargs["uidb64"]).decode()
#             self.user = UserModel._default_manager.get(pk=uid)
#         except (
#             TypeError,
#             ValueError,
#             OverflowError,
#             UserModel.DoesNotExist,
#             ValidationError,
#         ):
#             self.user = None


#         if self.user is not None:
#             print('*****Test 1')
#             token = kwargs["token"]
#             print(f'*****PRE Test 2, {token}, {self.reset_url_token}')
#             if token == self.reset_url_token:
#                 print(f'*****Test 2, {token}, {self.reset_url_token}')
#                 session_token = self.request.session.get(INTERNAL_RESET_SESSION_TOKEN)
#                 if self.token_generator.check_token(self.user, session_token):
#                     print('*****Test 3')
#                     # If the token is valid, display the password reset form.
#                     self.validlink = True
#                     return super().dispatch(request, *args, **kwargs)
#                 else:
#                     print('*****Test 4')
#                     if session_token != None:
#                         print('*****Test 5')
#                         del self.request.session[INTERNAL_RESET_SESSION_TOKEN]
#             else:
#                 print('*****Test 6')
#                 if self.token_generator.check_token(self.user, token):
#                     print('*****Test 7')
#                     # Store the token in the session and redirect to the
#                     # password reset form at a URL without the token. That
#                     # avoids the possibility of leaking the token in the
#                     # HTTP Referer header.
#                     self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
#                     redirect_url = self.request.path.replace(
#                         token, self.reset_url_token
#                     )
#                     return HttpResponseRedirect(redirect_url)
#                 else:
#                     print('*****Test 8')
#                     self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
#                     redirect_url = self.request.path.replace(
#                         token, self.reset_url_token
#                     )
#                     return HttpResponseRedirect(redirect_url)
        
#         # Display the "Password reset unsuccessful" page.
#         # return HttpResponseRedirect({'Password Reset' : "Password reset unsuccessful."}, status=status.HTTP_400_BAD_REQUEST)
#         return super().dispatch(request, *args, **kwargs)



#     # @api_view(['POST'])
#     # def get_user(self, uidb64):
#     #     try:
#     #         # urlsafe_base64_decode() decodes to bytestring
#     #         uid = urlsafe_base64_decode(uidb64).decode()
#     #         user = UserModel._default_manager.get(pk=uid)
#     #     except (
#     #         TypeError,
#     #         ValueError,
#     #         OverflowError,
#     #         UserModel.DoesNotExist,
#     #         ValidationError,
#     #     ):
#     #         user = None
#     #     return user

#     def get_serializer_context(self):
#         context = super().get_serializer_context()
#         context.update({'user' : self.user})
#         return context

#     def get(self, request, *args, **kwargs):
#         if self.validlink:
#             serializer = self.get_serializer()
#             return Response(serializer.data)
#         else:
#             raise PermissionDenied(detail='This link is not valid for resetting password.', code=status.HTTP_403_FORBIDDEN)

#     def post(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#         # Delete the session.
#         del self.request.session[INTERNAL_RESET_SESSION_TOKEN]
#         return Response({'Password' : "New password set."}, status=status.HTTP_200_OK)

