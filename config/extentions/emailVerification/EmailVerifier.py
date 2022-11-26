from django.contrib.sites.shortcuts import get_current_site  
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode  
from django.template.loader import render_to_string  
from .TokenGenerator import account_email_activation_token  
from django.core.mail import EmailMessage
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status





class EmailVerifier():
    account_activition_email_template = 'emailVerification/acc_active_email.html'
    new_email_activitation_template = 'emailVerification/email_active_email.html'
    mail_subject = None
    new_mail_subject = None



    def verify_email_DRF_BASE(self, request, user):
        # to get the domain of the current site
        current_site = get_current_site(request)  
        # mail_subject = 'Activation link has been sent to your email id' 
        message = render_to_string(self.account_activition_email_template, { 
            'user': user,  
            'domain': current_site.domain,
            'uid':urlsafe_base64_encode(force_bytes(user.pk)),  
            'token':account_email_activation_token.make_token(user),  
        })
        to_email = user.email
        email = EmailMessage(
                    self.mail_subject, message, to=[to_email]  
        )
        email.send()




    def verify_new_email_DRF_BASE(self, request, user):
        # to get the domain of the current site
        current_site = get_current_site(request)
        # mail_subject = 'Activation link has been sent to your email id'
        message = render_to_string(self.new_email_activitation_template, {
            'user': user,
            'domain': current_site.domain,
            'uid':urlsafe_base64_encode(force_bytes(user.pk)),
            'token':account_email_activation_token.make_token(user),
        })
        to_email = user.new_email
        email = EmailMessage(
                    self.new_mail_subject, message, to=[to_email]
        )
        email.send()







class ActivateView(APIView):

    def get(self, request, uidb64, token):
        User = get_user_model()
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is not None and user.is_account_verified is False and account_email_activation_token.check_token(user, token):
            user.is_active = True
            user.is_account_verified = True
            user.verification_token = None
            user.save()

            return Response("Account Verified.", status=status.HTTP_200_OK)
        else:
            return Response("Link is invalid. It may be used.", status=status.HTTP_400_BAD_REQUEST)








class ActivateNewEmailView(APIView):

    def get(self, request, uidb64, token):
        User = get_user_model()
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is not None and user.is_n_email_verified == False and account_email_activation_token.check_token(user, token) and user.new_email is not None:
            user.email = user.new_email
            user.new_email = None
            user.is_n_email_verified = True
            user.verification_token = None
            user.save()
            
            return Response("Email Verified.", status=status.HTTP_200_OK)
        else:
            return Response("Link is invalid. It may be used.", status=status.HTTP_400_BAD_REQUEST)


