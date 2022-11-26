from django.contrib.auth.tokens import PasswordResetTokenGenerator 
import six
# from django.utils import six  


class NewAccountTokenGenerator(PasswordResetTokenGenerator):  
    def _make_hash_value(self, user, timestamp):  
        return (  
            six.text_type(user.pk) + six.text_type(timestamp) +  
            six.text_type(user.is_active) + six.text_type(user.verification_token)
        )
account_email_activation_token = NewAccountTokenGenerator()
