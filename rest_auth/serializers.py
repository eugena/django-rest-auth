import hashlib
from django.contrib.auth import get_user_model, authenticate
from django.conf import settings
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
try:
    from django.utils.http import urlsafe_base64_decode as uid_decoder
except:
    # make compatible with django 1.5
    from django.utils.http import base36_to_int as uid_decoder
from django.contrib.auth.tokens import default_token_generator
from django.utils.translation import ugettext_lazy as _

from rest_framework import serializers, exceptions
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import ValidationError

from .utils import get_user_id_by_session_key


class SimpleVerificationTokenGenerator(object):
    """
    Strategy object used to generate and check tokens for the email
    verification mechanism.
    """
    @classmethod
    def make_token(cls, value):
        """
        Returns a token that can be used once to do verification
        for the given value.
        """
        return hashlib.sha1(settings.SECRET_KEY.encode() + value.encode()).hexdigest()

    @classmethod
    def check_token(cls, value, token):
        """
        Check that a token is correct for a given value.
        """
        return token == hashlib.sha1(settings.SECRET_KEY.encode() + value.encode()).hexdigest()


class SimpleLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(style={'input_type': 'password'})

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(username=username, password=password)

        else:
            msg = _('Must include "username" and "password".')
            raise exceptions.ValidationError(msg)

        # Did we get back an active user?
        if user:
            if not user.is_active:
                msg = _('User account is disabled.')
                raise exceptions.ValidationError(msg)
        else:
            msg = _("User with this pair of email and password wasn't found")
            raise exceptions.ValidationError(msg)

        attrs['user'] = user
        return attrs


class SimpleTokenLoginSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()

    def validate(self, attrs):
        uidb64 = attrs.get('uid')
        token = attrs.get('token')

        if uidb64 and token:
            UserModel = get_user_model()
            # Decode the uidb64 to uid to get User object
            try:
                uid = uid_decoder(uidb64)
                usr = UserModel._default_manager.get(pk=uid)
                if not SimpleVerificationTokenGenerator.check_token(usr.email, token):
                    raise ValidationError({'token': ['Invalid token']})
                user = usr
                user.backend = 'django.contrib.auth.backends.ModelBackend'
            except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
                raise ValidationError({'uid': ['Invalid uid']})
        else:
            msg = _('Must include "uidb64" and "token".')
            raise exceptions.ValidationError(msg)

        # Did we get back an active user?
        if user:
            if not user.is_active:
                msg = _('User account is disabled.')
                raise exceptions.ValidationError(msg)
        else:
            msg = _('Unable to log in with provided credentials.')
            raise exceptions.ValidationError(msg)

        attrs['user'] = user
        return attrs


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(style={'input_type': 'password'})

    def validate(self, attrs):
        username = attrs.get('username')
        email = attrs.get('email')
        password = attrs.get('password')

        if 'allauth' in settings.INSTALLED_APPS:
            from allauth.account import app_settings
            # Authentication through email
            if app_settings.AUTHENTICATION_METHOD == app_settings.AuthenticationMethod.EMAIL:
                if email and password:
                    user = authenticate(email=email, password=password)
                else:
                    msg = _('Must include "email" and "password".')
                    raise exceptions.ValidationError(msg)
            # Authentication through username
            elif app_settings.AUTHENTICATION_METHOD == app_settings.AuthenticationMethod.USERNAME:
                if username and password:
                    user = authenticate(username=username, password=password)
                else:
                    msg = _('Must include "username" and "password".')
                    raise exceptions.ValidationError(msg)
            # Authentication through either username or email
            else:
                if email and password:
                    user = authenticate(email=email, password=password)
                elif username and password:
                    user = authenticate(username=username, password=password)
                else:
                    msg = _('Must include either "username" or "email" and "password".')
                    raise exceptions.ValidationError(msg)

        elif username and password:
            user = authenticate(username=username, password=password)

        else:
            msg = _('Must include "username" and "password".')
            raise exceptions.ValidationError(msg)

        # Did we get back an active user?
        if user:
            if not user.is_active:
                msg = _('User account is disabled.')
                raise exceptions.ValidationError(msg)
        else:
            msg = _('Unable to log in with provided credentials.')
            raise exceptions.ValidationError(msg)

        # If required, is the email verified?
        if 'rest_auth.registration' in settings.INSTALLED_APPS:
            from allauth.account import app_settings
            if app_settings.EMAIL_VERIFICATION == app_settings.EmailVerificationMethod.MANDATORY:
                email_address = user.emailaddress_set.get(email=user.email)
                if not email_address.verified:
                    raise serializers.ValidationError('E-mail is not verified.')

        attrs['user'] = user
        return attrs


class TokenSerializer(serializers.ModelSerializer):
    """
    Serializer for Token model.
    """

    class Meta:
        model = Token
        fields = ('key',)


class UserDetailsSerializer(serializers.ModelSerializer):

    """
    User model w/o password
    """
    class Meta:
        model = get_user_model()
        fields = ('username', 'email', 'first_name', 'last_name')
        read_only_fields = ('email', )


class PasswordResetSerializer(serializers.Serializer):

    """
    Serializer for requesting a password reset e-mail.
    """

    email = serializers.EmailField()

    password_reset_form_class = PasswordResetForm

    def validate_email(self, value):
        # Create PasswordResetForm with the serializer
        self.reset_form = self.password_reset_form_class(data=self.initial_data)
        if not self.reset_form.is_valid():
            raise serializers.ValidationError('Error')
        return value

    def save(self):
        request = self.context.get('request')
        # Set some values to trigger the send_email method.
        opts = {
            'use_https': request.is_secure(),
            'from_email': getattr(settings, 'DEFAULT_FROM_EMAIL'),
            'request': request,
        }
        self.reset_form.save(**opts)


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset e-mail.
    """

    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)

    uid = serializers.CharField(required=True)
    token = serializers.CharField(required=True)

    set_password_form_class = SetPasswordForm

    def custom_validation(self, attrs):
        pass

    def validate(self, attrs):
        self._errors = {}
        # Get the UserModel
        UserModel = get_user_model()
        # Decode the uidb64 to uid to get User object
        try:
            uid = uid_decoder(attrs['uid'])
            self.user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            raise ValidationError({'uid': ['Invalid value']})

        self.custom_validation(attrs)
        # Construct SetPasswordForm instance
        self.set_password_form = self.set_password_form_class(
            user=self.user, data=attrs
        )
        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)
        if not default_token_generator.check_token(self.user, attrs['token']):
            raise ValidationError({'token': ['Invalid value']})

        return attrs

    def save(self):
        self.set_password_form.save()


class PasswordChangeSerializer(serializers.Serializer):

    old_password = serializers.CharField(max_length=128, required=False)
    new_password1 = serializers.CharField(max_length=128, required=False)
    new_password2 = serializers.CharField(max_length=128, required=False)

    set_password_form_class = SetPasswordForm

    def __init__(self, *args, **kwargs):
        self.old_password_field_enabled = getattr(
            settings, 'OLD_PASSWORD_FIELD_ENABLED', False
        )

        self.new_password_2_field_enabled = getattr(
            settings, 'NEW_PASSWORD_2_FIELD_ENABLED', True
        )
        super(PasswordChangeSerializer, self).__init__(*args, **kwargs)

        if not self.old_password_field_enabled:
            self.fields.pop('old_password')

        if not self.new_password_2_field_enabled:
            self.fields.pop('new_password2')

        self.request = self.context.get('request')

        if getattr(settings, 'USING_SESSION_KEY', False):
            try:
                self.user = get_user_model()._default_manager.get(
                    pk=get_user_id_by_session_key(self.context.get('view').kwargs.get('session_key') or None))
            except:
                self.user = None
        else:
            self.user = getattr(self.request, 'user', None)

    def get_fields(self):
        """
        Returns fields
        """
        if self.fields:
            fields = self.fields
        else:
            fields = super(PasswordChangeSerializer, self).get_fields()
        for field in fields:
            fields[field].required = True
        return fields

    def validate_old_password(self, value):
        invalid_password_conditions = (
            self.old_password_field_enabled,
            self.user,
            not self.user.check_password(value)
        )

        if all(invalid_password_conditions):
            raise serializers.ValidationError('Invalid password')
        return value

    def validate(self, attrs):

        if not self.new_password_2_field_enabled:
            attrs['new_password2'] = attrs['new_password1']

        self.set_password_form = self.set_password_form_class(
            user=self.user, data=attrs
        )

        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)
        return attrs

    def save(self):
        self.set_password_form.save()
