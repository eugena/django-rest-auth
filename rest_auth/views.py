from django.contrib.auth import login, logout, get_user_model
from django.conf import settings

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.models import Token
from rest_framework.generics import RetrieveUpdateAPIView

from .app_settings import (
    TokenSerializer, UserDetailsSerializer, SimpleLoginSerializer, SimpleTokenLoginSerializer,
    LoginSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer,
    PasswordChangeSerializer
)

from .utils import get_user_id_by_session_key, flush_session_by_session_key


class BaseSimpleLoginView(GenericAPIView):

    permission_classes = (AllowAny,)

    def login(self):
        self.user = self.serializer.validated_data['user']

        if getattr(settings, 'REST_SESSION_LOGIN', True):
            login(self.request, self.user)

    def get_error_response(self):
        return Response(
            self.serializer.errors, status=status.HTTP_400_BAD_REQUEST
        )

    def post(self, request, *args, **kwargs):
        self.serializer = self.get_serializer(data=self.request.data)
        if not self.serializer.is_valid():
            return self.get_error_response()
        self.login()
        return Response({'session_key': request.session.session_key}, status=status.HTTP_200_OK)


class SimpleLoginView(BaseSimpleLoginView):

    """
    Check the credentials and authenticated if the credentials are valid.
    Calls Django Auth login method to register User ID
    in Django session framework

    Accept the following POST parameters: username, password
    """
    serializer_class = SimpleLoginSerializer


class SimpleTokenLoginView(BaseSimpleLoginView):

    """
    Check the credentials and authenticated if the credentials are valid.
    Calls Django Auth login method to register User ID
    in Django session framework

    Accept the following POST parameters: uid, token
    """
    serializer_class = SimpleTokenLoginSerializer


class LoginView(GenericAPIView):

    """
    Check the credentials and return the REST Token
    if the credentials are valid and authenticated.
    Calls Django Auth login method to register User ID
    in Django session framework

    Accept the following POST parameters: username, password
    Return the REST Framework Token Object's key.
    """
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer
    token_model = Token
    response_serializer = TokenSerializer

    def login(self):
        self.user = self.serializer.validated_data['user']
        self.token, created = self.token_model.objects.get_or_create(
            user=self.user)
        if getattr(settings, 'REST_SESSION_LOGIN', True):
            login(self.request, self.user)

    def get_response(self):
        return Response(
            self.response_serializer(self.token).data, status=status.HTTP_200_OK
        )

    def get_error_response(self):
        return Response(
            self.serializer.errors, status=status.HTTP_400_BAD_REQUEST
        )

    def post(self, request, *args, **kwargs):
        self.serializer = self.get_serializer(data=self.request.data)
        if not self.serializer.is_valid():
            return self.get_error_response()
        self.login()
        return self.get_response()


class LogoutView(APIView):

    """
    Calls Django logout method and delete the Token object
    assigned to the current User object.

    Accepts/Returns nothing.
    """
    permission_classes = (AllowAny,)

    def post(self, request, **kwargs):
        if getattr(settings, 'USING_SESSION_KEY', False):
            flush_session_by_session_key(self.kwargs.get('session_key'))
        else:
            try:
                request.user.auth_token.delete()
            except:
                pass

            logout(request)
        response = Response(
            {"success": "Successfully logged out."},
            status=status.HTTP_200_OK)
        response.delete_cookie(settings.SESSION_COOKIE_NAME)
        return response


class UserDetailsView(RetrieveUpdateAPIView):

    """
    Returns User's details in JSON format.

    Accepts the following GET parameters: token
    Accepts the following POST parameters:
        Required: token
        Optional: email, first_name, last_name and UserProfile fields
    Returns the updated UserProfile and/or User object.
    """
    serializer_class = UserDetailsSerializer
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        if getattr(settings, 'USING_SESSION_KEY', False):
            try:
                user = get_user_model()._default_manager.get(
                    pk=get_user_id_by_session_key(self.context.get('view').kwargs.get('session_key') or None))
            except:
                user = None
        else:
            user = self.request.user
        return user


class PasswordResetView(GenericAPIView):

    """
    Calls Django Auth PasswordResetForm save method.

    Accepts the following POST parameters: email
    Returns the success/fail message.
    """

    serializer_class = PasswordResetSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        # Create a serializer with request.data
        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)
        serializer.save()
        # Return the success message with OK HTTP status
        return Response(
            {"success": "Password reset e-mail has been sent."},
            status=status.HTTP_200_OK
        )


class PasswordResetConfirmView(GenericAPIView):

    """
    Password reset e-mail link is confirmed, therefore this resets the user's password.

    Accepts the following POST parameters: new_password1, new_password2
    Accepts the following Django URL arguments: token, uid
    Returns the success/fail message.
    """

    serializer_class = PasswordResetConfirmSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )
        serializer.save()
        return Response({"success": "Password has been reset with the new password."})


class PasswordChangeView(GenericAPIView):

    """
    Calls Django Auth SetPasswordForm save method.

    Accepts the following POST parameters: new_password1, new_password2
    Returns the success/fail message.
    """

    serializer_class = PasswordChangeSerializer

    def __init__(self):
        if not getattr(settings, 'USING_SESSION_KEY', False):
            self.permission_classes = (IsAuthenticated,)
        super(PasswordChangeView, self).__init__()

    def post(self, request, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )
        serializer.save()
        return Response({"success": "New password has been saved."})
