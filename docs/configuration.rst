Configuration
=============

- **REST_AUTH_SERIALIZERS**

    You can define your custom serializers for each endpoint without overriding urls and views by adding ``REST_AUTH_SERIALIZERS`` dictionary in your django settings.
    Possible key values:

        - LOGIN_SERIALIZER - serializer class in ``rest_auth.views.LoginView``, default value ``rest_auth.serializers.LoginSerializer``

        - SIMPLE_LOGIN_SERIALIZER - serializer class in ``rest_auth.views.SimpleLoginView``, default value ``rest_auth.serializers.SimpleLoginSerializer``

        - TOKEN_SERIALIZER - response for successful authentication in ``rest_auth.views.LoginView``, default value ``rest_auth.serializers.TokenSerializer``

        - USER_DETAILS_SERIALIZER - serializer class in ``rest_auth.views.UserDetailsView``, default value ``rest_auth.serializers.UserDetailsSerializer``

        - PASSWORD_RESET_SERIALIZER - serializer class in ``rest_auth.views.PasswordResetView``, default value ``rest_auth.serializers.PasswordResetSerializer``

        - PASSWORD_RESET_CONFIRM_SERIALIZER - serializer class in ``rest_auth.views.PasswordResetConfirmView``, default value ``rest_auth.serializers.PasswordResetConfirmSerializer``

        - PASSWORD_CHANGE_SERIALIZER - serializer class in ``rest_auth.views.PasswordChangeView``, default value ``rest_auth.serializers.PasswordChangeSerializer``


    Example configuration:

    .. code-block:: python

        REST_AUTH_SERIALIZERS = {
            'LOGIN_SERIALIZER': 'path.to.custom.LoginSerializer',
            'TOKEN_SERIALIZER': 'path.to.custom.TokenSerializer',
            ...
        }


- **REST_SESSION_LOGIN** - Enable session login in Login API view (default: True)


- **OLD_PASSWORD_FIELD_ENABLED** - set it to True if you want to have old password verification on password change enpoint (default: False)


- **NEW_PASSWORD_2_FIELD_ENABLED** - set it to False if you don't need new password confirmation (default: True)


- **USER_DETAILS_INCLUDED** - is user details urls are needed


- **SIMPLE_LOGIN** - is simplified is used


- **USING_SESSION_KEY** - getting user by session_key, not from request object