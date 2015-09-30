from six import string_types
import sys
if sys.version_info < (2, 7):
    from django.utils.importlib import import_module
else:
    from importlib import import_module
from django.conf import settings
from django.contrib.auth import SESSION_KEY, get_user_model


def import_callable(path_or_callable):
    if hasattr(path_or_callable, '__call__'):
        return path_or_callable
    else:
        assert isinstance(path_or_callable, string_types)
        package, attr = path_or_callable.rsplit('.', 1)
        return getattr(import_module(package), attr)


def get_user_id_by_session_key(session_key):
    """
    Returns user identifier by session_key
    """
    store = get_session_by_session_key(session_key)
    return get_user_model()._meta.pk.to_python(store.get(SESSION_KEY or None))


def get_session_by_session_key(session_key):
    """
    Returns session store by session_key
    """
    session_store_module = import_module(settings.SESSION_ENGINE)
    return session_store_module.SessionStore(session_key=session_key)


def flush_session_by_session_key(session_key):
    """
    Flushes session by session_key
    """
    store = get_session_by_session_key(session_key)
    store.flush()
