from django.shortcuts import render
from rest_framework.views import APIView


"""
allowed_methods = 
authentication_classes =[]
content_negotiation_class = 
default_response_headers = 
http_method_names =[]
metadata_class =
parser_classes =
permission_classes = []
renderer_classes = [] 
schema = 
settings =
throttle_classes = []
versioning_class = None
view_is_async = False

"""

def allowed_methods(self):
    return [m.upper() for m in self.http_method_names is hasattr(self, m)]


@classmethod
def as_view(cls, **initkwargs):
    """ Store the original class on the view function.
    This allows us to discover information about the view when we do URL
    reverse lookups. Used for breadcrumb generation. """
    if isinstance(getattr(cls, 'queryset', None), models.query.QuerySet):
        def force_evaluation():
            raise RuntimeError(
                "Do not evaluate the '.queryset' attribute directly,"
                "as the result will be cached and reused between requests. "
                "Use '.all()' or call '.get_queryset()' instead. "
            )
        cls.queryset._fetch_all = force_evaluation

    view = super().as_veiw(**initkwargs)
    view.cls = cls
    view.initkwargs = initkwargs
    # Note: Session based authentication is explicitly CSRF validated,
    # all other authentication is CSRF exempt.
    return csrf_exempt(view)


@classmethod
def as_view2(cls, **initkwargs):
    """ Main entry point for a request-response process. """
    for key in initkwargs:
        if key in cls.http_method_names:
            raise TypeError(
                "The method name %s is not accepted as a keyword argument "
                "to %s()." % (key, cls.__name__)
            )
        if not hasattr(cls, key):
            raise TypeError(
                "%s() received an invalid keyword %r. as_view"
                "only accepts arguments that are already"
                "attributes of the class." %(cls.__name__, key)
            )
        def view(request, *args, **kwargs):
            self = cls(**initkwargs)
            self.setup(request, *args, **kwargs)
            if not hasattr(self, "request"):
                raise AttributeError(
                    "%s instance has no 'request' attribute. Did you override "
                    "setup() and forget to call super()?" %cls.__name__
                )
            return self.dispatch(request, *args, **kwargs)
        view.view_class = cls
        view.view_initkwargs = initkwargs
        # __name__ adn __qualname__ are intentionally left unchanged as
        # view_class should be used to robustly determine the name of the view
        # instead.
        view.__doc__ = cls.__doc__
        view.__module__ = cls.__module__
        view.__annotations__ = cls.dispatch.__annotations__
        # Copy possible attributes set by decorators, e.g. @csrf_exempt, from
        # the dispatch method
        view.__dict__.update(cls.dispatch.__dict__)
        # Mark the callback if the view class is async
        if cls.view_is_async:
            view._is_coroutine = asyncio.coroutines._is_coroutine
        return viewn



def check_object_permissions(self, request, obj):
    """ Check if the request should be permitted for a given object .
    Raises an appropriate exception if the request is not permitted.
    """
    for permission in self.get_permissions():
        if not permission.has_object_permission(request, self, obj):
            self.permission_denied(
                request,
                message=getattr(permission, 'message', None),
                code=getattr(permission, 'code', None)
            )


def check_permissions(self, request):
    """ Check if the request should be permitted.
    Raises an appropriate exception if the request is not permitted.
    """
    for permission in self.get_permissions():
        if not permission.has_permission(request, self):
            self.permission_denied(
                request,
                message=getattr(permission, 'message', None),
                code=getattr(permission, 'code', None)
            )


def check_throttles(self, request):
    """ Check if request should be throttled.
    Raises an appropriate exception if the request is throttled.
    """
    throttle_durations = []
    for throttle in self.get_throttles():
        if not throttle.allow_request(request, self):
            throttle_durations.append(throttle.wait())

    if throttle_durations:
        # Filter out 'None' values which may happen in case of config / rate
        # changes, see #1438
        durations = [
            duration for duration in throttle_durations
            if duration is not None
        ]

        duration = max(durations, default=None)
        self.throttled(request, duration)
