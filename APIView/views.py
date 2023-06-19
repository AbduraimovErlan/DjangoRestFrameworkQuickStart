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



def determine_version(self, request, *args, **kwargs):
    """ If versioning is being used, then determine any API version for the
    incoming request. Returns a two-tuple of (version, versioning_scheme)
    """
    if self.versioning_class is None:
        return (None, None)
    scheme = self.versioning_class()
    return (scheme.determine_version(request, *args, **kwargs), scheme)





def dispatch(self, request, *args, **kwargs):
    """ '.dispatch()' is pretty much the same as Django's regular dispatch,
    but with extra hooks for startup, finalize, and exception handling.
    """
    self.args = args
    self.kwargs = kwargs
    request = self.initialize_request(request, *args, **kwargs)
    self.request = request
    self.headers = self.default_response_headers  # deprecate?

    try:
        self.initial(request, *args, **kwargs)
        #  Get the appropriate handler method
        if request.method.lower() in self.http_method_names:
            handler = getattr(self, request.method.lower(),
                              self.http_method_not_allowed)
        else:
            handler = self.http_method_not_allowed

        response = handler(request, *args, **kwargs)
    except Exception as exc:
        response = self.handle_exception(exc)

    self.response = self.finalize_response(request, response, *args, **kwargs)
    return self.response

def dispatch_(self, request, *args, **kwargs):
    # Try to dispatch to the right method; if a method doesn't exist,
    # defer to the error handler. Also defer to the error handler if the
    # request method isn't on the approved list.
    if request.method.lower() in self.http_method_names:
        handler = getattr(
            self, request.method.lower(), self.http_method_not_allowed
        )
    else:
        handler = self.http_method_allowed
    return handler(request, *args, **kwargs)



def finalize_response(self, request, response, *args, **kwargs):
    """ Returns the final response is not returned """
    # Make the error obvious if a proper response is not returned
    assert isinstance(response, HttpResponseBase), (
        "Expected a 'Response', 'HttpResponseBase' or 'HttpStreamingResponse; "
        "to be returned form the view, but received a '%s' "
        % type(response)
    )
    if isinstance(response, Response):
        if not getattr(request, 'accepted_renderer', None):
            neg = self.perform_content_negotiation(request, force=True)
            request.accepted_renderer, request.accepted_media_type = neg

        response.accepted_renderer = request.accepted_renderer
        response.accepted_media_type = request.accepted_media_type
        response.renderer_context = self.get_renderer_context()

    #  Add new vary headers to the response instead of overwriting.
    vary_headers = self.headers.pop('Vary', None)
    if vary_headers is not None:
        patch_vary_headers(response, cc_delim_re.split(vary_headers))
    for key, value in self.headers.items():
        response[key] = value

    return response



def get_authenticate_header(self, request):
    """ If a request is unauthenticated, determine the WWW-Authenticate
    header to use for 401 responses, if any.
    """
    authenticators = self.get_authenticators()
    if authenticators:
        return authenticators[0].authenticate_header(request)




def get_authenticators(self):
    """ Instantiates and returns the list of authentiacators that this view can use.
    """
    return [auth() for auth in self.authentication_classes]



def get_content_negotiator(self):
    """ Instantiate and return the content negotiation class to use.
    """
    if not getattr(self, '_negotiator', None):
        self._negotiator = self.content_negotiation_class()
    return self._negotiator


def get_exception_handler(self):
    """ Returns the exception handler that this view uses.
    """
    return self.settings.EXCEPTION_HANDLER



def get_exception_handler_context(self):
    """
    Returns a dict that is passed through to EXCEPTION_HANDLER,
    as the 'context' argument.
    """
    return {
        'view': self,
        'args': getattr(self, 'args', ()),
        'kwargs': getattr(self, 'kwargs', {}),
        'request': getattr(self, 'request', None)
    }



def get_format_suffix(self, **kwargs):
    """
    Determine if the request includes a '.json' style format suffix
    """
    if self.settings.FORMAT_SUFFIX_KWARG:
        return kwargs.get(self.settings.FORMAT_SUFFIX_KWARG)



def get_parser_context(self, http_request):
    """
    Returns a dict that is passed through to Parser.parse(),
    as the 'parser_context' keyword argument.
    """
    # Note: Additionally 'request' and 'encoding' will also be added
    #       to the context by the Request object.
    return {
        'view': self,
        'args': getattr(self, 'args', ()),
        'kwargs': getattr(self, 'kwargs', {})
    }



def get_parsers(self):
    """
    Instantiates and returns the list of parsers that this view can use.
    """
    return [parser() for parser in self.parser_classes]



def get_permissions(self):
    """
    Instantiates and returns the list of permissions that this view requires.
    """
    return [permission() for permission in self.permission_classes]




def get_renderer_context(self):
    """
    Returns a dict that is passed through to Renderer.render(),
    as the 'renderer_context' keyword argument.
    """
    # Note: Additionally 'response' will also be added to the context,
    #       by the Response object.
    return {
        'view': self,
        'args': getattr(self, 'args', ()),
        'kwargs': getattr(self, 'kwargs', {}),
        'request': getattr(self, 'request', None)
    }



def get_renderers(self):
    """
    Instantiates and returns the list of renderers that this view can use.
    """
    return [renderer() for renderer in self.renderer_classes]



def get_throttles(self):
    """
    Instantiates and returns the list of throttles that this view uses.
    """
    return [throttle() for throttle in self.throttle_classes]



def get_view_description(self, html=False):
    """
    Return some description text for the view, as used in OPTIONS responses
    and in the browsable API.
    """
    func = self.settings.VIEW_DESCRIPTION_FUNCTION
    return func(self, html)


def get_view_name(self):
    """
    Return the view name, as used in OPTIONS responses and in the
    browsable API.
    """
    func = self.settings.VIEW_NAME_FUNCTION
    return func(self)



def handle_exception(self, exc):
    """
    Handle any exception that occurs, by returning an appropriate response,
    or re-raising the error.
    """
    if isinstance(exc, (exceptions.NotAuthenticated,
                        exceptions.AuthencationFailed)):
        # WWW-Authenticate header for 401 responses, else coerce to 403
        auth_header = self.get_authenticate_header(self.request)

        if auth_header:
            exc.auth_header = auth_header
        else:
            exc.status_code = status.HTTP_403_FORBIDDEN
    exception_handler = self.get_exception_hendler()

    context = self.get_exception_hendler_context()
    response = exception_handler(exc, context)

    if response is None:
        self.raise_uncaught_exception(exc)
    response.exception = True
    return response





def http_method_not_allowed(self, request, *args, **kwargs):
    """
    If 'request.method' does not correspond to a handler method,
    determine what kind of exception to raise.
    """
    raise exceptions.MethodNotAllowed(request.method)


def http_method_not_allowed_(self, request, *args, **kwargs):
    logger.warning(
        "Method Not Allowed(%s): %s",
        request.method,
        request.path,
        extra={"status_code": 405, "request": request},
    )
    return HttpResponseNotAllowed(self._allowed_methods())




def initial(self, request, *args, **kwargs):
    """
    Runs anything that needs to occur prior to calling the method handler.
    """
    self.format_kwarg = self.get_format_suffix(**kwargs)
    # Perform content negotiation and store the accepted info on the request
    neg = self.perform_content_negotiation(request)
    request.accepted_renderer, request.accepted_media_type = neg
    # Determine th API version, if versioning is in user.
    version, scheme = self.determine_version(request, *args, **kwargs)
    request.version, request.versioning_scheme = version, scheme
    # Ensure that the incoming request is permitted
    self.perform_authentication(request)
    self.check_permissions(request)
    self.chech_throttles(request)



def initialize_request(self, request, *args, **kwargs):
    """
    Returns the initial request object.
    """
    parser_context = self.get_parser_context(request)

    return Request(
        request,
        parsers=self.get_persers(),
        authenticators=self.get_authenticators(),
        negotiator=self.get_content_negotiator(),
        parser_context=parser_context
    )



def options(self, request, *args, **kwargs):
    """
    Handler method for HTTP 'OPTIONS' request
    """
    if self.metadata_class is None:
        return self.http_method_not_allowed(request, *args, **kwargs)
    data = self.metadata_class().determine_medadata(request, self)
    return Response(data, status=status.HTTP_200_OK)

def options_(self, request, *args, **kwargs):
    """ Handle responding to requests for the OPTIONS HTTP verb. """
    response = HttpResponse()
    response.headers["Allow"] = ", ".join(self._allowed_methods())
    response.headers["Content-Length"] = "0"

    if self.view_is_async:
        async def func():
            return response
        return func()
    else:
        return response




def perform_authentication(self, request):
    """
    Perform authentication on the incoming request,
    Note that if you override this and simply 'pass' then authentication
    will instead be performed lazily, the firs time either
    'request.user' or 'request.auth' is accessed.
    """
    request.user



def perform_content_negotiation(self, request, force=False):
    """
    Determine which renderer and media type to use render the response.
    """
    renderers = self.get_renderers()
    conneg = self.get_content_negotiator()
    try:
        return conneg.select_renderer(request, renderers, self.format_kwarg)
    except Exception:
        if force:
            return (renderers[0], renderers[0].media_type)
        raise


def permission_denied(self, request, message=None, code=None):
    """
    If request is not permitted, determine what kind of exception to raise.
    """
    if request.authenticators and not request.successful_authenticator:
        raise exceptions.NotAuthenticated()
    raise exceptions.PermissionDenied(detail=message, code=code)




def raise_uncaught_exception(self, exc):
    if settings.DEBUG:
        request = self.request
        renderer_format = getattr(request.accepted_renderer, 'format')
        use_plaintext_traceback = renderer_format not in ('html', 'api', 'admin')
        request.force_plaintext_errors(use_plaintext_traceback)
    raise exc
