import rest_framework.decorators
import rest_framework.response


@rest_framework.decorators.api_view(['GET'])
def protected_url(request):
    """Simple API demonstrating a protected URL.

    """
    resp = {
        'message': 'This is a protected URL'
    }

    return rest_framework.response.Response(resp)
