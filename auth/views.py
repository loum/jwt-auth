import jwt
import rest_framework
import rest_framework.decorators
import rest_framework.response
from rest_framework_jwt.views import JSONWebTokenAPIView
import rest_framework_jwt.serializers
from rest_framework_jwt.compat import get_request_data
from rest_framework_jwt.settings import api_settings
from rest_framework.response import Response
import requests_oauthlib
import oauthlib.oauth2

import auth.settings


jwt_response_payload_handler = api_settings.JWT_RESPONSE_PAYLOAD_HANDLER


class AsymmetricJSONWebTokenAPIView(JSONWebTokenAPIView):
    serializer_class = rest_framework_jwt.serializers.JSONWebTokenSerializer

    def post(self, request):
        serializer = self.get_serializer(data=get_request_data(request))

        if serializer.is_valid():
            user = serializer.object.get('user') or request.user
            payload = rest_framework_jwt.utils.jwt_payload_handler(user)
            encoded_token = jwt.encode(payload=payload,
                                       key=auth.settings.PRIVATE_KEY,
                                       algorithm='RS256')
            jwt_token_str = encoded_token.decode('utf-8')

            response_data = {'token': jwt_token_str}

            return Response(response_data)

        return Response(serializer.errors,
                        status=rest_framework.status.HTTP_400_BAD_REQUEST)


class AzureJSONWebTokenAPIView(JSONWebTokenAPIView):
    serializer_class = rest_framework_jwt.serializers.JSONWebTokenSerializer

    def post(self, request):
        serializer = self.get_serializer(data=get_request_data(request))

        if serializer.is_valid():
            user = serializer.object.get('user') or request.user
            client_id = auth.settings.AZURE_AD.get('CLIENT_ID')
            client_secret = auth.settings.AZURE_AD.get('CLIENT_SECRET')
            token_url = auth.settings.AZURE_AD.get('TOKEN_URL')
            resource_uri = auth.settings.AZURE_AD.get('RESOURCE_URL')

            client = oauthlib.oauth2.BackendApplicationClient(client_id=client_id)
            oauth = requests_oauthlib.OAuth2Session(client=client)

            azure_response = oauth.fetch_token(token_url,
                                               client_id=client_id,
                                               client_secret=client_secret)

            return Response(azure_response)

        return Response(serializer.errors,
                        status=rest_framework.status.HTTP_400_BAD_REQUEST)

obtain_asymmetric_jwt_token = AsymmetricJSONWebTokenAPIView.as_view()
obtain_azure_jwt_token = AzureJSONWebTokenAPIView.as_view()


@rest_framework.decorators.api_view(['GET'])
def protected_url(request):
    """Simple API demonstrating a protected URL.

    """
    resp = {
        'message': 'This is a protected URL'
    }

    return rest_framework.response.Response(resp)


@rest_framework.decorators.api_view(['GET'])
def azure_ad_token(request):
    """Asymmetric JWT sourced from Azure AD under the OAuth 2.0
    Client Credentilas Grant model.

    """
    pass
