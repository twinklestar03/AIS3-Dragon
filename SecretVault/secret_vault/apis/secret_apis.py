from flask import Flask, jsonify, request, Response
from flask.views import MethodView
from secret_vault.managers import SecretManager
from secret_vault.models import Secret
from secret_vault.utils import DB

__all__ = ['GetSecretAPI', 'CreateSecretAPI']


class GetSecretAPI(MethodView):
    def get(self, secret_name):
        if SecretManager.is_valid_secret(secret_name):
            access_token = str()
            if 'access_token' in request.headers:
                access_token = request.headers['access_token']

                if SecretManager.is_accessible(secret_name, access_token):
                    return jsonify({
                        'status': 'success',
                        'secret_name': secret_name,
                        'result': SecretManager.get_secret(secret_name, access_token) 
                    })
        else:
            return jsonify({
                'status': 'fail',
                'secret_name': secret_name,
                'result': 'invalid secret name'
            })


class CreateSecretAPI(MethodView):
    def get(self, secret_name, secret):

        return jsonify({
            'status': 'success',
            'result': 'testing auth api'
        })
