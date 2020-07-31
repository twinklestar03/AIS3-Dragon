from flask import Flask, jsonify, request, Response
from flask.views import MethodView
from secret_vault.managers import SecretManager
from secret_vault.models import Secret
from secret_vault.utils import DB

from .utils import *

__all__ = ['GetSecretAPI', 'CreateSecretAPI', 'ListSecretAPI']


class GetSecretAPI(MethodView):
    def get(self, secret_name):
        if SecretManager.is_valid_secret(secret_name):
            access_token = str()
            if 'access_token' in request.headers:
                access_token = request.headers['access_token']
                if SecretManager.is_accessible(secret_name, access_token=access_token):
                    return get_json(
                        ReturnStatus.Success,
                        SecretManager.get_secret(secret_name),
                        secret_name=secret_name
                    )
                    
            return get_json(
                ReturnStatus.Fail,
                SecretResult.NotAccessiable,
                secret_name=secret_name
            )

        else:
            return get_json(
                ReturnStatus.Fail,
                SecretResult.InvaildSecretName
            )


class CreateSecretAPI(MethodView):
    def post(self):
        secret_name = request.form.get('secret_name', None)
        secret_data = request.form.get('secret_data', None)

        if secret_name is None or secret_data is None:
            return get_json(
                ReturnStatus.Fail,
                SecretResult.BadRequest
            )

        if 'access_token' in request.headers:
                access_token = request.headers['access_token']

                if SecretManager.can_create(access_token):
                    if SecretManager.create_secret(secret_name, secret_data):
                        return get_json(
                            ReturnStatus.Success,
                            secret_name
                        )

                    else:
                        return get_json(
                            ReturnStatus.Fail,
                            SecretResult.NotAccessiable,
                            secret_name=secret_name
                        )
                    

        return get_json(
            ReturnStatus.Fail,
            SecretResult.NotAccessiable
        )

class ListSecretAPI(MethodView):
    def get(self):
        if 'access_token' in request.headers:
                access_token = request.headers['access_token']
                all_secret_names = SecretManager.get_all_secrets_name()

                res = []
                for n in all_secret_names:
                    if SecretManager.is_accessible(n, access_token=access_token):
                        res.append(n)
                print(all_secret_names)
                return get_json(
                    ReturnStatus.Success,
                    res
                )
        else:
            return get_json(
                ReturnStatus.Fail,
                SecretResult.NotAccessiable
            )