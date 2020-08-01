from flask import jsonify

__all__ = ['ReturnStatus', 'SecretResult', 'get_json']

class ReturnStatus:
    Success = 'success'
    Error = 'error'
    Fail = 'fail'
    Pending = 'pending'


class SecretResult:
    NotAccessiable = 'Not Accessiable to resources'
    InvaildSecretName = 'Invalid secret name'
    BadRequest = 'Bad Request'
    IsExposed = 'The Secret is EXPOSED'
    Safe = 'All seems fine'

def get_json(status, result, **kwargs):
    data = {}

    data['status'] = status
    data['result'] = result
    # Add extra data
    for k, v in kwargs.items():
        data[k] = v

    return jsonify(data)