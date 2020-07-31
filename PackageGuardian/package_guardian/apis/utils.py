from flask import jsonify

__all__ = ['ReturnStatus', 'get_json']

class ReturnStatus:
    Success = 'success'
    Error = 'error'
    Fail = 'fail'
    Pending = 'pending'


def get_json(status, result, **kwargs):
    data = {}

    data['status'] = status
    data['result'] = result
    # Add extra data
    for k, v in kwargs.items():
        data[k] = v

    return jsonify(data)