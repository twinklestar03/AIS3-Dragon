from flask import jsonify

__all__ = ["ReturnStatus", "get_json"]


class ReturnStatus:
    Success = "success"
    Error = "error"
    Fail = "fail"
    Pending = "pending"


def get_json(time, status, results, **kwargs):
    data = {}

    data["time"] = time
    data["status"] = status
    data["results"] = results

    return jsonify(data)
