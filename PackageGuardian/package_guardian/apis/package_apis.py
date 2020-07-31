from flask import Flask, jsonify, request, Response
from flask.views import MethodView
from package_guardian.managers import PackageManager

from .utils import *

__all__ = ["ScanPackageAPI", "LastScanPackageAPI"]


class ScanPackageAPI(MethodView):
    def get(self):
        time, results = PackageManager.scan_package()
        return get_json(time, ReturnStatus.Success, results)


class LastScanPackageAPI(MethodView):
    def get(self):
        result = PackageManager.get_last_result()
        if result:
            time = result["time"]
            results = result["results"]
            return get_json(time, ReturnStatus.Success, results)
        else:
            return get_json(None, ReturnStatus.Error, None)
