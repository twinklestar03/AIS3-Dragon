from flask import Flask, jsonify, request, Response
from flask.views import MethodView

from .utils import *

__all__ = ['ScanPackageAPI', 'LastScanPackageAPI']


class ScanPackageAPI(MethodView):
    def get(self):
        pass

class LastScanPackageAPI(MethodView):
    def get(self):
        pass
    