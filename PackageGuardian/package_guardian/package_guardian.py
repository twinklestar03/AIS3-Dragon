from flask import Flask
from package_guardian.apis import ScanPackageAPI, LastScanPackageAPI


class PackageGuardian(object):
    def __init__(self, port):
        self.app = Flask("__main__")
        self.port = port
        self._add_all_rules()

        # Place your initializations here

    def _add_all_rules(self):
        # Your API endpoints
        self.app.add_url_rule(
            "/scan_package", view_func=ScanPackageAPI.as_view("scan_package_api")
        )
        self.app.add_url_rule(
            "/last_scan_package",
            view_func=LastScanPackageAPI.as_view("last_scan_package_api"),
        )

    def run(self):
        self.app.run(port=self.port)
