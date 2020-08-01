from flask import Flask
from package_guardian.apis import ScanPackageAPI, LastScanPackageAPI
from package_guardian.managers import PackageManager
from package_guardian.utils import Config


class PackageGuardian(object):
    def __init__(self, port, config_file):
        self.app = Flask("__main__")
        self.port = port
        self.config = Config(config_file)
        self._add_all_rules()

        PackageManager.initialize(self.config)

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
