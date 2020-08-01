from distutils.version import LooseVersion
import sys, token, tokenize, dis, pathlib, json
from datetime import datetime

__all__ = ["PackageManager"]


class PackageManager:
    @classmethod
    def initialize(cls, config):
        cls.config = config

    @classmethod
    def scan_package(cls):
        code = cls.merge_repo_code()
        packages = cls.list_packages()
        used_packages = cls.package_coverage(code)
        results = cls.scan(packages)
        time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cls.save_result(time, results)
        return time, results

    @classmethod
    def save_result(cls, time, results):
        result = {"time": time, "results": results}
        with open("./scan_package_result.json", "w+") as f:
            json.dump(result, f)
        return

    @classmethod
    def get_last_result(cls):
        try:
            with open("./scan_package_result.json") as f:
                result = json.load(f)
        except FileNotFoundError:
            result = None
        return result

    @classmethod
    def search_package(cls, package_name, package_version):
        vuln_packages = {
            "Pillow": {
                "status": "high",
                "affected_versions": "<7.1.0",
                "patched_versions": "7.1.0",
                "description": "In libImaging/Jpeg2KDecode.c in Pillow before 7.0.0, there are multiple out-of-bounds reads via a crafted JP2 file.",
            }
        }
        vuln_package = (
            vuln_packages[package_name] if package_name in vuln_packages else None
        )
        return vuln_package

    @classmethod
    def clear_code(cls, filename):
        code_file = open(filename)
        modified_code_lines = []
        prev_toktype = token.INDENT
        first_line = None
        last_lineno = -1
        last_col = 0

        tokgen = tokenize.generate_tokens(code_file.readline)
        for toktype, ttext, (slineno, scol), (elineno, ecol), ltext in tokgen:

            if 0:
                print(
                    "%10s %-14s %-20r %r"
                    % (
                        tokenize.tok_name.get(toktype, toktype),
                        "%d.%d-%d.%d" % (slineno, scol, elineno, ecol),
                        ttext,
                        ltext,
                    )
                )
            if slineno > last_lineno:
                last_col = 0
            if scol > last_col:
                modified_code_lines.append(" " * (scol - last_col))
            if toktype == token.STRING and prev_toktype == token.INDENT:
                modified_code_lines.append("#--")
            elif toktype == tokenize.COMMENT:
                pass
            else:
                modified_code_lines.append(ttext)
            prev_toktype = toktype
            last_col = ecol
            last_lineno = elineno
        return modified_code_lines

    @classmethod
    def package_coverage(cls, code):
        code_lines = code.split("\n")
        used_packages = {}

        for code_line in code_lines:
            exec(code_line)
            instructions = iter(dis.Bytecode(code_line))
            for ins in instructions:
                if ins.opname == "IMPORT_NAME":
                    next1_ins = next(instructions)
                    if ins.argval not in used_packages:
                        used_packages[ins.argval] = {"sinks": set(), "use_times": 0}
                    if next1_ins.opname == "STORE_NAME":
                        used_packages[ins.argval]["sinks"].add(next1_ins.argval)
                        continue
                    next2_ins = next(instructions)
                    if (
                        next1_ins.opname == "IMPORT_FROM"
                        and next2_ins.opname == "STORE_NAME"
                    ):
                        used_packages[ins.argval]["sinks"].add(next2_ins.argval)
                elif ins.opname == "LOAD_NAME":
                    for package_name, package in used_packages.items():
                        if ins.argval in package["sinks"]:
                            package["use_times"] += 1
                            break
                elif ins.opname == "STORE_NAME":
                    argval_type = eval(f"type({ins.argval})")
                    argval_type = (
                        str(argval_type).replace("<class '", "").replace("'>", "")
                    )
                    package_name = argval_type.split(".")[0]
                    if package_name in used_packages:
                        used_packages[package_name]["sinks"].add(ins.argval)

        return used_packages

    @classmethod
    def scan(cls, packages):
        scan_results = []
        for package_name, package_version in packages.items():
            scan_result = {"package_name": package_name, "version": package_version}
            vuln_package_detail = cls.search_package(package_name, package_version)
            if vuln_package_detail:
                scan_result["status"] = "high"
                scan_result["detail"] = vuln_package_detail
            else:
                scan_result["status"] = "ok"
                scan_result["detail"] = None
            scan_results.append(scan_result)
        return scan_results

    @classmethod
    def list_packages(cls):
        with open("../repository/requirements.txt") as f:
            requirements = f.read().rstrip().split("\n")

        packages = {}
        for requirement in requirements:
            package_name, package_version = requirement.split("==")
            packages[package_name] = package_version
        return packages

    @classmethod
    def merge_repo_code(cls):
        print(cls.config)
        if cls.config.language == "python":
            filenames = list(pathlib.Path("../repository").glob("**/*.py"))
        else:
            filenames = []
        codes = []
        for filename in filenames:
            code = "".join(clear_code(str(filename)))
            code_lines = [code_line for code_line in code.split("\n") if code_line]
            code = "\n".join(code_lines)
            codes.append(code)
        code = "\n".join(codes)
        return code
