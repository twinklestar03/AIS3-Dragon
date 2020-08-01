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
        results = cls.scan(packages, used_packages)
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
                "cve": "CVE-2020-11538",
                "score": "8.1(High)",
                "affected_versions": "<7.1.0",
                "patched_versions": "7.1.0",
                "description": "In libImaging/Jpeg2KDecode.c in Pillow before 7.0.0, there are multiple out-of-bounds reads via a crafted JP2 file.",
            },
            "Twisted": {
                "cve": "CVE-2020-10108",
                "score": "9.8(Critical)",
                "affected_versions": "<20.3.0",
                "patched_versions": "20.3.0",
                "description": "In Twisted Web through 19.10.0, there was an HTTP request splitting vulnerability. When presented with two content-length headers, it ignored the first header. When the second content-length value was set to zero, the request body was interpreted as a pipelined request.",
            },
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
        load_name_times = 0
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
                    load_name_times += 1
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

        for package_name, used_package in used_packages.items():
            used_package["coverage"] = used_package["use_times"] / load_name_times

        print(used_packages)
        return used_packages

    @classmethod
    def scan(cls, packages, used_packages):
        scan_results = []
        for package_name, package_version in packages.items():
            scan_result = {"package_name": package_name, "version": package_version}
            vuln_package_detail = cls.search_package(package_name, package_version)
            if vuln_package_detail:
                if package_name == "Pillow":
                    used_package = used_packages["PIL"]
                elif package_name == "Twisted":
                    used_package = used_packages["twisted"]
                else:
                    used_package = used_packages[package_name]
                coverage = used_package["coverage"]
                origin_score = vuln_package_detail["score"]
                score = cls.calculate_new_score(coverage, origin_score)
                scan_result["score"] = score
                scan_result["detail"] = vuln_package_detail
            else:
                scan_result["score"] = "0.0(None)"
                scan_result["detail"] = None
            scan_results.append(scan_result)
        return scan_results

    @classmethod
    def calculate_new_score(cls, coverage, score):
        score = float(score.split("(")[0]) / 10
        print("score", score)
        print("coverage", coverage)
        score = (coverage * score) ** 0.5 * 10

        if score >= 9.0:
            level = "Critical"
        elif score >= 7.0:
            level = "High"
        elif score >= 4.0:
            level = "Medium"
        elif score >= 0.1:
            level = "Low"
        else:
            level = "None"
        score = format(score, ".1f")
        score = f"{score}({level})"
        print("new", score)

        return score

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
            # filenames = list(pathlib.Path("../repository").glob("**/*.py"))
            filenames = list(pathlib.Path("../repository").glob("**/test.py"))
        else:
            filenames = []
        codes = []
        for filename in filenames:
            code = "".join(cls.clear_code(str(filename)))
            code_lines = [code_line for code_line in code.split("\n") if code_line]
            code = "\n".join(code_lines)
            codes.append(code)
        code = "\n".join(codes)
        return code
