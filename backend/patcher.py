import subprocess
import tempfile
import os

def patch_java_code(code: str) -> dict:
    """
    Runs AutoPatcher.java against the provided Java code using AST patching
    and returns a dict with both the patched code and patch logs.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".java", mode="w", encoding="utf-8") as temp_file:
        temp_file.write(code)
        input_path = temp_file.name

    base_path = os.path.abspath(os.path.dirname(__file__))
    javaparser_jar = os.path.join(base_path, "..", "java_analyzer", "javaparser-core-3.26.4.jar")
    patcher_classpath = os.path.join(base_path, "..", "java_analyzer")

    try:
        result = subprocess.run(
            [
                "java",
                "-cp",
                f"{patcher_classpath}{os.pathsep}{javaparser_jar}",
                "AutoPatcher",
                input_path
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return {
            "patched_code": result.stdout,
            "patch_logs": result.stderr
        }
    except subprocess.CalledProcessError as e:
        return {
            "patched_code": "",
            "patch_logs": f"Patch failed:\n{e.stderr.strip()}"
        }
    finally:
        if os.path.exists(input_path):
            os.remove(input_path)
