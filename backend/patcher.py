import subprocess
import tempfile
import os
import re # Import re for parsing patch logs

def patch_java_code(code: str) -> dict:
    """
    Runs AutoPatcher.java against the provided Java code using AST patching
    and returns a dict with both the patched code and patch logs.
    """
    java_file_path = None
    try:
        # Robust line ending normalization:
        # Split by any combination of CR/LF and then join back with only LF.
        normalized_code = '\n'.join(code.splitlines())

        with tempfile.NamedTemporaryFile(delete=False, suffix=".java", mode="w", encoding="utf-8") as temp_file:
            temp_file.write(normalized_code) # Write the normalized code
            java_file_path = temp_file.name

        base_path = os.path.abspath(os.path.dirname(__file__))
        javaparser_jar = os.path.join(base_path, "..", "java_analyzer", "javaparser-core-3.26.4.jar")
        patcher_classpath = os.path.join(base_path, "..", "java_analyzer")

        result = subprocess.run(
            [
                "java",
                "-cp",
                f"{patcher_classpath}{os.pathsep}{javaparser_jar}",
                "AutoPatcher",
                java_file_path
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, # Capture stderr for patch logs
            text=True,
            check=True
        )

        # The AutoPatcher's stdout contains the patched code.
        # Its stderr contains the patch logs, delimited by "--- PATCH LOG START ---" and "--- PATCH LOG END ---".
        
        patched_code = result.stdout.strip()
        raw_patch_logs = result.stderr.strip()

        parsed_patch_logs = []
        log_start_match = re.search(r"--- PATCH LOG START ---\n", raw_patch_logs)
        log_end_match = re.search(r"\n--- PATCH LOG END ---", raw_patch_logs)

        if log_start_match and log_end_match:
            log_content = raw_patch_logs[log_start_match.end():log_end_match.start()].strip()
            for log_line in log_content.splitlines():
                log_match = re.match(r"Line (\d+): (.*)", log_line)
                if log_match:
                    line_num = int(log_match.group(1))
                    message = log_match.group(2)
                    parsed_patch_logs.append({"line": line_num, "message": message})
        
        return {
            "patched_code": patched_code,
            "patch_logs": parsed_patch_logs
        }
    except subprocess.CalledProcessError as e:
        return {
            "patched_code": "",
            "patch_logs": [],
            "error": f"AutoPatcher execution failed. Stderr: {e.stderr.strip()}"
        }
    except FileNotFoundError as e:
        return {
            "patched_code": "",
            "patch_logs": [],
            "error": f"Java or AutoPatcher dependencies not found. Ensure JDK is installed and JARs are in 'java_analyzer' directory. Error: {str(e)}"
        }
    except Exception as e:
        return {
            "patched_code": "",
            "patch_logs": [],
            "error": f"An unexpected error occurred in Python patcher script: {str(e)}"
        }
    finally:
        if java_file_path and os.path.exists(java_file_path):
            os.remove(java_file_path)

