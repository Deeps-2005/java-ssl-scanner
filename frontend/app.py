import streamlit as st
import requests
import json
import zipfile
import io
import hashlib # For hashing ZIP file content

# --- Page Configuration ---
st.set_page_config(
    page_title="SSL/HTTPS Vulnerability Scanner",
    layout="centered", # "wide" can also be used for more space
    initial_sidebar_state="collapsed",
    menu_items={
        'Get Help': 'https://www.example.com/help',
        'Report a bug': "https://www.example.com/bug",
        'About': "# This is an SSL/HTTPS Vulnerability Scanner powered by AI."
    }
)

# --- Session State Initialization ---
def init_session_state():
    """Initializes default values for Streamlit's session state."""
    defaults = {
        # Input-specific states for single file/pasted code
        "uploaded_file_bytes": None,
        "uploaded_filename": None,
        "pasted_code_bytes": None,
        "pasted_code_filename": "pasted_code.java", # Consistent name for pasted code

        # Input-specific states for ZIP files
        "zip_file_raw_bytes": None,
        "zip_file_content_hash": None, # MD5 hash of the ZIP content
        "zip_file_name": None,

        # Track which tab's content is currently being displayed/processed
        "current_display_source_tab": None, # "upload_file", "paste_code", "zip_file"

        # Analysis/Patching results for single file/pasted code
        "analysis_report_items": None,
        "complete_sanitized_code_overall": None,
        "trigger_patch_for_active_file": False,
        "patched_code_result": None,
        "patch_logs_result": None, # This will now be a list of dicts
        
        # Keep track of the uploader's state to detect actual changes for uploaded file
        "last_uploaded_filename": None,
        "last_uploaded_file_size": None,

        # Analysis/Patching results for ZIP files (cached dictionaries)
        # {filename_in_zip: {"analysis_items": [...], "complete_sanitized_code": "..."}}
        "zip_analysis_cache": {}, 
        # {filename_in_zip: {"patched_code": "...", "patch_logs": "..."}}
        "zip_patch_cache": {},
        # Set of filenames in ZIP for which patching has been triggered by a button click
        "zip_patch_triggered_files": set() 
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()


# --- Application Header ---
st.title("🔐 SSL/HTTPS Vulnerability Scanner & Auto-Patcher")
st.markdown(
    """
    Analyze your Java code for insecure usage of **X509TrustManager**,
    **HostnameVerifier**, weak **cipher suites**, and more. Get suggestions and **auto-patch** options.
    Choose your input method below:
    """
)

# --- Helper Function to Display Analysis Report ---
def display_analysis_items(analysis_items, filename_for_key=""):
    """Displays analysis results in an expandable format."""
    # Check for the specific "No vulnerabilities found" message first
    if isinstance(analysis_items, list) and len(analysis_items) == 1 and \
       analysis_items[0].get("issue") == "No vulnerabilities found by analyzer." and \
       analysis_items[0].get("severity") == "INFO":
        st.success("✅ No SSL/HTTPS vulnerabilities found in this code. Good job!")
        st.info("No analysis results to display.")
        return
        
    if isinstance(analysis_items, list) and len(analysis_items) == 1 and analysis_items[0].get("severity") == "ERROR":
        item = analysis_items[0]
        st.error(f"**❗ Analysis Error**: {item.get('issue', 'Unknown error')}")
        if item.get('suggestion'):
            st.warning(f"**💡 Suggestion**: {item.get('suggestion')}")
        return

    # Filter out ERRORs and the specific "No vulnerabilities found" INFO message
    valid_issues = [item for item in analysis_items 
                    if item.get("severity") != "ERROR" and item.get("issue") and 
                       not (item.get("issue") == "No vulnerabilities found by analyzer." and item.get("severity") == "INFO")]
    
    if valid_issues:
        st.info(f"Found {len(valid_issues)} potential vulnerabilities. Expand each section for details:")
        for i, item in enumerate(valid_issues):
            severity = item.get('severity', 'UNKNOWN')
            # Ensure issue_summary is robust
            issue_full = item.get('issue', 'Vulnerability Details')
            issue_parts = issue_full.split(':', 1)
            issue_summary_text = issue_parts[-1].strip().split('-')[0].strip() if issue_parts else issue_full
            
            line_info = f" (Line {item.get('line', 'N/A')})" if item.get('line') else ""
            
            color_emoji = "🔴" if severity == "CRITICAL" else \
                          "🔥" if severity == "HIGH" else \
                          "🟡" if severity == "MEDIUM" else \
                          "⚪" if severity == "UNKNOWN" else \
                          "❗"
            
            expander_title = f"{color_emoji} **{severity}**: {issue_summary_text}{line_info}"
            # Ensure unique key by incorporating filename and index
            expander_key = f"expander_{filename_for_key.replace('.', '_').replace('/', '_')}_{i}"

            with st.expander(expander_title):
                st.markdown(f"**❗ Full Issue**: {item.get('issue', '-')}")
                st.markdown(f"**💡 Suggestion**: {item.get('suggestion', 'No suggestion available')}")
                if "sanitized_code" in item and item["sanitized_code"] is not None:
                    st.markdown("**🔧 Code Snippet (Suggestion):**")
                    st.code(item["sanitized_code"].strip(), language="java")


# --- Helper Function to call Backend API ---
def call_backend_api(endpoint: str, filename: str, code_bytes: bytes, timeout: int = 60):
    """Calls a backend API endpoint (analyze or patch) and handles common errors."""
    api_url = f"http://127.0.0.1:8000/{endpoint}" # Consider making this configurable for deployment
    files_data = {'file': (filename, code_bytes, 'application/java')}
    try:
        response = requests.post(api_url, files=files_data, timeout=timeout)
        if response.ok:
            return {"ok": True, "data": response.json()}
        else:
            st.error(f"❌ API call to '{endpoint}' failed for {filename}. Status: {response.status_code}")
            return {"ok": False, "error": f"API Error: {response.status_code} - {response.text}"}
    except requests.exceptions.Timeout:
        st.error(f"⏰ API call to '{endpoint}' timed out for {filename}.")
        return {"ok": False, "error": "Timeout"}
    except requests.exceptions.ConnectionError:
        st.error(f"🔌 Could not connect to the backend for {filename}. Please ensure the backend server is running.")
        return {"ok": False, "error": "Connection Error"}
    except Exception as e:
        st.error(f"An unexpected error occurred during API call to '{endpoint}' for {filename}: {e}")
        return {"ok": False, "error": str(e)}


# --- Helper Function to clear processing results for single file/pasted code ---
def clear_processing_results_single_file():
    """Clears analysis/patching results related to single file/pasted code."""
    st.session_state.analysis_report_items = None
    st.session_state.complete_sanitized_code_overall = None
    st.session_state.trigger_patch_for_active_file = False
    st.session_state.patched_code_result = None
    st.session_state.patch_logs_result = None
    st.session_state.last_analyzed_filename = None
    st.session_state.last_analyzed_bytes = None


# --- Main processing function for single file/pasted code ---
def process_and_display_single_file(filename: str, code_bytes: bytes, source_tab_name: str):
    """
    Handles analysis and patching for a single Java file or pasted code.
    Caches results in session state to prevent redundant API calls.
    """
    # Only process if this is the content currently designated for display
    if st.session_state.current_display_source_tab != source_tab_name:
        return

    st.markdown(f"---")
    st.subheader(f"Processing: {filename}")

    # --- Analysis Section ---
    # Perform analysis only if results are not already in session state for the current active file
    # or if the file/source has changed.
    # We need to store the filename and bytes that were *last analyzed* to avoid re-analyzing.
    if st.session_state.analysis_report_items is None or \
       st.session_state.get("last_analyzed_filename") != filename or \
       st.session_state.get("last_analyzed_bytes") != code_bytes: # Compare bytes for pasted code

        clear_processing_results_single_file() # Clear previous results before new analysis
        st.session_state.last_analyzed_filename = filename
        st.session_state.last_analyzed_bytes = code_bytes # Store bytes for comparison

        with st.spinner(f"Analyzing {filename} for vulnerabilities..."):
            analysis_result = call_backend_api("analyze", filename, code_bytes, timeout=30)
            if analysis_result["ok"]:
                results_payload = analysis_result["data"].get("report", [])
                temp_analysis_items = []
                for item in results_payload:
                    if "complete_sanitized_code" in item:
                        st.session_state.complete_sanitized_code_overall = item["complete_sanitized_code"]
                    else:
                        temp_analysis_items.append(item)
                st.session_state.analysis_report_items = temp_analysis_items if temp_analysis_items else [{"issue": "No vulnerabilities found by analyzer.", "severity": "INFO"}]
            else:
                st.session_state.analysis_report_items = [{"issue": f"Analysis Failed: {analysis_result['error']}", "severity": "ERROR"}]
    
    # Display analysis results from session state
    if st.session_state.analysis_report_items is not None:
        display_analysis_items(st.session_state.analysis_report_items, filename)
    if st.session_state.complete_sanitized_code_overall:
        st.subheader(f"✅ Complete Auto-Patched Version for {filename} (from Analyzer)")
        st.code(st.session_state.complete_sanitized_code_overall.strip(), language="java")

    # --- Auto-Patch Section ---
    # Only show patch button if analysis found actual vulnerabilities (not just the INFO message or an ERROR)
    can_attempt_patch = st.session_state.analysis_report_items is not None and \
                        any(item.get("severity") not in ["ERROR", "INFO"] for item in st.session_state.analysis_report_items)

    if can_attempt_patch:
        st.markdown(f"#### ⚙️ Auto-Patch Code for: {filename}")
        patch_button_key = f"patch_button_active_{filename.replace('.', '_').replace('/', '_').replace(' ', '_')}_{source_tab_name}"
        
        if st.button(f"Generate Patched Code for {filename}", key=patch_button_key):
            st.session_state.trigger_patch_for_active_file = True
            st.session_state.patched_code_result = None 
            st.session_state.patch_logs_result = None
            st.rerun() # Rerun to trigger the patching logic in the next script execution
    
    # Execute patching logic if triggered
    if st.session_state.trigger_patch_for_active_file:
        with st.spinner(f"Attempting to auto-patch {filename}..."):
            patch_result = call_backend_api("patch", filename, code_bytes, timeout=60)
            if patch_result["ok"]:
                patch_data = patch_result["data"]
                st.session_state.patched_code_result = patch_data.get("patched_code", "")
                st.session_state.patch_logs_result = patch_data.get("patch_logs", []) # Ensure it's a list
                if not st.session_state.patched_code_result and not st.session_state.patch_logs_result:
                     st.session_state.patch_logs_result = [{"message": "Patching service returned an empty response. No changes made or no applicable patches found.", "line": "N/A"}]
            else:
                st.session_state.patched_code_result = "" # Ensure no old code is shown
                st.session_state.patch_logs_result = [{"message": f"Patching failed: {patch_result['error']}", "line": "N/A"}]

        # Display patched code and logs after patching is complete
        if st.session_state.patched_code_result:
            st.subheader(f"🧰 Patched Java Code Output for {filename}")
            st.code(st.session_state.patched_code_result.strip(), language="java")
            st.success("Auto-patching completed! Review the patched code above.")
            st.info("Remember: Automated patches may require manual review and testing.")
        
        # Display patch logs
        if st.session_state.patch_logs_result:
            st.subheader(f"📝 Patch Logs for {filename}")
            # Check if it's a list (expected) or a string (fallback from previous errors)
            if isinstance(st.session_state.patch_logs_result, list):
                if st.session_state.patch_logs_result:
                    for log_entry in st.session_state.patch_logs_result:
                        line = log_entry.get("line", "N/A")
                        message = log_entry.get("message", "No message provided.")
                        st.text_area(f"Line {line}", value=message, height=70, disabled=True, key=f"log_display_{filename}_{line}_{message[:20]}")
                else:
                    st.info("No specific patch logs were generated.")
            else: # Fallback for unexpected string format
                st.text_area("Raw Patch Logs (Unexpected Format):", value=str(st.session_state.patch_logs_result), height=100, disabled=True)
        
        # Reset trigger after display
        st.session_state.trigger_patch_for_active_file = False
        st.session_state.patch_logs_result = None # Clear logs after display

# --- Streamlit Tabs for Input Method ---
tab1, tab2, tab3 = st.tabs(["Upload .java File", "Paste Java Code", "Upload ZIP File (Multiple Files)"])

# --- Tab 1: Upload .java File ---
with tab1:
    st.subheader("Upload a Single Java (.java) File")
    uploaded_file_single = st.file_uploader("Choose a .java file", type=["java"], key="single_file_uploader")

    # Clear results if a new file is uploaded
    if uploaded_file_single and (st.session_state.last_uploaded_filename != uploaded_file_single.name or \
                                 st.session_state.last_uploaded_file_size != uploaded_file_single.size):
        clear_processing_results_single_file()
        st.session_state.uploaded_file_bytes = uploaded_file_single.read()
        st.session_state.uploaded_filename = uploaded_file_single.name
        st.session_state.last_uploaded_filename = uploaded_file_single.name
        st.session_state.last_uploaded_file_size = uploaded_file_single.size
        st.session_state.current_display_source_tab = "upload_file"
        st.rerun() # Rerun to process the new file

    # If the file exists and is the current active display source, process it
    if st.session_state.current_display_source_tab == "upload_file" and \
       st.session_state.uploaded_file_bytes is not None and \
       st.session_state.uploaded_filename is not None:
        process_and_display_single_file(st.session_state.uploaded_filename, st.session_state.uploaded_file_bytes, "upload_file")
    elif uploaded_file_single is None and st.session_state.current_display_source_tab == "upload_file":
        clear_processing_results_single_file() # Clear if user removed the file

# --- Tab 2: Paste Java Code ---
with tab2:
    st.subheader("Paste Your Java Code Here")
    pasted_code_input = st.text_area("Paste code...", height=300, key="pasted_code_area")
    
    # Check if pasted code has changed and update session state
    if pasted_code_input:
        current_pasted_bytes = pasted_code_input.encode("utf-8")
        if st.session_state.pasted_code_bytes != current_pasted_bytes:
            clear_processing_results_single_file()
            st.session_state.pasted_code_bytes = current_pasted_bytes
            st.session_state.current_display_source_tab = "paste_code"
            st.rerun() # Rerun to process new pasted code
    elif not pasted_code_input and st.session_state.current_display_source_tab == "paste_code":
        clear_processing_results_single_file() # Clear if user cleared the text area

    # If pasted code exists and is the current active display source, process it
    if st.session_state.current_display_source_tab == "paste_code" and \
       st.session_state.pasted_code_bytes is not None:
        process_and_display_single_file(st.session_state.pasted_code_filename, st.session_state.pasted_code_bytes, "paste_code")


# --- Tab 3: Upload ZIP File ---
with tab3:
    st.subheader("Upload a ZIP File containing .java files")
    zip_file_upload = st.file_uploader("Choose a .zip file", type=["zip"], key="zip_file_uploader")

    if zip_file_upload:
        raw_bytes = zip_file_upload.read()
        current_hash = hashlib.md5(raw_bytes).hexdigest()

        # Check if a new ZIP file is uploaded or content changed
        if st.session_state.zip_file_content_hash != current_hash:
            st.session_state.zip_file_raw_bytes = raw_bytes
            st.session_state.zip_file_content_hash = current_hash
            st.session_state.zip_file_name = zip_file_upload.name
            st.session_state.zip_analysis_cache = {} # Clear cache for new zip
            st.session_state.zip_patch_cache = {}
            st.session_state.zip_patch_triggered_files = set()
            st.session_state.current_display_source_tab = "zip_file" # Set active tab
            st.rerun() # Rerun to process the new zip

        st.markdown(f"**Processing ZIP**: `{st.session_state.zip_file_name}`")
        st.info("Results for each Java file within the ZIP will be displayed below.")

        try:
            with zipfile.ZipFile(io.BytesIO(st.session_state.zip_file_raw_bytes), 'r') as zf:
                java_files_in_zip = [name for name in zf.namelist() if name.lower().endswith('.java') and not name.startswith('__MACOSX/')]

                if not java_files_in_zip:
                    st.warning("No .java files found in the uploaded ZIP archive.")
                    st.session_state.zip_analysis_cache = {} # Ensure empty if no java files
                    st.session_state.zip_patch_cache = {}
                else:
                    for member_name in sorted(java_files_in_zip): # Sort for consistent display order
                        st.markdown(f"---")
                        st.markdown(f"### File: `{member_name}`")

                        # --- ZIP File Analysis ---
                        # Only analyze if not already cached
                        if member_name not in st.session_state.zip_analysis_cache:
                            st.subheader("Scanning for Vulnerabilities...")
                            with st.spinner(f"Analyzing `{member_name}`..."):
                                member_content = zf.read(member_name)
                                analysis_result = call_backend_api("analyze", member_name, member_content, timeout=30)
                                if analysis_result["ok"]:
                                    st.session_state.zip_analysis_cache[member_name] = {
                                        "analysis_items": analysis_result["data"].get("report", []),
                                        # "complete_sanitized_code": analysis_result["data"].get("complete_sanitized_code", "") # Analyzer doesn't send this
                                    }
                                else:
                                    st.session_state.zip_analysis_cache[member_name] = {
                                        "analysis_items": [{"issue": f"Analysis Failed: {analysis_result['error']}", "severity": "ERROR"}],
                                    }
                        
                        # Display analysis results for the current ZIP member
                        if member_name in st.session_state.zip_analysis_cache:
                            display_analysis_items(st.session_state.zip_analysis_cache[member_name]["analysis_items"], member_name)

                            # --- ZIP File Patching ---
                            # Only show patch button if analysis found actual vulnerabilities for this file
                            member_analysis_items = st.session_state.zip_analysis_cache[member_name]["analysis_items"]
                            can_patch_zip_member = any(item.get("severity") not in ["ERROR", "INFO"] for item in member_analysis_items)

                            if can_patch_zip_member:
                                st.markdown(f"#### ⚙️ Auto-Patch Code for: `{member_name}`")
                                patch_button_key_zip = f"patch_button_zip_{member_name.replace('.', '_').replace('/', '_')}"
                                
                                if st.button(f"Generate Patched Code for {member_name}", key=patch_button_key_zip):
                                    st.session_state.zip_patch_triggered_files.add(member_name)
                                    st.session_state.zip_patch_cache[member_name] = {"patched_code": None, "patch_logs": None} # Reset before patch
                                    st.rerun() # Trigger rerun for patching

                                # Execute patching logic if triggered for this file
                                if member_name in st.session_state.zip_patch_triggered_files:
                                    if st.session_state.zip_patch_cache[member_name].get("patched_code") is None: # Only run if not already patched/cached
                                        with st.spinner(f"Attempting to auto-patch `{member_name}`..."):
                                            member_content = zf.read(member_name) # Re-read content
                                            patch_result = call_backend_api("patch", member_name, member_content, timeout=60)
                                            if patch_result["ok"]:
                                                patch_data = patch_result["data"]
                                                st.session_state.zip_patch_cache[member_name]["patched_code"] = patch_data.get("patched_code", "")
                                                st.session_state.zip_patch_cache[member_name]["patch_logs"] = patch_data.get("patch_logs", []) # Ensure it's a list
                                                if not st.session_state.zip_patch_cache[member_name]["patched_code"] and not st.session_state.zip_patch_cache[member_name]["patch_logs"]:
                                                     st.session_state.zip_patch_cache[member_name]["patch_logs"] = [{"message": "Patching service returned an empty response. No changes made or no applicable patches found.", "line": "N/A"}]
                                            else:
                                                st.session_state.zip_patch_cache[member_name]["patched_code"] = ""
                                                st.session_state.zip_patch_cache[member_name]["patch_logs"] = [{"message": f"Patching failed: {patch_result['error']}", "line": "N/A"}]
                                    
                                    # Display patched code and logs for the current ZIP member
                                    patched_code_display = st.session_state.zip_patch_cache[member_name]["patched_code"]
                                    patch_logs_display = st.session_state.zip_patch_cache[member_name]["patch_logs"]

                                    if patched_code_display:
                                        st.subheader(f"🧰 Patched Code Output for {member_name}")
                                        st.code(patched_code_display.strip(), language="java")
                                        st.success(f"Auto-patching completed for {member_name}! Review the patched code.")
                                    else:
                                        st.warning(f"No patched code was returned for {member_name}.")

                                    # Display patch logs for ZIP file members
                                    if patch_logs_display:
                                        st.subheader(f"📝 Patch Logs for {member_name}")
                                        if isinstance(patch_logs_display, list):
                                            if patch_logs_display:
                                                for log_entry in patch_logs_display:
                                                    line = log_entry.get("line", "N/A")
                                                    message = log_entry.get("message", "No message provided.")
                                                    st.text_area(f"Line {line}", value=message, height=70, disabled=True, key=f"log_zip_display_{member_name}_{line}_{message[:20]}")
                                            else:
                                                st.info(f"No specific patch logs were generated for {member_name}.")
                                        else: # Fallback for unexpected string format
                                            st.text_area("Raw Patch Logs (Unexpected Format):", value=str(patch_logs_display), height=100, disabled=True)
                            else:
                                st.warning(f"No analysis results available for {member_name} to patch, or no vulnerabilities found.")


        except zipfile.BadZipFile:
            st.error("The uploaded file is not a valid ZIP archive or is corrupted.")
            # Clear ZIP state on bad file
            st.session_state.zip_file_raw_bytes = None
            st.session_state.zip_file_content_hash = None
            st.session_state.zip_file_name = None
            st.session_state.zip_analysis_cache = {}
            st.session_state.zip_patch_cache = {}
            st.session_state.zip_patch_triggered_files = set()
        except Exception as e:
            st.error(f"An error occurred while processing the ZIP file: {e}")
            st.exception(e)
            # Clear ZIP state on error
            st.session_state.zip_file_raw_bytes = None
            st.session_state.zip_file_content_hash = None
            st.session_state.zip_file_name = None
            st.session_state.zip_analysis_cache = {}
            st.session_state.zip_patch_cache = {}
            st.session_state.zip_patch_triggered_files = set()

