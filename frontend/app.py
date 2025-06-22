import streamlit as st
import requests
import json
import zipfile
import io
import hashlib # For hashing ZIP file content

# --- Page Configuration ---
st.set_page_config(
    page_title="SSL/HTTPS Vulnerability Scanner",
    layout="centered",
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
        "patch_logs_result": None,
        
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
                st.session_state.patch_logs_result = patch_data.get("patch_logs", "")
                if not st.session_state.patched_code_result and not st.session_state.patch_logs_result:
                     st.session_state.patch_logs_result = "Patching service returned an empty response. No changes made or no applicable patches found."
            else:
                st.session_state.patched_code_result = "" # Ensure no old code is shown
                st.session_state.patch_logs_result = f"Patching failed: {patch_result['error']}"

        # Display patched code and logs after patching is complete
        if st.session_state.patched_code_result:
            st.subheader(f"🧰 Patched Java Code Output for {filename}")
            st.code(st.session_state.patched_code_result.strip(), language="java")
        if st.session_state.patch_logs_result:
            st.subheader(f"📝 Patch Log Details for {filename}")
            st.text_area("Patch Log:", value=st.session_state.patch_logs_result.strip(), height=150, disabled=True, 
                         key=f"log_patch_active_{filename.replace('.', '_')}_{source_tab_name}")

        st.session_state.trigger_patch_for_active_file = False # Reset trigger


# --- Input Tabs ---
tab1_obj, tab2_obj, tab3_obj = st.tabs(["📤 Upload .java File", "📝 Paste Java Code", "🗂️ Upload ZIP Archive"])

with tab1_obj:
    st.subheader("📂 Upload a Single Java File")
    uploaded_file_widget = st.file_uploader(
        "Select your .java file",
        type=["java"],
        key="java_file_uploader_widget", # Unique key for the widget
        label_visibility="collapsed"
    )

    if uploaded_file_widget is not None:
        # Check if this uploaded file is different from the one currently active in session_state
        # or if no file is active yet.
        if (st.session_state.last_uploaded_filename != uploaded_file_widget.name or
            st.session_state.last_uploaded_file_size != uploaded_file_widget.size):
            
            st.session_state.uploaded_file_bytes = uploaded_file_widget.read()
            st.session_state.uploaded_filename = uploaded_file_widget.name
            st.session_state.last_uploaded_filename = uploaded_file_widget.name # Store name
            st.session_state.last_uploaded_file_size = uploaded_file_widget.size   # Store size
            
            # Set this tab as the source for display and clear other tab's results
            st.session_state.current_display_source_tab = "upload_file"
            clear_processing_results_single_file()
            st.session_state.zip_file_raw_bytes = None # Clear ZIP content when switching
            st.session_state.zip_file_content_hash = None
            st.session_state.zip_file_name = None
            st.session_state.zip_analysis_cache = {}
            st.session_state.zip_patch_cache = {}
            st.session_state.zip_patch_triggered_files = set()
            st.rerun() # Trigger a rerun to process the new file
    elif st.session_state.last_uploaded_filename is not None and uploaded_file_widget is None:
        # File was cleared by the user in this widget
        st.session_state.uploaded_file_bytes = None
        st.session_state.uploaded_filename = None
        st.session_state.last_uploaded_filename = None
        st.session_state.last_uploaded_file_size = None
        # If this was the active display source, clear it and rerun
        if st.session_state.current_display_source_tab == "upload_file":
            st.session_state.current_display_source_tab = None
            clear_processing_results_single_file()
            st.rerun()

    # Display results if this tab is the current source and file bytes are available
    if st.session_state.uploaded_file_bytes and st.session_state.current_display_source_tab == "upload_file":
        process_and_display_single_file(st.session_state.uploaded_filename, st.session_state.uploaded_file_bytes, "upload_file")


with tab2_obj:
    st.subheader("✍️ Paste Java Code")
    java_code_pasted_area = st.text_area(
        "Paste your Java code snippet here:",
        height=300,
        key="java_code_pasted_widget", # Unique key
        placeholder="public class MyClass {\n    // ... your Java code ...\n}"
    )
    if st.button("Scan Pasted Code", key="scan_pasted_code_button"):
        if java_code_pasted_area:
            pasted_bytes = java_code_pasted_area.encode("utf-8")
            # Check if the pasted code is different from what's stored
            if st.session_state.pasted_code_bytes != pasted_bytes:
                st.session_state.pasted_code_bytes = pasted_bytes
                # Set this tab as the source for display and clear other tab's results
                st.session_state.current_display_source_tab = "paste_code"
                clear_processing_results_single_file()
                st.session_state.zip_file_raw_bytes = None # Clear ZIP content when switching
                st.session_state.zip_file_content_hash = None
                st.session_state.zip_file_name = None
                st.session_state.zip_analysis_cache = {}
                st.session_state.zip_patch_cache = {}
                st.session_state.zip_patch_triggered_files = set()
                st.rerun() # Rerun to process this newly active pasted code
            elif st.session_state.current_display_source_tab != "paste_code":
                # If same code, but switched from another tab, re-activate display
                st.session_state.current_display_source_tab = "paste_code"
                st.rerun() # Rerun to display existing results
        else:
            st.warning("Please paste some Java code into the text area.")
            # If text area is empty and button clicked, clear state
            if st.session_state.current_display_source_tab == "paste_code":
                st.session_state.pasted_code_bytes = None
                st.session_state.current_display_source_tab = None
                clear_processing_results_single_file()
                st.rerun() # Rerun to clear display

    # Display results if this tab is the current source and pasted code bytes are available
    if st.session_state.pasted_code_bytes and st.session_state.current_display_source_tab == "paste_code":
        process_and_display_single_file(st.session_state.pasted_code_filename, st.session_state.pasted_code_bytes, "paste_code")


with tab3_obj:
    st.subheader("🗂️ Upload ZIP Archive")
    uploaded_zip_file = st.file_uploader(
        "Upload a ZIP archive containing .java files",
        type=["zip"],
        key="zip_file_uploader_widget", # Unique key
        label_visibility="collapsed"
    )

    # --- ZIP File Upload and Caching Logic ---
    if uploaded_zip_file:
        current_zip_bytes = uploaded_zip_file.read()
        current_zip_hash = hashlib.md5(current_zip_bytes).hexdigest()

        # Check if a new ZIP file has been uploaded or if content changed
        if st.session_state.zip_file_content_hash != current_zip_hash:
            st.session_state.zip_file_raw_bytes = current_zip_bytes
            st.session_state.zip_file_content_hash = current_zip_hash
            st.session_state.zip_file_name = uploaded_zip_file.name
            
            # Clear results related to other input types
            clear_processing_results_single_file()
            # Clear previous ZIP results
            st.session_state.zip_analysis_cache = {}
            st.session_state.zip_patch_cache = {}
            st.session_state.zip_patch_triggered_files = set()
            
            # Set this tab as the current display source and trigger rerun for processing
            st.session_state.current_display_source_tab = "zip_file"
            st.rerun() # Rerun to start processing the new ZIP
        else:
            # Same ZIP file, ensure this tab is active for display
            st.session_state.current_display_source_tab = "zip_file"
    elif st.session_state.zip_file_raw_bytes is not None and uploaded_zip_file is None:
        # ZIP uploader was cleared by the user, clear session state related to ZIP
        st.session_state.zip_file_raw_bytes = None
        st.session_state.zip_file_content_hash = None
        st.session_state.zip_file_name = None
        st.session_state.zip_analysis_cache = {}
        st.session_state.zip_patch_cache = {}
        st.session_state.zip_patch_triggered_files = set()
        if st.session_state.current_display_source_tab == "zip_file":
            st.session_state.current_display_source_tab = None
            st.rerun() # Rerun to clear display

    # --- ZIP File Processing and Display Logic ---
    # Only proceed if ZIP tab is active and we have ZIP content
    if st.session_state.current_display_source_tab == "zip_file" and st.session_state.zip_file_raw_bytes:
        st.markdown("---")
        st.write(f"Processing ZIP file: **{st.session_state.zip_file_name}**")
        
        java_files_in_zip = []
        try:
            with zipfile.ZipFile(io.BytesIO(st.session_state.zip_file_raw_bytes), 'r') as zip_ref:
                java_files_in_zip = [
                    name for name in zip_ref.namelist() 
                    if name.endswith(".java") and not zip_ref.getinfo(name).is_dir()
                ]
                if not java_files_in_zip:
                    st.warning("No .java files found in the uploaded ZIP archive.")
                else:
                    st.info(f"Found {len(java_files_in_zip)} Java file(s) in the ZIP.")
                    
                    # --- Analysis Pass for ZIP files ---
                    # Only analyze files not already in cache
                    files_to_analyze = [name for name in java_files_in_zip if name not in st.session_state.zip_analysis_cache]
                    if files_to_analyze:
                        st.write("Performing analysis on new/unprocessed Java files in ZIP...")
                        for member_name in files_to_analyze:
                            try:
                                file_bytes_zip = zip_ref.read(member_name)
                                with st.spinner(f"Analyzing {member_name} from ZIP..."):
                                    analysis_result = call_backend_api("analyze", member_name, file_bytes_zip, timeout=30)
                                    if analysis_result["ok"]:
                                        results_payload = analysis_result["data"].get("report", [])
                                        temp_analysis_items = []
                                        complete_sanitized_code_overall_zip = None
                                        for item in results_payload:
                                            if "complete_sanitized_code" in item:
                                                complete_sanitized_code_overall_zip = item["complete_sanitized_code"]
                                            else:
                                                temp_analysis_items.append(item)
                                        # If no vulnerabilities, create INFO message
                                        analysis_items_to_cache = temp_analysis_items if temp_analysis_items else [{"issue": "No vulnerabilities found by analyzer.", "severity": "INFO"}]
                                        
                                        st.session_state.zip_analysis_cache[member_name] = {
                                            "analysis_items": analysis_items_to_cache,
                                            "complete_sanitized_code_overall": complete_sanitized_code_overall_zip
                                        }
                                    else:
                                        st.session_state.zip_analysis_cache[member_name] = {
                                            "analysis_items": [{"issue": f"Analysis Failed (ZIP): {analysis_result['error']}", "severity": "ERROR"}],
                                            "complete_sanitized_code_overall": None
                                        }
                            except Exception as e:
                                st.error(f"Error processing {member_name} from ZIP: {e}")
                                st.session_state.zip_analysis_cache[member_name] = {
                                    "analysis_items": [{"issue": f"Unexpected Error (ZIP): {e}", "severity": "ERROR"}],
                                    "complete_sanitized_code_overall": None
                                }
                        st.success(f"Finished analyzing {len(files_to_analyze)} new Java file(s) from the ZIP archive.")
                        # Rerun if new analysis results were added, to ensure display updates cleanly
                        if files_to_analyze:
                            st.rerun()

                    # --- Display Loop for ZIP files ---
                    # This loop always displays from the cache, preventing repeated API calls
                    for member_name in java_files_in_zip:
                        st.markdown(f"---")
                        st.markdown(f"#### File: `{member_name}`")
                        
                        cached_data = st.session_state.zip_analysis_cache.get(member_name)
                        if cached_data:
                            display_analysis_items(cached_data["analysis_items"], filename_for_key=f"zip_display_{member_name}")
                            if cached_data["complete_sanitized_code_overall"]:
                                st.subheader(f"✅ Complete Auto-Patched Version for {member_name} (from Analyzer)")
                                st.code(cached_data["complete_sanitized_code_overall"].strip(), language="java")

                            # --- Auto-Patch Section for individual ZIP files ---
                            can_attempt_patch_zip = any(item.get("severity") not in ["ERROR", "INFO"] for item in cached_data["analysis_items"])
                            if can_attempt_patch_zip:
                                st.markdown(f"###### ⚙️ Auto-Patch Code for: {member_name}")
                                patch_button_key_zip = f"patch_button_zip_{member_name.replace('.', '_').replace('/', '_').replace(' ', '_')}"
                                
                                # Check if patching for this file was triggered or results are cached
                                patched_result_cached = st.session_state.zip_patch_cache.get(member_name)
                                
                                if st.button(f"Generate Patched Code for {member_name}", key=patch_button_key_zip):
                                    st.session_state.zip_patch_triggered_files.add(member_name)
                                    st.rerun() # Rerun to trigger the patching logic below
                                
                                # Process patch if triggered and not yet cached
                                if member_name in st.session_state.zip_patch_triggered_files and not patched_result_cached:
                                    file_bytes_zip = zip_ref.read(member_name) # Re-read bytes for patch API call
                                    with st.spinner(f"Auto-patching {member_name} from ZIP..."):
                                        patch_result = call_backend_api("patch", member_name, file_bytes_zip, timeout=60)
                                        if patch_result["ok"]:
                                            patched_code_zip = patch_result["data"].get("patched_code", "")
                                            patch_logs_zip = patch_result["data"].get("patch_logs", "")
                                            st.session_state.zip_patch_cache[member_name] = {
                                                "patched_code": patched_code_zip,
                                                "patch_logs": patch_logs_zip
                                            }
                                        else:
                                            st.session_state.zip_patch_cache[member_name] = {
                                                "patched_code": "",
                                                "patch_logs": f"Patching failed: {patch_result['error']}"
                                            }
                                    st.session_state.zip_patch_triggered_files.discard(member_name) # Remove from triggered set
                                    st.rerun() # Rerun to display the newly patched code
                                
                                # Display patched results from cache
                                if member_name in st.session_state.zip_patch_cache:
                                    patched_code_display = st.session_state.zip_patch_cache[member_name]["patched_code"]
                                    patch_logs_display = st.session_state.zip_patch_cache[member_name]["patch_logs"]

                                    if patched_code_display:
                                        st.subheader(f"🧰 Patched Code for {member_name}")
                                        st.code(patched_code_display.strip(), language="java")
                                    if patch_logs_display:
                                        st.text_area(f"Patch Log for {member_name}:", value=patch_logs_display.strip(), height=100, disabled=True, key=f"log_zip_display_{patch_button_key_zip}")
                        else:
                            st.warning(f"No analysis results available for {member_name}. An error might have occurred during processing.")

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


# --- Footer ---
st.markdown("---")
#st.markdown("<sub>Powered by Gemini Code Assist. For educational and illustrative purposes.</sub>", unsafe_allow_html=True)
