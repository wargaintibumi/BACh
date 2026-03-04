#!/usr/bin/env python3
"""
BAC Checker v2.0 - API Server
Flask API for multi-role BAC testing with Burpsuite integration

Endpoints:
    Role Management:
        GET  /api/roles              - List all roles
        POST /api/roles/add          - Add a new role
        PUT  /api/roles/update       - Update role cookie
        DELETE /api/roles/delete     - Delete a role

    URL Management:
        POST /api/urls/add           - Add URLs
        POST /api/urls/clear         - Clear all URLs
        GET  /api/urls/list          - List all URLs

    Testing:
        POST /api/test/start         - Start multi-role test
        POST /api/test/stop          - Stop running test
        GET  /api/test/status        - Get test progress
        GET  /api/test/results       - Get latest results

    Health:
        GET  /health                 - Health check
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from pathlib import Path
from datetime import datetime
import json
import threading
import subprocess
import sys

# Import our testing module
from bac_tester_v2 import test_all_urls_with_roles, save_results_to_json
from json_to_excel import json_to_excel

app = Flask(__name__)
CORS(app)

# Configuration
BASE_DIR = Path(__file__).parent
URLS_FILE = BASE_DIR / "urls.json"
URLS_FILE_TXT = BASE_DIR / "urls.txt"  # Legacy plain text format
ROLES_FILE = BASE_DIR / "roles.json"
EXCLUSIONS_FILE = BASE_DIR / "exclusions.json"
RESULTS_DIR = BASE_DIR / "results"

# Ensure directories exist
RESULTS_DIR.mkdir(exist_ok=True)

# Global state
roles = []  # List of {name: str, cookie: str}
urls = []   # List of URL objects: {url: str, method: str, body: str, content_type: str}
exclusion_patterns = []  # List of regex patterns to exclude
test_status = {
    "running": False,
    "progress": 0,
    "total": 0,
    "current_url": "",
    "current_role": "",
    "started_at": None,
    "completed_at": None,
    "stopped": False
}
test_results = None
test_thread = None
stop_test_flag = False


def load_roles():
    """Load roles from file"""
    global roles
    if ROLES_FILE.exists():
        with open(ROLES_FILE, 'r', encoding='utf-8') as f:
            roles = json.load(f)
    else:
        roles = []


def save_roles():
    """Save roles to file"""
    with open(ROLES_FILE, 'w', encoding='utf-8') as f:
        json.dump(roles, f, indent=2)


def normalize_url_entry(entry):
    """Normalize a URL entry to a standard dict format"""
    if isinstance(entry, str):
        return {'url': entry.strip(), 'method': 'GET', 'body': None, 'content_type': None}
    return {
        'url': entry.get('url', '').strip(),
        'method': entry.get('method', 'GET').upper(),
        'body': entry.get('body') or None,
        'content_type': entry.get('content_type') or None,
    }


def url_entry_key(entry):
    """Generate a unique key for dedup: 'METHOD url'"""
    return f"{entry.get('method', 'GET').upper()} {entry.get('url', '')}"


def load_urls():
    """Load URLs from file (JSON format, with legacy txt fallback)"""
    global urls
    if URLS_FILE.exists():
        with open(URLS_FILE, 'r', encoding='utf-8') as f:
            raw = json.load(f)
            urls = [normalize_url_entry(e) for e in raw]
    elif URLS_FILE_TXT.exists():
        # Legacy: load from plain text urls.txt
        with open(URLS_FILE_TXT, 'r', encoding='utf-8') as f:
            urls = [normalize_url_entry(line.strip()) for line in f if line.strip()]
    else:
        urls = []


def save_urls():
    """Save URLs to JSON file"""
    with open(URLS_FILE, 'w', encoding='utf-8') as f:
        json.dump(urls, f, indent=2, ensure_ascii=False)


def load_exclusions():
    """Load exclusion patterns from file"""
    global exclusion_patterns
    if EXCLUSIONS_FILE.exists():
        with open(EXCLUSIONS_FILE, 'r', encoding='utf-8') as f:
            exclusion_patterns = json.load(f)
    else:
        exclusion_patterns = []


def save_exclusions():
    """Save exclusion patterns to file"""
    with open(EXCLUSIONS_FILE, 'w', encoding='utf-8') as f:
        json.dump(exclusion_patterns, f, indent=2)


def is_url_excluded(url):
    """Check if URL matches any exclusion pattern"""
    import re
    for pattern in exclusion_patterns:
        try:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


# Load initial data
load_roles()
load_urls()
load_exclusions()


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "ok",
        "service": "BAC Checker v2.0 API",
        "version": "2.0.0"
    })


# ============================================================================
# ROLE MANAGEMENT
# ============================================================================

@app.route('/api/roles', methods=['GET'])
def get_roles():
    """List all configured roles"""
    return jsonify({
        "success": True,
        "roles": roles,
        "count": len(roles)
    })


@app.route('/api/roles/add', methods=['POST'])
def add_role():
    """Add a new role (supports cookie, Bearer token, or custom header)"""
    try:
        data = request.json
        role_name = data.get('name', '').strip()
        auth_type = data.get('auth_type', 'cookie').strip().lower()  # 'cookie', 'token', or 'header'
        auth_value = data.get('auth_value', '').strip()
        header_name = data.get('header_name', '').strip()

        # Backwards compatibility: if 'cookie' field exists, use it
        if not auth_value and data.get('cookie'):
            auth_value = data.get('cookie', '').strip()
            auth_type = 'cookie'

        if not role_name:
            return jsonify({"success": False, "error": "Role name is required"}), 400

        if not auth_value:
            return jsonify({"success": False, "error": "Authentication value is required"}), 400

        if auth_type not in ['cookie', 'token', 'header']:
            return jsonify({"success": False, "error": "Auth type must be 'cookie', 'token', or 'header'"}), 400

        if auth_type == 'header' and not header_name:
            return jsonify({"success": False, "error": "Header name is required for custom header auth type"}), 400

        # Check if role already exists
        if any(r['name'] == role_name for r in roles):
            return jsonify({"success": False, "error": f"Role '{role_name}' already exists"}), 400

        # Add role with auth type
        roles.append({
            "name": role_name,
            "auth_type": auth_type,
            "auth_value": auth_value,
            "header_name": header_name if auth_type == 'header' else "",
            # Backwards compatibility fields
            "cookie": auth_value if auth_type == 'cookie' else ""
        })
        save_roles()

        return jsonify({
            "success": True,
            "message": f"Role '{role_name}' added",
            "total_roles": len(roles)
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/roles/update', methods=['PUT'])
def update_role():
    """Update role authentication"""
    try:
        data = request.json
        role_name = data.get('name', '').strip()
        auth_type = data.get('auth_type', 'cookie').strip().lower()
        auth_value = data.get('auth_value', '').strip()
        header_name = data.get('header_name', '').strip()

        # Backwards compatibility
        if not auth_value and data.get('cookie'):
            auth_value = data.get('cookie', '').strip()
            auth_type = 'cookie'

        if not role_name:
            return jsonify({"success": False, "error": "Role name is required"}), 400

        if auth_type not in ['cookie', 'token', 'header']:
            return jsonify({"success": False, "error": "Auth type must be 'cookie', 'token', or 'header'"}), 400

        if auth_type == 'header' and not header_name:
            return jsonify({"success": False, "error": "Header name is required for custom header auth type"}), 400

        # Find and update role
        for role in roles:
            if role['name'] == role_name:
                role['auth_type'] = auth_type
                role['auth_value'] = auth_value
                role['header_name'] = header_name if auth_type == 'header' else ""
                # Backwards compatibility
                role['cookie'] = auth_value if auth_type == 'cookie' else ""
                save_roles()
                return jsonify({
                    "success": True,
                    "message": f"Role '{role_name}' updated"
                })

        return jsonify({"success": False, "error": f"Role '{role_name}' not found"}), 404

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/roles/delete', methods=['DELETE'])
def delete_role():
    """Delete a role"""
    try:
        data = request.json
        role_name = data.get('name', '').strip()

        if not role_name:
            return jsonify({"success": False, "error": "Role name is required"}), 400

        # Find and remove role
        global roles
        initial_count = len(roles)
        roles = [r for r in roles if r['name'] != role_name]

        if len(roles) < initial_count:
            save_roles()
            return jsonify({
                "success": True,
                "message": f"Role '{role_name}' deleted",
                "total_roles": len(roles)
            })

        return jsonify({"success": False, "error": f"Role '{role_name}' not found"}), 404

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/roles/clear', methods=['POST'])
def clear_all_roles():
    """Delete all roles"""
    try:
        global roles
        count = len(roles)
        roles = []
        save_roles()

        return jsonify({
            "success": True,
            "message": "All roles deleted",
            "deleted_count": count
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================================
# EXCLUSION PATTERN MANAGEMENT
# ============================================================================

@app.route('/api/exclusions', methods=['GET'])
def get_exclusions():
    """List all exclusion patterns"""
    return jsonify({
        "success": True,
        "patterns": exclusion_patterns,
        "count": len(exclusion_patterns)
    })


@app.route('/api/exclusions/add', methods=['POST'])
def add_exclusion():
    """Add exclusion pattern"""
    try:
        data = request.json
        pattern = data.get('pattern', '').strip()

        if not pattern:
            return jsonify({"success": False, "error": "Pattern is required"}), 400

        # Validate regex
        import re
        try:
            re.compile(pattern)
        except re.error as e:
            return jsonify({"success": False, "error": f"Invalid regex: {str(e)}"}), 400

        # Check if pattern already exists
        if pattern in exclusion_patterns:
            return jsonify({"success": False, "error": "Pattern already exists"}), 400

        exclusion_patterns.append(pattern)
        save_exclusions()

        return jsonify({
            "success": True,
            "message": f"Exclusion pattern added",
            "total_patterns": len(exclusion_patterns)
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/exclusions/delete', methods=['DELETE'])
def delete_exclusion():
    """Delete exclusion pattern"""
    try:
        data = request.json
        pattern = data.get('pattern', '').strip()

        if not pattern:
            return jsonify({"success": False, "error": "Pattern is required"}), 400

        global exclusion_patterns
        if pattern in exclusion_patterns:
            exclusion_patterns.remove(pattern)
            save_exclusions()
            return jsonify({
                "success": True,
                "message": "Pattern deleted",
                "total_patterns": len(exclusion_patterns)
            })

        return jsonify({"success": False, "error": "Pattern not found"}), 404

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/exclusions/clear', methods=['POST'])
def clear_exclusions():
    """Clear all exclusion patterns"""
    try:
        global exclusion_patterns
        exclusion_patterns = []
        save_exclusions()

        return jsonify({
            "success": True,
            "message": "All exclusion patterns cleared"
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================================
# URL MANAGEMENT
# ============================================================================

@app.route('/api/urls/add', methods=['POST'])
def add_urls():
    """Add URLs to the list (supports plain strings or URL objects with method/body)"""
    try:
        data = request.json
        new_urls = data.get('urls', [])
        append = data.get('append', True)

        if not new_urls:
            return jsonify({"success": False, "error": "No URLs provided"}), 400

        global urls

        if not append:
            urls = []

        # Build set of existing keys for fast dedup lookup
        existing_keys = {url_entry_key(u) for u in urls}

        # Add new URLs (avoid duplicates and check exclusions)
        added = 0
        duplicates = 0
        excluded = 0

        for entry in new_urls:
            normalized = normalize_url_entry(entry)
            url_str = normalized['url']

            if not url_str:
                continue

            # Check if URL matches exclusion pattern
            if is_url_excluded(url_str):
                excluded += 1
                continue

            key = url_entry_key(normalized)
            if key not in existing_keys:
                urls.append(normalized)
                existing_keys.add(key)
                added += 1
            else:
                duplicates += 1

        save_urls()

        return jsonify({
            "success": True,
            "added": added,
            "total": len(urls),
            "duplicates_skipped": duplicates,
            "excluded": excluded
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/urls/clear', methods=['POST'])
def clear_urls():
    """Clear all URLs"""
    try:
        global urls
        urls = []
        save_urls()

        return jsonify({
            "success": True,
            "message": "All URLs cleared"
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/urls/list', methods=['GET'])
def list_urls():
    """List all URLs"""
    return jsonify({
        "success": True,
        "urls": urls,
        "count": len(urls)
    })


@app.route('/api/urls/deduplicate', methods=['POST'])
def deduplicate_urls():
    """Deduplicate URLs (treat /path and /path/ as same, per method)"""
    try:
        global urls

        # Deduplicate by normalized key (method + url without trailing slash)
        seen = {}
        for entry in urls:
            norm_url = entry['url'].rstrip('/')
            key = f"{entry['method']} {norm_url}"
            if key not in seen:
                # Store with normalized URL
                deduped = dict(entry)
                deduped['url'] = norm_url
                seen[key] = deduped

        original_count = len(urls)
        urls = list(seen.values())
        save_urls()

        removed = original_count - len(urls)

        return jsonify({
            "success": True,
            "message": "URLs deduplicated",
            "original_count": original_count,
            "unique_count": len(urls),
            "removed": removed
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================================
# TESTING
# ============================================================================

def progress_callback(current, total, url, role):
    """Update test progress"""
    test_status["progress"] = int((current / total) * 100)
    test_status["current_url"] = url
    test_status["current_role"] = role


def should_stop():
    """Check if testing should stop"""
    return stop_test_flag


def run_test_background():
    """Run multi-role test in background"""
    global test_status, test_results, stop_test_flag

    try:
        test_status["running"] = True
        test_status["started_at"] = datetime.now().isoformat()
        test_status["completed_at"] = None
        test_status["progress"] = 0
        test_status["stopped"] = False
        stop_test_flag = False

        # Run the test
        test_results = test_all_urls_with_roles(
            urls=urls,
            roles=roles,
            progress_callback=progress_callback,
            stop_callback=should_stop
        )

        # Save to JSON
        json_file = save_results_to_json(test_results, output_dir=str(RESULTS_DIR))

        # Auto-convert to Excel
        print("\n🔄 Converting to Excel...")
        excel_file = json_to_excel(json_file)

        # Update status
        test_status["running"] = False
        test_status["completed_at"] = datetime.now().isoformat()
        test_status["progress"] = 100
        test_status["stopped"] = test_results.get('stopped', False)
        test_status["json_file"] = json_file
        test_status["excel_file"] = excel_file

        print(f"\n✅ Test complete! Excel file: {excel_file}")

    except Exception as e:
        test_status["running"] = False
        test_status["error"] = str(e)
        print(f"\n❌ Test error: {str(e)}")


@app.route('/api/test/start', methods=['POST'])
def start_test():
    """Start multi-role BAC test"""
    global test_thread, test_status

    try:
        if test_status["running"]:
            return jsonify({"success": False, "error": "Test is already running"}), 400

        if not urls:
            return jsonify({"success": False, "error": "No URLs to test. Add URLs first."}), 400

        if not roles:
            return jsonify({"success": False, "error": "No roles configured. Add roles first."}), 400

        # Start test in background thread
        test_thread = threading.Thread(target=run_test_background)
        test_thread.daemon = True
        test_thread.start()

        return jsonify({
            "success": True,
            "message": "Test started",
            "total_urls": len(urls),
            "total_roles": len(roles),
            "total_tests": len(urls) * len(roles)
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/test/stop', methods=['POST'])
def stop_test():
    """Stop running test"""
    global stop_test_flag

    try:
        if not test_status["running"]:
            return jsonify({"success": False, "error": "No test is running"}), 400

        stop_test_flag = True

        return jsonify({
            "success": True,
            "message": "Test stop requested"
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/test/status', methods=['GET'])
def get_test_status():
    """Get current test status"""
    return jsonify({
        "success": True,
        "status": test_status
    })


@app.route('/api/test/results', methods=['GET'])
def get_test_results():
    """Get latest test results"""
    try:
        # Find the latest results file
        result_files = sorted(RESULTS_DIR.glob("test_*.json"), reverse=True)

        if not result_files:
            return jsonify({
                "success": False,
                "error": "No test results found"
            }), 404

        with open(result_files[0], 'r', encoding='utf-8') as f:
            results = json.load(f)

        # Find corresponding Excel file
        excel_file = result_files[0].with_suffix('.xlsx')

        return jsonify({
            "success": True,
            "results": results,
            "json_file": str(result_files[0]),
            "excel_file": str(excel_file) if excel_file.exists() else None
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("="*70)
    print("BAC Checker v2.0 API Server")
    print("="*70)
    print(f"URLs file: {URLS_FILE} (legacy: {URLS_FILE_TXT})")
    print(f"Roles file: {ROLES_FILE}")
    print(f"Results directory: {RESULTS_DIR}")
    print(f"Loaded: {len(roles)} roles, {len(urls)} URLs")
    print("\nAPI Endpoints:")
    print("  Role Management:")
    print("    GET    /api/roles                - List roles")
    print("    POST   /api/roles/add            - Add role")
    print("    PUT    /api/roles/update         - Update role")
    print("    DELETE /api/roles/delete         - Delete role")
    print("  Exclusion Patterns:")
    print("    GET    /api/exclusions           - List exclusion patterns")
    print("    POST   /api/exclusions/add       - Add exclusion pattern")
    print("    DELETE /api/exclusions/delete    - Delete exclusion pattern")
    print("    POST   /api/exclusions/clear     - Clear all exclusion patterns")
    print("  URL Management:")
    print("    POST   /api/urls/add             - Add URLs (auto-excludes)")
    print("    POST   /api/urls/clear           - Clear URLs")
    print("    GET    /api/urls/list            - List URLs")
    print("  Testing:")
    print("    POST   /api/test/start           - Start test")
    print("    POST   /api/test/stop            - Stop test")
    print("    GET    /api/test/status          - Test status")
    print("    GET    /api/test/results         - Get results")
    print("  Health:")
    print("    GET    /health                   - Health check")
    print("\nStarting server on http://localhost:5001")
    print("="*70)

    app.run(host='0.0.0.0', port=5001, debug=False)
