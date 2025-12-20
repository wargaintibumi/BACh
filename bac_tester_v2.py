#!/usr/bin/env python3
"""
BAC Checker v2.0 - Core Testing Engine
Multi-role access control testing with matrix output

This module provides the core functionality for testing URLs with multiple roles
and generating a matrix of results (paths × roles).
"""

import subprocess
import os
import json
from datetime import datetime
from pathlib import Path


def test_url_with_role(url, role_name, cookie=None, auth_type='cookie', auth_value=None, timeout=10):
    """
    Test a single URL with a specific role's authentication.

    Args:
        url: URL to test
        role_name: Name of the role being tested
        cookie: Cookie string for authentication (deprecated, use auth_value)
        auth_type: Type of authentication ('cookie' or 'token')
        auth_value: Authentication value (cookie string or Bearer token)
        timeout: Request timeout in seconds

    Returns:
        dict: {
            'url': str,
            'role': str,
            'status_code': str,
            'redirected': bool,
            'final_url': str,
            'error': str or None
        }
    """
    try:
        # Backwards compatibility: if cookie is provided, use it
        if cookie and not auth_value:
            auth_value = cookie
            auth_type = 'cookie'

        # Build curl command with browser-like headers
        cmd = [
            'curl.exe',
            '-s',  # Silent mode
            '-o', 'nul' if os.name == 'nt' else '/dev/null',  # Discard response body
            '-w', '%{http_code}|%{url_effective}',  # Output: status|final_url
            '--max-time', str(timeout),
            '-L',  # Follow redirects
            '-k',  # Allow insecure SSL
        ]

        # Add authentication header based on type
        if auth_type == 'token':
            cmd.extend(['-H', f'Authorization: Bearer {auth_value}'])
        else:  # cookie (default)
            cmd.extend(['-H', f'Cookie: {auth_value}'])

        # Add browser-like headers to avoid anti-bot protection
        cmd.extend([
            '-H', 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            '-H', 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            '-H', 'Accept-Language: en-US,en;q=0.9',
            '-H', 'Accept-Encoding: gzip, deflate',
            '-H', 'Connection: keep-alive',
            '-H', 'Upgrade-Insecure-Requests: 1',
            '-H', 'Sec-Fetch-Dest: document',
            '-H', 'Sec-Fetch-Mode: navigate',
            '-H', 'Sec-Fetch-Site: none',
            '-H', 'Sec-Fetch-User: ?1',
            url
        ])

        # Execute curl
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5
        )

        # Parse output: http_code|url_effective
        output = result.stdout.strip()

        if output and '|' in output:
            parts = output.split('|')
            status_code = parts[0]
            final_url = parts[1] if len(parts) > 1 else url

            # Determine if URL was redirected
            redirected = (url.rstrip('/') != final_url.rstrip('/'))

            return {
                'url': url,
                'role': role_name,
                'status_code': status_code,
                'redirected': redirected,
                'final_url': final_url,
                'error': None
            }
        else:
            return {
                'url': url,
                'role': role_name,
                'status_code': '000',
                'redirected': False,
                'final_url': url,
                'error': 'No response from curl'
            }

    except subprocess.TimeoutExpired:
        return {
            'url': url,
            'role': role_name,
            'status_code': '000',
            'redirected': False,
            'final_url': url,
            'error': 'Timeout'
        }
    except Exception as e:
        return {
            'url': url,
            'role': role_name,
            'status_code': '000',
            'redirected': False,
            'final_url': url,
            'error': str(e)
        }


def test_all_urls_with_roles(urls, roles, progress_callback=None, stop_callback=None):
    """
    Test all URLs with all roles, creating a matrix of results.

    Args:
        urls: List of URLs to test
        roles: List of role dicts [{'name': 'admin', 'cookie': 'PHPSESSID=...'}, ...]
        progress_callback: Optional callback(current, total, url, role) for progress updates
        stop_callback: Optional callback() returning True if testing should stop

    Returns:
        dict: {
            'test_date': str (ISO format),
            'urls': list of URLs,
            'roles': list of role names,
            'results': {
                '/path1': {'role1': '200', 'role2': '403', ...},
                '/path2': {'role1': '200', 'role2': '200', ...}
            },
            'details': {
                '/path1': {
                    'role1': {'status': '200', 'redirected': False, 'final_url': '...'},
                    'role2': {'status': '403', 'redirected': False, 'final_url': '...'}
                }
            }
        }
    """

    print("="*70)
    print("BAC Checker v2.0 - Multi-Role Testing")
    print("="*70)
    print(f"URLs to test: {len(urls)}")
    print(f"Roles: {', '.join([r['name'] for r in roles])}")
    print(f"Total requests: {len(urls)} × {len(roles)} = {len(urls) * len(roles)}")
    print("="*70)

    # Initialize results structure
    results = {}
    details = {}
    role_names = [role['name'] for role in roles]

    total_tests = len(urls) * len(roles)
    current_test = 0
    stopped = False

    # Test each URL with each role
    for url in urls:
        results[url] = {}
        details[url] = {}

        for role in roles:
            # Check if testing should stop
            if stop_callback and stop_callback():
                print("\n⚠️  Testing stopped by user")
                stopped = True
                break

            current_test += 1

            # Progress update
            if progress_callback:
                progress_callback(current_test, total_tests, url, role['name'])

            print(f"[{current_test}/{total_tests}] Testing {url} as {role['name']}", end=' ', flush=True)

            # Test the URL with this role
            # Support both old format (cookie) and new format (auth_type + auth_value)
            auth_type = role.get('auth_type', 'cookie')
            auth_value = role.get('auth_value', role.get('cookie', ''))
            result = test_url_with_role(
                url,
                role['name'],
                auth_type=auth_type,
                auth_value=auth_value,
                timeout=10
            )

            # Store status code in results matrix
            if result['redirected']:
                # Mark as redirect even if final status is 200
                results[url][role['name']] = f"{result['status_code']} →"
            else:
                results[url][role['name']] = result['status_code']

            # Store detailed information
            details[url][role['name']] = {
                'status': result['status_code'],
                'redirected': result['redirected'],
                'final_url': result['final_url'],
                'error': result['error']
            }

            # Display result
            if result['error']:
                print(f"[FAIL] {result['error']}")
            else:
                status_display = f"{result['status_code']}"
                if result['redirected']:
                    status_display += f" → {result['final_url'][:40]}..."
                print(f"[{status_display}]")

        if stopped:
            break

    # Generate summary
    print(f"\n{'='*70}")
    if stopped:
        print("Testing Stopped - Partial Results")
    else:
        print("Testing Complete")
    print(f"{'='*70}")

    # Create result object
    test_results = {
        'test_date': datetime.now().isoformat(),
        'urls': list(results.keys()),
        'roles': role_names,
        'results': results,
        'details': details,
        'stopped': stopped,
        'total_urls': len(urls),
        'tested_urls': len(results),
        'total_roles': len(roles)
    }

    return test_results


def save_results_to_json(results, output_dir='results'):
    """
    Save test results to JSON file.

    Args:
        results: Results dictionary from test_all_urls_with_roles()
        output_dir: Directory to save results

    Returns:
        str: Path to saved JSON file
    """
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = output_path / f"test_{timestamp}.json"

    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Results saved to: {json_file}")
    return str(json_file)


if __name__ == "__main__":
    # Example usage
    print("BAC Tester v2.0 - Core Testing Engine")
    print("This module is meant to be imported and used by the API server.")
    print("\nExample usage:")
    print("""
    from bac_tester_v2 import test_all_urls_with_roles, save_results_to_json

    urls = ['/admin', '/user', '/dashboard']
    roles = [
        {'name': 'admin', 'cookie': 'PHPSESSID=abc123'},
        {'name': 'user', 'cookie': 'PHPSESSID=xyz789'}
    ]

    results = test_all_urls_with_roles(urls, roles)
    json_file = save_results_to_json(results)
    """)
