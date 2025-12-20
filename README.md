# BACh
**Broken Access Control Checker: A Multi-role Access Control Testing with Matrix Output**


### Architecture:
```
┌─────────────────┐
│  Burp Extension │  ← Configure roles, collect URLs, run tests
│     (v2.0)      │
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│   API Server    │  ← Manage roles/URLs, orchestrate testing
│   (port 5001)   │
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│  BAC Tester     │  ← Core testing engine
│   (Core)        │
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│ JSON → Excel    │  ← Auto color-coded conversion
│  (Converter)    │
└─────────────────┘
```

## 📦 Installation

### 1. Install Python Dependencies
```bash
cd v2.0
pip install -r requirements_v2.txt
```

**Dependencies:**
- Flask 2.3.0 (API server)
- flask-cors 4.0.0 (CORS support)
- openpyxl 3.1.2 (Excel generation)

### 2. Start API Server
```bash
python bac_api_server_v2.py
```

**Server will start on**: `http://localhost:5001`

### 3. Load Burp Extension
1. Open Burpsuite
2. Go to **Extender → Extensions**
3. Click **Add**
4. Extension Type: **Python**
5. Select: `burp_extension_v2.py`
6. Click **Next**

### 4. Verify Installation
- Check Burp extension loaded: Look for "BAC Checker v2.0" tab
- Check API server: Visit `http://localhost:5001/health`

## 🎯 Usage Workflow

### Step 1: Configure Roles

**In Burp Extension → Role Management tab:**

1. Enter role name (e.g., "admin", "user", "guest")
2. Paste authentication cookie
3. Click **Add Role**
4. Repeat for all roles you want to test

**Example:**
```
Role: admin
Cookie: PHPSESSID=abc123; user_token=xyz789

Role: user
Cookie: PHPSESSID=def456; user_token=uvw012
```

**Tips:**
- Get cookies from browser DevTools (F12 → Application → Cookies)
- You can add unlimited roles
- Roles are stored in `roles.json`

### Step 2: Collect URLs

**Method A: Auto-capture from Burp**
1. Go to **URL Collector** tab
2. Check **Auto-capture URLs**
3. Browse the target application in Burp's browser
4. URLs are automatically collected

**Method B: Right-click menu**
1. Browse target application
2. Right-click on any request
3. Select **Send to BAC Checker v2.0**

**Method C: Manual file**
1. Create/edit `urls.txt`
2. Add one URL per line
3. URLs are loaded automatically

### Step 3: Send URLs to API
1. In **URL Collector** tab
2. Click **Send to API**
3. Verifies URLs are stored for testing

### Step 4: Run Multi-Role Test
1. Go to **Test & Results** tab
2. Verify counts:
   - Roles configured: 3
   - URLs to test: 50
   - Total tests: 150 (50 × 3)
3. Click **Run BAC Test**
4. Monitor progress

**What happens:**
- Tests ALL URLs with ALL roles
- Shows progress: "Testing URL 25/50 with role 2/3"
- Saves results to JSON
- **Automatically converts to Excel**
- Shows "Excel file: test_20251210_153045.xlsx"

### Step 5: Analyze Results
1. Click **Open Excel** button
2. Review color-coded matrix:
   - **Green**: 200 OK (accessible)
   - **Orange**: Redirect (200→ or 301/302)
   - **Red**: Access Denied (403/404/401)
   - **Purple**: Server Error (500+)

**Example Excel Output:**
| Paths | admin | user | guest |
|-------|-------|------|-------|
| /dashboard | 200 (green) | 200 (green) | 200 (green) |
| /admin_page | 200 (green) | 403 (red) | 403 (red) |
| /user_profile | 200 (green) | 200 (green) | 302 (orange) |
| /api/admin/users | 200 (green) | 401 (red) | 401 (red) |

### Step 6: Find BAC Vulnerabilities

**Manual Analysis - Look for patterns:**

1. **User accessing Admin pages with 200**
   - Example: `/admin_page` shows green for "user" role
   - = BAC VULNERABILITY

2. **Guest accessing User pages with 200**
   - Example: `/user_profile` shows green for "guest" role
   - = BAC VULNERABILITY

3. **Proper Access Control (expected)**
   - Admin: Green (can access everything)
   - User: Green for user pages, Red for admin pages
   - Guest: Red or Orange for most pages

## 📊 Excel Color Coding

### Color Meanings:
```
🟢 Green (FF00B050)
   - Status: 200 OK (no redirect)
   - Meaning: Page is accessible
   - Action: Check if this role SHOULD access this page

🟠 Orange (FFFFC000)
   - Status: 200 → or 301/302
   - Meaning: Redirected (access blocked)
   - Action: Proper access control (expected)

🔴 Red (FFFF0000)
   - Status: 403/404/401
   - Meaning: Access explicitly denied
   - Action: Proper access control (expected)

🟣 Purple (FF7030A0)
   - Status: 500+
   - Meaning: Server error
   - Action: Needs investigation (not BAC)
```

### Important Notes:

**Redirect Detection:**
- Even if final status is 200, if URL redirected → marked ORANGE
- Example: `/admin` → `/login` → `/dashboard` (200) = ORANGE
- This indicates proper access control (blocked from original URL)

**No Automatic BAC Detection:**
- Tool reports facts, doesn't judge vulnerabilities
- Pentester decides what's proper vs. vulnerable
- Context matters (role permissions, application design)

## 🗂️ File Structure

```
v2.0/
├── bac_api_server_v2.py        # API server (port 5001)
├── bac_tester_v2.py            # Core testing engine
├── burp_extension_v2.py        # Burp extension
├── json_to_excel.py            # JSON → Excel converter
├── requirements_v2.txt         # Python dependencies
├── README_v2.md                # This file
├── urls.txt                    # URL list (auto-generated)
├── roles.json                  # Roles config (auto-generated)
└── results/                    # Test results
    ├── test_20251210_153045.json
    └── test_20251210_153045.xlsx
```

## 🔧 API Endpoints

### Role Management
```
GET    /api/roles                - List all roles
POST   /api/roles/add            - Add new role
PUT    /api/roles/update         - Update role cookie
DELETE /api/roles/delete         - Delete role
```

### URL Management
```
POST   /api/urls/add             - Add URLs
POST   /api/urls/clear           - Clear URLs
GET    /api/urls/list            - List URLs
```

### Testing
```
POST   /api/test/start           - Start multi-role test
POST   /api/test/stop            - Stop running test
GET    /api/test/status          - Get progress
GET    /api/test/results         - Get latest results
```

### Health
```
GET    /health                   - Health check
```

## 🐛 Troubleshooting

### "Connection refused" error
- **Cause**: API server not running
- **Fix**: Start server with `python bac_api_server_v2.py`

### "No roles configured" error
- **Cause**: No roles added
- **Fix**: Add roles in Role Management tab

### "No URLs to test" error
- **Cause**: URLs not sent to API
- **Fix**: Click "Send to API" in URL Collector tab

### Excel file not opening
- **Cause**: File path incorrect or file doesn't exist
- **Fix**: Check `results/` directory for latest `.xlsx` file

### 404 false positives
- **Cause**: Server blocking curl/bots
- **Fix**: Already handled with browser-like headers
- If still happening: Check server-side protections

## 🆚 v1.0 vs v2.0 Comparison

| Feature | v1.0 | v2.0 |
|---------|------|------|
| **Testing Mode** | Single role per run | Multi-role in one run |
| **Output Format** | Linear list | Matrix (paths × roles) |
| **Excel Export** | Manual CSV | Auto color-coded XLSX |
| **Role Management** | CLI prompts | Burp extension UI |
| **BAC Detection** | Automatic (error-prone) | Manual analysis |
| **Use Case** | Quick single-role tests | Comprehensive multi-role audit |
| **API Port** | 5000 | 5001 |
| **Burp Extension** | Basic | Advanced with role mgmt |

**When to use v1.0:**
- Quick testing with one role
- Real-time testing
- Simple access status check

**When to use v2.0:**
- Comprehensive multi-role audit
- Matrix comparison needed
- Professional pentest reports
- Complex access control analysis

## 📝 Example Test Scenario

### Target: E-commerce Application
**Roles to test:**
1. admin (full access)
2. vendor (can manage own products)
3. customer (can view and purchase)
4. guest (unauthenticated)

### URLs to test:
```
/admin/dashboard
/admin/users
/vendor/products
/vendor/orders
/customer/profile
/customer/cart
/products
/login
```

### Expected Results Matrix:
| Path | admin | vendor | customer | guest |
|------|-------|--------|----------|-------|
| /admin/dashboard | 200 | 403 | 403 | 302 |
| /admin/users | 200 | 403 | 403 | 302 |
| /vendor/products | 200 | 200 | 403 | 302 |
| /vendor/orders | 200 | 200 | 403 | 302 |
| /customer/profile | 200 | 403 | 200 | 302 |
| /customer/cart | 200 | 200 | 200 | 302 |
| /products | 200 | 200 | 200 | 200 |
| /login | 200 | 200 | 200 | 200 |

### BAC Vulnerability Example:
If customer shows **200 (green)** for `/admin/users`:
- ❌ BAC VULNERABILITY - Customer should NOT access admin pages
- Report this in your pentest findings

## 📚 Additional Resources

- **v1.0 Documentation**: See `../CLAUDE.md`
- **Burpsuite Integration**: See `../BURPSUITE_INTEGRATION.md`
- **OWASP BAC**: https://owasp.org/www-project-top-ten/
- **Access Control Testing**: OWASP Testing Guide v4

## 🤝 Contributing

This is a security testing tool for authorized penetration testing only.

## 📄 License

Use for authorized security testing and educational purposes only.

## ⚠️ Disclaimer

This tool is for authorized security testing only. Only use on applications you have permission to test. Unauthorized access testing is illegal.

---

**Version**: 2.0.0
**Author**: Security Researcher
**Last Updated**: 2025-12-10




