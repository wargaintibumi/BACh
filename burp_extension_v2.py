#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
BurpSuite Extension for BAC Checker v2.0
Multi-role access control testing with matrix output

Features:
- Multi-role configuration and management
- URL collection from Burp traffic
- Multi-role testing (all URLs × all roles)
- Auto Excel generation
- Matrix result viewing

Author: Security Researcher
Version: 2.0
"""

try:
    from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpListener
    from java.awt import Component, BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints, Insets, Dimension
    from javax.swing import (JPanel, JLabel, JTextField, JButton, JTextArea,
                            JScrollPane, JSplitPane, JTabbedPane, JTable,
                            JCheckBox, JComboBox, JMenuItem, SwingUtilities, JOptionPane, Timer, JProgressBar)
    from java.awt.event import ActionListener
    from javax.swing.table import DefaultTableModel
    from java.util import ArrayList
    from java.net import URL
    from java.awt import Desktop
    from java.io import File
    import json
    import urllib2
    import time
    import re

    print("[OK] All imports successful")
except Exception as e:
    print("[ERROR] Import error: {}".format(str(e)))


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        try:
            self._callbacks = callbacks
            self._helpers = callbacks.getHelpers()

            # Extension info
            callbacks.setExtensionName("BAC Checker v2.0")

            # API configuration
            self.api_host = "localhost"
            self.api_port = "5001"  # Different port from v1.0
            self.auto_capture = False

            # Data storage
            self.captured_urls = {}  # key: "METHOD url" -> {url, method, body, content_type}
            self.roles = []  # List of {name: str, cookie: str}
            self.exclusion_patterns = []  # List of regex patterns

            # Auto-polling timer for test status
            self.status_poll_timer = None
            self._last_logged_progress = -1  # Track last logged progress to avoid spam
            self._test_completed_logged = False  # Track if completion was already logged
            self._poll_error_count = 0  # Track consecutive polling errors

            # Register listeners
            callbacks.registerContextMenuFactory(self)
            callbacks.registerHttpListener(self)

            # Create UI
            self.createUI()
            callbacks.addSuiteTab(self)

            # Load roles, exclusions, and URLs from API
            self.loadRolesFromAPI()
            self.loadExclusionsFromAPI()
            self.loadURLsFromAPI()

            print("[INIT] BAC Checker v2.0 Extension Loaded")
            print("[INFO] API Server: http://{}:{}".format(self.api_host, self.api_port))

        except Exception as e:
            print("[ERROR] Extension initialization error: {}".format(str(e)))

    def createUI(self):
        try:
            # Main panel with tabs
            self._main_panel = JTabbedPane()

            # Tab 1: Role Management
            role_tab = self.createRoleManagementTab()
            self._main_panel.addTab("Role Management", role_tab)

            # Auth type combo listener to toggle header name field and update label
            def onAuthTypeChanged(event):
                selected = str(self._auth_type_combo.getSelectedItem())
                self._header_name_field.setEnabled(selected == "Custom Header")
                if selected != "Custom Header":
                    self._header_name_field.setText("")
                # Update value label based on auth type
                if selected == "Cookie":
                    self._auth_value_label.setText("Cookie:")
                elif selected == "Bearer Token":
                    self._auth_value_label.setText("Token:")
                else:
                    self._auth_value_label.setText("Header Value:")

            self._auth_type_combo.addActionListener(onAuthTypeChanged)

            # Tab 2: URL Exclusions
            exclusion_tab = self.createExclusionTab()
            self._main_panel.addTab("URL Exclusions", exclusion_tab)

            # Tab 3: URL Collector
            collector_tab = self.createURLCollectorTab()
            self._main_panel.addTab("URL Collector", collector_tab)

            # Tab 4: Test & Results
            test_tab = self.createTestTab()
            self._main_panel.addTab("Test & Results", test_tab)

        except Exception as e:
            print("[ERROR] UI creation error: {}".format(str(e)))
            self._main_panel = JPanel()
            self._main_panel.add(JLabel("Extension loaded but UI failed to create"))

    # ========================================================================
    # TAB 1: ROLE MANAGEMENT
    # ========================================================================

    def createRoleManagementTab(self):
        panel = JPanel(BorderLayout())

        # Top panel - Add role form
        form_panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.HORIZONTAL

        gbc.gridx = 0; gbc.gridy = 0
        form_panel.add(JLabel("Role Name:"), gbc)
        gbc.gridx = 1
        self._role_name_field = JTextField(15)
        form_panel.add(self._role_name_field, gbc)

        gbc.gridx = 0; gbc.gridy = 1
        form_panel.add(JLabel("Auth Type:"), gbc)
        gbc.gridx = 1
        self._auth_type_combo = JComboBox(["Cookie", "Bearer Token", "Custom Header"])
        form_panel.add(self._auth_type_combo, gbc)

        gbc.gridx = 0; gbc.gridy = 2
        form_panel.add(JLabel("Header Name:"), gbc)
        gbc.gridx = 1
        self._header_name_field = JTextField(15)
        self._header_name_field.setToolTipText("e.g. X-API-Key, Authorization, X-Session-Token")
        self._header_name_field.setEnabled(False)
        form_panel.add(self._header_name_field, gbc)

        gbc.gridx = 0; gbc.gridy = 3
        self._auth_value_label = JLabel("Cookie:")
        form_panel.add(self._auth_value_label, gbc)
        gbc.gridx = 1
        self._role_cookie_field = JTextField(30)
        form_panel.add(self._role_cookie_field, gbc)

        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2
        button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        add_role_btn = JButton("Add Role", actionPerformed=self.addRole)
        button_panel.add(add_role_btn)
        update_role_btn = JButton("Update Selected", actionPerformed=self.updateRole)
        button_panel.add(update_role_btn)
        delete_role_btn = JButton("Delete Selected", actionPerformed=self.deleteRole)
        button_panel.add(delete_role_btn)
        delete_all_roles_btn = JButton("Delete All Roles", actionPerformed=self.deleteAllRoles)
        button_panel.add(delete_all_roles_btn)
        refresh_roles_btn = JButton("Refresh", actionPerformed=lambda e: self.loadRolesFromAPI())
        button_panel.add(refresh_roles_btn)
        form_panel.add(button_panel, gbc)

        panel.add(form_panel, BorderLayout.NORTH)

        # Center panel - Roles table
        column_names = ["Role Name", "Auth Type", "Header Name", "Auth Value"]
        self._roles_model = DefaultTableModel(column_names, 0)
        self._roles_table = JTable(self._roles_model)
        self._roles_table.getColumnModel().getColumn(0).setPreferredWidth(120)
        self._roles_table.getColumnModel().getColumn(1).setPreferredWidth(100)
        self._roles_table.getColumnModel().getColumn(2).setPreferredWidth(120)
        self._roles_table.getColumnModel().getColumn(3).setPreferredWidth(300)

        scroll_pane = JScrollPane(self._roles_table)
        panel.add(scroll_pane, BorderLayout.CENTER)

        # Bottom panel - Log
        self._role_log = JTextArea(6, 60)
        self._role_log.setEditable(False)
        panel.add(JScrollPane(self._role_log), BorderLayout.SOUTH)

        return panel

    # ========================================================================
    # TAB 2: URL EXCLUSIONS
    # ========================================================================

    def createExclusionTab(self):
        panel = JPanel(BorderLayout())

        # Top panel - Add exclusion form
        form_panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.HORIZONTAL

        gbc.gridx = 0; gbc.gridy = 0
        form_panel.add(JLabel("Exclusion Pattern (Regex):"), gbc)
        gbc.gridx = 1
        self._exclusion_pattern_field = JTextField(40)
        form_panel.add(self._exclusion_pattern_field, gbc)

        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2
        help_label = JLabel("Example: .*/logout.* or .*signout.* or .*session.*")
        help_label.setFont(help_label.getFont().deriveFont(10.0))
        form_panel.add(help_label, gbc)

        gbc.gridy = 2
        button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        add_pattern_btn = JButton("Add Pattern", actionPerformed=self.addExclusionPattern)
        button_panel.add(add_pattern_btn)
        delete_pattern_btn = JButton("Delete Selected", actionPerformed=self.deleteExclusionPattern)
        button_panel.add(delete_pattern_btn)
        clear_patterns_btn = JButton("Clear All", actionPerformed=self.clearExclusionPatterns)
        button_panel.add(clear_patterns_btn)
        refresh_patterns_btn = JButton("Refresh", actionPerformed=lambda e: self.loadExclusionsFromAPI())
        button_panel.add(refresh_patterns_btn)
        form_panel.add(button_panel, gbc)

        panel.add(form_panel, BorderLayout.NORTH)

        # Center panel - Patterns table
        column_names = ["Exclusion Pattern", "Example Match"]
        self._exclusions_model = DefaultTableModel(column_names, 0)
        self._exclusions_table = JTable(self._exclusions_model)
        self._exclusions_table.getColumnModel().getColumn(0).setPreferredWidth(300)
        self._exclusions_table.getColumnModel().getColumn(1).setPreferredWidth(250)

        scroll_pane = JScrollPane(self._exclusions_table)
        panel.add(scroll_pane, BorderLayout.CENTER)

        # Bottom panel - Log
        self._exclusion_log = JTextArea(6, 60)
        self._exclusion_log.setEditable(False)
        panel.add(JScrollPane(self._exclusion_log), BorderLayout.SOUTH)

        return panel

    # ========================================================================
    # TAB 3: URL COLLECTOR
    # ========================================================================

    def createURLCollectorTab(self):
        panel = JPanel(BorderLayout())

        # Top panel - Controls (two rows)
        top_panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(2, 3, 2, 3)
        gbc.anchor = GridBagConstraints.WEST

        # Row 1: Capture controls
        gbc.gridx = 0; gbc.gridy = 0
        self._auto_capture_cb = JCheckBox("Auto-capture URLs", self.auto_capture)
        top_panel.add(self._auto_capture_cb, gbc)

        gbc.gridx = 1
        send_urls_btn = JButton("Send to API", actionPerformed=self.sendURLsToAPI)
        top_panel.add(send_urls_btn, gbc)

        gbc.gridx = 2
        refresh_urls_btn = JButton("Refresh from API", actionPerformed=lambda e: self.loadURLsFromAPI())
        top_panel.add(refresh_urls_btn, gbc)

        gbc.gridx = 3
        deduplicate_urls_btn = JButton("Deduplicate URLs", actionPerformed=self.deduplicateURLs)
        top_panel.add(deduplicate_urls_btn, gbc)

        # Row 2: Clear controls + stats
        gbc.gridx = 0; gbc.gridy = 1
        clear_table_btn = JButton("Clear Table", actionPerformed=self.clearLocalTable)
        top_panel.add(clear_table_btn, gbc)

        gbc.gridx = 1
        clear_api_urls_btn = JButton("Clear API URLs", actionPerformed=self.clearURLsFromAPI)
        top_panel.add(clear_api_urls_btn, gbc)

        gbc.gridx = 2
        self._url_stats_label = JLabel("Captured: 0")
        top_panel.add(self._url_stats_label, gbc)

        gbc.gridx = 3
        self._api_url_stats_label = JLabel("API: 0")
        top_panel.add(self._api_url_stats_label, gbc)

        panel.add(top_panel, BorderLayout.NORTH)

        # Center panel - URL list
        column_names = ["#", "Method", "URL", "Status"]
        self._url_model = DefaultTableModel(column_names, 0)
        self._url_table = JTable(self._url_model)

        self._url_table.getColumnModel().getColumn(0).setPreferredWidth(50)
        self._url_table.getColumnModel().getColumn(1).setPreferredWidth(80)
        self._url_table.getColumnModel().getColumn(2).setPreferredWidth(400)
        self._url_table.getColumnModel().getColumn(3).setPreferredWidth(80)

        scroll_pane = JScrollPane(self._url_table)
        panel.add(scroll_pane, BorderLayout.CENTER)

        # Bottom panel - Log
        self._url_log = JTextArea(6, 60)
        self._url_log.setEditable(False)
        panel.add(JScrollPane(self._url_log), BorderLayout.SOUTH)

        return panel

    # ========================================================================
    # TAB 3: TEST & RESULTS
    # ========================================================================

    def createTestTab(self):
        panel = JPanel(BorderLayout())

        # Top panel - Test controls (two rows)
        top_panel = JPanel(GridBagLayout())
        tgbc = GridBagConstraints()
        tgbc.insets = Insets(3, 5, 3, 5)
        tgbc.anchor = GridBagConstraints.WEST

        # Row 1: API connection settings
        tgbc.gridx = 0; tgbc.gridy = 0
        top_panel.add(JLabel("API Host:"), tgbc)
        tgbc.gridx = 1
        self._api_host_field = JTextField(self.api_host, 10)
        top_panel.add(self._api_host_field, tgbc)
        tgbc.gridx = 2
        top_panel.add(JLabel("Port:"), tgbc)
        tgbc.gridx = 3
        self._api_port_field = JTextField(self.api_port, 5)
        top_panel.add(self._api_port_field, tgbc)
        tgbc.gridx = 4
        apply_api_btn = JButton("Apply", actionPerformed=self.applyAPIConfig)
        top_panel.add(apply_api_btn, tgbc)

        # Row 2: Test controls
        tgbc.gridx = 0; tgbc.gridy = 1
        start_test_btn = JButton("Run BAC Test", actionPerformed=self.startTest)
        start_test_btn.setPreferredSize(Dimension(150, 30))
        top_panel.add(start_test_btn, tgbc)

        tgbc.gridx = 1
        stop_test_btn = JButton("Stop Test", actionPerformed=self.stopTest)
        top_panel.add(stop_test_btn, tgbc)

        tgbc.gridx = 2
        status_btn = JButton("Check Status", actionPerformed=self.checkTestStatus)
        top_panel.add(status_btn, tgbc)

        tgbc.gridx = 3
        open_excel_btn = JButton("Open Excel", actionPerformed=self.openExcelFile)
        top_panel.add(open_excel_btn, tgbc)

        tgbc.gridx = 4
        self._test_status_label = JLabel("Status: Ready")
        top_panel.add(self._test_status_label, tgbc)

        panel.add(top_panel, BorderLayout.NORTH)

        # Center panel - Info
        info_panel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.HORIZONTAL

        gbc.gridx = 0; gbc.gridy = 0
        info_panel.add(JLabel("Roles configured:"), gbc)
        gbc.gridx = 1
        self._roles_count_label = JLabel("0")
        info_panel.add(self._roles_count_label, gbc)

        gbc.gridx = 0; gbc.gridy = 1
        info_panel.add(JLabel("URLs to test:"), gbc)
        gbc.gridx = 1
        self._urls_count_label = JLabel("0")
        info_panel.add(self._urls_count_label, gbc)

        gbc.gridx = 0; gbc.gridy = 2
        info_panel.add(JLabel("Total tests:"), gbc)
        gbc.gridx = 1
        self._total_tests_label = JLabel("0")
        info_panel.add(self._total_tests_label, gbc)

        gbc.gridx = 0; gbc.gridy = 3
        info_panel.add(JLabel("Progress:"), gbc)
        gbc.gridx = 1
        self._progress_label = JLabel("0%")
        info_panel.add(self._progress_label, gbc)

        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2
        self._progress_bar = JProgressBar(0, 100)
        self._progress_bar.setStringPainted(True)
        self._progress_bar.setValue(0)
        self._progress_bar.setPreferredSize(Dimension(400, 25))
        info_panel.add(self._progress_bar, gbc)

        gbc.gridwidth = 1
        gbc.gridx = 0; gbc.gridy = 5
        info_panel.add(JLabel("Excel file:"), gbc)
        gbc.gridx = 1
        self._excel_file_label = JLabel("Not generated yet")
        info_panel.add(self._excel_file_label, gbc)

        panel.add(info_panel, BorderLayout.CENTER)

        # Bottom panel - Log
        self._test_log = JTextArea(10, 60)
        self._test_log.setEditable(False)
        panel.add(JScrollPane(self._test_log), BorderLayout.SOUTH)

        return panel

    # ========================================================================
    # METHODS: Role Management
    # ========================================================================

    def addRole(self, event):
        """Add new role to API"""
        try:
            role_name = self._role_name_field.getText().strip()
            auth_value = self._role_cookie_field.getText().strip()
            auth_type_str = str(self._auth_type_combo.getSelectedItem())
            header_name = self._header_name_field.getText().strip()

            if auth_type_str == "Custom Header":
                auth_type = "header"
            elif auth_type_str == "Bearer Token":
                auth_type = "token"
            else:
                auth_type = "cookie"

            if not role_name:
                self.log_role("[ERROR] Role name is required")
                return

            if not auth_value:
                self.log_role("[ERROR] Authentication value is required")
                return

            if auth_type == "header" and not header_name:
                self.log_role("[ERROR] Header name is required for Custom Header type")
                return

            url = "http://{}:{}/api/roles/add".format(self.api_host, self.api_port)
            data = {
                "name": role_name,
                "auth_type": auth_type,
                "auth_value": auth_value,
                "header_name": header_name
            }

            req = urllib2.Request(url)
            req.add_header('Content-Type', 'application/json')
            response = urllib2.urlopen(req, json.dumps(data), timeout=10)
            result = json.loads(response.read())

            if result.get('success'):
                self.log_role("[OK] Role '{}' added ({}{})".format(
                    role_name, auth_type_str,
                    ": " + header_name if header_name else ""
                ))
                self._role_name_field.setText("")
                self._role_cookie_field.setText("")
                self._header_name_field.setText("")
                self.loadRolesFromAPI()
            else:
                self.log_role("[ERROR] {}".format(result.get('error')))

        except Exception as e:
            self.log_role("[ERROR] Add role failed: {}".format(str(e)))

    def updateRole(self, event):
        """Update selected role"""
        try:
            selected_row = self._roles_table.getSelectedRow()
            if selected_row < 0:
                self.log_role("[ERROR] Please select a role to update")
                return

            role_name = str(self._roles_model.getValueAt(selected_row, 0))
            auth_value = self._role_cookie_field.getText().strip()
            auth_type_str = str(self._auth_type_combo.getSelectedItem())
            header_name = self._header_name_field.getText().strip()

            if auth_type_str == "Custom Header":
                auth_type = "header"
            elif auth_type_str == "Bearer Token":
                auth_type = "token"
            else:
                auth_type = "cookie"

            if not auth_value:
                self.log_role("[ERROR] Authentication value is required")
                return

            if auth_type == "header" and not header_name:
                self.log_role("[ERROR] Header name is required for Custom Header type")
                return

            url = "http://{}:{}/api/roles/update".format(self.api_host, self.api_port)
            data = {
                "name": role_name,
                "auth_type": auth_type,
                "auth_value": auth_value,
                "header_name": header_name
            }

            req = urllib2.Request(url)
            req.add_header('Content-Type', 'application/json')
            req.get_method = lambda: 'PUT'
            response = urllib2.urlopen(req, json.dumps(data), timeout=10)
            result = json.loads(response.read())

            if result.get('success'):
                self.log_role("[OK] Role '{}' updated".format(role_name))
                self.loadRolesFromAPI()
            else:
                self.log_role("[ERROR] {}".format(result.get('error')))

        except Exception as e:
            self.log_role("[ERROR] Update role failed: {}".format(str(e)))

    def deleteRole(self, event):
        """Delete selected role"""
        try:
            selected_row = self._roles_table.getSelectedRow()
            if selected_row < 0:
                self.log_role("[ERROR] Please select a role to delete")
                return

            role_name = str(self._roles_model.getValueAt(selected_row, 0))

            # Confirm deletion
            confirm = JOptionPane.showConfirmDialog(
                None,
                "Delete role '{}'?".format(role_name),
                "Confirm Deletion",
                JOptionPane.YES_NO_OPTION
            )

            if confirm != JOptionPane.YES_OPTION:
                return

            url = "http://{}:{}/api/roles/delete".format(self.api_host, self.api_port)
            data = {"name": role_name}

            req = urllib2.Request(url)
            req.add_header('Content-Type', 'application/json')
            req.get_method = lambda: 'DELETE'
            response = urllib2.urlopen(req, json.dumps(data), timeout=10)
            result = json.loads(response.read())

            if result.get('success'):
                self.log_role("[OK] Role '{}' deleted".format(role_name))
                self.loadRolesFromAPI()
            else:
                self.log_role("[ERROR] {}".format(result.get('error')))

        except Exception as e:
            self.log_role("[ERROR] Delete role failed: {}".format(str(e)))

    def deleteAllRoles(self, event):
        """Delete all roles"""
        try:
            if len(self.roles) == 0:
                self.log_role("[ERROR] No roles to delete")
                return

            # Confirm deletion
            confirm = JOptionPane.showConfirmDialog(
                None,
                "Delete all {} role(s)? This cannot be undone.".format(len(self.roles)),
                "Confirm Delete All",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            )

            if confirm != JOptionPane.YES_OPTION:
                return

            url = "http://{}:{}/api/roles/clear".format(self.api_host, self.api_port)

            req = urllib2.Request(url)
            req.get_method = lambda: 'POST'
            response = urllib2.urlopen(req, "", timeout=10)
            result = json.loads(response.read())

            if result.get('success'):
                deleted = result.get('deleted_count', 0)
                self.log_role("[OK] All roles deleted ({} roles)".format(deleted))
                self.loadRolesFromAPI()
            else:
                self.log_role("[ERROR] {}".format(result.get('error')))

        except Exception as e:
            self.log_role("[ERROR] Delete all roles failed: {}".format(str(e)))

    def loadRolesFromAPI(self):
        """Load roles from API and update table"""
        try:
            url = "http://{}:{}/api/roles".format(self.api_host, self.api_port)
            response = urllib2.urlopen(url, timeout=5)
            data = json.loads(response.read())

            if data.get('success'):
                self.roles = data.get('roles', [])

                # Update table
                self._roles_model.setRowCount(0)
                for role in self.roles:
                    auth_type = role.get('auth_type', 'cookie')
                    auth_value = role.get('auth_value', role.get('cookie', ''))
                    header_name = role.get('header_name', '')
                    if auth_type == 'header':
                        auth_type_display = "Custom Header"
                    elif auth_type == 'token':
                        auth_type_display = "Bearer Token"
                    else:
                        auth_type_display = "Cookie"
                    auth_value_preview = auth_value[:50] + '...' if len(auth_value) > 50 else auth_value
                    self._roles_model.addRow([role['name'], auth_type_display, header_name, auth_value_preview])

                # Update counts
                self._roles_count_label.setText(str(len(self.roles)))
                self.updateTestCounts()

                self.log_role("[OK] Loaded {} roles from API".format(len(self.roles)))

        except Exception as e:
            self.log_role("[ERROR] Load roles failed: {}".format(str(e)))

    # ========================================================================
    # METHODS: Exclusion Patterns
    # ========================================================================

    def addExclusionPattern(self, event):
        """Add new exclusion pattern to API"""
        try:
            pattern = self._exclusion_pattern_field.getText().strip()

            if not pattern:
                self.log_exclusion("[ERROR] Pattern is required")
                return

            url = "http://{}:{}/api/exclusions/add".format(self.api_host, self.api_port)
            data = {"pattern": pattern}

            req = urllib2.Request(url)
            req.add_header('Content-Type', 'application/json')
            response = urllib2.urlopen(req, json.dumps(data), timeout=10)
            result = json.loads(response.read())

            if result.get('success'):
                self.log_exclusion("[OK] Exclusion pattern added: {}".format(pattern))
                self._exclusion_pattern_field.setText("")
                self.loadExclusionsFromAPI()
            else:
                self.log_exclusion("[ERROR] {}".format(result.get('error')))

        except Exception as e:
            self.log_exclusion("[ERROR] Add pattern failed: {}".format(str(e)))

    def deleteExclusionPattern(self, event):
        """Delete selected exclusion pattern"""
        try:
            selected_row = self._exclusions_table.getSelectedRow()
            if selected_row < 0:
                self.log_exclusion("[ERROR] Please select a pattern to delete")
                return

            pattern = str(self._exclusions_model.getValueAt(selected_row, 0))

            url = "http://{}:{}/api/exclusions/delete".format(self.api_host, self.api_port)
            data = {"pattern": pattern}

            req = urllib2.Request(url)
            req.add_header('Content-Type', 'application/json')
            req.get_method = lambda: 'DELETE'
            response = urllib2.urlopen(req, json.dumps(data), timeout=10)
            result = json.loads(response.read())

            if result.get('success'):
                self.log_exclusion("[OK] Pattern deleted")
                self.loadExclusionsFromAPI()
            else:
                self.log_exclusion("[ERROR] {}".format(result.get('error')))

        except Exception as e:
            self.log_exclusion("[ERROR] Delete pattern failed: {}".format(str(e)))

    def clearExclusionPatterns(self, event):
        """Clear all exclusion patterns"""
        try:
            confirm = JOptionPane.showConfirmDialog(
                None,
                "Clear all exclusion patterns?",
                "Confirm Clear",
                JOptionPane.YES_NO_OPTION
            )

            if confirm != JOptionPane.YES_OPTION:
                return

            url = "http://{}:{}/api/exclusions/clear".format(self.api_host, self.api_port)

            req = urllib2.Request(url)
            req.get_method = lambda: 'POST'
            response = urllib2.urlopen(req, "", timeout=10)
            result = json.loads(response.read())

            if result.get('success'):
                self.log_exclusion("[OK] All patterns cleared")
                self.loadExclusionsFromAPI()
            else:
                self.log_exclusion("[ERROR] {}".format(result.get('error')))

        except Exception as e:
            self.log_exclusion("[ERROR] Clear patterns failed: {}".format(str(e)))

    def loadExclusionsFromAPI(self):
        """Load exclusion patterns from API and update table"""
        try:
            url = "http://{}:{}/api/exclusions".format(self.api_host, self.api_port)
            response = urllib2.urlopen(url, timeout=5)
            data = json.loads(response.read())

            if data.get('success'):
                patterns = data.get('patterns', [])

                # Store patterns in memory for URL filtering
                self.exclusion_patterns = patterns

                # Update table
                self._exclusions_model.setRowCount(0)
                for pattern in patterns:
                    example = "Matches: " + pattern.replace(".*", "*")
                    self._exclusions_model.addRow([pattern, example])

                self.log_exclusion("[OK] Loaded {} exclusion patterns".format(len(patterns)))

        except Exception as e:
            self.log_exclusion("[ERROR] Load patterns failed: {}".format(str(e)))

    # ========================================================================
    # METHODS: URL Collection
    # ========================================================================

    def isURLExcluded(self, url):
        """Check if URL matches any exclusion pattern"""
        try:
            for pattern in self.exclusion_patterns:
                if re.search(pattern, url):
                    return True
            return False
        except Exception as e:
            self.log_url("[ERROR] Error checking exclusion pattern: {}".format(str(e)))
            return False

    def addURLFromMessage(self, message):
        """Extract and add URL, method, and body from HTTP message"""
        try:
            request_info = self._helpers.analyzeRequest(message)
            url = str(request_info.getUrl())
            method = str(request_info.getMethod()).upper()

            # Check if URL is excluded
            if self.isURLExcluded(url):
                return

            # Dedup key: "METHOD url"
            dedup_key = "{} {}".format(method, url)
            if dedup_key in self.captured_urls:
                return

            # Extract POST body and content type
            body = None
            content_type = None
            if method == "POST":
                try:
                    request_bytes = message.getRequest()
                    body_offset = request_info.getBodyOffset()
                    if body_offset < len(request_bytes):
                        body = self._helpers.bytesToString(request_bytes[body_offset:])
                        if not body.strip():
                            body = None
                except:
                    pass

                # Extract Content-Type header
                for header in request_info.getHeaders():
                    if header.lower().startswith("content-type:"):
                        content_type = header[13:].strip()
                        break

            # Store URL object
            self.captured_urls[dedup_key] = {
                "url": url,
                "method": method,
                "body": body,
                "content_type": content_type
            }

            row_num = len(self.captured_urls)

            status = "-"
            try:
                response = message.getResponse()
                if response:
                    response_info = self._helpers.analyzeResponse(response)
                    status = str(response_info.getStatusCode())
            except:
                pass

            # UI updates must run on Swing EDT (this method is called from Burp's HTTP thread)
            _row_num = str(row_num)
            _method = method
            _url = url
            _status = status
            _count = len(self.captured_urls)
            def updateTableUI():
                self._url_model.addRow([_row_num, _method, _url, _status])
                self._url_stats_label.setText("Captured: {}".format(_count))
            SwingUtilities.invokeLater(updateTableUI)

        except Exception as e:
            self.log_url("[ERROR] Error adding URL: {}".format(str(e)))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Auto-capture URLs if enabled"""
        try:
            if not messageIsRequest and self._auto_capture_cb.isSelected():
                self.addURLFromMessage(messageInfo)
        except Exception as e:
            pass

    def clearLocalTable(self, event):
        """Clear captured URLs from table only (does NOT clear API)"""
        try:
            self.captured_urls = {}
            self._url_model.setRowCount(0)
            self._url_stats_label.setText("Captured: 0")
            self.log_url("[OK] Table cleared (API URLs unchanged)")

        except Exception as e:
            self.log_url("[ERROR] Clear table failed: {}".format(str(e)))

    def clearURLsFromAPI(self, event):
        """Delete all URLs from API storage"""
        try:
            confirm = JOptionPane.showConfirmDialog(
                None,
                "Delete all URLs from API storage?",
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION
            )

            if confirm != JOptionPane.YES_OPTION:
                return

            url = "http://{}:{}/api/urls/clear".format(self.api_host, self.api_port)

            req = urllib2.Request(url)
            req.get_method = lambda: 'POST'
            response = urllib2.urlopen(req, "", timeout=10)
            result = json.loads(response.read())

            if result.get('success'):
                self.log_url("[OK] All URLs deleted from API storage")
                self._api_url_stats_label.setText("API: 0")
                self._urls_count_label.setText("0")
                self.updateTestCounts()
            else:
                self.log_url("[ERROR] {}".format(result.get('error')))

        except Exception as e:
            self.log_url("[ERROR] Delete URLs failed: {}".format(str(e)))

    def sendURLsToAPI(self, event):
        """Send URLs to API (with method and body)"""
        try:
            if not self.captured_urls:
                self.log_url("[ERROR] No URLs to send")
                return

            url = "http://{}:{}/api/urls/add".format(self.api_host, self.api_port)
            data = {"urls": list(self.captured_urls.values()), "append": True}

            req = urllib2.Request(url)
            req.add_header('Content-Type', 'application/json')
            response = urllib2.urlopen(req, json.dumps(data), timeout=10)
            result = json.loads(response.read())

            if result.get('success'):
                added = result.get('added', 0)
                total = result.get('total', 0)
                excluded = result.get('excluded', 0)
                self.log_url("[OK] Sent {} URLs to API (total: {}, excluded: {})".format(added, total, excluded))
                self._api_url_stats_label.setText("API: {}".format(total))
                self._urls_count_label.setText(str(total))
                self.updateTestCounts()
            else:
                self.log_url("[ERROR] {}".format(result.get('error')))

        except Exception as e:
            self.log_url("[ERROR] Send failed: {}".format(str(e)))

    def deduplicateURLs(self, event):
        """Deduplicate URLs in API storage"""
        try:
            url = "http://{}:{}/api/urls/deduplicate".format(self.api_host, self.api_port)

            req = urllib2.Request(url)
            req.add_header('Content-Type', 'application/json')
            response = urllib2.urlopen(req, json.dumps({}), timeout=10)
            result = json.loads(response.read())

            if result.get('success'):
                original = result.get('original_count', 0)
                unique = result.get('unique_count', 0)
                removed = result.get('removed', 0)

                self.log_url("[OK] Deduplication complete!")
                self.log_url("     Original: {} URLs".format(original))
                self.log_url("     Unique: {} URLs".format(unique))
                self.log_url("     Removed: {} duplicates".format(removed))

                # Update URL count display
                self._api_url_stats_label.setText("API: {}".format(unique))
                self._urls_count_label.setText(str(unique))
                self.updateTestCounts()
            else:
                self.log_url("[ERROR] {}".format(result.get('error')))

        except Exception as e:
            self.log_url("[ERROR] Deduplication failed: {}".format(str(e)))

    def loadURLsFromAPI(self):
        """Load URLs from API and update counts"""
        try:
            url = "http://{}:{}/api/urls/list".format(self.api_host, self.api_port)
            response = urllib2.urlopen(url, timeout=5)
            data = json.loads(response.read())

            if data.get('success'):
                api_urls = data.get('urls', [])
                count = data.get('count', len(api_urls))

                # Update API count labels
                self._api_url_stats_label.setText("API: {}".format(count))
                self._urls_count_label.setText(str(count))
                self.updateTestCounts()

                self.log_url("[OK] API has {} URLs".format(count))

        except Exception as e:
            self.log_url("[WARN] Could not load URLs from API: {}".format(str(e)))

    # ========================================================================
    # METHODS: Testing
    # ========================================================================

    def startTest(self, event):
        """Start multi-role BAC test"""
        try:
            if len(self.roles) == 0:
                self.log_test("[ERROR] No roles configured. Add roles first.")
                return

            url = "http://{}:{}/api/test/start".format(self.api_host, self.api_port)

            req = urllib2.Request(url)
            req.add_header('Content-Type', 'application/json')
            response = urllib2.urlopen(req, json.dumps({}), timeout=10)
            result = json.loads(response.read())

            if result.get('success'):
                self.log_test("[OK] Test started!")
                self.log_test("   URLs: {}".format(result.get('total_urls', 0)))
                self.log_test("   Roles: {}".format(result.get('total_roles', 0)))
                self.log_test("   Total tests: {}".format(result.get('total_tests', 0)))
                self._test_status_label.setText("Status: Running...")

                # Reset progress bar and tracking state
                self._progress_bar.setValue(0)
                self._progress_label.setText("0%")
                self._last_logged_progress = -1
                self._test_completed_logged = False
                self._poll_error_count = 0

                # Start auto-polling status every 2 seconds
                self.startStatusPolling()
            else:
                self.log_test("[ERROR] {}".format(result.get('error')))

        except Exception as e:
            self.log_test("[ERROR] Start test failed: {}".format(str(e)))

    def stopTest(self, event):
        """Stop running test"""
        try:
            url = "http://{}:{}/api/test/stop".format(self.api_host, self.api_port)

            req = urllib2.Request(url)
            req.get_method = lambda: 'POST'
            response = urllib2.urlopen(req, "", timeout=10)
            result = json.loads(response.read())

            if result.get('success'):
                self.log_test("[OK] Test stop requested")
                self._test_status_label.setText("Status: Stopping...")

                # Stop auto-polling
                self.stopStatusPolling()
            else:
                self.log_test("[ERROR] {}".format(result.get('error')))

        except Exception as e:
            self.log_test("[ERROR] Stop test failed: {}".format(str(e)))

    def checkTestStatus(self, event=None):
        """Check test progress (can be called manually or by timer)"""
        try:
            url = "http://{}:{}/api/test/status".format(self.api_host, self.api_port)
            response = urllib2.urlopen(url, timeout=5)
            data = json.loads(response.read())

            # Reset error counter on success
            self._poll_error_count = 0

            if data.get('success'):
                status = data.get('status', {})
                running = status.get('running', False)
                progress = status.get('progress', 0)

                self._progress_label.setText("{}%".format(progress))
                self._progress_bar.setValue(progress)

                if running:
                    self._test_status_label.setText("Status: Running ({}%)".format(progress))
                    # Only log when progress actually changes
                    if progress != self._last_logged_progress:
                        self._last_logged_progress = progress
                        self.log_test("[PROGRESS] {}%".format(progress))
                else:
                    self._test_status_label.setText("Status: Completed")
                    self._progress_bar.setValue(100)

                    # Only log completion once
                    if not self._test_completed_logged:
                        self._test_completed_logged = True
                        excel_file = status.get('excel_file')
                        if excel_file:
                            self._excel_file_label.setText(excel_file)
                            self.log_test("[OK] Test complete! Excel: {}".format(excel_file))
                        else:
                            self.log_test("[OK] Test complete!")

                    # Stop auto-polling when test completes
                    self.stopStatusPolling()

        except Exception as e:
            self._poll_error_count += 1
            # Only log first error, then stop after 5 consecutive failures
            if self._poll_error_count == 1:
                self.log_test("[ERROR] Status check failed: {}".format(str(e)))
            if self._poll_error_count >= 5:
                self.log_test("[ERROR] API unreachable after 5 attempts, stopping auto-refresh")
                self.stopStatusPolling()

    def startStatusPolling(self):
        """Start automatic status polling every 2 seconds"""
        try:
            # Stop existing timer if any
            self.stopStatusPolling()

            # Create action listener for timer
            class StatusPoller(ActionListener):
                def __init__(self, extender):
                    self.extender = extender

                def actionPerformed(self, event):
                    self.extender.checkTestStatus()

            # Create and start timer (2000ms = 2 seconds)
            self.status_poll_timer = Timer(2000, StatusPoller(self))
            self.status_poll_timer.start()

            self.log_test("[INFO] Auto-refresh enabled (every 2 seconds)")

        except Exception as e:
            self.log_test("[ERROR] Failed to start auto-polling: {}".format(str(e)))

    def stopStatusPolling(self):
        """Stop automatic status polling"""
        try:
            if self.status_poll_timer is not None and self.status_poll_timer.isRunning():
                self.status_poll_timer.stop()
                self.status_poll_timer = None
                self.log_test("[INFO] Auto-refresh stopped")

        except Exception as e:
            self.log_test("[ERROR] Failed to stop auto-polling: {}".format(str(e)))

    def openExcelFile(self, event):
        """Open generated Excel file"""
        try:
            excel_path = self._excel_file_label.getText()

            if excel_path == "Not generated yet":
                self.log_test("[ERROR] No Excel file generated yet")
                return

            excel_file = File(excel_path)

            if excel_file.exists():
                Desktop.getDesktop().open(excel_file)
                self.log_test("[INFO] Opening Excel file...")
            else:
                self.log_test("[ERROR] File not found: {}".format(excel_path))

        except Exception as e:
            self.log_test("[ERROR] Open Excel failed: {}".format(str(e)))

    def updateTestCounts(self):
        """Update test count labels"""
        try:
            url_count = int(self._urls_count_label.getText())
            role_count = len(self.roles)
            total = url_count * role_count

            self._total_tests_label.setText(str(total))

        except:
            pass

    def applyAPIConfig(self, event):
        """Apply API host/port configuration from text fields"""
        try:
            new_host = self._api_host_field.getText().strip()
            new_port = self._api_port_field.getText().strip()

            if not new_host:
                self.log_test("[ERROR] API host cannot be empty")
                return
            if not new_port:
                self.log_test("[ERROR] API port cannot be empty")
                return

            self.api_host = new_host
            self.api_port = new_port
            self.log_test("[OK] API config updated: http://{}:{}".format(self.api_host, self.api_port))

            # Reload data from new API endpoint
            self.loadRolesFromAPI()
            self.loadExclusionsFromAPI()
            self.loadURLsFromAPI()

        except Exception as e:
            self.log_test("[ERROR] Apply config failed: {}".format(str(e)))

    # ========================================================================
    # METHODS: Context Menu
    # ========================================================================

    def createMenuItems(self, invocation):
        """Create context menu items"""
        menu_list = ArrayList()

        if invocation.getInvocationContext() in [
            invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            invocation.CONTEXT_PROXY_HISTORY,
            invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            invocation.CONTEXT_TARGET_SITE_MAP_TREE
        ]:
            # Menu item 1: Send URL to BAC Checker
            menu_item = JMenuItem("Send to BAC Checker v2.0")
            menu_item.addActionListener(lambda x: self.menuItemClicked(invocation))
            menu_list.add(menu_item)

            # Menu item 2: Extract Cookie
            cookie_menu_item = JMenuItem("Extract Cookie for BAC Checker v2.0")
            cookie_menu_item.addActionListener(lambda x: self.extractCookieFromMessage(invocation))
            menu_list.add(cookie_menu_item)

            # Menu item 3: Extract Bearer Token
            token_menu_item = JMenuItem("Extract Bearer Token for BAC Checker v2.0")
            token_menu_item.addActionListener(lambda x: self.extractBearerTokenFromMessage(invocation))
            menu_list.add(token_menu_item)

            # Menu item 4: Extract Custom Header
            header_menu_item = JMenuItem("Extract Custom Header for BAC Checker v2.0")
            header_menu_item.addActionListener(lambda x: self.extractCustomHeaderFromMessage(invocation))
            menu_list.add(header_menu_item)

            # Menu item 5: Add to Exclusions
            exclusion_menu_item = JMenuItem("Add to Exclusions (BAC Checker v2.0)")
            exclusion_menu_item.addActionListener(lambda x: self.addURLToExclusions(invocation))
            menu_list.add(exclusion_menu_item)

        return menu_list

    def menuItemClicked(self, invocation):
        """Handle context menu click"""
        try:
            messages = invocation.getSelectedMessages()
            for message in messages:
                self.addURLFromMessage(message)
            self.log_url("[OK] Added {} URL(s)".format(len(messages)))
        except Exception as e:
            self.log_url("[ERROR] Error: {}".format(str(e)))

    def extractCookieFromMessage(self, invocation):
        """Extract Cookie header from selected request and populate role management"""
        try:
            messages = invocation.getSelectedMessages()
            if not messages or len(messages) == 0:
                self.log_role("[ERROR] No message selected")
                return

            # Get first message
            message = messages[0]
            request_info = self._helpers.analyzeRequest(message)
            headers = request_info.getHeaders()

            # Find Cookie header
            cookie_value = None
            for header in headers:
                if header.lower().startswith("cookie:"):
                    cookie_value = header[7:].strip()  # Remove "Cookie: " prefix
                    break

            if cookie_value:
                # Populate the cookie field and switch tab on EDT
                def updateUI():
                    self._role_cookie_field.setText(cookie_value)
                    self._auth_type_combo.setSelectedItem("Cookie")
                    self._main_panel.setSelectedIndex(0)
                    self.log_role("[OK] Cookie extracted and populated ({} chars)".format(len(cookie_value)))
                    self.log_role("     Preview: {}...".format(cookie_value[:50] if len(cookie_value) > 50 else cookie_value))

                SwingUtilities.invokeLater(updateUI)
            else:
                self.log_role("[ERROR] No Cookie header found in request")

        except Exception as e:
            self.log_role("[ERROR] Error extracting cookie: {}".format(str(e)))

    def extractBearerTokenFromMessage(self, invocation):
        """Extract Bearer token from selected request and populate role management"""
        try:
            messages = invocation.getSelectedMessages()
            if not messages or len(messages) == 0:
                self.log_role("[ERROR] No message selected")
                return

            # Get first message
            message = messages[0]
            request_info = self._helpers.analyzeRequest(message)
            headers = request_info.getHeaders()

            # Find Authorization header
            token_value = None
            for header in headers:
                if header.lower().startswith("authorization:"):
                    auth_header = header[14:].strip()  # Remove "Authorization: " prefix
                    # Extract Bearer token
                    if auth_header.lower().startswith("bearer "):
                        token_value = auth_header[7:].strip()  # Remove "Bearer " prefix
                    break

            if token_value:
                # Populate the auth field and switch tab on EDT
                def updateUI():
                    self._role_cookie_field.setText(token_value)
                    self._auth_type_combo.setSelectedItem("Bearer Token")
                    self._main_panel.setSelectedIndex(0)
                    self.log_role("[OK] Bearer token extracted and populated ({} chars)".format(len(token_value)))
                    self.log_role("     Preview: {}...".format(token_value[:50] if len(token_value) > 50 else token_value))

                SwingUtilities.invokeLater(updateUI)
            else:
                self.log_role("[ERROR] No Authorization Bearer header found in request")

        except Exception as e:
            self.log_role("[ERROR] Error extracting Bearer token: {}".format(str(e)))

    def extractCustomHeaderFromMessage(self, invocation):
        """Prompt user for header name, extract it from request, and populate role management"""
        try:
            messages = invocation.getSelectedMessages()
            if not messages or len(messages) == 0:
                self.log_role("[ERROR] No message selected")
                return

            # Ask user which header to extract
            header_name_input = JOptionPane.showInputDialog(
                None,
                "Enter the header name to extract\n(e.g. X-API-Key, X-Session-Token, Authorization):",
                "Extract Custom Header",
                JOptionPane.QUESTION_MESSAGE
            )

            if not header_name_input or not header_name_input.strip():
                return

            header_name_input = header_name_input.strip()

            # Get first message
            message = messages[0]
            request_info = self._helpers.analyzeRequest(message)
            headers = request_info.getHeaders()

            # Find the requested header
            header_value = None
            for header in headers:
                if header.lower().startswith(header_name_input.lower() + ":"):
                    header_value = header[len(header_name_input) + 1:].strip()
                    break

            if header_value:
                def updateUI():
                    self._role_cookie_field.setText(header_value)
                    self._header_name_field.setText(header_name_input)
                    self._auth_type_combo.setSelectedItem("Custom Header")
                    self._header_name_field.setEnabled(True)
                    self._main_panel.setSelectedIndex(0)
                    self.log_role("[OK] Header '{}' extracted and populated ({} chars)".format(
                        header_name_input, len(header_value)))
                    self.log_role("     Preview: {}...".format(
                        header_value[:50] if len(header_value) > 50 else header_value))

                SwingUtilities.invokeLater(updateUI)
            else:
                self.log_role("[ERROR] Header '{}' not found in request".format(header_name_input))

        except Exception as e:
            self.log_role("[ERROR] Error extracting custom header: {}".format(str(e)))

    def addURLToExclusions(self, invocation):
        """Extract URL from selected request and add to exclusion patterns"""
        try:
            messages = invocation.getSelectedMessages()
            if not messages or len(messages) == 0:
                self.log_exclusion("[ERROR] No message selected")
                return

            # Get first message
            message = messages[0]
            request_info = self._helpers.analyzeRequest(message)
            url = str(request_info.getUrl())

            # Escape regex metacharacters in URL before using as pattern
            escaped_url = re.escape(url)

            # Add URL to exclusions via API
            api_url = "http://{}:{}/api/exclusions/add".format(self.api_host, self.api_port)
            data = {"pattern": escaped_url}
            req = urllib2.Request(api_url)
            req.add_header('Content-Type', 'application/json')
            response = urllib2.urlopen(req, json.dumps(data), timeout=10)
            result = json.loads(response.read())

            if result.get('success'):
                # Switch to Exclusions tab and reload on EDT
                def updateUI():
                    self._main_panel.setSelectedIndex(1)
                    self.log_exclusion("[OK] URL added to exclusions (escaped): {}".format(url))
                    self.loadExclusionsFromAPI()

                SwingUtilities.invokeLater(updateUI)
            else:
                self.log_exclusion("[ERROR] {}".format(result.get('error')))

        except Exception as e:
            self.log_exclusion("[ERROR] Error adding URL to exclusions: {}".format(str(e)))

    # ========================================================================
    # METHODS: Logging
    # ========================================================================

    def log_role(self, message):
        """Log to role management tab"""
        try:
            timestamp = time.strftime("%H:%M:%S")
            self._role_log.append("[{}] {}\n".format(timestamp, message))
            self._role_log.setCaretPosition(self._role_log.getDocument().getLength())
        except:
            print("[{}] {}".format(timestamp, message))

    def log_url(self, message):
        """Log to URL collector tab"""
        try:
            timestamp = time.strftime("%H:%M:%S")
            self._url_log.append("[{}] {}\n".format(timestamp, message))
            self._url_log.setCaretPosition(self._url_log.getDocument().getLength())
        except:
            print("[{}] {}".format(timestamp, message))

    def log_exclusion(self, message):
        """Log to exclusion tab"""
        try:
            timestamp = time.strftime("%H:%M:%S")
            self._exclusion_log.append("[{}] {}\n".format(timestamp, message))
            self._exclusion_log.setCaretPosition(self._exclusion_log.getDocument().getLength())
        except:
            print("[{}] {}".format(timestamp, message))

    def log_test(self, message):
        """Log to test tab"""
        try:
            timestamp = time.strftime("%H:%M:%S")
            self._test_log.append("[{}] {}\n".format(timestamp, message))
            self._test_log.setCaretPosition(self._test_log.getDocument().getLength())
        except:
            print("[{}] {}".format(timestamp, message))

    # ========================================================================
    # BURP INTERFACE
    # ========================================================================

    def getTabCaption(self):
        return "BAC Checker v2.0"

    def getUiComponent(self):
        return self._main_panel
