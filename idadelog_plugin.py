import idaapi
import idautils
import idc
import re
from PyQt5 import QtWidgets, QtCore
from collections import defaultdict

class LogAnalyzerDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super(LogAnalyzerDialog, self).__init__(parent)
        self.setWindowTitle("Log Analyzer")
        self.setWindowFlags(self.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint)
        self.resize(600, 400)
        
        # save analysis results
        self.analysis_results = defaultdict(list)
        self.current_matches = []
        
        self.setup_ui()
        
    def setup_ui(self):
        layout = QtWidgets.QVBoxLayout()
        
        # input area
        input_group = QtWidgets.QGroupBox("Analysis Parameters")
        input_layout = QtWidgets.QFormLayout()
        
        self.log_func_edit = QtWidgets.QLineEdit("log_function_name")
        self.arg_index_spin = QtWidgets.QSpinBox()
        self.arg_index_spin.setRange(0, 20)
        self.arg_index_spin.setValue(4)
        
        self.regex_check = QtWidgets.QCheckBox("Enable Regex Transformation")
        self.pattern_edit = QtWidgets.QLineEdit()
        self.replace_edit = QtWidgets.QLineEdit()
        
        input_layout.addRow("Log Function Name:", self.log_func_edit)
        input_layout.addRow("Argument Index (0-based):", self.arg_index_spin)
        input_layout.addRow(self.regex_check)
        input_layout.addRow("Pattern:", self.pattern_edit)
        input_layout.addRow("Replacement:", self.replace_edit)
        
        input_group.setLayout(input_layout)
        
        # preview area
        result_group = QtWidgets.QGroupBox("Preview Results")
        result_layout = QtWidgets.QVBoxLayout()
        
        self.result_table = QtWidgets.QTableWidget()
        self.result_table.setColumnCount(4)
        self.result_table.setHorizontalHeaderLabels(["Address", "Old Name", "New Name", "Log Message"])
        self.result_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.result_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.result_table.horizontalHeader().setStretchLastSection(True)
        self.result_table.setSortingEnabled(True)
        
        result_layout.addWidget(self.result_table)
        result_group.setLayout(result_layout)
        
        # button area
        button_layout = QtWidgets.QHBoxLayout()
        self.test_button = QtWidgets.QPushButton("Test")
        self.apply_button = QtWidgets.QPushButton("Apply")
        self.close_button = QtWidgets.QPushButton("Close")
        
        self.apply_button.setEnabled(False)
        
        button_layout.addWidget(self.test_button)
        button_layout.addWidget(self.apply_button)
        button_layout.addWidget(self.close_button)
        
        # main layout
        layout.addWidget(input_group)
        layout.addWidget(result_group)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # connect buttons to functions
        self.test_button.clicked.connect(self.run_test)
        self.apply_button.clicked.connect(self.apply_changes)
        self.close_button.clicked.connect(self.close)
        self.regex_check.stateChanged.connect(self.toggle_regex_fields)
        
        # initially disable regex fields
        self.toggle_regex_fields()
    
    def toggle_regex_fields(self):
        enabled = self.regex_check.isChecked()
        self.pattern_edit.setEnabled(enabled)
        self.replace_edit.setEnabled(enabled)
    
    def run_test(self, apply=False):
        # run the analysis, use apply=False to just test
        log_func = self.log_func_edit.text().strip()
        arg_index = self.arg_index_spin.value()
        
        if not log_func:
            QtWidgets.QMessageBox.warning(self, "Error", "Please specify a log function name")
            return
        
        # get regex pattern and replacement
        rename_regex = None
        if self.regex_check.isChecked():
            pattern = self.pattern_edit.text().strip()
            replacement = self.replace_edit.text().strip()
            if pattern:
                rename_regex = (pattern, replacement)
        
        # run the analysis
        self.analysis_results.clear()
        self.current_matches = []
        
        try:
            analyzer = LogAnalyzer(log_func, arg_index, rename_regex, apply)
            analyzer.analyze()
            self.current_matches = analyzer.match_results
        except Exception as e:
            print(f"[EXCEPTION] Error : {e}")
            self.apply_button.setEnabled(False)
            
        
        # update the results table
        self.update_results_table()
        self.apply_button.setEnabled(len(self.current_matches) > 0)
    
    def update_results_table(self):
        # update the results table with the current matches
        self.result_table.setRowCount(len(self.current_matches))
        self.result_table.clearContents()
        
        for row, match in enumerate(self.current_matches):
            self.result_table.setItem(row, 0, QtWidgets.QTableWidgetItem(hex(match['address'])))
            self.result_table.setItem(row, 1, QtWidgets.QTableWidgetItem(match['old_name']))
            self.result_table.setItem(row, 2, QtWidgets.QTableWidgetItem(match['new_name']))
            self.result_table.setItem(row, 3, QtWidgets.QTableWidgetItem(match['log_message']))
        
        self.result_table.resizeColumnsToContents()
    
    def apply_changes(self):
        # apply the changes to rename functions
        print("[INFO] Applying changes...")
        if not self.current_matches:
            return
            
        renamed = 0
        for match in self.current_matches:
            if idc.set_name(match['address'], match['new_name']):
                renamed += 1
        
        QtWidgets.QMessageBox.information(
            self, 
            "Complete", 
            f"Successfully renamed {renamed}/{len(self.current_matches)} functions"
        )
        
        # update the results table
        self.run_test(apply=True)


class LogAnalyzer:
    def __init__(self, log_func_name, arg_index=1, rename_regex=None, apply=False):
        self.log_func_name = log_func_name
        self.arg_index = arg_index
        self.rename_regex = rename_regex
        self.log_func_addr = idc.get_name_ea_simple(log_func_name)
        self.result = {}
        self.match_results = []
        self.apply = apply

        if self.log_func_addr == idc.BADADDR:
            raise ValueError(f"[ERROR] Could not find function: {log_func_name}")
        print(f"[INFO] Found log function '{log_func_name}' at {hex(self.log_func_addr)}")

    def analyze(self):
        """
        Main analysis routine: find call sites, extract args, rename functions.
        """
        callers = self.find_callers()
        for func_addr, old_function_name in callers:
            if old_function_name not in self.result:
                self.result[old_function_name] = []
            extracted_args = self.extract_log_arguments(func_addr)
            # print(f"[INFO] Extracted args from {old_function_name}: {extracted_args}")
            if extracted_args:
                # Use the specified argument index to get the relevant argument
                if self.arg_index < len(extracted_args):
                    new_function_name = extracted_args[self.arg_index]
                    self.result[old_function_name].append(new_function_name)
                    # print(f"[INFO] Raw name from {old_function_name}: {new_function_name}")
            else:
                print(f"[WARNING] No arguments found for {old_function_name}")
            
        
        # rename functions by results
        for old_function_name, args in self.result.items():
            most_common_function_name = max(set(args), key=args.count)
            sanitized_name = self.sanitize_name(most_common_function_name)
            
            if old_function_name not in self.match_results:
                self.match_results.append({
                    'address': idc.get_name_ea_simple(old_function_name),
                    'old_name': old_function_name,
                    'new_name': sanitized_name,
                    'log_message': str(args)
                })
            if self.apply:
                self.rename_function(old_function_name, args[0])
        return self.match_results


        

    def find_callers(self):
        """
        Find all functions calling the log function.
        """
        callers = []
        for ref in idautils.CodeRefsTo(self.log_func_addr, 0):
            func_start = idc.get_func_attr(ref, idc.FUNCATTR_START)
            if func_start == idc.BADADDR:
                continue
            func_name = idc.get_func_name(func_start)
            callers.append((func_start, func_name))
            # print(f"[CALLER] Found call to {self.log_func_name} in {func_name} at {hex(ref)}")
        return callers

    def extract_log_arguments(self, func_addr):
        """
        Enhanced version that better handles multi-line log calls and complex arguments
        """
        try:
            cfunc = idaapi.decompile(func_addr)
            if not cfunc:
                # print(f"[ERROR] Could not decompile function at {hex(func_addr)}")
                return []

            decompiled_code = str(cfunc)
            log_call_start = self.log_func_name + '('
            log_call_len = len(log_call_start)
            
            start_pos = 0
            while True:
                # Find next log call
                call_pos = decompiled_code.find(log_call_start, start_pos)
                if call_pos == -1:
                    break
                    
                # Initialize parsing state
                in_string = False
                escape = False
                paren_depth = 1
                current_arg = []
                args = []
                i = call_pos + log_call_len  # Position after '('
                
                # Parse until matching closing paren
                while i < len(decompiled_code) and paren_depth > 0:
                    char = decompiled_code[i]
                    
                    # Handle strings and escapes
                    if char == '"' and not escape:
                        in_string = not in_string
                        current_arg.append(char)
                    elif in_string and char == '\\':
                        escape = not escape
                        current_arg.append(char)
                    elif in_string:
                        escape = False
                        current_arg.append(char)
                    # Handle parentheses
                    elif char == '(':
                        paren_depth += 1
                        current_arg.append(char)
                    elif char == ')':
                        paren_depth -= 1
                        if paren_depth > 0:
                            current_arg.append(char)
                    # Handle argument separators
                    elif char == ',' and paren_depth == 1:
                        args.append(''.join(current_arg).strip())
                        current_arg = []
                        i += 1  # Skip whitespace after comma
                        while i < len(decompiled_code) and decompiled_code[i].isspace():
                            i += 1
                        continue  # Don't add comma to current_arg
                    else:
                        current_arg.append(char)
                    
                    i += 1
                
                # Add the last argument
                if current_arg:
                    # print(f"[INFO] Found args: {args}")
                    args.append(''.join(current_arg).strip())
                
                start_pos = i
            # print(f"[INFO] Found args: {args}")
            return args

        except Exception as e:
            # print(f"[EXCEPTION] Error in function {hex(func_addr)}: {e}")
            return []
        
    def sanitize_name(self, name):
        """Apply regex substitution and sanitize to IDA-valid function name"""
        original = name
        name = name.replace("'", "").replace('"', "")

        if self.rename_regex:
            try:
                pattern, repl = self.rename_regex
                name = re.sub(pattern, repl, name)
                print(f"[TRANSFORM] Regex applied: '{original}' -> '{name}'")
            except Exception as e:
                print(f"[ERROR] Regex error: {e}")
        
        return re.sub(r"[^a-zA-Z0-9_]", "_", name)
    def rename_function(self, func_addr, new_function_name):
        """
        Rename the function using extracted argument strings and optional regex transformation.
        """
        old_function_name = idc.get_func_name(func_addr)
        if not new_function_name:
            return

        if new_function_name and old_function_name != new_function_name:
            success = idc.set_name(func_addr, new_function_name)
            if success:
                print(f"[INFO] Renamed {old_function_name} -> {new_function_name}")
            else:
                print(f"[ERROR] Rename failed for {old_function_name} -> {new_function_name}")
        else:
            print(f"[SKIP] No rename needed for {old_function_name}")

class LogAnalyzerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    wanted_name = "Log Analyzer"
    wanted_hotkey = ""
    comment = "Analyze log calls and rename functions"
    help = "This plugin analyzes log function calls and renames functions based on log messages"

    def init(self):
        # create action
        self.action_desc = idaapi.action_desc_t(
            'loganalyzer:action',
            'Log Analyzer',
            self.run,
            None,
            'Analyze log calls and rename functions',
            199
        )
        
        # register action
        if not idaapi.register_action(self.action_desc):
            return idaapi.PLUGIN_SKIP
        
        # add action to menu
        if not idaapi.attach_action_to_menu(
            "Edit/",
            'loganalyzer:action',
            idaapi.SETMENU_APP
        ):
            return idaapi.PLUGIN_SKIP
        
        return idaapi.PLUGIN_OK

    def run(self, arg):
        # create and show the dialog
        dialog = LogAnalyzerDialog()
        dialog.exec_()

    def term(self):
        # unregister action
        idaapi.unregister_action('loganalyzer:action')

def PLUGIN_ENTRY():
    return LogAnalyzerPlugin()