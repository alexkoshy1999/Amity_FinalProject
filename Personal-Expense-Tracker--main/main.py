import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
import csv
import os
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import bcrypt
from dotenv import load_dotenv
import pymongo
from bson.objectid import ObjectId

# Load hidden environment configurations
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")

from cryptography.fernet import Fernet

# ---------------------- Cryptographic Key Management ----------------------
KEY_FILE = "secret.key"

def load_or_generate_key():
    """Loads an existing key or generates a new AES-256 key file if missing."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        # Generate a secure, random symmetric key
        new_key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(new_key)
        return new_key

try:
    crypto_key = load_or_generate_key()
    cipher_suite = Fernet(crypto_key)
except Exception as crypto_err:
    print(f"Cryptographic Initialization Failure: {crypto_err}")

# Establish secure client connection to the Cloud Cluster
try:
    client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client['ExpenseTrackerCloud']  # This creates your cloud database
except Exception as e:
    print(f"Cloud Connection Error: {e}")

# ---------------------- Database Setup ----------------------

def init_db():
    """Validates the cryptographic handshake with the cloud node at startup."""
    try:
        # Force a network ping command execution to verify authentication credentials
        client.admin.command('ping')
        print("Successfully connected to MongoDB Cloud Atlas!")
        messagebox.showinfo("Database Status", "Secure Connection to MongoDB Cloud Atlas Established Successfully!")
    except Exception as e:
        messagebox.showerror("Database Connection Error", 
                             f"Security Authentication Failed or Cloud Target Unreachable:\n\n{e}\n\n"
                             "Troubleshooting Steps:\n"
                             "1. Verify the credentials inside your local hidden .env file.\n"
                             "2. Confirm your current public network IP is whitelisted on MongoDB Atlas.")
        os._exit(1) # Kill framework processing on connection failure

# ---------------------- Utilities ----------------------

def hash_password(pw: str) -> str:
    """Generates a secure, salted bcrypt hash from a plain-text password."""
    salt = bcrypt.gensalt(rounds=12)  # 12 rounds is standard for production-grade security
    return bcrypt.hashpw(pw.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_pw: str, hashed_pw: str) -> bool:
    """Safely verifies a password attempt against a stored bcrypt hash."""
    return bcrypt.checkpw(plain_pw.encode('utf-8'), hashed_pw.encode('utf-8'))

def log_security_event(username: str, event_type: str, status: str, description: str):
    """Commits an immutable security log document to the cloud cluster for audit compliance."""
    try:
        log_payload = {
            "timestamp": datetime.now().isoformat(),
            "username": username,
            "event_type": event_type,   # e.g., 'AUTH_ATTEMPT', 'PROFILE_UPDATE', 'CRYPTO_ERROR'
            "status": status,           # 'SUCCESS' or 'FAILURE'
            "description": description,
            "system_environment": "Desktop-Tkinter-ClientNode"
        }
        db.security_logs.insert_one(log_payload)
    except Exception as log_err:
        print(f"SIEM Logging Failure: {log_err}")

# ---------------------- App ----------------------
class ExpenseApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Expense Tracker')
        self.geometry('900x600')
        self.minsize(820, 520)
        # ttk style for modern-ish look
        style = ttk.Style(self)
        try:
            style.theme_use('clam')
        except Exception:
            pass

        self.current_user = None  # will be (id, username)
        # main container
        self.container = ttk.Frame(self)
        self.container.pack(fill='both', expand=True)

        # frames
        self.frames = {}
        for F in (LoginFrame, RegisterFrame, DashboardFrame):
            frame = F(parent=self.container, controller=self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky='nsew')

        self.show_frame('LoginFrame')

    def show_frame(self, name):
        frame = self.frames[name]
        frame.tkraise()

    def login_user(self, user_id, username):
        self.current_user = (user_id, username)
        self.frames['DashboardFrame'].refresh_user()
        self.show_frame('DashboardFrame')

    def logout(self):
        self.current_user = None
        self.show_frame('LoginFrame')

# ---------------------- Login Frame ----------------------
class LoginFrame(ttk.Frame):
    def __init__(self, parent, controller: ExpenseApp):
        super().__init__(parent)
        self.controller = controller

        # left: brand
        left = ttk.Frame(self, padding=20)
        left.pack(side='left', fill='y')
        brand = ttk.Label(left, text='Expense Tracker', font=('Inter', 22, 'bold'))
        brand.pack(pady=(40, 10))
        sub = ttk.Label(left, text='Securely manage your expenses', font=('Inter', 10))
        sub.pack(pady=(0, 20))

        # right: login card
        right = ttk.Frame(self, padding=30)
        right.pack(side='left', fill='both', expand=True)

        card = ttk.LabelFrame(right, text='Login', padding=20)
        card.pack(anchor='center', pady=60, ipadx=20, ipady=10)

        ttk.Label(card, text='Username').grid(row=0, column=0, sticky='w')
        self.username_entry = ttk.Entry(card, width=30)
        self.username_entry.grid(row=0, column=1, pady=6)

        ttk.Label(card, text='Password').grid(row=1, column=0, sticky='w')
        self.password_entry = ttk.Entry(card, show='*', width=30)
        self.password_entry.grid(row=1, column=1, pady=6)

        login_btn = ttk.Button(card, text='Login', command=self.handle_login)
        login_btn.grid(row=2, column=0, columnspan=2, pady=(12, 6), sticky='we')

        reg_btn = ttk.Button(card, text='Register', command=lambda: controller.show_frame('RegisterFrame'))
        reg_btn.grid(row=3, column=0, columnspan=2, sticky='we')

    def handle_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showwarning('Validation Error', 'Fields cannot be left completely empty.')
            return
            
        try:
            # 1. Query the User Document from your Cloud Cluster
            user_document = db.users.find_one({"username": username})
            
            if not user_document:
                messagebox.showerror('Identity Status', 'No account entry found matching that username.')
                return
                
            # 2. CYBERSECURITY ENFORCEMENT CHECK: Reject right away if account is locked
            if user_document.get("is_locked", False):
                messagebox.showerror('Security Lockout', 'This account has been locked due to excessive failed login attempts.\nPlease contact the school administrator.')
                log_security_event(username, "AUTH_REJECTED", "FAILURE", "Blocked access attempt to locked account namespace.")
                return
                
            # 3. Secure Bcrypt Password Validation Check
            if verify_password(password, user_document['password_hash']):
                # Reset failure counters to 0 immediately upon a successful login match
                db.users.update_one({"_id": user_document["_id"]}, {"$set": {"failed_attempts": 0}})
                
                self.username_entry.delete(0, tk.END)
                self.password_entry.delete(0, tk.END)
                
                session_uid = str(user_document['_id'])
                
                # Write an audit trail success marker onto the cloud
                log_security_event(username, "AUTH_ATTEMPT", "SUCCESS", "User session successfully authenticated.")
                
                self.controller.login_user(session_uid, username)
                return  
                
            else:
                # 4. TRACKING ATTEMPTS: Calculate current sequential failure metrics
                current_failures = user_document.get("failed_attempts", 0) + 1
                update_fields = {"failed_attempts": current_failures}
                
                # Check if the failure counter breaches the threshold boundary limit
                if current_failures >= 5:
                    update_fields["is_locked"] = True
                    messagebox.showerror('Security Lockout', 'Account Locked! 5 consecutive invalid authentication attempts detected.')
                    
                    # Log a high-severity alert to your SIEM audit tracking board
                    log_security_event(username, "ACCOUNT_LOCKOUT", "FAILURE", "Account state locked automatically after threshold breach.")
                else:
                    messagebox.showerror('Security Rejection', f'Access Denied: Invalid credentials.\nAttempts remaining: {5 - current_failures}')
                    
                    # Log standard invalid access entry attempts
                    log_security_event(username, "AUTH_ATTEMPT", "FAILURE", f"Invalid credentials. Failure count: {current_failures}")
                    
                # Update the target user document schema in the cloud live
                db.users.update_one({"_id": user_document["_id"]}, {"$set": update_fields})
                
        except Exception as e:
            messagebox.showerror('Cloud Query Error', f'Transmission error fetching user data: {e}')

# ---------------------- Register Frame ----------------------
class RegisterFrame(ttk.Frame):
    def __init__(self, parent, controller: ExpenseApp):
        super().__init__(parent)
        self.controller = controller

        frame = ttk.Frame(self, padding=30)
        frame.pack(fill='both', expand=True)

        card = ttk.LabelFrame(frame, text='Account Registration System', padding=20)
        card.pack(pady=40)

        ttk.Label(card, text='Username').grid(row=0, column=0, sticky='w')
        self.username_entry = ttk.Entry(card, width=30)
        self.username_entry.grid(row=0, column=1, pady=6)

        ttk.Label(card, text='Password').grid(row=1, column=0, sticky='w')
        self.password_entry = ttk.Entry(card, show='*', width=30)
        self.password_entry.grid(row=1, column=1, pady=6)

        ttk.Label(card, text='Confirm').grid(row=2, column=0, sticky='w')
        self.confirm_entry = ttk.Entry(card, show='*', width=30)
        self.confirm_entry.grid(row=2, column=1, pady=6)

        # ROLE SPECIFICATION RBAC INTERFACE
        ttk.Label(card, text='Account Type').grid(row=3, column=0, sticky='w')
        self.role_var = tk.StringVar(value='student')
        self.role_cb = ttk.Combobox(card, textvariable=self.role_var, values=['student', 'parent'], state='readonly', width=28)
        self.role_cb.grid(row=3, column=1, pady=6)
        self.role_cb.bind('<<ComboboxSelected>>', lambda e: self.toggle_parent_field())

        # PARENT DYNAMIC DROPDOWN MENU
        self.parent_lbl = ttk.Label(card, text='Select Parent')
        self.parent_cb = ttk.Combobox(card, postcommand=self.populate_parents, width=28)
        
        # Display the dropdown by default since 'student' is the default choice
        self.parent_lbl.grid(row=4, column=0, sticky='w', pady=6)
        self.parent_cb.grid(row=4, column=1, pady=6)

        self.register_btn = ttk.Button(card, text='Register', command=self.handle_register)
        self.register_btn.grid(row=5, column=0, columnspan=2, pady=(15, 6), sticky='we')

        back_btn = ttk.Button(card, text='Back to Login', command=lambda: controller.show_frame('LoginFrame'))
        back_btn.grid(row=6, column=0, columnspan=2, sticky='we')

    def populate_parents(self):
        """Queries the cloud cluster live to fetch all registered parent profiles."""
        try:
            # Look up all database documents where role is explicitly 'parent'
            parent_cursor = db.users.find({"role": "parent"}, {"username": 1, "_id": 0})
            parent_list = [user["username"] for user in parent_cursor]
            
            # Inject the active array into the dropdown values
            if parent_list:
                self.parent_cb['values'] = sorted(parent_list)
            else:
                self.parent_cb['values'] = ['No Parents Registered Yet']
        except Exception as e:
            print(f"Failed to load parent profiles from cloud: {e}")
            self.parent_cb['values'] = ['Error fetching database entries']

    def toggle_parent_field(self):
        """Dynamically toggles fields based on chosen system privileges."""
        if self.role_var.get() == 'parent':
            self.parent_lbl.grid_remove()
            self.parent_cb.grid_remove()
        else:
            self.parent_lbl.grid(row=4, column=0, sticky='w', pady=6)
            self.parent_cb.grid(row=4, column=1, pady=6)
            self.populate_parents() # Auto-refresh the list when returning to student mode

    def handle_register(self):
        username = self.username_entry.get().strip()
        pw = self.password_entry.get().strip()
        conf = self.confirm_entry.get().strip()
        role = self.role_var.get()
        parent_username = self.parent_cb.get().strip()

        if not username or not pw or not conf:
            messagebox.showwarning('Missing Fields', 'Please fill all authentication boxes.')
            return
        if pw != conf:
            messagebox.showerror('Mismatch', 'Passwords do not match.')
            return
        if role == 'student' and (not parent_username or parent_username in ['No Parents Registered Yet', 'Error fetching database entries']):
            messagebox.showwarning('Validation Error', 'Student accounts must select a valid Parent from the dropdown menu.')
            return

        try:
            existing_account = db.users.find_one({"username": username})
            if existing_account:
                messagebox.showerror('Namespace Conflict', 'This username is already taken in the cloud.')
                return
                
            # Extra security fallback: Verify chosen parent exists
            if role == 'student':
                parent_check = db.users.find_one({"username": parent_username, "role": "parent"})
                if not parent_check:
                    messagebox.showwarning('Identity Error', f"Selected parent '{parent_username}' is invalid or no longer active.")
                    return

            secured_hash = hash_password(pw)
            
            user_schema_document = {
                "username": username,
                "password_hash": secured_hash,
                "role": role,
                "created_at": datetime.now().isoformat()
            }
            
            if role == 'student':
                user_schema_document["parent_username"] = parent_username

            db.users.insert_one(user_schema_document)

            log_security_event(username, "ACCOUNT_CREATION", "SUCCESS", f"New user signed up with role: {role.upper()}")
            
            messagebox.showinfo('Infrastructure Status', f'Account ({role.upper()}) created securely in the Cloud!')
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.confirm_entry.delete(0, tk.END)
            self.parent_cb.set('')
            self.controller.show_frame('LoginFrame')
        except Exception as e:
            messagebox.showerror('Cloud Cluster Insertion Error', f'Failed to write profile to database: {e}')

# ---------------------- Dashboard Frame ----------------------
class DashboardFrame(ttk.Frame):
    def __init__(self, parent, controller: ExpenseApp):
        super().__init__(parent)
        self.controller = controller

        topbar = ttk.Frame(self, padding=(10, 8))
        topbar.pack(fill='x')
        self.user_label = ttk.Label(topbar, text='', font=('Inter', 10, 'bold'))
        self.user_label.pack(side='left')

        logout_btn = ttk.Button(topbar, text='Logout', command=self.controller.logout)
        logout_btn.pack(side='right', padx=(5, 0))

        profile_btn = ttk.Button(topbar, text='Manage Profile', command=self.open_profile_management)
        profile_btn.pack(side='right', padx=(0, 5))

        # main content split
        content = ttk.PanedWindow(self, orient='horizontal')
        content.pack(fill='both', expand=True, padx=10, pady=10)

        # left panel - add expense
        left = ttk.Frame(content, width=320)
        content.add(left, weight=1)

        # ASSIGNED INSTANCE VARIABLE HANDLE TO DYNAMICALLY RE-LABEL
        self.input_card = ttk.LabelFrame(left, text='Add Expense', padding=12)
        self.input_card.pack(fill='x', padx=6, pady=6)

        ttk.Label(self.input_card, text='Amount').grid(row=0, column=0, sticky='w')
        self.amount_entry = ttk.Entry(self.input_card)
        self.amount_entry.grid(row=0, column=1, pady=6)

        ttk.Label(self.input_card, text='Category').grid(row=1, column=0, sticky='w')
        self.category_cb = ttk.Combobox(self.input_card, values=['Food', 'Travel', 'Groceries', 'Bills', 'Entertainment', 'Other'])
        self.category_cb.grid(row=1, column=1, pady=6)
        self.category_cb.set('Food')

        ttk.Label(self.input_card, text='Note').grid(row=2, column=0, sticky='w')
        self.note_entry = ttk.Entry(self.input_card)
        self.note_entry.grid(row=2, column=1, pady=6)

        # ASSIGNED INSTANCE VARIABLE HANDLE TO DISABLE
        self.add_btn = ttk.Button(self.input_card, text='Add Record', command=self.add_expense)
        self.add_btn.grid(row=3, column=0, columnspan=2, sticky='we', pady=(8, 0))

        # NEW: OVERSIGHT CONTROL PANEL CONTAINER (FOR PARENT LOGINS)
        self.supervisor_frame = ttk.LabelFrame(left, text="Oversight Controls (Parent Mode)", padding=10)
        
        ttk.Label(self.supervisor_frame, text="Select Student:").pack(anchor='w', pady=(0,2))
        self.student_selector_var = tk.StringVar()
        self.student_selector_cb = ttk.Combobox(self.supervisor_frame, textvariable=self.student_selector_var, state='readonly')
        self.student_selector_cb.pack(fill='x', pady=(0, 5))
        # When parent switches student, refresh the table view live
        self.student_selector_cb.bind('<<ComboboxSelected>>', lambda e: self.refresh_table())

        # analytical operations & tools panel
        tools = ttk.Frame(left, padding=6)
        tools.pack(fill='x', padx=6, pady=6)
        
        exp_btn = ttk.Button(tools, text='Export CSV', command=self.export_csv)
        exp_btn.pack(side='left', padx=(0,6))
        
        chart_btn = ttk.Button(tools, text='Show Charts', command=self.show_charts)
        chart_btn.pack(side='left', padx=(0,6))

        monthly_btn = ttk.Button(tools, text='Monthly Summary', command=self.show_monthly_totals_window)
        monthly_btn.pack(side='left')

        # right panel - table
        right = ttk.Frame(content)
        content.add(right, weight=3)

        searchbar = ttk.Frame(right)
        searchbar.pack(fill='x', pady=(0,8))
        ttk.Label(searchbar, text='Search Ledger').pack(side='left')
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(searchbar, textvariable=self.search_var)
        search_entry.pack(side='left', padx=(6,6))
        search_entry.bind('<KeyRelease>', lambda e: self.refresh_table())

        self.tree = ttk.Treeview(right, columns=('id','amount','category','note','date'), show='headings')
        for col, w in [('id',40), ('amount',90), ('category',120), ('note',260), ('date',150)]:
            self.tree.heading(col, text=col.title())
            self.tree.column(col, width=w, anchor='center')
        self.tree.pack(fill='both', expand=True)

        # ASSIGNED INSTANCE VARIABLE HANDLE TO DISABLE
        self.del_btn = ttk.Button(right, text='Delete Selected', command=self.delete_selected)
        self.del_btn.pack(pady=6)

    def get_monthly_analytics(self):
        """Executes local decryption and data-mining to compile time-series monthly totals."""
        uid, uname = self.controller.current_user
        try:
            user_doc = db.users.find_one({"_id": ObjectId(uid)})
            role = user_doc.get("role", "student").lower()
            
            target_user_ids = []
            if role == "parent":
                selected_child_name = self.student_selector_var.get()
                child_doc = db.users.find_one({"username": selected_child_name, "parent_username": uname})
                if child_doc:
                    target_user_ids.append(str(child_doc["_id"]))
            else:
                target_user_ids.append(uid)
                
            # Fetch raw records belonging to the target scope accounts
            cursor = db.expenses.find({"user_id": {"$in": target_user_ids}})
            
            # Local collection matrix dictionary
            monthly_map = {}
            
            for r in cursor:
                try:
                    cipher_amount = r.get('amount', '')
                    # Decrypt locally on the fly
                    amount_str = cipher_suite.decrypt(cipher_amount.encode('utf-8')).decode('utf-8')
                    amount_val = float(amount_str)
                except Exception:
                    continue # Skip unreadable or corrupted records
                    
                # Extract year-month string segment (YYYY-MM) from ISO timestamp
                date_str = r.get('date', '')
                month_key = date_str[0:7] if date_str else "Unknown"
                
                # Perform local summation aggregation
                monthly_map[month_key] = monthly_map.get(month_key, 0.0) + amount_val
                
            # Convert back to MongoDB matching list-of-dictionary structures for your UI
            aggregated_data = [{"_id": m, "monthly_total": monthly_map[m]} for m in sorted(monthly_map.keys())]
            return aggregated_data
            
        except Exception as e:
            print(f"Local analytics aggregation mapping failed: {e}")
            return []
        
    def show_monthly_totals_window(self):
        """Spawns an interactive grid view displaying historical monthly trends."""
        win = tk.Toplevel(self)
        win.title("Historical Monthly Expenditure Analytics")
        win.geometry("450x380")  # Slightly expanded height to give widgets breathing room
        win.resizable(False, False)
        win.grab_set()
        
        frame = ttk.Frame(win, padding=20)
        frame.pack(fill='both', expand=True)
        
        ttk.Label(frame, text="Time-Series Monthly Overview", font=('Inter', 12, 'bold')).pack(pady=(0, 10))
        
        # Build a structured data sheet treeview widget
        columns = ('month', 'total')
        analytics_tree = ttk.Treeview(frame, columns=columns, show='headings', height=8) # Lowered row height parameter
        analytics_tree.heading('month', text='Billing Cycle (Year-Month)')
        analytics_tree.heading('total', text='Cumulative Outflow Amount')
        
        analytics_tree.column('month', anchor='center', width=180)
        analytics_tree.column('total', anchor='e', width=180)
        
        # CRITICAL FIX: Pack the treeview with fill='both' but expand=True, 
        # allowing it to take space gracefully without overrunning the button container bounds.
        analytics_tree.pack(fill='both', expand=True, pady=(0, 15))
        
        # Pull processed calculations straight from the cloud database tier
        monthly_records = self.get_monthly_analytics()
        
        if not monthly_records:
            analytics_tree.insert('', tk.END, values=("No Data Tracked", "₹ 0.00"))
        else:
            for item in monthly_records:
                month_string = item['_id']  # Extract the YYYY-MM identifier
                total_volume = f"₹ {item['monthly_total']:.2f}"
                analytics_tree.insert('', tk.END, values=(month_string, total_volume))
                
        # Packed explicitly at the bottom with explicit side and padding parameters to secure its visibility
        close_btn = ttk.Button(frame, text="Close View", command=win.destroy)
        close_btn.pack(side='bottom', fill='x', pady=(5, 0))

    def refresh_user(self):
        """Evaluates database authorization states to lock down panels and configure child selectors."""
        uid, uname = self.controller.current_user
        try:
            # Look up active user document profile settings inside the cloud
            user_doc = db.users.find_one({"_id": ObjectId(uid)})
            role = user_doc.get("role", "student").lower()
            
            self.user_label.config(text=f'School Portal | Account: {uname} ({role.upper()} VIEW)')
            
            if role == "parent":
                # HIERARCHICAL RBAC RULE: Lock input pipelines if account type is parent
                self.amount_entry.config(state='disabled')
                self.note_entry.config(state='disabled')
                self.category_cb.config(state='disabled')
                self.add_btn.config(state='disabled')
                self.del_btn.config(state='disabled')
                self.input_card.config(text="Data Capture Lock (Read-Only Supervisor View)")
                
                # Dynamic Discovery of Linked Children from the cloud shard
                linked_students = db.users.find({"parent_username": uname})
                student_names = [student["username"] for student in linked_students]
                
                if student_names:
                    self.student_selector_cb['values'] = sorted(student_names)
                    self.student_selector_cb.set(sorted(student_names)[0]) # Auto-select the first child
                else:
                    self.student_selector_cb['values'] = ['No Students Linked']
                    self.student_selector_cb.set('No Students Linked')
                
                # Dynamically pack the supervisor frame onto the window layout
                self.supervisor_frame.pack(fill='x', padx=6, pady=6)
            else:
                # Student Mode: Fully enable creation interfaces and remove parent panel from layout view
                self.amount_entry.config(state='normal')
                self.note_entry.config(state='normal')
                self.category_cb.config(state='readonly')
                self.add_btn.config(state='normal')
                self.del_btn.config(state='normal')
                self.input_card.config(text="Add Expense")
                
                self.supervisor_frame.pack_forget() # Cleanly hides the selector frame
                
        except Exception as e:
            self.user_label.config(text=f'Logged in as: {uname}')
            
        self.refresh_table()

    def add_expense(self):
        try:
            amount_raw = self.amount_entry.get().strip()
            float(amount_raw) # Check type validity
        except ValueError:
            messagebox.showerror('Schema Type Error', 'Transaction quantitative amounts must strictly map to numbers.')
            return
            
        category = self.category_cb.get().strip() or 'Other'
        note_raw = self.note_entry.get().strip()
        date = datetime.now().isoformat()
        uid, _ = self.controller.current_user
        
        try:
            # --- CLIENT-SIDE CRYPTOGRAPHIC HARDENING ENGINE ---
            # AES-256 Fernet expects byte streams, so we encode strings before encrypting
            encrypted_amount = cipher_suite.encrypt(amount_raw.encode('utf-8')).decode('utf-8')
            encrypted_note = cipher_suite.encrypt(note_raw.encode('utf-8')).decode('utf-8')
            
            expense_document = {
                "user_id": uid, 
                "amount": encrypted_amount,  # Pushed as cipher ciphertext
                "category": category,         # Kept plain text for server-side chart aggregation
                "note": encrypted_note,      # Pushed as cipher ciphertext
                "date": date
            }
            db.expenses.insert_one(expense_document)
            
            self.amount_entry.delete(0, tk.END)
            self.note_entry.delete(0, tk.END)
            self.refresh_table()
        except Exception as e:
            messagebox.showerror('Cloud Push Exception', f'Cluster storage node pipeline blocked: {e}')

    def refresh_table(self):
        """Queries cluster data using implicit segregation arrays to support parent oversight."""
        # 1. Clear out all existing data entries from the visual grid UI
        for r in self.tree.get_children():
            self.tree.delete(r)
        uid, uname = self.controller.current_user
        
        try:
            user_doc = db.users.find_one({"_id": ObjectId(uid)})
            role = user_doc.get("role", "student").lower()
            
            target_user_ids = []
            
            if role == "parent":
                # Get the explicitly chosen student name from your dropdown interface
                selected_child_name = self.student_selector_var.get()
                
                # Query that specific child's document profile information
                child_doc = db.users.find_one({"username": selected_child_name, "parent_username": uname})
                if child_doc:
                    target_user_ids.append(str(child_doc["_id"]))
            else:
                target_user_ids.append(uid)
                
            # Perform multi-tenant list aggregation scanning using the $in operator array mapping
            cursor = db.expenses.find({"user_id": {"$in": target_user_ids}}).sort("date", -1)
            rows = list(cursor)
        except Exception as e:
            print(f"Cluster pipeline payload read error exception context: {e}")
            return
            
        term = self.search_var.get().lower().strip()
        serial_number = 1
        
        for r in rows:
            # --- CLIENT-SIDE LOCAL DECRYPTION LOOP ---
            try:
                # Retrieve cipher tokens straight from database document fields
                cipher_amount = r.get('amount', '')
                cipher_note = r.get('note', '')
                
                # Decrypt ciphertext bytes and decode back to user readable strings
                amount_str = cipher_suite.decrypt(cipher_amount.encode('utf-8')).decode('utf-8')
                note_val = cipher_suite.decrypt(cipher_note.encode('utf-8')).decode('utf-8')
                
                # Convert back to numeric format for standard visual table layouts
                amount_display = float(amount_str)
            except Exception as decrypt_error:
                # Fallback if key management mismatch occurs or field is unencrypted legacy record
                amount_str = "0.00"
                amount_display = 0.0
                note_val = "[Decryption Failure: Missing Secret Token Key File]"
                
            category_val = r.get('category', 'Other')
            date_val = r.get('date', '')
            string_object_id = str(r['_id']) 
            
            if term:
                if term in amount_str.lower() or term in category_val.lower() or term in note_val.lower() or term in date_val.lower():
                    self.tree.insert('', tk.END, iid=string_object_id, values=(serial_number, amount_display, category_val, note_val, date_val))
                    serial_number += 1
            else:
                self.tree.insert('', tk.END, iid=string_object_id, values=(serial_number, amount_display, category_val, note_val, date_val))
                serial_number += 1

    def delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning('Operational Alert', 'Select a targeted data payload entry row first.')
            return
            
        # CRITICAL FIX: Grab the hidden internal structural item IDs ('sel'), 
        # which map perfectly back to our MongoDB cloud hex ObjectIds due to the 'iid' mapping above!
        ids = [s for s in sel] 
        
        if not messagebox.askyesno('Confirm Purge Transaction', f'Are you sure you want to completely erase these {len(ids)} record entries permanently?'):
            return
            
        try:
            for i in ids:
                # Target deletion explicitly using the true cloud indexing format token keys
                db.expenses.delete_one({"_id": ObjectId(i)})
            self.refresh_table()
            messagebox.showinfo('Database Sync', 'Cloud records erased successfully across active clusters.')
        except Exception as e:
            messagebox.showerror('Cloud Deletion Exception', f'Cluster indexing transaction loop rejected command: {e}')

    def export_csv(self):
        """Decrypts encrypted records and writes them out into standard format spreadsheets."""
        uid, uname = self.controller.current_user
        try:
            user_doc = db.users.find_one({"_id": ObjectId(uid)})
            role = user_doc.get("role", "student").lower()
            
            target_user_ids = []
            if role == "parent":
                selected_child_name = self.student_selector_var.get()
                child_doc = db.users.find_one({"username": selected_child_name, "parent_username": uname})
                if child_doc:
                    target_user_ids.append(str(child_doc["_id"]))
            else:
                target_user_ids.append(uid)

            # Query raw tracking documents
            rows = list(db.expenses.find({"user_id": {"$in": target_user_ids}}).sort("date", -1))
        except Exception as e:
            messagebox.showerror('Cloud Export Failure', f'Could not query dataset tables: {e}')
            return
            
        if not rows:
            messagebox.showinfo('Empty', 'No records to export')
            return
            
        f = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV files','*.csv')], initialfile=f'expenses_audit_{uname}.csv')
        if not f:
            return
            
        with open(f, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Amount', 'Category', 'Note', 'Date'])
            
            for r in rows:
                try:
                    # Decrypt values sequentially before dropping into files
                    amount_str = cipher_suite.decrypt(r['amount'].encode('utf-8')).decode('utf-8')
                    note_val = cipher_suite.decrypt(r['note'].encode('utf-8')).decode('utf-8')
                except Exception:
                    # Fallback default if unencrypted legacy fields hit loop
                    amount_str = str(r.get('amount', 0))
                    note_val = r.get('note', '')
                    
                writer.writerow([amount_str, r['category'], note_val, r['date']])
                
        messagebox.showinfo('Saved', f'Exported to {os.path.basename(f)}')

    def open_profile_management(self):
        """Spawns a secure modal window to modify user credentials in the cloud."""
        uid, uname = self.controller.current_user
        
        win = tk.Toplevel(self)
        win.title('Identity Management Security Panel')
        win.geometry('400x300')
        win.resizable(False, False)
        win.grab_set()  # Focus lock on this window
        
        frame = ttk.Frame(win, padding=20)
        frame.pack(fill='both', expand=True)
        
        ttk.Label(frame, text="Update Profile Credentials", font=('Inter', 12, 'bold')).pack(pady=(0, 15))
        
        # New Username Entry
        ttk.Label(frame, text="New Username").pack(anchor='w')
        new_user_entry = ttk.Entry(frame, width=30)
        new_user_entry.insert(0, uname)  # Pre-fill with current name
        new_user_entry.pack(fill='x', pady=(2, 10))
        
        # New Password Entry
        ttk.Label(frame, text="New Password (Leave blank to keep current)").pack(anchor='w')
        new_pw_entry = ttk.Entry(frame, show='*', width=30)
        new_pw_entry.pack(fill='x', pady=(2, 15))
        
        def save_profile_changes():
            new_username = new_user_entry.get().strip()
            new_password = new_pw_entry.get().strip()
            
            if not new_username:
                messagebox.showwarning("Validation Error", "Username field cannot be empty.")
                return
                
            try:
                update_payload = {}
                
                # 1. If username is changing, verify namespace availability
                if new_username != uname:
                    conflict_check = db.users.find_one({"username": new_username})
                    if conflict_check:
                        messagebox.showerror("Conflict", "This username is already taken in the cloud.")
                        return
                    update_payload["username"] = new_username
                
                # 2. If password field is filled, hash it securely via bcrypt
                if new_password:
                    update_payload["password_hash"] = self.controller.frames['RegisterFrame'].controller.register_shape_hash(new_password) if hasattr(self.controller, 'register_shape_hash') else bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')
                
                if not update_payload:
                    messagebox.showinfo("No Changes", "No modifications were entered.")
                    win.destroy()
                    return
                
                # 3. Commit changes to MongoDB Atlas targeting document ObjectId
                db.users.update_one({"_id": ObjectId(uid)}, {"$set": update_payload})
                
                log_security_event(new_username, "PROFILE_UPDATE", "SUCCESS", "User altered credentials inside profile settings.")

                messagebox.showinfo("Success", "Cloud profile updated successfully!\nPlase log back in to apply changes.")
                win.destroy()
                self.controller.logout()  # Force safe session termination
                
            except Exception as e:
                messagebox.showerror("Cloud Error", f"Failed to sync updates to cluster shards: {e}")

        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill='x', pady=10)
        
        ttk.Button(btn_frame, text="Save Changes", command=save_profile_changes).pack(side='left', expand=True, fill='x', padx=(0, 5))
        ttk.Button(btn_frame, text="Cancel", command=win.destroy).pack(side='right', expand=True, fill='x', padx=(5, 0))

    def show_charts(self):
        """Builds interactive visual analytics tracking locally decrypted expenditures."""
        uid, uname = self.controller.current_user
        try:
            user_doc = db.users.find_one({"_id": ObjectId(uid)})
            role = user_doc.get("role", "student").lower()
            
            target_user_ids = []
            if role == "parent":
                selected_child_name = self.student_selector_var.get()
                child_doc = db.users.find_one({"username": selected_child_name, "parent_username": uname})
                if child_doc:
                    target_user_ids.append(str(child_doc["_id"]))
            else:
                target_user_ids.append(uid)

            cursor = db.expenses.find({"user_id": {"$in": target_user_ids}})
            
            category_map = {}
            for r in cursor:
                try:
                    cipher_amount = r.get('amount', '')
                    amount_str = cipher_suite.decrypt(cipher_amount.encode('utf-8')).decode('utf-8')
                    amount_val = float(amount_str)
                except Exception:
                    continue
                    
                cat_val = r.get('category', 'Other')
                category_map[cat_val] = category_map.get(cat_val, 0.0) + amount_val
                
        except Exception as e:
            messagebox.showerror('Cryptographic Mapping Blocked', f'Local charts extraction rejected: {e}')
            return
            
        if not category_map:
            messagebox.showinfo('No Metric Tracking Present', 'No logs present to generate charts.')
            return
            
        categories = list(category_map.keys())
        totals = list(category_map.values())

        win = tk.Toplevel(self)
        win.title('Spending Distribution Charts')
        win.geometry('700x500')

        nb = ttk.Notebook(win)
        nb.pack(fill='both', expand=True)

        f1 = ttk.Frame(nb)
        nb.add(f1, text='Pie Chart Distribution')
        fig1 = plt.Figure(figsize=(6,4), dpi=100)
        ax1 = fig1.add_subplot(111)
        ax1.pie(totals, labels=categories, autopct='%1.1f%%', startangle=140)
        ax1.axis('equal')
        canvas1 = FigureCanvasTkAgg(fig1, master=f1)
        canvas1.draw()
        canvas1.get_tk_widget().pack(fill='both', expand=True)

        f2 = ttk.Frame(nb)
        nb.add(f2, text='Bar Chart Metric')
        fig2 = plt.Figure(figsize=(6,4), dpi=100)
        ax2 = fig2.add_subplot(111)
        ax2.bar(categories, totals)
        ax2.set_ylabel('Aggregated Amount (₹)')
        ax2.set_title('Spending Distribution by Category')
        canvas2 = FigureCanvasTkAgg(fig2, master=f2)
        canvas2.draw()
        canvas2.get_tk_widget().pack(fill='both', expand=True)

# ---------------------- Main ----------------------
if __name__ == '__main__':
    init_db()
    app = ExpenseApp()
    app.mainloop()
