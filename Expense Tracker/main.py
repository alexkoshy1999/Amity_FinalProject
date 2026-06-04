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
            # 1. Query User Document from MongoDB Cloud Atlas
            user_document = db.users.find_one({"username": username})
            
            if not user_document:
                messagebox.showerror('Identity Status', 'No account entry found matching that username.')
                return
                
            # 2. Secure Bcrypt Password Validation Check
            if verify_password(password, user_document['password_hash']):
                self.username_entry.delete(0, tk.END)
                self.password_entry.delete(0, tk.END)
                
                # Unpack unique object metadata string for active cloud tracking session
                session_uid = str(user_document['_id'])
                self.controller.login_user(session_uid, username)
                return  # CRITICAL: Exits the function immediately so it never reads any lower code!
                
            else:
                messagebox.showerror('Security Rejection', 'Access Denied: Invalid credentials.')
                
        except Exception as e:
            messagebox.showerror('Cloud Query Error', f'Transmission error fetching user data: {e}')

# ---------------------- Register Frame ----------------------
class RegisterFrame(ttk.Frame):
    def __init__(self, parent, controller: ExpenseApp):
        super().__init__(parent)
        self.controller = controller

        frame = ttk.Frame(self, padding=30)
        frame.pack(fill='both', expand=True)

        card = ttk.LabelFrame(frame, text='Create Account', padding=20)
        card.pack(pady=60)

        ttk.Label(card, text='Username').grid(row=0, column=0, sticky='w')
        self.username_entry = ttk.Entry(card, width=30)
        self.username_entry.grid(row=0, column=1, pady=6)

        ttk.Label(card, text='Password').grid(row=1, column=0, sticky='w')
        self.password_entry = ttk.Entry(card, show='*', width=30)
        self.password_entry.grid(row=1, column=1, pady=6)

        ttk.Label(card, text='Confirm').grid(row=2, column=0, sticky='w')
        self.confirm_entry = ttk.Entry(card, show='*', width=30)
        self.confirm_entry.grid(row=2, column=1, pady=6)

        register_btn = ttk.Button(card, text='Register', command=self.handle_register)
        register_btn.grid(row=3, column=0, columnspan=2, pady=(10, 6), sticky='we')

        back_btn = ttk.Button(card, text='Back to Login', command=lambda: controller.show_frame('LoginFrame'))
        back_btn.grid(row=4, column=0, columnspan=2, sticky='we')

    def handle_register(self):
        username = self.username_entry.get().strip()
        pw = self.password_entry.get().strip()
        conf = self.confirm_entry.get().strip()
        if not username or not pw or not conf:
            messagebox.showwarning('Missing', 'Fill all fields')
            return
        if pw != conf:
            messagebox.showerror('Mismatch', 'Passwords do not match')
            return
        try:
            # Check if the username is already taken in our cloud collection
            existing_account = db.users.find_one({"username": username})
            if existing_account:
                messagebox.showerror('Namespace Conflict', 'This username is already taken in the cloud.')
                return
                
            secured_hash = hash_password(pw)
            
            # Map user registration data to a document structure
            user_schema_document = {
                "username": username,
                "password_hash": secured_hash,
                "created_at": datetime.now().isoformat()
            }
            
            # Write document payload directly to your live cluster
            db.users.insert_one(user_schema_document)
            
            messagebox.showinfo('Infrastructure Status', 'Account created securely in the Cloud! Please login.')
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.confirm_entry.delete(0, tk.END)
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
        self.user_label = ttk.Label(topbar, text='')
        self.user_label.pack(side='left')

        logout_btn = ttk.Button(topbar, text='Logout', command=self.controller.logout)
        logout_btn.pack(side='right', padx=(5, 0))

        # Modern Profile Security Action Entry Gateway
        profile_btn = ttk.Button(topbar, text='Manage Profile', command=self.open_profile_management)
        profile_btn.pack(side='right', padx=(0, 5))

        # main content split
        content = ttk.PanedWindow(self, orient='horizontal')
        content.pack(fill='both', expand=True, padx=10, pady=10)

        # left panel - add expense
        left = ttk.Frame(content, width=320)
        content.add(left, weight=1)

        card = ttk.LabelFrame(left, text='Add Expense', padding=12)
        card.pack(fill='x', padx=6, pady=6)

        ttk.Label(card, text='Amount').grid(row=0, column=0, sticky='w')
        self.amount_entry = ttk.Entry(card)
        self.amount_entry.grid(row=0, column=1, pady=6)

        ttk.Label(card, text='Category').grid(row=1, column=0, sticky='w')
        self.category_cb = ttk.Combobox(card, values=['Food', 'Travel', 'Groceries', 'Bills', 'Entertainment', 'Other'])
        self.category_cb.grid(row=1, column=1, pady=6)
        self.category_cb.set('Food')

        ttk.Label(card, text='Note').grid(row=2, column=0, sticky='w')
        self.note_entry = ttk.Entry(card)
        self.note_entry.grid(row=2, column=1, pady=6)

        add_btn = ttk.Button(card, text='Add', command=self.add_expense)
        add_btn.grid(row=3, column=0, columnspan=2, sticky='we', pady=(8, 0))

        # export and chart buttons
        # analytical operations & tools panel
        tools = ttk.Frame(left, padding=6)
        tools.pack(fill='x', padx=6, pady=6)
        
        exp_btn = ttk.Button(tools, text='Export CSV', command=self.export_csv)
        exp_btn.pack(side='left', padx=(0,6))
        
        chart_btn = ttk.Button(tools, text='Show Charts', command=self.show_charts)
        chart_btn.pack(side='left', padx=(0,6))

        # Time-Series NoSQL Cloud Data Mining Aggregate Trigger
        monthly_btn = ttk.Button(tools, text='Monthly Summary', command=self.show_monthly_totals_window)
        monthly_btn.pack(side='left')

        # right panel - table
        right = ttk.Frame(content)
        content.add(right, weight=3)

        searchbar = ttk.Frame(right)
        searchbar.pack(fill='x', pady=(0,8))
        ttk.Label(searchbar, text='Search').pack(side='left')
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(searchbar, textvariable=self.search_var)
        search_entry.pack(side='left', padx=(6,6))
        search_entry.bind('<KeyRelease>', lambda e: self.refresh_table())

        self.tree = ttk.Treeview(right, columns=('id','amount','category','note','date'), show='headings')
        for col, w in [('id',40), ('amount',90), ('category',120), ('note',260), ('date',150)]:
            self.tree.heading(col, text=col.title())
            self.tree.column(col, width=w, anchor='center')
        self.tree.pack(fill='both', expand=True)

        # delete button
        del_btn = ttk.Button(right, text='Delete Selected', command=self.delete_selected)
        del_btn.pack(pady=6)

    def get_monthly_analytics(self):
        """Executes a server-side aggregation pipeline to extract time-series monthly totals."""
        uid, _ = self.controller.current_user
        try:
            # High-performance NoSQL data-mining aggregation pipeline
            pipeline = [
                # 1. Isolate entries belonging strictly to the active logged-in user
                {"$match": {"user_id": uid}},
                
                # 2. Extract the Year-Month string sequence (YYYY-MM) from the ISO date stamp
                #    and compute the mathematical sum of the transaction amounts
                {"$group": {
                    "_id": {"$substr": ["$date", 0, 7]}, 
                    "monthly_total": {"$sum": "$amount"}
                }},
                
                # 3. Sort chronologically from the earliest month to the most recent month
                {"$sort": {"_id": 1}}
            ]
            
            aggregated_data = list(db.expenses.aggregate(pipeline))
            return aggregated_data
        except Exception as e:
            print(f"Data mining pipeline analytics execution failed: {e}")
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
        uid, uname = self.controller.current_user
        self.user_label.config(text=f'Logged in as: {uname}')
        self.refresh_table()

    def add_expense(self):
        try:
            amount = float(self.amount_entry.get())
        except ValueError:
            messagebox.showerror('Schema Type Error', 'Transaction quantitative amounts must strictly map to numbers.')
            return
        category = self.category_cb.get().strip() or 'Other'
        note = self.note_entry.get().strip()
        date = datetime.now().isoformat()
        uid, _ = self.controller.current_user
        
        try:
            # Construct a clean document structure mapping for cloud cluster ingestion
            expense_document = {
                "user_id": uid, 
                "amount": amount,
                "category": category,
                "note": note,
                "date": date
            }
            
            # Commit the payload straight onto the live cloud instances
            db.expenses.insert_one(expense_document)
            
            self.amount_entry.delete(0, tk.END)
            self.note_entry.delete(0, tk.END)
            messagebox.showinfo('Ledger Status', 'Transactional ledger entry processed and pushed securely to cloud cluster!')
            self.refresh_table()
        except Exception as e:
            messagebox.showerror('Cloud Push Exception', f'Cluster storage node pipeline blocked: {e}')

    def refresh_table(self):
        # 1. Clear out all existing data entries from the visual grid UI
        for r in self.tree.get_children():
            self.tree.delete(r)
        uid, _ = self.controller.current_user
        
        try:
            # 2. Fetch data payload records from your live cloud cluster
            cursor = db.expenses.find({"user_id": uid}).sort("date", -1)
            rows = list(cursor)
        except Exception as e:
            print(f"Cluster pipeline payload read error exception context: {e}")
            return
            
        term = self.search_var.get().lower().strip()
        
        # 3. Initialize a dynamic serial number counter
        serial_number = 1
        
        for r in rows:
            note_val = r.get('note', '') or ''
            amount_str = str(r.get('amount', 0))
            category_val = r.get('category', 'Other')
            date_val = r.get('date', '')
            
            # Extract the actual MongoDB hex identifier string token
            string_object_id = str(r['_id']) 
            
            # 4. If a search keyword is active, filter the dataset fields dynamically
            if term:
                if term in amount_str.lower() or term in category_val.lower() or term in note_val.lower() or term in date_val.lower():
                    # --- CRITICAL ARCHITECTURE FIX ---
                    # We pass the real 'string_object_id' to Tkinter's internal structural item ID block (iid),
                    # but we only display the clean, incrementing 'serial_number' in the table values!
                    self.tree.insert('', tk.END, iid=string_object_id, values=(serial_number, r['amount'], category_val, note_val, date_val))
                    serial_number += 1
            else:
                # Standard unfiltered sequential insertion block
                self.tree.insert('', tk.END, iid=string_object_id, values=(serial_number, r['amount'], category_val, note_val, date_val))
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
        uid, uname = self.controller.current_user
        try:
            rows = list(db.expenses.find({"user_id": uid}).sort("date", -1))
        except Exception as e:
            messagebox.showerror('Cloud Export Failure', f'Could not query dataset cluster tables: {e}')
            return
        if not rows:
            messagebox.showinfo('Empty', 'No records to export')
            return
        f = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV files','*.csv')], initialfile=f'expenses_{uname}.csv')
        if not f:
            return
        with open(f, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Amount', 'Category', 'Note', 'Date'])
            for r in rows:
                writer.writerow([r['amount'], r['category'], r['note'], r['date']])
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
        uid, _ = self.controller.current_user
        try:
            pipeline = [
                {"$match": {"user_id": uid}},
                {"$group": {"_id": "$category", "total_volume": {"$sum": "$amount"}}}
            ]
            aggregated_metrics = list(db.expenses.aggregate(pipeline))
        except Exception as e:
            messagebox.showerror('Cloud Aggregate Computations Blocked', f'Mathematical execution rejected by cloud engines: {e}')
            return
            
        if not aggregated_metrics:
            messagebox.showinfo('No Metric Tracking Present', 'Log transaction profiles first to track metrics analytics processing maps.')
            return
            
        categories = [r['_id'] for r in aggregated_metrics]
        totals = [r['total_volume'] for r in aggregated_metrics]

        # create a new Toplevel window for charts
        win = tk.Toplevel(self)
        win.title('Spending Charts')
        win.geometry('700x500')

        nb = ttk.Notebook(win)
        nb.pack(fill='both', expand=True)

        # Pie chart tab
        f1 = ttk.Frame(nb)
        nb.add(f1, text='Pie Chart')
        fig1 = plt.Figure(figsize=(6,4), dpi=100)
        ax1 = fig1.add_subplot(111)
        ax1.pie(totals, labels=categories, autopct='%1.1f%%', startangle=140)
        ax1.axis('equal')
        canvas1 = FigureCanvasTkAgg(fig1, master=f1)
        canvas1.draw()
        canvas1.get_tk_widget().pack(fill='both', expand=True)

        # Bar chart tab
        f2 = ttk.Frame(nb)
        nb.add(f2, text='Bar Chart')
        fig2 = plt.Figure(figsize=(6,4), dpi=100)
        ax2 = fig2.add_subplot(111)
        ax2.bar(categories, totals)
        ax2.set_ylabel('Amount')
        ax2.set_title('Spending by Category')
        canvas2 = FigureCanvasTkAgg(fig2, master=f2)
        canvas2.draw()
        canvas2.get_tk_widget().pack(fill='both', expand=True)

# ---------------------- Main ----------------------
if __name__ == '__main__':
    init_db()
    app = ExpenseApp()
    app.mainloop()
