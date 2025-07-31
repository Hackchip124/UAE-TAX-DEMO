import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
from fpdf import FPDF
import hashlib
import re
import os
import time
import base64
from io import BytesIO
import xml.etree.ElementTree as ET

# =============================================
# HELPER FUNCTIONS
# =============================================

def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def validate_password(password):
    """Check if password meets complexity requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, ""

def validate_email(email):
    """Basic email validation"""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None

def validate_username(username):
    """Validate username requirements"""
    if len(username) < 4:
        return False, "Username must be at least 4 characters long"
    if not username.isalnum():
        return False, "Username can only contain letters and numbers"
    return True, ""

def validate_trn(trn):
    """Validate UAE TRN (15 digits)"""
    return trn.isdigit() and len(trn) == 15

def validate_phone(phone):
    """Validate UAE phone number"""
    pattern = r"^\+971[0-9]{9}$"
    return re.match(pattern, phone) is not None

def log_activity(user_id, action, details="", ip_address="", user_agent=""):
    try:
        conn = sqlite3.connect('data/tax_management.db')
        c = conn.cursor()
        c.execute("""INSERT INTO activity_log 
                  (user_id, action, details, ip_address, user_agent) 
                  VALUES (?, ?, ?, ?, ?)""",
                 (user_id, action, details, ip_address, user_agent))
        conn.commit()
    except Exception as e:
        st.error(f"Error logging activity: {str(e)}")
    finally:
        conn.close()

def calculate_vat(amount, rate=0.05):
    """Calculate VAT amount based on UAE standard rate (5%)"""
    return round(amount * rate, 2)

def calculate_corporate_tax(taxable_income, is_free_zone=False):
    """
    Calculate corporate tax based on UAE rules:
    - 0% for taxable income up to AED 375,000
    - 9% for taxable income above AED 375,000
    - 0% for qualifying Free Zone businesses
    """
    if is_free_zone:
        return 0
    if taxable_income <= 375000:
        return 0
    return taxable_income * 0.09

def generate_vat_invoice_pdf(invoice_data):
    """Generate a VAT-compliant invoice PDF"""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    
    # Header
    pdf.cell(0, 10, "TAX INVOICE", 0, 1, 'C')
    pdf.set_font("Arial", '', 12)
    pdf.cell(0, 10, f"Invoice No: {invoice_data['invoice_number']}", 0, 1)
    pdf.cell(0, 10, f"Date: {invoice_data['date']}", 0, 1)
    pdf.cell(0, 10, f"TRN: {invoice_data['company_trn']}", 0, 1)
    pdf.ln(10)
    
    # Seller and Buyer info
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(95, 10, "Seller Information", 0, 0)
    pdf.cell(95, 10, "Buyer Information", 0, 1)
    pdf.set_font("Arial", '', 10)
    
    pdf.cell(95, 6, invoice_data['company_name'], 0, 0)
    pdf.cell(95, 6, invoice_data['customer_name'], 0, 1)
    
    if invoice_data.get('customer_trn'):
        pdf.cell(95, 6, "", 0, 0)
        pdf.cell(95, 6, f"TRN: {invoice_data['customer_trn']}", 0, 1)
    
    pdf.ln(10)
    
    # Items table
    pdf.set_font("Arial", 'B', 10)
    pdf.cell(100, 10, "Description", 1, 0)
    pdf.cell(30, 10, "Quantity", 1, 0, 'C')
    pdf.cell(30, 10, "Unit Price", 1, 0, 'R')
    pdf.cell(30, 10, "Amount", 1, 1, 'R')
    pdf.set_font("Arial", '', 10)
    
    for item in invoice_data['items']:
        pdf.cell(100, 8, item['description'], 1, 0)
        pdf.cell(30, 8, str(item['quantity']), 1, 0, 'C')
        pdf.cell(30, 8, f"AED {item['unit_price']:,.2f}", 1, 0, 'R')
        pdf.cell(30, 8, f"AED {item['amount']:,.2f}", 1, 1, 'R')
    
    # Totals
    pdf.set_font("Arial", 'B', 10)
    pdf.cell(160, 8, "Subtotal:", 1, 0, 'R')
    pdf.cell(30, 8, f"AED {invoice_data['subtotal']:,.2f}", 1, 1, 'R')
    
    pdf.cell(160, 8, f"VAT ({invoice_data['vat_rate']*100}%):", 1, 0, 'R')
    pdf.cell(30, 8, f"AED {invoice_data['vat_amount']:,.2f}", 1, 1, 'R')
    
    pdf.cell(160, 8, "Total Amount:", 1, 0, 'R')
    pdf.cell(30, 8, f"AED {invoice_data['total_amount']:,.2f}", 1, 1, 'R')
    
    # Footer
    pdf.ln(10)
    pdf.set_font("Arial", 'I', 8)
    pdf.cell(0, 6, "Thank you for your business!", 0, 1, 'C')
    pdf.cell(0, 6, "This is a computer-generated invoice. No signature required.", 0, 1, 'C')
    
    return pdf.output(dest='S').encode('latin1')

def generate_vat_return_xml(company_info, vat_data, period):
    """Generate FTA-compliant VAT return XML"""
    root = ET.Element("VATReturn", xmlns="http://www.tax.gov.ae/schemas")
    
    # Company Information
    company = ET.SubElement(root, "Company")
    ET.SubElement(company, "TRN").text = company_info['trn']
    ET.SubElement(company, "Name").text = company_info['name']
    ET.SubElement(company, "Address")
    
    # Return Period
    ET.SubElement(root, "ReturnPeriod").text = period
    
    # Sales
    sales = ET.SubElement(root, "Sales")
    ET.SubElement(sales, "StandardRated").text = str(vat_data['standard_rated_sales'])
    ET.SubElement(sales, "ZeroRated").text = str(vat_data['zero_rated_sales'])
    ET.SubElement(sales, "Exempt").text = str(vat_data['exempt_sales'])
    ET.SubElement(sales, "TotalSales").text = str(vat_data['standard_rated_sales'] + 
                                             vat_data['zero_rated_sales'] + 
                                             vat_data['exempt_sales'])
    
    # Purchases
    purchases = ET.SubElement(root, "Purchases")
    ET.SubElement(purchases, "StandardRated").text = str(vat_data['standard_rated_purchases'])
    ET.SubElement(purchases, "ZeroRated").text = str(vat_data['zero_rated_purchases'])
    ET.SubElement(purchases, "Exempt").text = str(vat_data['exempt_purchases'])
    ET.SubElement(purchases, "TotalPurchases").text = str(vat_data['standard_rated_purchases'] + 
                                                     vat_data['zero_rated_purchases'] + 
                                                     vat_data['exempt_purchases'])
    
    # Tax Calculation
    tax = ET.SubElement(root, "TaxCalculation")
    ET.SubElement(tax, "OutputTax").text = str(vat_data['output_tax'])
    ET.SubElement(tax, "InputTax").text = str(vat_data['input_tax'])
    ET.SubElement(tax, "NetTaxPayable").text = str(vat_data['net_tax_payable'])
    
    # Generate XML string
    xml_str = ET.tostring(root, encoding='unicode', method='xml')
    declaration = '<?xml version="1.0" encoding="UTF-8"?>\n'
    return declaration + xml_str

def generate_corporate_tax_pdf(company_info, tax_data):
    """Generate corporate tax return PDF"""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    
    # Header
    pdf.cell(0, 10, "CORPORATE TAX RETURN", 0, 1, 'C')
    pdf.set_font("Arial", '', 12)
    pdf.cell(0, 10, f"Tax Year: {tax_data['tax_year']}", 0, 1)
    pdf.cell(0, 10, f"Company Name: {company_info['name']}", 0, 1)
    pdf.cell(0, 10, f"TRN: {company_info['trn']}", 0, 1)
    pdf.ln(10)
    
    # Tax Calculation
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "Tax Calculation", 0, 1)
    pdf.set_font("Arial", '', 10)
    
    pdf.cell(100, 8, "Taxable Income:", 1, 0)
    pdf.cell(90, 8, f"AED {tax_data['taxable_income']:,.2f}", 1, 1, 'R')
    
    pdf.cell(100, 8, "Applicable Tax Rate:", 1, 0)
    pdf.cell(90, 8, f"{tax_data['tax_rate']*100}%", 1, 1, 'R')
    
    if company_info['free_zone']:
        pdf.cell(100, 8, "Free Zone Deductions:", 1, 0)
        pdf.cell(90, 8, f"AED {tax_data.get('free_zone_deductions', 0):,.2f}", 1, 1, 'R')
    
    if tax_data.get('tax_credits', 0) > 0:
        pdf.cell(100, 8, "Tax Credits:", 1, 0)
        pdf.cell(90, 8, f"AED {tax_data['tax_credits']:,.2f}", 1, 1, 'R')
    
    pdf.set_font("Arial", 'B', 10)
    pdf.cell(100, 8, "Net Tax Payable:", 1, 0)
    pdf.cell(90, 8, f"AED {tax_data['net_tax_payable']:,.2f}", 1, 1, 'R')
    
    # Footer
    pdf.ln(20)
    pdf.set_font("Arial", 'I', 8)
    pdf.cell(0, 6, "This document is generated by UAE Tax Management System", 0, 1, 'C')
    
    return pdf.output(dest='S')

# =============================================
# DATABASE INITIALIZATION
# =============================================

def init_db():
    os.makedirs('data', exist_ok=True)
    
    conn = sqlite3.connect('data/tax_management.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  role TEXT NOT NULL CHECK(role IN ('admin', 'user', 'accountant')),
                  full_name TEXT,
                  phone TEXT,
                  is_active BOOLEAN DEFAULT 1,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  last_login TIMESTAMP)''')
    
    # Companies table (UAE-specific fields)
    c.execute('''CREATE TABLE IF NOT EXISTS companies
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  name TEXT NOT NULL,
                  trn TEXT UNIQUE CHECK(length(trn) = 15),
                  establishment_date DATE,
                  license_issuance_date DATE,
                  free_zone BOOLEAN DEFAULT 0,
                  free_zone_name TEXT,
                  vat_registered BOOLEAN DEFAULT 0,
                  vat_registration_date DATE,
                  corporate_tax_registered BOOLEAN DEFAULT 0,
                  ct_registration_date DATE,
                  legal_form TEXT CHECK(legal_form IN ('LLC', 'FZCO', 'FZE', 'Branch', 'Other')),
                  financial_year_start DATE,
                  financial_year_end DATE,
                  bank_account TEXT,
                  license_number TEXT,
                  license_expiry DATE,
                  economic_activity TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)''')
    
    # Transactions table (VAT-compliant)
    c.execute('''CREATE TABLE IF NOT EXISTS transactions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  date DATE NOT NULL,
                  description TEXT NOT NULL,
                  amount REAL NOT NULL,
                  vat_amount REAL,
                  type TEXT NOT NULL CHECK(type IN ('sale', 'purchase', 'expense', 'income')),
                  vat_category TEXT NOT NULL CHECK(vat_category IN ('standard', 'zero-rated', 'exempt', 'out-of-scope')),
                  tax_invoice_number TEXT,
                  tax_invoice_date DATE,
                  supplier_trn TEXT,
                  customer_trn TEXT,
                  document BLOB,
                  source TEXT,
                  bank_reference TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE CASCADE)''')
    
    # Invoices table (VAT-compliant)
    c.execute('''CREATE TABLE IF NOT EXISTS invoices
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  invoice_number TEXT NOT NULL,
                  date DATE NOT NULL,
                  customer_name TEXT NOT NULL,
                  customer_trn TEXT,
                  customer_address TEXT,
                  items TEXT NOT NULL,
                  subtotal REAL NOT NULL,
                  vat_amount REAL NOT NULL,
                  total_amount REAL NOT NULL,
                  vat_rate REAL DEFAULT 0.05,
                  payment_status TEXT CHECK(payment_status IN ('paid', 'unpaid', 'partial')),
                  due_date DATE,
                  document BLOB,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE CASCADE)''')
    
    # VAT Returns table
    c.execute('''CREATE TABLE IF NOT EXISTS vat_returns
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  period TEXT NOT NULL,
                  filing_date DATE NOT NULL,
                  status TEXT CHECK(status IN ('draft', 'submitted', 'approved', 'rejected')),
                  standard_rated_sales REAL NOT NULL,
                  zero_rated_sales REAL NOT NULL,
                  exempt_sales REAL NOT NULL,
                  standard_rated_purchases REAL NOT NULL,
                  zero_rated_purchases REAL NOT NULL,
                  exempt_purchases REAL NOT NULL,
                  output_tax REAL NOT NULL,
                  input_tax REAL NOT NULL,
                  net_tax_payable REAL NOT NULL,
                  fta_submission_id TEXT,
                  payment_reference TEXT,
                  xml_data TEXT,
                  pdf_data BLOB,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE CASCADE)''')
    
    # Corporate Tax Returns table
    c.execute('''CREATE TABLE IF NOT EXISTS corporate_tax_returns
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  tax_year TEXT NOT NULL,
                  filing_date DATE NOT NULL,
                  status TEXT CHECK(status IN ('draft', 'submitted', 'approved', 'rejected')),
                  taxable_income REAL NOT NULL,
                  tax_rate REAL NOT NULL,
                  tax_payable REAL NOT NULL,
                  free_zone_deductions REAL,
                  tax_credits REAL,
                  net_tax_payable REAL NOT NULL,
                  fta_submission_id TEXT,
                  payment_reference TEXT,
                  xml_data TEXT,
                  pdf_data BLOB,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE CASCADE)''')
    
    # Bank Statements table
    c.execute('''CREATE TABLE IF NOT EXISTS bank_statements
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company_id INTEGER NOT NULL,
                  bank_name TEXT NOT NULL,
                  account_number TEXT NOT NULL,
                  statement_date DATE NOT NULL,
                  period_start DATE NOT NULL,
                  period_end DATE NOT NULL,
                  opening_balance REAL NOT NULL,
                  closing_balance REAL NOT NULL,
                  currency TEXT NOT NULL DEFAULT 'AED',
                  transactions_count INTEGER,
                  document BLOB,
                  processed BOOLEAN DEFAULT 0,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(company_id) REFERENCES companies(id) ON DELETE CASCADE)''')
    
    # Activity Log table
    c.execute('''CREATE TABLE IF NOT EXISTS activity_log
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  action TEXT NOT NULL,
                  details TEXT,
                  ip_address TEXT,
                  user_agent TEXT,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL)''')
    
    # Add admin user if not exists
    try:
        c.execute("SELECT COUNT(*) FROM users WHERE username='admin'")
        if c.fetchone()[0] == 0:
            hashed_password = hash_password('Admin@1234')
            c.execute("""INSERT INTO users 
                      (username, password, email, role, full_name, phone) 
                      VALUES (?, ?, ?, ?, ?, ?)""",
                     ('admin', hashed_password, 'admin@taxsystem.ae', 'admin', 
                      'System Administrator', '+971501234567'))
        conn.commit()
    except Exception as e:
        conn.rollback()
        st.error(f"Database initialization error: {str(e)}")
    finally:
        conn.close()

# Initialize the database
init_db()

# =============================================
# AUTHENTICATION PAGES
# =============================================

def login_page():
    st.title("🇦🇪 UAE Tax Management System")
    st.markdown("---")
    
    with st.form("login_form"):
        username = st.text_input("Username", placeholder="Enter your username")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        submitted = st.form_submit_button("Login")
        
        if submitted:
            if not username or not password:
                st.error("Please enter both username and password")
                return
            
            try:
                conn = sqlite3.connect('data/tax_management.db')
                c = conn.cursor()
                c.execute("""SELECT id, username, password, role, is_active 
                          FROM users WHERE username=?""", (username,))
                user = c.fetchone()
                
                if user:
                    if not user[4]:  # Check if account is active
                        st.error("This account is inactive. Please contact admin.")
                        return
                        
                    if hash_password(password) == user[2]:
                        st.session_state.user = {
                            'id': user[0],
                            'username': user[1],
                            'role': user[3]
                        }
                        # Update last login
                        c.execute("UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?", (user[0],))
                        conn.commit()
                        log_activity(user[0], "login_success")
                        st.success("Login successful!")
                        st.rerun()
                    else:
                        log_activity(None, "login_failed", f"Failed login attempt for {username}")
                        st.error("Invalid username or password")
                else:
                    log_activity(None, "login_failed", f"Unknown user attempt: {username}")
                    st.error("Invalid username or password")
            except Exception as e:
                st.error(f"Database error: {str(e)}")
            finally:
                conn.close()
    
    # Registration link for new users
    if st.button("New User? Register Here"):
        st.session_state.show_register = True
        st.rerun()

def register_page():
    st.title("👤 New User Registration")
    st.markdown("---")
    
    if st.button("← Back to Login"):
        if 'show_register' in st.session_state:
            del st.session_state.show_register
        st.rerun()
    
    with st.form("register_form", clear_on_submit=True):
        st.subheader("Create Your Account")
        
        col1, col2 = st.columns(2)
        with col1:
            username = st.text_input("Username", placeholder="4-20 alphanumeric characters")
        with col2:
            email = st.text_input("Email", placeholder="your.email@example.com")
        
        col1, col2 = st.columns(2)
        with col1:
            password = st.text_input("Password", type="password", 
                                   placeholder="At least 8 chars with uppercase, lowercase, number, and special char")
        with col2:
            confirm_password = st.text_input("Confirm Password", type="password", 
                                          placeholder="Re-enter your password")
        
        col1, col2 = st.columns(2)
        with col1:
            full_name = st.text_input("Full Name", placeholder="Your full name")
        with col2:
            phone = st.text_input("Phone Number", placeholder="+971501234567")
        
        submitted = st.form_submit_button("Register Account")
        
        if submitted:
            # Validate inputs
            valid = True
            
            # Username validation
            username_valid, username_msg = validate_username(username)
            if not username_valid:
                st.error(username_msg)
                valid = False
            
            # Email validation
            if not validate_email(email):
                st.error("Please enter a valid email address")
                valid = False
            
            # Password validation
            password_valid, password_msg = validate_password(password)
            if not password_valid:
                st.error(password_msg)
                valid = False
            elif password != confirm_password:
                st.error("Passwords do not match")
                valid = False
            
            # Phone validation
            if phone and not validate_phone(phone):
                st.error("Please enter a valid UAE phone number starting with +971")
                valid = False
            
            if valid:
                try:
                    conn = sqlite3.connect('data/tax_management.db')
                    c = conn.cursor()
                    
                    # Check if username or email already exists
                    c.execute("SELECT COUNT(*) FROM users WHERE username=? OR email=?", 
                             (username, email))
                    if c.fetchone()[0] > 0:
                        st.error("Username or email already exists")
                        return
                    
                    # Create new user
                    hashed_password = hash_password(password)
                    c.execute("""INSERT INTO users 
                              (username, password, email, role, full_name, phone) 
                              VALUES (?, ?, ?, 'user', ?, ?)""",
                             (username, hashed_password, email, full_name, phone))
                    conn.commit()
                    
                    # Get the new user ID
                    user_id = c.lastrowid
                    log_activity(user_id, "registration_success")
                    
                    st.success("Registration successful! Please login with your new account.")
                    st.balloons()
                    
                    # Clear form and return to login after 2 seconds
                    st.session_state.register_success = True
                    time.sleep(2)
            
                    
                except sqlite3.Error as e:
                    conn.rollback()
                    log_activity(None, "registration_failed", f"Error: {str(e)}")
                    st.error(f"Registration failed: {str(e)}")
                finally:
                    conn.close()

# =============================================
# ADMIN PANEL
# =============================================

def admin_panel():
    st.sidebar.title("Admin Dashboard")
    st.sidebar.markdown(f"Welcome, **{st.session_state.user['username']}**")
    
    menu_options = ["User Management", "Company Management", "System Logs", "Tax Reports"]
    choice = st.sidebar.selectbox("Menu", menu_options)
    
    if choice == "User Management":
        st.header("👥 User Management")
        
        tab1, tab2 = st.tabs(["All Users", "Add New User"])
        
        with tab1:
            st.subheader("Registered Users")
            
            try:
                conn = sqlite3.connect('data/tax_management.db')
                users = pd.read_sql("SELECT id, username, email, role, full_name, phone, is_active, last_login FROM users", conn)
                
                if not users.empty:
                    # Display active/inactive toggle
                    col1, col2 = st.columns(2)
                    with col1:
                        show_active = st.checkbox("Show active users", value=True)
                    with col2:
                        show_inactive = st.checkbox("Show inactive users", value=False)
                    
                    filtered_users = users.copy()
                    if not show_active:
                        filtered_users = filtered_users[~filtered_users['is_active']]
                    if not show_inactive:
                        filtered_users = filtered_users[filtered_users['is_active']]
                    
                    st.dataframe(filtered_users)
                    
                    # User actions
                    selected_user = st.selectbox("Select user to manage", 
                                               filtered_users['username'].tolist())
                    user_data = filtered_users[filtered_users['username'] == selected_user].iloc[0]
                    
                    with st.form("user_actions_form"):
                        st.write(f"Managing user: **{selected_user}**")
                        
                        new_role = st.selectbox("Role", ["admin", "user", "accountant"], 
                                              index=["admin", "user", "accountant"].index(user_data['role']))
                        is_active = st.checkbox("Active", value=bool(user_data['is_active']))
                        
                        submitted = st.form_submit_button("Update User")
                        if submitted:
                            try:
                                c = conn.cursor()
                                c.execute("""UPDATE users SET role=?, is_active=? WHERE id=?""",
                                         (new_role, is_active, user_data['id']))
                                conn.commit()
                                log_activity(st.session_state.user['id'], "update_user", 
                                           f"Updated user {selected_user} (role: {new_role}, active: {is_active})")
                                st.success("User updated successfully!")
                                st.rerun()
                            except Exception as e:
                                conn.rollback()
                                st.error(f"Error updating user: {str(e)}")
                else:
                    st.info("No users found in the system")
            except Exception as e:
                st.error(f"Error retrieving users: {str(e)}")
            finally:
                conn.close()
        
        with tab2:
            st.subheader("Add New User")
            register_page()
    
    elif choice == "Company Management":
        st.header("🏢 Company Management")
        
        try:
            conn = sqlite3.connect('data/tax_management.db')
            companies = pd.read_sql("SELECT * FROM companies", conn)
            
            if not companies.empty:
                st.dataframe(companies)
            else:
                st.info("No companies registered in the system")
        except Exception as e:
            st.error(f"Error retrieving companies: {str(e)}")
        finally:
            conn.close()
    
    elif choice == "System Logs":
        st.header("📝 System Activity Logs")
        
        try:
            conn = sqlite3.connect('data/tax_management.db')
            logs = pd.read_sql("""SELECT l.timestamp, u.username, l.action, l.details 
                               FROM activity_log l
                               LEFT JOIN users u ON l.user_id = u.id
                               ORDER BY l.timestamp DESC LIMIT 200""", conn)
            
            if not logs.empty:
                st.dataframe(logs)
            else:
                st.info("No activity logs found")
        except Exception as e:
            st.error(f"Error retrieving logs: {str(e)}")
        finally:
            conn.close()
    
    elif choice == "Tax Reports":
        st.header("📊 Tax Reports")
        
        st.subheader("VAT Summary")
        try:
            conn = sqlite3.connect('data/tax_management.db')
            vat_returns = pd.read_sql("""SELECT c.name, c.trn, v.period, v.filing_date, 
                                        v.status, v.net_tax_payable 
                                        FROM vat_returns v
                                        JOIN companies c ON v.company_id = c.id
                                        ORDER BY v.period DESC""", conn)
            
            if not vat_returns.empty:
                st.dataframe(vat_returns)
                
                # VAT summary statistics
                st.subheader("VAT Statistics")
                col1, col2, col3 = st.columns(3)
                with col1:
                    total_vat = vat_returns['net_tax_payable'].sum()
                    st.metric("Total VAT Collected", f"AED {total_vat:,.2f}")
                with col2:
                    avg_vat = vat_returns['net_tax_payable'].mean()
                    st.metric("Average VAT per Return", f"AED {avg_vat:,.2f}")
                with col3:
                    last_period = vat_returns.iloc[0]['period']
                    st.metric("Last Filing Period", last_period)
            else:
                st.info("No VAT returns filed yet")
        except Exception as e:
            st.error(f"Error retrieving VAT returns: {str(e)}")
        finally:
            conn.close()

# =============================================
# USER DASHBOARD
# =============================================

def user_dashboard():
    st.sidebar.title("Tax Dashboard")
    st.sidebar.markdown(f"Welcome, **{st.session_state.user['username']}**")
    
    # Get user's companies
    try:
        conn = sqlite3.connect('data/tax_management.db')
        c = conn.cursor()
        c.execute("SELECT id, name FROM companies WHERE user_id=?", 
                 (st.session_state.user['id'],))
        companies = c.fetchall()
        
        if companies:
            company_names = [company[1] for company in companies]
            selected_company_name = st.sidebar.selectbox("Select Company", company_names)
            selected_company_id = companies[company_names.index(selected_company_name)][0]
            
            # Get company details
            c.execute("""SELECT name, trn, free_zone, vat_registered, corporate_tax_registered 
                      FROM companies WHERE id=?""", (selected_company_id,))
            company_info = c.fetchone()
            company_data = {
                'id': selected_company_id,
                'name': company_info[0],
                'trn': company_info[1],
                'free_zone': company_info[2],
                'vat_registered': company_info[3],
                'corporate_tax_registered': company_info[4]
            }
        else:
            st.sidebar.warning("No companies registered")
            selected_company_id = None
            company_data = None
    except Exception as e:
        st.error(f"Error retrieving companies: {str(e)}")
        selected_company_id = None
        company_data = None
    finally:
        conn.close()
    
    # Main menu options
    menu_options = ["Dashboard", "Company Profile", "Transactions", "Invoices", 
                   "Bank Statements", "VAT Returns", "Corporate Tax", "Reports"]
    
    if not selected_company_id:
        menu_options = ["Dashboard", "Company Profile"]
    
    choice = st.sidebar.selectbox("Menu", menu_options)
    
    if choice == "Dashboard":
        st.header("📊 Dashboard")
        
        if not selected_company_id:
            st.warning("Please register a company to access the dashboard")
            return
        
        # Display key metrics
        try:
            conn = sqlite3.connect('data/tax_management.db')
            
            # Get transaction summary
            transactions = pd.read_sql(f"""SELECT type, SUM(amount) as total_amount, 
                                         SUM(vat_amount) as total_vat 
                                         FROM transactions 
                                         WHERE company_id={selected_company_id}
                                         AND date >= date('now', '-3 months')
                                         GROUP BY type""", conn)
            
            # Get VAT return status
            vat_status = pd.read_sql(f"""SELECT status, COUNT(*) as count 
                                       FROM vat_returns 
                                       WHERE company_id={selected_company_id}
                                       GROUP BY status""", conn)
            
            # Get corporate tax status
            ct_status = pd.read_sql(f"""SELECT status, COUNT(*) as count 
                                      FROM corporate_tax_returns 
                                      WHERE company_id={selected_company_id}
                                      GROUP BY status""", conn)
            
            # Display metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                total_sales = transactions[transactions['type'] == 'sale']['total_amount'].sum()
                st.metric("Total Sales (3 months)", f"AED {total_sales:,.2f}")
            with col2:
                total_purchases = transactions[transactions['type'] == 'purchase']['total_amount'].sum()
                st.metric("Total Purchases (3 months)", f"AED {total_purchases:,.2f}")
            with col3:
                total_vat = transactions['total_vat'].sum()
                st.metric("Total VAT (3 months)", f"AED {total_vat:,.2f}")
            
            # Display charts
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Recent Transactions")
                if not transactions.empty:
                    st.bar_chart(transactions.set_index('type')['total_amount'])
                else:
                    st.info("No transactions found")
            
            with col2:
                st.subheader("Tax Status")
                if not vat_status.empty:
                    st.write("VAT Returns:")
                    st.bar_chart(vat_status.set_index('status')['count'])
                if not ct_status.empty:
                    st.write("Corporate Tax Returns:")
                    st.bar_chart(ct_status.set_index('status')['count'])
            
        except Exception as e:
            st.error(f"Error loading dashboard data: {str(e)}")
        finally:
            conn.close()
    
    elif choice == "Company Profile":
        st.header("🏢 Company Profile")
        
        if not selected_company_id:
            # Register new company form
            with st.form("new_company_form"):
                st.subheader("Register New Company")
                
                col1, col2 = st.columns(2)
                with col1:
                    name = st.text_input("Company Name*", help="Legal name of the company")
                    trn = st.text_input("TRN (Tax Registration Number)*", 
                                      help="15-digit UAE TRN", 
                                      max_chars=15)
                    establishment_date = st.date_input("Establishment Date*")
                    legal_form = st.selectbox("Legal Form*", 
                                           ["LLC", "FZCO", "FZE", "Branch", "Other"])
                with col2:
                    license_number = st.text_input("Trade License Number*")
                    license_expiry = st.date_input("License Expiry Date*")
                    economic_activity = st.text_input("Main Economic Activity*")
                    financial_year_start = st.date_input("Financial Year Start*")
                
                col1, col2 = st.columns(2)
                with col1:
                    free_zone = st.checkbox("Free Zone Company")
                    if free_zone:
                        free_zone_name = st.text_input("Free Zone Name")
                with col2:
                    vat_registered = st.checkbox("VAT Registered")
                    if vat_registered:
                        vat_registration_date = st.date_input("VAT Registration Date")
                
                bank_account = st.text_input("Bank Account Number")
                
                submitted = st.form_submit_button("Register Company")
                
                if submitted:
                    # Validate required fields
                    if not name or not trn or not establishment_date or not legal_form or not license_number:
                        st.error("Please fill all required fields (marked with *)")
                        return
                    
                    if not validate_trn(trn):
                        st.error("Invalid TRN. Must be 15 digits.")
                        return
                    
                    try:
                        conn = sqlite3.connect('data/tax_management.db')
                        c = conn.cursor()
                        
                        # Insert company
                        c.execute("""INSERT INTO companies 
                                  (user_id, name, trn, establishment_date, 
                                   license_issuance_date, free_zone, free_zone_name,
                                   vat_registered, vat_registration_date,
                                   legal_form, license_number, license_expiry,
                                   economic_activity, financial_year_start,
                                   financial_year_end, bank_account)
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                (st.session_state.user['id'], name, trn, 
                                 establishment_date.strftime('%Y-%m-%d'),
                                 establishment_date.strftime('%Y-%m-%d'),  # Using establishment as license date for demo
                                 free_zone, free_zone_name if free_zone else None,
                                 vat_registered, vat_registration_date.strftime('%Y-%m-%d') if vat_registered else None,
                                 legal_form, license_number, 
                                 license_expiry.strftime('%Y-%m-%d'),
                                 economic_activity, 
                                 financial_year_start.strftime('%Y-%m-%d'),
                                 (financial_year_start + timedelta(days=364)).strftime('%Y-%m-%d'),
                                 bank_account))
                        conn.commit()
                        
                        log_activity(st.session_state.user['id'], "company_registration", 
                                    f"Registered company {name}")
                        st.success("Company registered successfully!")
                        st.balloons()
                        st.rerun()
                    except sqlite3.IntegrityError:
                        st.error("A company with this TRN or name already exists")
                    except Exception as e:
                        conn.rollback()
                        st.error(f"Error registering company: {str(e)}")
                    finally:
                        conn.close()
        else:
            # View/Edit existing company
            try:
                conn = sqlite3.connect('data/tax_management.db')
                company = pd.read_sql(f"""SELECT * FROM companies WHERE id={selected_company_id}""", conn).iloc[0]
                
                with st.form("company_form"):
                    st.subheader(f"Company: {company['name']}")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        name = st.text_input("Company Name*", value=company['name'])
                        trn = st.text_input("TRN*", value=company['trn'], max_chars=15)
                        establishment_date = st.date_input("Establishment Date*", 
                                                         value=datetime.strptime(company['establishment_date'], '%Y-%m-%d'))
                        legal_form = st.selectbox("Legal Form*", 
                                               ["LLC", "FZCO", "FZE", "Branch", "Other"],
                                               index=["LLC", "FZCO", "FZE", "Branch", "Other"].index(company['legal_form']))
                    with col2:
                        license_number = st.text_input("Trade License Number*", 
                                                     value=company['license_number'])
                        license_expiry = st.date_input("License Expiry Date*", 
                                                     value=datetime.strptime(company['license_expiry'], '%Y-%m-%d'))
                        economic_activity = st.text_input("Main Economic Activity*", 
                                                         value=company['economic_activity'])
                        financial_year_start = st.date_input("Financial Year Start*", 
                                                           value=datetime.strptime(company['financial_year_start'], '%Y-%m-%d'))
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        free_zone = st.checkbox("Free Zone Company", 
                                              value=bool(company['free_zone']))
                        if free_zone:
                            free_zone_name = st.text_input("Free Zone Name", 
                                                         value=company['free_zone_name'])
                    with col2:
                        vat_registered = st.checkbox("VAT Registered", 
                                                   value=bool(company['vat_registered']))
                        if vat_registered:
                            vat_reg_date = company['vat_registration_date']
                            vat_registration_date = st.date_input("VAT Registration Date", 
                                                                value=datetime.strptime(vat_reg_date, '%Y-%m-%d') if vat_reg_date else datetime.now())
                    
                    bank_account = st.text_input("Bank Account Number", 
                                               value=company['bank_account'])
                    
                    submitted = st.form_submit_button("Update Company")
                    
                    if submitted:
                        # Validate required fields
                        if not name or not trn or not establishment_date or not legal_form or not license_number:
                            st.error("Please fill all required fields (marked with *)")
                            return
                        
                        if not validate_trn(trn):
                            st.error("Invalid TRN. Must be 15 digits.")
                            return
                        
                        try:
                            c = conn.cursor()
                            c.execute("""UPDATE companies SET
                                      name=?, trn=?, establishment_date=?, 
                                      license_issuance_date=?, free_zone=?, free_zone_name=?,
                                      vat_registered=?, vat_registration_date=?,
                                      legal_form=?, license_number=?, license_expiry=?,
                                      economic_activity=?, financial_year_start=?,
                                      financial_year_end=?, bank_account=?
                                      WHERE id=?""",
                                    (name, trn, establishment_date.strftime('%Y-%m-%d'),
                                     establishment_date.strftime('%Y-%m-%d'),  # Using establishment as license date for demo
                                     free_zone, free_zone_name if free_zone else None,
                                     vat_registered, vat_registration_date.strftime('%Y-%m-%d') if vat_registered else None,
                                     legal_form, license_number, 
                                     license_expiry.strftime('%Y-%m-%d'),
                                     economic_activity, 
                                     financial_year_start.strftime('%Y-%m-%d'),
                                     (financial_year_start + timedelta(days=364)).strftime('%Y-%m-%d'),
                                     bank_account, selected_company_id))
                            conn.commit()
                            
                            log_activity(st.session_state.user['id'], "company_update", 
                                       f"Updated company {name}")
                            st.success("Company information updated successfully!")
                            st.rerun()
                        except sqlite3.IntegrityError:
                            st.error("A company with this TRN or name already exists")
                        except Exception as e:
                            conn.rollback()
                            st.error(f"Error updating company: {str(e)}")
            except Exception as e:
                st.error(f"Error loading company data: {str(e)}")
            finally:
                conn.close()
    
    elif choice == "Transactions":
        st.header("💳 Transaction Management")
        
        if not selected_company_id:
            st.warning("Please register a company to manage transactions")
            return
        
        tab1, tab2, tab3 = st.tabs(["Add Transaction", "View Transactions", "Bulk Import"])
        
        with tab1:
            with st.form("transaction_form", clear_on_submit=True):
                st.subheader("Add New Transaction")
                
                col1, col2 = st.columns(2)
                with col1:
                    date = st.date_input("Date*", value=datetime.now())
                    trans_type = st.selectbox("Type*", 
                                           ["sale", "purchase", "expense", "income"])
                    amount = st.number_input("Amount (AED)*", 
                                          min_value=0.0, 
                                          format="%.2f",
                                          step=0.01)
                with col2:
                    vat_category = st.selectbox("VAT Category*", 
                                              ["standard", "zero-rated", "exempt", "out-of-scope"])
                    vat_amount = st.number_input("VAT Amount (AED)", 
                                               min_value=0.0, 
                                               format="%.2f",
                                               step=0.01,
                                               value=calculate_vat(amount) if vat_category == "standard" else 0.0)
                    tax_invoice_number = st.text_input("Tax Invoice Number")
                
                description = st.text_area("Description*")
                
                # Additional fields based on transaction type
                if trans_type == "sale":
                    customer_trn = st.text_input("Customer TRN", max_chars=15)
                    supplier_trn = None
                elif trans_type == "purchase":
                    supplier_trn = st.text_input("Supplier TRN", max_chars=15)
                    customer_trn = None
                else:
                    supplier_trn = None
                    customer_trn = None
                
                document = st.file_uploader("Attach Document", type=["pdf", "jpg", "png"])
                
                submitted = st.form_submit_button("Add Transaction")
                
                if submitted:
                    # Validate required fields
                    if not description or not amount:
                        st.error("Please fill all required fields (marked with *)")
                        return
                    
                    if vat_category == "standard" and vat_amount != calculate_vat(amount):
                        st.warning(f"Standard VAT should be AED {calculate_vat(amount):.2f} for amount AED {amount:.2f}")
                    
                    try:
                        conn = sqlite3.connect('data/tax_management.db')
                        c = conn.cursor()
                        
                        # Insert transaction
                        c.execute("""INSERT INTO transactions 
                                  (company_id, date, description, amount, vat_amount,
                                   type, vat_category, tax_invoice_number, tax_invoice_date,
                                   supplier_trn, customer_trn, document)
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                (selected_company_id, date.strftime('%Y-%m-%d'), 
                                 description, amount, vat_amount,
                                 trans_type, vat_category, tax_invoice_number,
                                 date.strftime('%Y-%m-%d') if tax_invoice_number else None,
                                 supplier_trn, customer_trn,
                                 document.read() if document else None))
                        conn.commit()
                        
                        log_activity(st.session_state.user['id'], "add_transaction", 
                                   f"Added {trans_type} transaction of AED {amount:.2f}")
                        st.success("Transaction added successfully!")
                        st.rerun()
                    except Exception as e:
                        conn.rollback()
                        st.error(f"Error adding transaction: {str(e)}")
                    finally:
                        conn.close()
        
        with tab2:
            st.subheader("Transaction History")
            
            # Filters
            with st.expander("Filters"):
                col1, col2 = st.columns(2)
                with col1:
                    start_date = st.date_input("From Date", 
                                             value=datetime.now() - timedelta(days=30))
                with col2:
                    end_date = st.date_input("To Date", 
                                           value=datetime.now())
                
                col1, col2 = st.columns(2)
                with col1:
                    trans_type_filter = st.selectbox("Transaction Type", 
                                                   ["All", "sale", "purchase", "expense", "income"])
                with col2:
                    vat_category_filter = st.selectbox("VAT Category", 
                                                     ["All", "standard", "zero-rated", "exempt", "out-of-scope"])
            
            try:
                conn = sqlite3.connect('data/tax_management.db')
                
                # Build query
                query = f"""SELECT id, date, description, type, vat_category, 
                           amount, vat_amount, tax_invoice_number 
                           FROM transactions 
                           WHERE company_id={selected_company_id}
                           AND date BETWEEN '{start_date.strftime('%Y-%m-%d')}' 
                           AND '{end_date.strftime('%Y-%m-%d')}'"""
                
                if trans_type_filter != "All":
                    query += f" AND type='{trans_type_filter}'"
                if vat_category_filter != "All":
                    query += f" AND vat_category='{vat_category_filter}'"
                
                query += " ORDER BY date DESC"
                
                transactions = pd.read_sql(query, conn)
                
                if not transactions.empty:
                    # Display summary
                    st.write(f"Found {len(transactions)} transactions")
                    
                    # Group by type and vat category
                    summary = transactions.groupby(['type', 'vat_category'])['amount'].sum().unstack()
                    st.dataframe(summary.style.format("{:,.2f}"))
                    
                    # Show detailed transactions
                    st.subheader("Transaction Details")
                    st.dataframe(transactions)
                    
                    # View transaction details
                    selected_trans_id = st.selectbox("Select transaction to view details", 
                                                   transactions['id'])
                    
                    if selected_trans_id:
                        trans_details = pd.read_sql(f"""SELECT * FROM transactions 
                                                     WHERE id={selected_trans_id}""", conn).iloc[0]
                        
                        with st.expander("Transaction Details", expanded=True):
                            col1, col2 = st.columns(2)
                            with col1:
                                st.write(f"**Date:** {trans_details['date']}")
                                st.write(f"**Type:** {trans_details['type']}")
                                st.write(f"**VAT Category:** {trans_details['vat_category']}")
                                st.write(f"**Amount:** AED {trans_details['amount']:,.2f}")
                            with col2:
                                st.write(f"**VAT Amount:** AED {trans_details['vat_amount']:,.2f}")
                                if trans_details['tax_invoice_number']:
                                    st.write(f"**Tax Invoice No:** {trans_details['tax_invoice_number']}")
                                if trans_details['supplier_trn']:
                                    st.write(f"**Supplier TRN:** {trans_details['supplier_trn']}")
                                if trans_details['customer_trn']:
                                    st.write(f"**Customer TRN:** {trans_details['customer_trn']}")
                            
                            st.write(f"**Description:** {trans_details['description']}")
                            
                            if trans_details['document']:
                                st.download_button(
                                    label="Download Attached Document",
                                    data=trans_details['document'],
                                    file_name=f"transaction_{selected_trans_id}.pdf",
                                    mime="application/pdf"
                                )
                else:
                    st.info("No transactions found for the selected filters")
            except Exception as e:
                st.error(f"Error retrieving transactions: {str(e)}")
            finally:
                conn.close()
        
        with tab3:
            st.subheader("Bulk Import Transactions")
            
            st.info("Download the template file to ensure proper formatting")
            
            # Download template
            template = pd.DataFrame(columns=[
                "date", "description", "type", "amount", "vat_category", 
                "vat_amount", "tax_invoice_number", "supplier_trn", "customer_trn"
            ])
            
            csv = template.to_csv(index=False)
            st.download_button(
                label="Download CSV Template",
                data=csv,
                file_name="transactions_template.csv",
                mime="text/csv"
            )
            
            uploaded_file = st.file_uploader("Upload CSV file", type=["csv"])
            
            if uploaded_file:
                try:
                    df = pd.read_csv(uploaded_file)
                    st.write("Preview of uploaded data:")
                    st.dataframe(df.head())
                    
                    # Validate required columns
                    required_cols = ["date", "description", "type", "amount", "vat_category"]
                    missing_cols = [col for col in required_cols if col not in df.columns]
                    
                    if missing_cols:
                        st.error(f"Missing required columns: {', '.join(missing_cols)}")
                        return
                    
                    if st.button("Import Transactions"):
                        try:
                            conn = sqlite3.connect('data/tax_management.db')
                            c = conn.cursor()
                            
                            imported = 0
                            errors = 0
                            
                            for _, row in df.iterrows():
                                try:
                                    # Validate data
                                    if pd.isna(row['date']) or pd.isna(row['description']) or pd.isna(row['type']) or pd.isna(row['amount']):
                                        errors += 1
                                        continue
                                    
                                    # Calculate VAT if not provided
                                    vat_amount = row['vat_amount'] if 'vat_amount' in row and not pd.isna(row['vat_amount']) else (
                                        calculate_vat(row['amount']) if row['vat_category'] == 'standard' else 0.0
                                    )
                                    
                                    c.execute("""INSERT INTO transactions 
                                              (company_id, date, description, type, 
                                               amount, vat_amount, vat_category,
                                               tax_invoice_number, supplier_trn, customer_trn)
                                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                            (selected_company_id, 
                                             row['date'], 
                                             row['description'], 
                                             row['type'],
                                             float(row['amount']),
                                             float(vat_amount),
                                             row['vat_category'],
                                             row['tax_invoice_number'] if 'tax_invoice_number' in row and not pd.isna(row['tax_invoice_number']) else None,
                                             row['supplier_trn'] if 'supplier_trn' in row and not pd.isna(row['supplier_trn']) else None,
                                             row['customer_trn'] if 'customer_trn' in row and not pd.isna(row['customer_trn']) else None))
                                    imported += 1
                                except Exception as e:
                                    errors += 1
                                    continue
                            
                            conn.commit()
                            log_activity(st.session_state.user['id'], "bulk_import", 
                                       f"Imported {imported} transactions with {errors} errors")
                            
                            st.success(f"Successfully imported {imported} transactions!")
                            if errors > 0:
                                st.warning(f"{errors} records could not be imported due to errors")
                            st.rerun()
                        except Exception as e:
                            conn.rollback()
                            st.error(f"Error during import: {str(e)}")
                        finally:
                            conn.close()
                except Exception as e:
                    st.error(f"Error processing file: {str(e)}")
    
    elif choice == "Invoices":
     st.header("🧾 Invoice Management")
    
     if not selected_company_id:
        st.warning("Please register a company to manage invoices")
        return
    
     tab1, tab2 = st.tabs(["Create Invoice", "Invoice History"])
    
     with tab1:
        with st.form("invoice_form", clear_on_submit=True):
            st.subheader("Create New Invoice")
            
            col1, col2 = st.columns(2)
            with col1:
                invoice_number = st.text_input("Invoice Number*")
                date = st.date_input("Invoice Date*", value=datetime.now())
                due_date = st.date_input("Due Date", value=datetime.now() + timedelta(days=30))
            with col2:
                customer_name = st.text_input("Customer Name*")
                customer_trn = st.text_input("Customer TRN", max_chars=15)
                customer_address = st.text_area("Customer Address")
            
            # Invoice items
            st.subheader("Invoice Items")
            items = []
            
            col1, col2, col3, col4 = st.columns([4, 2, 2, 2])
            with col1:
                st.write("**Description**")
            with col2:
                st.write("**Quantity**")
            with col3:
                st.write("**Unit Price (AED)**")
            with col4:
                st.write("**Amount (AED)**")
            
            for i in range(3):  # Start with 3 empty rows
                col1, col2, col3, col4 = st.columns([4, 2, 2, 2])
                with col1:
                    desc = st.text_input(f"Item {i+1} Description", key=f"desc_{i}")
                with col2:
                    qty = st.number_input(f"Qty", min_value=1, value=1, key=f"qty_{i}")
                with col3:
                    unit_price = st.number_input(f"Price", min_value=0.0, value=0.0, 
                                                format="%.2f", step=0.01, key=f"price_{i}")
                with col4:
                    amount = qty * unit_price
                    st.write(f"{amount:,.2f}")
                    
                    if desc and qty and unit_price:
                        items.append({
                            'description': desc,
                            'quantity': qty,
                            'unit_price': unit_price,
                            'amount': amount
                        })
            
            # Add more items button - moved outside the form
            if st.form_submit_button("Add More Items"):
                st.session_state.invoice_items = items
            
            # Calculate totals
            subtotal = sum(item['amount'] for item in items)
            vat_amount = calculate_vat(subtotal)
            total_amount = subtotal + vat_amount
            
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Subtotal:** AED {subtotal:,.2f}")
                st.write(f"**VAT (5%):** AED {vat_amount:,.2f}")
                st.write(f"**Total Amount:** AED {total_amount:,.2f}")
            
            payment_status = st.selectbox("Payment Status", 
                                       ["unpaid", "paid", "partial"])
            
            document = st.file_uploader("Attach Supporting Document", type=["pdf", "jpg", "png"])
            
            submitted = st.form_submit_button("Create Invoice")
            
            if submitted:
                # Validate required fields
                if not invoice_number or not customer_name or not items:
                    st.error("Please fill all required fields (marked with *)")
                    return
                
                try:
                    conn = sqlite3.connect('data/tax_management.db')
                    c = conn.cursor()
                    
                    # Insert invoice
                    c.execute("""INSERT INTO invoices 
                              (company_id, invoice_number, date, customer_name,
                               customer_trn, customer_address, items, subtotal,
                               vat_amount, total_amount, vat_rate, payment_status,
                               due_date, document)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (selected_company_id, invoice_number, 
                             date.strftime('%Y-%m-%d'), customer_name,
                             customer_trn if customer_trn else None,
                             customer_address if customer_address else None,
                             str(items), subtotal, vat_amount, total_amount,
                             0.05, payment_status,
                             due_date.strftime('%Y-%m-%d') if due_date else None,
                             document.read() if document else None))
                    conn.commit()
                    
                    # Generate PDF invoice
                    company_info = pd.read_sql(f"""SELECT name, trn FROM companies 
                                                WHERE id={selected_company_id}""", conn).iloc[0]
                    
                    invoice_data = {
                        'invoice_number': invoice_number,
                        'date': date.strftime('%Y-%m-%d'),
                        'company_name': company_info['name'],
                        'company_trn': company_info['trn'],
                        'customer_name': customer_name,
                        'customer_trn': customer_trn,
                        'items': items,
                        'subtotal': subtotal,
                        'vat_amount': vat_amount,
                        'total_amount': total_amount,
                        'vat_rate': 0.05
                    }
                    
                    pdf_data = generate_vat_invoice_pdf(invoice_data)
                    
                    # Update invoice with generated PDF
                    c.execute("UPDATE invoices SET document=? WHERE invoice_number=?", 
                            (pdf_data, invoice_number))
                    conn.commit()
                    
                    log_activity(st.session_state.user['id'], "create_invoice", 
                               f"Created invoice {invoice_number} for AED {total_amount:,.2f}")
                    st.success("Invoice created successfully!")
                    st.balloons()
                    st.rerun()
                except sqlite3.IntegrityError:
                    st.error("An invoice with this number already exists")
                except Exception as e:
                    conn.rollback()
                    st.error(f"Error creating invoice: {str(e)}")
                finally:
                    conn.close()
    
     with tab2:
        st.subheader("Invoice History")
        
        # Filters
        with st.expander("Filters"):
            col1, col2 = st.columns(2)
            with col1:
                start_date = st.date_input("From Date", 
                                         value=datetime.now() - timedelta(days=30),
                                         key="inv_start")
            with col2:
                end_date = st.date_input("To Date", 
                                       value=datetime.now(),
                                       key="inv_end")
            
            payment_status_filter = st.selectbox("Payment Status", 
                                               ["All", "paid", "unpaid", "partial"])
        
        try:
            conn = sqlite3.connect('data/tax_management.db')
            
            # Build query
            query = f"""SELECT id, invoice_number, date, customer_name, total_amount, 
                      payment_status, due_date 
                      FROM invoices 
                      WHERE company_id={selected_company_id}
                      AND date BETWEEN '{start_date.strftime('%Y-%m-%d')}' 
                      AND '{end_date.strftime('%Y-%m-%d')}'"""
            
            if payment_status_filter != "All":
                query += f" AND payment_status='{payment_status_filter}'"
            
            query += " ORDER BY date DESC"
            
            invoices = pd.read_sql(query, conn)
            
            if not invoices.empty:
                # Display summary
                st.write(f"Found {len(invoices)} invoices")
                
                # Group by payment status
                summary = invoices.groupby('payment_status')['total_amount'].agg(['count', 'sum'])
                st.dataframe(summary.style.format("{:,.2f}"))
                
                # Show detailed invoices
                st.subheader("Invoice Details")
                st.dataframe(invoices)
                
                # View invoice details
                selected_inv_id = st.selectbox("Select invoice to view details", 
                                            invoices['id'])
                
                if selected_inv_id:
                    inv_details = pd.read_sql(f"""SELECT * FROM invoices 
                                               WHERE id={selected_inv_id}""", conn).iloc[0]
                    
                    with st.expander("Invoice Details", expanded=True):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write(f"**Invoice No:** {inv_details['invoice_number']}")
                            st.write(f"**Date:** {inv_details['date']}")
                            st.write(f"**Customer:** {inv_details['customer_name']}")
                            if inv_details['customer_trn']:
                                st.write(f"**Customer TRN:** {inv_details['customer_trn']}")
                        with col2:
                            st.write(f"**Subtotal:** AED {inv_details['subtotal']:,.2f}")
                            st.write(f"**VAT (5%):** AED {inv_details['vat_amount']:,.2f}")
                            st.write(f"**Total:** AED {inv_details['total_amount']:,.2f}")
                            st.write(f"**Status:** {inv_details['payment_status']}")
                        
                        # Display items
                        st.subheader("Items")
                        try:
                            items = eval(inv_details['items'])  # Convert string to list
                            items_df = pd.DataFrame(items)
                            st.dataframe(items_df)
                        except:
                            st.warning("Could not display items")
                        
                        if inv_details['document']:
                            st.download_button(
                                label="Download Invoice PDF",
                                data=inv_details['document'],
                                file_name=f"invoice_{inv_details['invoice_number']}.pdf",
                                mime="application/pdf"
                            )
            else:
                st.info("No invoices found for the selected filters")
        except Exception as e:
            st.error(f"Error retrieving invoices: {str(e)}")
        finally:
            conn.close()
    
    elif choice == "Bank Statements":
        st.header("🏦 Bank Statement Processing")
        
        if not selected_company_id:
            st.warning("Please register a company to manage bank statements")
            return
        
        tab1, tab2 = st.tabs(["Upload Statement", "Statement History"])
        
        with tab1:
            with st.form("bank_statement_form", clear_on_submit=True):
                st.subheader("Upload Bank Statement")
                
                col1, col2 = st.columns(2)
                with col1:
                    bank_name = st.selectbox("Bank Name*", 
                                          ["Emirates NBD", "Mashreq", "ADCB", "DIB", "RAK Bank", "Other"])
                    account_number = st.text_input("Account Number*")
                    statement_date = st.date_input("Statement Date*", value=datetime.now())
                with col2:
                    period_start = st.date_input("Period Start Date*", 
                                               value=datetime.now() - timedelta(days=30))
                    period_end = st.date_input("Period End Date*", 
                                             value=datetime.now())
                    currency = st.selectbox("Currency*", ["AED", "USD", "EUR"], index=0)
                
                col1, col2 = st.columns(2)
                with col1:
                    opening_balance = st.number_input("Opening Balance*", 
                                                    format="%.2f")
                with col2:
                    closing_balance = st.number_input("Closing Balance*", 
                                                    format="%.2f")
                
                statement_file = st.file_uploader("Statement File*", type=["pdf", "csv"])
                
                submitted = st.form_submit_button("Upload Statement")
                
                if submitted:
                    # Validate required fields
                    if not bank_name or not account_number or not statement_file:
                        st.error("Please fill all required fields (marked with *)")
                        return
                    
                    try:
                        conn = sqlite3.connect('data/tax_management.db')
                        c = conn.cursor()
                        
                        # Insert bank statement
                        c.execute("""INSERT INTO bank_statements 
                                  (company_id, bank_name, account_number, 
                                   statement_date, period_start, period_end,
                                   opening_balance, closing_balance, currency,
                                   document)
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                (selected_company_id, bank_name, account_number,
                                 statement_date.strftime('%Y-%m-%d'),
                                 period_start.strftime('%Y-%m-%d'),
                                 period_end.strftime('%Y-%m-%d'),
                                 opening_balance, closing_balance, currency,
                                 statement_file.read()))
                        conn.commit()
                        
                        log_activity(st.session_state.user['id'], "upload_statement", 
                                   f"Uploaded {bank_name} statement for account {account_number}")
                        st.success("Bank statement uploaded successfully!")
                        st.rerun()
                    except Exception as e:
                        conn.rollback()
                        st.error(f"Error uploading statement: {str(e)}")
                    finally:
                        conn.close()
        
        with tab2:
            st.subheader("Statement History")
            
            try:
                conn = sqlite3.connect('data/tax_management.db')
                statements = pd.read_sql(f"""SELECT id, bank_name, account_number, 
                                           statement_date, period_start, period_end,
                                           opening_balance, closing_balance, currency,
                                           processed 
                                           FROM bank_statements 
                                           WHERE company_id={selected_company_id}
                                           ORDER BY statement_date DESC""", conn)
                
                if not statements.empty:
                    st.dataframe(statements)
                    
                    # View statement details
                    selected_stmt_id = st.selectbox("Select statement to view details", 
                                                  statements['id'])
                    
                    if selected_stmt_id:
                        stmt_details = pd.read_sql(f"""SELECT * FROM bank_statements 
                                                     WHERE id={selected_stmt_id}""", conn).iloc[0]
                        
                        with st.expander("Statement Details", expanded=True):
                            col1, col2 = st.columns(2)
                            with col1:
                                st.write(f"**Bank:** {stmt_details['bank_name']}")
                                st.write(f"**Account No:** {stmt_details['account_number']}")
                                st.write(f"**Statement Date:** {stmt_details['statement_date']}")
                            with col2:
                                st.write(f"**Period:** {stmt_details['period_start']} to {stmt_details['period_end']}")
                                st.write(f"**Currency:** {stmt_details['currency']}")
                                st.write(f"**Processed:** {'Yes' if stmt_details['processed'] else 'No'}")
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                st.write(f"**Opening Balance:** {stmt_details['opening_balance']:,.2f}")
                            with col2:
                                st.write(f"**Closing Balance:** {stmt_details['closing_balance']:,.2f}")
                            
                            if stmt_details['document']:
                                st.download_button(
                                    label="Download Statement",
                                    data=stmt_details['document'],
                                    file_name=f"statement_{stmt_details['bank_name']}_{stmt_details['statement_date']}.pdf",
                                    mime="application/pdf"
                                )
                            
                            if not stmt_details['processed']:
                                if st.button("Process Statement for Transactions"):
                                    try:
                                        c = conn.cursor()
                                        c.execute("""UPDATE bank_statements SET processed=1 
                                                  WHERE id=?""", (selected_stmt_id,))
                                        conn.commit()
                                        
                                        log_activity(st.session_state.user['id'], "process_statement", 
                                                   f"Processed statement {selected_stmt_id}")
                                        st.success("Statement marked as processed!")
                                        st.rerun()
                                    except Exception as e:
                                        conn.rollback()
                                        st.error(f"Error processing statement: {str(e)}")
                else:
                    st.info("No bank statements found")
            except Exception as e:
                st.error(f"Error retrieving statements: {str(e)}")
            finally:
                conn.close()
    
    elif choice == "VAT Returns":
        st.header("📑 VAT Returns")
        
        if not selected_company_id:
            st.warning("Please register a company to manage VAT returns")
            return
        
        if not company_data['vat_registered']:
            st.warning("This company is not VAT registered")
            return
        
        tab1, tab2 = st.tabs(["File New Return","Coming soon.."])
        
        with tab1:
            st.subheader("Prepare VAT Return")
            
            # Get VAT period
            col1, col2 = st.columns(2)
            with col1:
                period_month = st.selectbox("Month", range(1, 13), 
                                         format_func=lambda x: datetime(1900, x, 1).strftime('%B'))
            with col2:
                current_year = datetime.now().year
                period_year = st.selectbox("Year", range(current_year-5, current_year+1))
            
            vat_period = f"{period_year}-{period_month:02d}"
            
            # Check if return already exists
            try:
                conn = sqlite3.connect('data/tax_management.db')
                c = conn.cursor()
                c.execute("""SELECT COUNT(*) FROM vat_returns 
                          WHERE company_id=? AND period=?""", 
                         (selected_company_id, vat_period))
                if c.fetchone()[0] > 0:
                    st.warning(f"A VAT return for {vat_period} already exists")
                    st.stop()
            except Exception as e:
                st.error(f"Error checking existing returns: {str(e)}")
                st.stop()
            finally:
                conn.close()
            
            # Calculate VAT return
            try:
                conn = sqlite3.connect('data/tax_management.db')
                
                # Get transactions for the period
                period_start = f"{period_year}-{period_month:02d}-01"
                if period_month == 12:
                    period_end = f"{period_year}-12-31"
                else:
                    period_end = f"{period_year}-{period_month+1:02d}-01"
                    period_end = (datetime.strptime(period_end, '%Y-%m-%d') - timedelta(days=1)).strftime('%Y-%m-%d')
                
                transactions = pd.read_sql(f"""SELECT type, vat_category, 
                                             SUM(amount) as amount, SUM(vat_amount) as vat_amount 
                                             FROM transactions 
                                             WHERE company_id={selected_company_id}
                                             AND date BETWEEN '{period_start}' AND '{period_end}'
                                             GROUP BY type, vat_category""", conn)
                
                if transactions.empty:
                    st.warning("No transactions found for the selected period")
                    st.stop()
                
                # Calculate VAT figures
                standard_rated_sales = transactions[(transactions['type'] == 'sale') & 
                                                   (transactions['vat_category'] == 'standard')]['amount'].sum()
                zero_rated_sales = transactions[(transactions['type'] == 'sale') & 
                                               (transactions['vat_category'] == 'zero-rated')]['amount'].sum()
                exempt_sales = transactions[(transactions['type'] == 'sale') & 
                                          (transactions['vat_category'] == 'exempt')]['amount'].sum()
                
                standard_rated_purchases = transactions[(transactions['type'] == 'purchase') & 
                                                      (transactions['vat_category'] == 'standard')]['amount'].sum()
                zero_rated_purchases = transactions[(transactions['type'] == 'purchase') & 
                                                  (transactions['vat_category'] == 'zero-rated')]['amount'].sum()
                exempt_purchases = transactions[(transactions['type'] == 'purchase') & 
                                              (transactions['vat_category'] == 'exempt')]['amount'].sum()
                
                output_tax = transactions[(transactions['type'] == 'sale') & 
                                        (transactions['vat_category'] == 'standard')]['vat_amount'].sum()
                input_tax = transactions[(transactions['type'] == 'purchase') & 
                                       (transactions['vat_category'] == 'standard')]['vat_amount'].sum()
                net_tax_payable = output_tax - input_tax
                
                # Display VAT calculation
                st.subheader("VAT Calculation")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.write("**Sales**")
                    st.write(f"Standard Rated: AED {standard_rated_sales:,.2f}")
                    st.write(f"Zero Rated: AED {zero_rated_sales:,.2f}")
                    st.write(f"Exempt: AED {exempt_sales:,.2f}")
                    st.write(f"**Output Tax:** AED {output_tax:,.2f}")
                with col2:
                    st.write("**Purchases**")
                    st.write(f"Standard Rated: AED {standard_rated_purchases:,.2f}")
                    st.write(f"Zero Rated: AED {zero_rated_purchases:,.2f}")
                    st.write(f"Exempt: AED {exempt_purchases:,.2f}")
                    st.write(f"**Input Tax:** AED {input_tax:,.2f}")
                
                st.write(f"**Net VAT Payable:** AED {net_tax_payable:,.2f}", 
                        style="font-size: 18px; font-weight: bold;")
                
                # File return
                if st.button("File VAT Return"):
                    try:
                        # Generate XML
                        vat_data = {
                            'standard_rated_sales': standard_rated_sales,
                            'zero_rated_sales': zero_rated_sales,
                            'exempt_sales': exempt_sales,
                            'standard_rated_purchases': standard_rated_purchases,
                            'zero_rated_purchases': zero_rated_purchases,
                            'exempt_purchases': exempt_purchases,
                            'output_tax': output_tax,
                            'input_tax': input_tax,
                            'net_tax_payable': net_tax_payable
                        }
                        
                        xml_data = generate_vat_return_xml(company_data, vat_data, vat_period)
                        
                        # Insert VAT return
                        c = conn.cursor()
                        c.execute("""INSERT INTO vat_returns 
                                  (company_id, period, filing_date, status,
                                   standard_rated_sales, zero_rated_sales, exempt_sales,
                                   standard_rated_purchases, zero_rated_purchases, exempt_purchases,
                                   output_tax, input_tax, net_tax_payable, xml_data)
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)""",
                                (selected_company_id, vat_period,
                                 datetime.now().strftime('%Y-%m-%d'), 'submitted',
                                 standard_rated_sales, zero_rated_sales, exempt_sales,
                                 standard_rated_purchases, zero_rated_purchases, exempt_purchases,
                                 output_tax, input_tax, net_tax_payable, xml_data))
                        conn.commit()
                        
                        log_activity(st.session_state.user['id'], "file_vat_return", 
                                   f"Filed VAT return for {vat_period}")
                        st.success("VAT return filed successfully!")
                        st.balloons()
                        st.rerun()
                    except Exception as e:
                        conn.rollback()
                        st.error(f"Error filing VAT return: {str(e)}")
            except Exception as e:
                st.error(f"Error calculating VAT: {str(e)}")
            finally:
                conn.close()
    
    elif choice == "Corporate Tax":
        st.header("🏛 Corporate Tax")
        
        if not selected_company_id:
            st.warning("Please register a company to manage corporate tax")
            return
        
        tab1, tab2 = st.tabs(["File New Return", "Return History"])
        
        with tab1:
            st.subheader("Prepare Corporate Tax Return")
            
            # Get tax year
            current_year = datetime.now().year
            tax_year = st.selectbox("Tax Year", range(current_year-5, current_year+1))
            
            # Check if return already exists
            try:
                conn = sqlite3.connect('data/tax_management.db')
                c = conn.cursor()
                c.execute("""SELECT COUNT(*) FROM corporate_tax_returns 
                          WHERE company_id=? AND tax_year=?""", 
                         (selected_company_id, str(tax_year)))
                if c.fetchone()[0] > 0:
                    st.warning(f"A corporate tax return for {tax_year} already exists")
                    st.stop()
            except Exception as e:
                st.error(f"Error checking existing returns: {str(e)}")
                st.stop()
            finally:
                conn.close()
            
            # Calculate corporate tax
            with st.form("ct_calculation_form"):
                st.subheader("Tax Calculation")
                
                taxable_income = st.number_input("Taxable Income (AED)*", 
                                               min_value=0.0, 
                                               format="%.2f",
                                               step=1000.0)
                
                # Free zone deductions
                if company_data['free_zone']:
                    free_zone_deductions = st.number_input("Free Zone Deductions (AED)", 
                                                          min_value=0.0, 
                                                          format="%.2f",
                                                          step=1000.0,
                                                          value=0.0)
                    taxable_income_after_deductions = max(0, taxable_income - free_zone_deductions)
                else:
                    free_zone_deductions = 0.0
                    taxable_income_after_deductions = taxable_income
                
                # Tax credits
                tax_credits = st.number_input("Tax Credits (AED)", 
                                            min_value=0.0, 
                                            format="%.2f",
                                            step=1000.0,
                                            value=0.0)
                
                # Calculate tax
                tax_amount = calculate_corporate_tax(taxable_income_after_deductions, 
                                                   company_data['free_zone'])
                net_tax_payable = max(0, tax_amount - tax_credits)
                
                # Display calculation
                st.write(f"**Taxable Income:** AED {taxable_income:,.2f}")
                
                if company_data['free_zone']:
                    st.write(f"**Free Zone Deductions:** AED {free_zone_deductions:,.2f}")
                    st.write(f"**Taxable Income After Deductions:** AED {taxable_income_after_deductions:,.2f}")
                
                st.write(f"**Corporate Tax ({'0%' if company_data['free_zone'] else '9%'}):** AED {tax_amount:,.2f}")
                
                if tax_credits > 0:
                    st.write(f"**Tax Credits:** AED {tax_credits:,.2f}")
                
                st.write(f"**Net Tax Payable:** AED {net_tax_payable:,.2f}", 
                        style="font-size: 18px; font-weight: bold;")
                
                submitted = st.form_submit_button("File Corporate Tax Return")
                
                if submitted:
                    if taxable_income <= 0:
                        st.error("Taxable income must be greater than 0")
                        return
                    
                    try:
                        # Generate PDF
                        tax_data = {
                            'tax_year': str(tax_year),
                            'taxable_income': taxable_income,
                            'free_zone_deductions': free_zone_deductions,
                            'tax_rate': 0.0 if company_data['free_zone'] else 0.09,
                            'tax_payable': tax_amount,
                            'tax_credits': tax_credits,
                            'net_tax_payable': net_tax_payable
                        }
                        
                        pdf_data = generate_corporate_tax_pdf(company_data, tax_data)
                        
                        # Insert corporate tax return
                        conn = sqlite3.connect('data/tax_management.db')
                        c = conn.cursor()
                        c.execute("""INSERT INTO corporate_tax_returns 
                                  (company_id, tax_year, filing_date, status,
                                   taxable_income, tax_rate, tax_payable,
                                   free_zone_deductions, tax_credits, net_tax_payable,
                                   pdf_data)
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                (selected_company_id, str(tax_year), 
                                 datetime.now().strftime('%Y-%m-%d'), 'submitted',
                                 taxable_income, 0.0 if company_data['free_zone'] else 0.09,
                                 tax_amount, free_zone_deductions, tax_credits,
                                 net_tax_payable, pdf_data))
                        conn.commit()
                        
                        log_activity(st.session_state.user['id'], "file_ct_return", 
                                   f"Filed corporate tax return for {tax_year}")
                        st.success("Corporate tax return filed successfully!")
                        st.balloons()
                        st.rerun()
                    except Exception as e:
                        conn.rollback()
                        st.error(f"Error filing corporate tax return: {str(e)}")
                    finally:
                        conn.close()
        
        with tab2:
            st.subheader("Corporate Tax Return History")
            
            try:
                conn = sqlite3.connect('data/tax_management.db')
                returns = pd.read_sql(f"""SELECT id, tax_year, filing_date, status,
                                        taxable_income, tax_payable, net_tax_payable,
                                        fta_submission_id 
                                        FROM corporate_tax_returns 
                                        WHERE company_id={selected_company_id}
                                        ORDER BY tax_year DESC""", conn)
                
                if not returns.empty:
                    st.dataframe(returns)
                    
                    # View return details
                    selected_return_id = st.selectbox("Select return to view details", 
                                                    returns['id'])
                    
                    if selected_return_id:
                        return_details = pd.read_sql(f"""SELECT * FROM corporate_tax_returns 
                                                        WHERE id={selected_return_id}""", conn).iloc[0]
                        
                        with st.expander("Return Details", expanded=True):
                            st.write(f"**Tax Year:** {return_details['tax_year']}")
                            st.write(f"**Filing Date:** {return_details['filing_date']}")
                            st.write(f"**Status:** {return_details['status']}")
                            
                            st.write(f"**Taxable Income:** AED {return_details['taxable_income']:,.2f}")
                            
                            if company_data['free_zone']:
                                st.write(f"**Free Zone Deductions:** AED {return_details['free_zone_deductions']:,.2f}")
                                st.write(f"**Taxable Income After Deductions:** AED {return_details['taxable_income'] - return_details['free_zone_deductions']:,.2f}")
                            
                            st.write(f"**Corporate Tax Rate:** {return_details['tax_rate']*100}%")
                            st.write(f"**Tax Payable:** AED {return_details['tax_payable']:,.2f}")
                            
                            if return_details['tax_credits'] > 0:
                                st.write(f"**Tax Credits:** AED {return_details['tax_credits']:,.2f}")
                            
                            st.write(f"**Net Tax Payable:** AED {return_details['net_tax_payable']:,.2f}", 
                                    style="font-size: 18px; font-weight: bold;")
                            
                            if return_details['pdf_data']:
                                st.download_button(
                                    label="Download Corporate Tax Return PDF",
                                    data=return_details['pdf_data'],
                                    file_name=f"corporate_tax_{return_details['tax_year']}.pdf",
                                    mime="application/pdf"
                                )
                else:
                    st.info("No corporate tax returns filed yet")
            except Exception as e:
                st.error(f"Error retrieving corporate tax returns: {str(e)}")
            finally:
                conn.close()
    
    elif choice == "Reports":
        st.header("📊 Reports")
        
        if not selected_company_id:
            st.warning("Please register a company to view reports")
            return
        
        report_type = st.selectbox("Select Report Type", 
                                 ["Transaction Summary", "VAT Summary", 
                                  "Corporate Tax Summary", "Financial Overview"])
        
        if report_type == "Transaction Summary":
            st.subheader("Transaction Summary Report")
            
            # Filters
            with st.expander("Filters"):
                col1, col2 = st.columns(2)
                with col1:
                    start_date = st.date_input("From Date", 
                                             value=datetime.now() - timedelta(days=90),
                                             key="trans_start")
                with col2:
                    end_date = st.date_input("To Date", 
                                           value=datetime.now(),
                                           key="trans_end")
                
                trans_type = st.selectbox("Transaction Type", 
                                        ["All", "sale", "purchase", "expense", "income"])
                vat_category = st.selectbox("VAT Category", 
                                          ["All", "standard", "zero-rated", "exempt", "out-of-scope"])
            
            try:
                conn = sqlite3.connect('data/tax_management.db')
                
                # Build query
                query = f"""SELECT date, type, vat_category, description, amount, vat_amount 
                          FROM transactions 
                          WHERE company_id={selected_company_id}
                          AND date BETWEEN '{start_date.strftime('%Y-%m-%d')}' 
                          AND '{end_date.strftime('%Y-%m-%d')}'"""
                
                if trans_type != "All":
                    query += f" AND type='{trans_type}'"
                if vat_category != "All":
                    query += f" AND vat_category='{vat_category}'"
                
                query += " ORDER BY date"
                
                transactions = pd.read_sql(query, conn)
                
                if not transactions.empty:
                    # Summary statistics
                    st.subheader("Summary Statistics")
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        total_amount = transactions['amount'].sum()
                        st.metric("Total Amount", f"AED {total_amount:,.2f}")
                    with col2:
                        total_vat = transactions['vat_amount'].sum()
                        st.metric("Total VAT", f"AED {total_vat:,.2f}")
                    with col3:
                        count = len(transactions)
                        st.metric("Transaction Count", count)
                    
                    # Grouped analysis
                    st.subheader("Analysis by Type and VAT Category")
                    
                    grouped = transactions.groupby(['type', 'vat_category'])['amount'].agg(['count', 'sum'])
                    st.dataframe(grouped.style.format("{:,.2f}"))
                    
                    # Monthly trend
                    st.subheader("Monthly Trend")
                    
                    monthly = transactions.copy()
                    monthly['month'] = pd.to_datetime(monthly['date']).dt.to_period('M')
                    monthly_trend = monthly.groupby('month')['amount'].sum().reset_index()
                    monthly_trend['month'] = monthly_trend['month'].astype(str)
                    
                    st.line_chart(monthly_trend.set_index('month'))
                    
                    # Detailed transactions
                    st.subheader("Detailed Transactions")
                    st.dataframe(transactions)
                    
                    # Export options
                    st.subheader("Export Report")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("Export to CSV"):
                            csv = transactions.to_csv(index=False)
                            st.download_button(
                                label="Download CSV",
                                data=csv,
                                file_name=f"transactions_{start_date}_{end_date}.csv",
                                mime="text/csv"
                            )
                   
                else:
                    st.info("No transactions found for the selected filters")
            except Exception as e:
                st.error(f"Error generating report: {str(e)}")
            finally:
                conn.close()
        
        elif report_type == "VAT Summary":
            st.subheader("VAT Summary Report")
            
            try:
                conn = sqlite3.connect('data/tax_management.db')
                vat_returns = pd.read_sql(f"""SELECT period, filing_date, status,
                                            standard_rated_sales, zero_rated_sales, exempt_sales,
                                            standard_rated_purchases, zero_rated_purchases, exempt_purchases,
                                            output_tax, input_tax, net_tax_payable 
                                            FROM vat_returns 
                                            WHERE company_id={selected_company_id}
                                            ORDER BY period DESC""", conn)
                
                if not vat_returns.empty:
                    # Summary statistics
                    st.subheader("VAT Summary")
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        total_vat = vat_returns['net_tax_payable'].sum()
                        st.metric("Total VAT Payable", f"AED {total_vat:,.2f}")
                    with col2:
                        avg_vat = vat_returns['net_tax_payable'].mean()
                        st.metric("Average VAT per Return", f"AED {avg_vat:,.2f}")
                    with col3:
                        last_period = vat_returns.iloc[0]['period']
                        st.metric("Last Filing Period", last_period)
                    
                    # VAT trend
                    st.subheader("VAT Trend Over Time")
                    
                    vat_trend = vat_returns[['period', 'output_tax', 'input_tax', 'net_tax_payable']]
                    vat_trend = vat_trend.set_index('period')
                    st.line_chart(vat_trend)
                    
                    # Detailed returns
                    st.subheader("Detailed VAT Returns")
                    st.dataframe(vat_returns)
                    
                    # Export options
                    st.subheader("Export Report")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("Export to CSV", key="vat_csv"):
                            csv = vat_returns.to_csv(index=False)
                            st.download_button(
                                label="Download CSV",
                                data=csv,
                                file_name="vat_summary.csv",
                                mime="text/csv"
                            )
                    with col2:
                        if st.button("Export to Excel", key="vat_excel"):
                            excel = vat_returns.to_excel(index=False)
                            st.download_button(
                                label="Download Excel",
                                data=excel,
                                file_name="vat_summary.xlsx",
                                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                            )
                else:
                    st.info("No VAT returns filed yet")
            except Exception as e:
                st.error(f"Error generating report: {str(e)}")
            finally:
                conn.close()
        
        elif report_type == "Corporate Tax Summary":
            st.subheader("Corporate Tax Summary Report")
            
            try:
                conn = sqlite3.connect('data/tax_management.db')
                ct_returns = pd.read_sql(f"""SELECT tax_year, filing_date, status,
                                           taxable_income, tax_rate, tax_payable,
                                           free_zone_deductions, tax_credits, net_tax_payable
                                           FROM corporate_tax_returns 
                                           WHERE company_id={selected_company_id}
                                           ORDER BY tax_year DESC""", conn)
                
                if not ct_returns.empty:
                    # Summary statistics
                    st.subheader("Corporate Tax Summary")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        total_tax = ct_returns['net_tax_payable'].sum()
                        st.metric("Total Tax Payable", f"AED {total_tax:,.2f}")
                    with col2:
                        avg_tax = ct_returns['net_tax_payable'].mean()
                        st.metric("Average Tax per Year", f"AED {avg_tax:,.2f}")
                    
                    # Tax trend
                    st.subheader("Tax Trend Over Years")
                    
                    tax_trend = ct_returns[['tax_year', 'taxable_income', 'net_tax_payable']]
                    tax_trend = tax_trend.set_index('tax_year')
                    st.bar_chart(tax_trend)
                    
                    # Detailed returns
                    st.subheader("Detailed Corporate Tax Returns")
                    st.dataframe(ct_returns)
                    
                    # Export options
                    st.subheader("Export Report")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("Export to CSV", key="ct_csv"):
                            csv = ct_returns.to_csv(index=False)
                            st.download_button(
                                label="Download CSV",
                                data=csv,
                                file_name="corporate_tax_summary.csv",
                                mime="text/csv"
                            )
                    
                else:
                    st.info("No corporate tax returns filed yet")
            except Exception as e:
                st.error(f"Error generating report: {str(e)}")
            finally:
                conn.close()
        
        elif report_type == "Financial Overview":
            st.subheader("Financial Overview Report")
            
            # Filters
            with st.expander("Filters"):
                col1, col2 = st.columns(2)
                with col1:
                    start_date = st.date_input("From Date", 
                                             value=datetime.now() - timedelta(days=365),
                                             key="fin_start")
                with col2:
                    end_date = st.date_input("To Date", 
                                           value=datetime.now(),
                                           key="fin_end")
            
            try:
                conn = sqlite3.connect('data/tax_management.db')
                
                # Get transactions
                transactions = pd.read_sql(f"""SELECT date, type, amount 
                                            FROM transactions 
                                            WHERE company_id={selected_company_id}
                                            AND date BETWEEN '{start_date.strftime('%Y-%m-%d')}' 
                                            AND '{end_date.strftime('%Y-%m-%d')}'
                                            ORDER BY date""", conn)
                
                if transactions.empty:
                    st.info("No transactions found for the selected period")
                    return
                
                # Process data
                transactions['date'] = pd.to_datetime(transactions['date'])
                transactions['month'] = transactions['date'].dt.to_period('M')
                
                # Income vs Expenses
                st.subheader("Income vs Expenses")
                
                income = transactions[transactions['type'].isin(['sale', 'income'])].groupby('month')['amount'].sum()
                expenses = transactions[transactions['type'].isin(['purchase', 'expense'])].groupby('month')['amount'].sum()
                
                financials = pd.DataFrame({
                    'Income': income,
                    'Expenses': expenses
                }).reset_index()
                financials['month'] = financials['month'].astype(str)
                financials['Profit'] = financials['Income'] - financials['Expenses']
                
                st.line_chart(financials.set_index('month')[['Income', 'Expenses', 'Profit']])
                
                # Monthly breakdown
                st.subheader("Monthly Breakdown")
                st.dataframe(financials.set_index('month').style.format("{:,.2f}"))
                
                # Category breakdown
                st.subheader("Category Breakdown")
                
                category = transactions.groupby('type')['amount'].sum()
                st.bar_chart(category)
                
                # Export options
                st.subheader("Export Report")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Export to CSV", key="fin_csv"):
                        csv = financials.to_csv(index=False)
                        st.download_button(
                            label="Download CSV",
                            data=csv,
                            file_name="financial_overview.csv",
                            mime="text/csv"
                        )
               
            except Exception as e:
                st.error(f"Error generating report: {str(e)}")
            finally:
                conn.close()
    
    # Logout button
    if st.sidebar.button("🚪 Logout"):
        log_activity(st.session_state.user['id'], "logout")
        del st.session_state.user
        st.rerun()

# =============================================
# MAIN APP
# =============================================

def main():
    st.set_page_config(
        page_title="UAE Tax Management",
        page_icon="🇦🇪",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Custom CSS
    st.markdown("""
        <style>
            .stTextInput input, .stPassword input {
                padding: 10px !important;
            }
            .stButton button {
                width: 100%;
                padding: 10px;
                border-radius: 5px;
            }
            .stAlert {
                border-radius: 10px;
            }
            .st-b7 {
                color: #ffffff !important;
            }
            .st-bb {
                background-color: #0e4f7a;
            }
            .st-c0 {
                background-color: #0e4f7a;
            }
            .css-1v3fvcr {
                padding: 1rem;
            }
        </style>
    """, unsafe_allow_html=True)
    
    if 'user' not in st.session_state:
        if st.session_state.get('show_register'):
            register_page()
        else:
            login_page()
    else:
        if st.session_state.user.get('role') == 'admin':
            admin_panel()
        else:
            user_dashboard()

if __name__ == "__main__":
    main()

