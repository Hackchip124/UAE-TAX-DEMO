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
import tempfile
import csv

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
        if conn:
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
    
    return pdf.output(dest='S').encode('latin1')

def generate_csv_report(data, filename):
    """Generate CSV report from data"""
    output = BytesIO()
    if isinstance(data, pd.DataFrame):
        data.to_csv(output, index=False)
    else:
        writer = csv.writer(output)
        writer.writerows(data)
    output.seek(0)
    return output

# =============================================
# DATABASE INITIALIZATION
# =============================================

def init_db():
    os.makedirs('data', exist_ok=True)
    
    conn = None
    try:
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
                      branch TEXT,
                      cost_center TEXT,
                      project TEXT,
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
                      branch TEXT,
                      project TEXT,
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
        
        # Contacts table (Customers/Suppliers)
        c.execute('''CREATE TABLE IF NOT EXISTS contacts
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      company_id INTEGER NOT NULL,
                      name TEXT NOT NULL,
                      type TEXT CHECK(type IN ('customer', 'supplier', 'employee')),
                      trn TEXT,
                      phone TEXT,
                      email TEXT,
                      address TEXT,
                      is_active BOOLEAN DEFAULT 1,
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
        if conn:
            conn.rollback()
        st.error(f"Database initialization error: {str(e)}")
    finally:
        if conn:
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
            
            conn = None
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
                if conn:
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
                conn = None
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
                    st.rerun()
                    
                except sqlite3.Error as e:
                    if conn:
                        conn.rollback()
                    log_activity(None, "registration_failed", f"Error: {str(e)}")
                    st.error(f"Registration failed: {str(e)}")
                finally:
                    if conn:
                        conn.close()

# =============================================
# ADMIN PANEL
# =============================================

def admin_panel():
    st.sidebar.title("Admin Dashboard")
    st.sidebar.markdown(f"Welcome, **{st.session_state.user['username']}**")
    
    menu_options = ["User Management", "Company Management", "System Logs", "Tax Reports", "System Settings"]
    choice = st.sidebar.selectbox("Menu", menu_options)
    
    if choice == "User Management":
        st.header("👥 User Management")
        
        tab1, tab2 = st.tabs(["All Users", "Add New User"])
        
        with tab1:
            st.subheader("Registered Users")
            
            conn = None
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
                if conn:
                    conn.close()
        
        with tab2:
            st.subheader("Add New User")
            register_page()
    
    elif choice == "Company Management":
        st.header("🏢 Company Management")
        
        conn = None
        try:
            conn = sqlite3.connect('data/tax_management.db')
            companies = pd.read_sql("SELECT * FROM companies", conn)
            
            if not companies.empty:
                st.dataframe(companies)
                
                # Export companies data
                st.subheader("Export Data")
                if st.button("Export Companies to CSV"):
                    csv = companies.to_csv(index=False)
                    st.download_button(
                        label="Download CSV",
                        data=csv,
                        file_name="companies.csv",
                        mime="text/csv"
                    )
            else:
                st.info("No companies registered in the system")
        except Exception as e:
            st.error(f"Error retrieving companies: {str(e)}")
        finally:
            if conn:
                conn.close()
    
    elif choice == "System Logs":
        st.header("📝 System Activity Logs")
        
        conn = None
        try:
            conn = sqlite3.connect('data/tax_management.db')
            logs = pd.read_sql("""SELECT l.timestamp, u.username, l.action, l.details 
                               FROM activity_log l
                               LEFT JOIN users u ON l.user_id = u.id
                               ORDER BY l.timestamp DESC LIMIT 200""", conn)
            
            if not logs.empty:
                st.dataframe(logs)
                
                # Export logs
                st.subheader("Export Logs")
                if st.button("Export Logs to CSV"):
                    csv = logs.to_csv(index=False)
                    st.download_button(
                        label="Download CSV",
                        data=csv,
                        file_name="activity_logs.csv",
                        mime="text/csv"
                    )
            else:
                st.info("No activity logs found")
        except Exception as e:
            st.error(f"Error retrieving logs: {str(e)}")
        finally:
            if conn:
                conn.close()
    
    elif choice == "Tax Reports":
        st.header("📊 Tax Reports")
        
        tab1, tab2 = st.tabs(["VAT Reports", "Corporate Tax Reports"])
        
        with tab1:
            st.subheader("VAT Summary")
            conn = None
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
                    
                    # Export VAT data
                    st.subheader("Export Data")
                    if st.button("Export VAT Returns to CSV"):
                        csv = vat_returns.to_csv(index=False)
                        st.download_button(
                            label="Download CSV",
                            data=csv,
                            file_name="vat_returns.csv",
                            mime="text/csv"
                        )
                else:
                    st.info("No VAT returns filed yet")
            except Exception as e:
                st.error(f"Error retrieving VAT returns: {str(e)}")
            finally:
                if conn:
                    conn.close()
        
        with tab2:
            st.subheader("Corporate Tax Summary")
            conn = None
            try:
                conn = sqlite3.connect('data/tax_management.db')
                ct_returns = pd.read_sql("""SELECT c.name, c.trn, ct.tax_year, ct.filing_date, 
                                          ct.status, ct.net_tax_payable 
                                          FROM corporate_tax_returns ct
                                          JOIN companies c ON ct.company_id = c.id
                                          ORDER BY ct.tax_year DESC""", conn)
                
                if not ct_returns.empty:
                    st.dataframe(ct_returns)
                    
                    # CT summary statistics
                    st.subheader("Corporate Tax Statistics")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        total_ct = ct_returns['net_tax_payable'].sum()
                        st.metric("Total CT Collected", f"AED {total_ct:,.2f}")
                    with col2:
                        avg_ct = ct_returns['net_tax_payable'].mean()
                        st.metric("Average CT per Return", f"AED {avg_ct:,.2f}")
                    with col3:
                        last_year = ct_returns.iloc[0]['tax_year']
                        st.metric("Last Filing Year", last_year)
                    
                    # Export CT data
                    st.subheader("Export Data")
                    if st.button("Export CT Returns to CSV"):
                        csv = ct_returns.to_csv(index=False)
                        st.download_button(
                            label="Download CSV",
                            data=csv,
                            file_name="corporate_tax_returns.csv",
                            mime="text/csv"
                        )
                else:
                    st.info("No corporate tax returns filed yet")
            except Exception as e:
                st.error(f"Error retrieving corporate tax returns: {str(e)}")
            finally:
                if conn:
                    conn.close()
    
    elif choice == "System Settings":
        st.header("⚙️ System Settings")
        
        with st.form("system_settings"):
            st.subheader("Application Settings")
            
            # Demo settings - in a real app these would be stored in the database
            app_name = st.text_input("Application Name", value="UAE Tax Management System")
            default_currency = st.selectbox("Default Currency", ["AED", "USD", "EUR"], index=0)
            vat_rate = st.number_input("Default VAT Rate (%)", min_value=0.0, max_value=100.0, value=5.0)
            
            submitted = st.form_submit_button("Save Settings")
            if submitted:
                st.success("Settings saved successfully!")

# =============================================
# USER DASHBOARD
# =============================================

def user_dashboard():
    st.sidebar.title("Tax Dashboard")
    st.sidebar.markdown(f"Welcome, **{st.session_state.user['username']}**")
    
    # Get user's companies
    conn = None
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
        if conn:
            conn.close()
    
    # Main menu options
    menu_options = ["Dashboard", "Company Profile", "Transactions", "Invoices", 
                   "Bank Statements", "Contacts", "VAT Returns", "Corporate Tax", 
                   "Financial Statements", "Reports", "Settings"]
    
    if not selected_company_id:
        menu_options = ["Dashboard", "Company Profile"]
    
    choice = st.sidebar.selectbox("Menu", menu_options)
    
    if choice == "Dashboard":
        st.header("📊 Dashboard")
        
        if not selected_company_id:
            st.warning("Please register a company to access the dashboard")
            return
        
        # Display key metrics
        conn = None
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
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                total_sales = transactions[transactions['type'] == 'sale']['total_amount'].sum()
                st.metric("Total Sales (3 months)", f"AED {total_sales:,.2f}")
            with col2:
                total_purchases = transactions[transactions['type'] == 'purchase']['total_amount'].sum()
                st.metric("Total Purchases (3 months)", f"AED {total_purchases:,.2f}")
            with col3:
                total_expenses = transactions[transactions['type'] == 'expense']['total_amount'].sum()
                st.metric("Total Expenses (3 months)", f"AED {total_expenses:,.2f}")
            with col4:
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
            
            # Recent activity
            st.subheader("Recent Activity")
            try:
                activity = pd.read_sql(f"""SELECT a.timestamp, a.action, a.details 
                                         FROM activity_log a
                                         WHERE a.user_id={st.session_state.user['id']}
                                         ORDER BY a.timestamp DESC
                                         LIMIT 10""", conn)
                if not activity.empty:
                    st.dataframe(activity)
                else:
                    st.info("No recent activity")
            except:
                st.warning("Could not load activity log")
            
        except Exception as e:
            st.error(f"Error loading dashboard data: {str(e)}")
        finally:
            if conn:
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
                    
                    conn = None
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
                        if conn:
                            conn.rollback()
                        st.error(f"Error registering company: {str(e)}")
                    finally:
                        if conn:
                            conn.close()
        else:
            # View/Edit existing company
            conn = None
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
                            if conn:
                                conn.rollback()
                            st.error(f"Error updating company: {str(e)}")
            except Exception as e:
                st.error(f"Error loading company data: {str(e)}")
            finally:
                if conn:
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
                
                # Additional dimensions
                col1, col2, col3 = st.columns(3)
                with col1:
                    branch = st.text_input("Branch")
                with col2:
                    cost_center = st.text_input("Cost Center")
                with col3:
                    project = st.text_input("Project")
                
                document = st.file_uploader("Attach Document", type=["pdf", "jpg", "png"])
                
                submitted = st.form_submit_button("Add Transaction")
                
                if submitted:
                    # Validate required fields
                    if not description or not amount:
                        st.error("Please fill all required fields (marked with *)")
                        return
                    
                    if vat_category == "standard" and vat_amount != calculate_vat(amount):
                        st.warning(f"Standard VAT should be AED {calculate_vat(amount):.2f} for amount AED {amount:.2f}")
                    
                    conn = None
                    try:
                        conn = sqlite3.connect('data/tax_management.db')
                        c = conn.cursor()
                        
                        # Insert transaction
                        c.execute("""INSERT INTO transactions 
                                  (company_id, date, description, amount, vat_amount,
                                   type, vat_category, tax_invoice_number, tax_invoice_date,
                                   supplier_trn, customer_trn, document, branch, cost_center, project)
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                (selected_company_id, date.strftime('%Y-%m-%d'), 
                                 description, amount, vat_amount,
                                 trans_type, vat_category, tax_invoice_number,
                                 date.strftime('%Y-%m-%d') if tax_invoice_number else None,
                                 supplier_trn, customer_trn,
                                 document.read() if document else None,
                                 branch, cost_center, project))
                        conn.commit()
                        
                        log_activity(st.session_state.user['id'], "add_transaction", 
                                   f"Added {trans_type} transaction of AED {amount:.2f}")
                        st.success("Transaction added successfully!")
                        st.rerun()
                    except Exception as e:
                        if conn:
                            conn.rollback()
                        st.error(f"Error adding transaction: {str(e)}")
                    finally:
                        if conn:
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
            
            conn = None
            try:
                conn = sqlite3.connect('data/tax_management.db')
                
                # Build query
                query = f"""SELECT id, date, description, type, vat_category, 
                           amount, vat_amount, tax_invoice_number, branch, cost_center, project 
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
                    
                    # Export transactions
                    st.subheader("Export Transactions")
                    csv = transactions.to_csv(index=False)
                    st.download_button(
                        label="Download Transactions CSV",
                        data=csv,
                        file_name="transactions.csv",
                        mime="text/csv"
                    )
                    
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
                            
                            if trans_details['branch']:
                                st.write(f"**Branch:** {trans_details['branch']}")
                            if trans_details['cost_center']:
                                st.write(f"**Cost Center:** {trans_details['cost_center']}")
                            if trans_details['project']:
                                st.write(f"**Project:** {trans_details['project']}")
                            
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
                if conn:
                    conn.close()
        
        with tab3:
            st.subheader("Bulk Import Transactions")
            
            st.info("Download the template file to ensure proper formatting")
            
            # Download template
            template = pd.DataFrame(columns=[
                "date", "description", "type", "amount", "vat_category", 
                "vat_amount", "tax_invoice_number", "supplier_trn", "customer_trn",
                "branch", "cost_center", "project"
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
                        conn = None
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
                                               tax_invoice_number, supplier_trn, customer_trn,
                                               branch, cost_center, project)
                                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                            (selected_company_id, 
                                             row['date'], 
                                             row['description'], 
                                             row['type'],
                                             float(row['amount']),
                                             float(vat_amount),
                                             row['vat_category'],
                                             row['tax_invoice_number'] if 'tax_invoice_number' in row and not pd.isna(row['tax_invoice_number']) else None,
                                             row['supplier_trn'] if 'supplier_trn' in row and not pd.isna(row['supplier_trn']) else None,
                                             row['customer_trn'] if 'customer_trn' in row and not pd.isna(row['customer_trn']) else None,
                                             row['branch'] if 'branch' in row and not pd.isna(row['branch']) else None,
                                             row['cost_center'] if 'cost_center' in row and not pd.isna(row['cost_center']) else None,
                                             row['project'] if 'project' in row and not pd.isna(row['project']) else None))
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
                            if conn:
                                conn.rollback()
                            st.error(f"Error during import: {str(e)}")
                        finally:
                            if conn:
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
                
                # Additional dimensions
                col1, col2 = st.columns(2)
                with col1:
                    branch = st.text_input("Branch")
                with col2:
                    project = st.text_input("Project")
                
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
                    
                    conn = None
                    try:
                        conn = sqlite3.connect('data/tax_management.db')
                        c = conn.cursor()
                        
                        # Insert invoice
                        c.execute("""INSERT INTO invoices 
                                  (company_id, invoice_number, date, customer_name,
                                   customer_trn, customer_address, items, subtotal,
                                   vat_amount, total_amount, vat_rate, payment_status,
                                   due_date, document, branch, project)
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                (selected_company_id, invoice_number, 
                                 date.strftime('%Y-%m-%d'), customer_name,
                                 customer_trn if customer_trn else None,
                                 customer_address if customer_address else None,
                                 str(items), subtotal, vat_amount, total_amount,
                                 0.05, payment_status,
                                 due_date.strftime('%Y-%m-%d') if due_date else None,
                                 document.read() if document else None,
                                 branch, project))
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
                        if conn:
                            conn.rollback()
                        st.error(f"Error creating invoice: {str(e)}")
                    finally:
                        if conn:
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
            
            conn = None
            try:
                conn = sqlite3.connect('data/tax_management.db')
                
                # Build query
                query = f"""SELECT id, invoice_number, date, customer_name, total_amount, 
                          payment_status, due_date, branch, project 
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
                    
                    # Export invoices
                    st.subheader("Export Invoices")
                    csv = invoices.to_csv(index=False)
                    st.download_button(
                        label="Download Invoices CSV",
                        data=csv,
                        file_name="invoices.csv",
                        mime="text/csv"
                    )
                    
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
                            
                            if inv_details['branch']:
                                st.write(f"**Branch:** {inv_details['branch']}")
                            if inv_details['project']:
                                st.write(f"**Project:** {inv_details['project']}")
                            
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
                if conn:
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
                    
                    conn = None
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
                        if conn:
                            conn.rollback()
                        st.error(f"Error uploading statement: {str(e)}")
                    finally:
                        if conn:
                            conn.close()
        
        with tab2:
            st.subheader("Statement History")
            
            conn = None
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
                    
                    # Export statements
                    st.subheader("Export Statements")
                    csv = statements.to_csv(index=False)
                    st.download_button(
                        label="Download Statements CSV",
                        data=csv,
                        file_name="bank_statements.csv",
                        mime="text/csv"
                    )
                    
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
                                        if conn:
                                            conn.rollback()
                                        st.error(f"Error processing statement: {str(e)}")
                else:
                    st.info("No bank statements found")
            except Exception as e:
                st.error(f"Error retrieving statements: {str(e)}")
            finally:
                if conn:
                    conn.close()
    
    elif choice == "Contacts":
        st.header("📇 Contact Management")
        
        if not selected_company_id:
            st.warning("Please register a company to manage contacts")
            return
        
        tab1, tab2 = st.tabs(["Add Contact", "View Contacts"])
        
        with tab1:
            with st.form("contact_form", clear_on_submit=True):
                st.subheader("Add New Contact")
                
                col1, col2 = st.columns(2)
                with col1:
                    name = st.text_input("Name*")
                    contact_type = st.selectbox("Type*", 
                                              ["customer", "supplier", "employee"])
                with col2:
                    trn = st.text_input("TRN", max_chars=15)
                    phone = st.text_input("Phone", placeholder="+971501234567")
                
                email = st.text_input("Email")
                address = st.text_area("Address")
                
                submitted = st.form_submit_button("Add Contact")
                
                if submitted:
                    # Validate required fields
                    if not name or not contact_type:
                        st.error("Please fill all required fields (marked with *)")
                        return
                    
                    if trn and not validate_trn(trn):
                        st.error("Invalid TRN. Must be 15 digits.")
                        return
                    
                    if phone and not validate_phone(phone):
                        st.error("Please enter a valid UAE phone number starting with +971")
                        return
                    
                    conn = None
                    try:
                        conn = sqlite3.connect('data/tax_management.db')
                        c = conn.cursor()
                        
                        # Insert contact
                        c.execute("""INSERT INTO contacts 
                                  (company_id, name, type, trn, phone, email, address)
                                  VALUES (?, ?, ?, ?, ?, ?, ?)""",
                                (selected_company_id, name, contact_type,
                                 trn if trn else None,
                                 phone if phone else None,
                                 email if email else None,
                                 address if address else None))
                        conn.commit()
                        
                        log_activity(st.session_state.user['id'], "add_contact", 
                                   f"Added {contact_type} contact: {name}")
                        st.success("Contact added successfully!")
                        st.rerun()
                    except Exception as e:
                        if conn:
                            conn.rollback()
                        st.error(f"Error adding contact: {str(e)}")
                    finally:
                        if conn:
                            conn.close()
        
        with tab2:
            st.subheader("Contact List")
            
            # Filters
            with st.expander("Filters"):
                contact_type_filter = st.selectbox("Filter by Type", 
                                                ["All", "customer", "supplier", "employee"])
                
            conn = None
            try:
                conn = sqlite3.connect('data/tax_management.db')
                
                # Build query
                query = f"""SELECT id, name, type, trn, phone, email, address 
                          FROM contacts 
                          WHERE company_id={selected_company_id}"""
                
                if contact_type_filter != "All":
                    query += f" AND type='{contact_type_filter}'"
                
                query += " ORDER BY name"
                
                contacts = pd.read_sql(query, conn)
                
                if not contacts.empty:
                    st.dataframe(contacts)
                    
                    # Export contacts
                    st.subheader("Export Contacts")
                    csv = contacts.to_csv(index=False)
                    st.download_button(
                        label="Download Contacts CSV",
                        data=csv,
                        file_name="contacts.csv",
                        mime="text/csv"
                    )
                    
                    # View contact details
                    selected_contact_id = st.selectbox("Select contact to view details", 
                                                     contacts['id'])
                    
                    if selected_contact_id:
                        contact_details = pd.read_sql(f"""SELECT * FROM contacts 
                                                       WHERE id={selected_contact_id}""", conn).iloc[0]
                        
                        with st.expander("Contact Details", expanded=True):
                            col1, col2 = st.columns(2)
                            with col1:
                                st.write(f"**Name:** {contact_details['name']}")
                                st.write(f"**Type:** {contact_details['type']}")
                                if contact_details['trn']:
                                    st.write(f"**TRN:** {contact_details['trn']}")
                            with col2:
                                if contact_details['phone']:
                                    st.write(f"**Phone:** {contact_details['phone']}")
                                if contact_details['email']:
                                    st.write(f"**Email:** {contact_details['email']}")
                            
                            if contact_details['address']:
                                st.write(f"**Address:** {contact_details['address']}")
                else:
                    st.info("No contacts found for the selected filters")
            except Exception as e:
                st.error(f"Error retrieving contacts: {str(e)}")
            finally:
                if conn:
                    conn.close()
    
    elif choice == "VAT Returns":
        st.header("🧾 VAT Return Management")
        
        if not selected_company_id:
            st.warning("Please register a company to manage VAT returns")
            return
        
        if not company_data['vat_registered']:
            st.warning("This company is not VAT registered. Update company profile to enable VAT features.")
            return
        
        tab1, tab2 = st.tabs(["File VAT Return", "VAT Return History"])
        
        with tab1:
            st.subheader("Prepare VAT Return")
            
            # Select period
            col1, col2 = st.columns(2)
            with col1:
                period_type = st.selectbox("Period Type", ["Monthly", "Quarterly"])
            with col2:
                if period_type == "Monthly":
                    period = st.date_input("Select Month", value=datetime.now()).strftime("%Y-%m")
                else:
                    quarter = st.selectbox("Select Quarter", ["Q1", "Q2", "Q3", "Q4"])
                    year = st.selectbox("Year", [datetime.now().year, datetime.now().year-1])
                    period = f"{year}-{quarter}"
            
            if st.button("Calculate VAT"):
                conn = None
                try:
                    conn = sqlite3.connect('data/tax_management.db')
                    
                    # Calculate sales
                    sales = pd.read_sql(f"""SELECT vat_category, SUM(amount) as amount, SUM(vat_amount) as vat
                                        FROM transactions 
                                        WHERE company_id={selected_company_id}
                                        AND type='sale'
                                        AND date BETWEEN date('{period}-01', 'start of month') 
                                        AND date('{period}-01', 'start of month', '+1 month', '-1 day')
                                        GROUP BY vat_category""", conn)
                    
                    # Calculate purchases
                    purchases = pd.read_sql(f"""SELECT vat_category, SUM(amount) as amount, SUM(vat_amount) as vat
                                            FROM transactions 
                                            WHERE company_id={selected_company_id}
                                            AND type='purchase'
                                            AND date BETWEEN date('{period}-01', 'start of month') 
                                            AND date('{period}-01', 'start of month', '+1 month', '-1 day')
                                            GROUP BY vat_category""", conn)
                    
                    # Initialize VAT data
                    vat_data = {
                        'standard_rated_sales': 0.0,
                        'zero_rated_sales': 0.0,
                        'exempt_sales': 0.0,
                        'standard_rated_purchases': 0.0,
                        'zero_rated_purchases': 0.0,
                        'exempt_purchases': 0.0,
                        'output_tax': 0.0,
                        'input_tax': 0.0,
                        'net_tax_payable': 0.0
                    }
                    
                    # Process sales
                    if not sales.empty:
                        for _, row in sales.iterrows():
                            if row['vat_category'] == 'standard':
                                vat_data['standard_rated_sales'] = row['amount']
                                vat_data['output_tax'] = row['vat']
                            elif row['vat_category'] == 'zero-rated':
                                vat_data['zero_rated_sales'] = row['amount']
                            elif row['vat_category'] == 'exempt':
                                vat_data['exempt_sales'] = row['amount']
                    
                    # Process purchases
                    if not purchases.empty:
                        for _, row in purchases.iterrows():
                            if row['vat_category'] == 'standard':
                                vat_data['standard_rated_purchases'] = row['amount']
                                vat_data['input_tax'] = row['vat']
                            elif row['vat_category'] == 'zero-rated':
                                vat_data['zero_rated_purchases'] = row['amount']
                            elif row['vat_category'] == 'exempt':
                                vat_data['exempt_purchases'] = row['amount']
                    
                    # Calculate net tax
                    vat_data['net_tax_payable'] = vat_data['output_tax'] - vat_data['input_tax']
                    
                    # Display VAT return
                    st.subheader("VAT Return Summary")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**Sales**")
                        st.write(f"Standard Rated: AED {vat_data['standard_rated_sales']:,.2f}")
                        st.write(f"Zero Rated: AED {vat_data['zero_rated_sales']:,.2f}")
                        st.write(f"Exempt: AED {vat_data['exempt_sales']:,.2f}")
                        st.write(f"**Output Tax:** AED {vat_data['output_tax']:,.2f}")
                    with col2:
                        st.write("**Purchases**")
                        st.write(f"Standard Rated: AED {vat_data['standard_rated_purchases']:,.2f}")
                        st.write(f"Zero Rated: AED {vat_data['zero_rated_purchases']:,.2f}")
                        st.write(f"Exempt: AED {vat_data['exempt_purchases']:,.2f}")
                        st.write(f"**Input Tax:** AED {vat_data['input_tax']:,.2f}")
                    
                    st.write(f"**Net VAT Payable:** AED {vat_data['net_tax_payable']:,.2f}")
                    
                    # Generate XML and PDF
                    company_info = pd.read_sql(f"""SELECT name, trn FROM companies 
                                                WHERE id={selected_company_id}""", conn).iloc[0]
                    
                    # Save to session for submission
                    st.session_state.vat_data = vat_data
                    st.session_state.vat_period = period
                    
                except Exception as e:
                    st.error(f"Error calculating VAT: {str(e)}")
                finally:
                    if conn:
                        conn.close()
            
            # Submit VAT return
            if 'vat_data' in st.session_state:
                if st.button("Submit VAT Return"):
                    conn = None
                    try:
                        conn = sqlite3.connect('data/tax_management.db')
                        c = conn.cursor()
                        
                        # Insert VAT return
                        c.execute("""INSERT INTO vat_returns 
                                    (company_id, period, filing_date, status,
                                     standard_rated_sales, zero_rated_sales, exempt_sales,
                                     standard_rated_purchases, zero_rated_purchases, exempt_purchases,
                                     output_tax, input_tax, net_tax_payable)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                 (selected_company_id, st.session_state.vat_period,
                                  datetime.now().strftime('%Y-%m-%d'), 'submitted',
                                  st.session_state.vat_data['standard_rated_sales'],
                                  st.session_state.vat_data['zero_rated_sales'],
                                  st.session_state.vat_data['exempt_sales'],
                                  st.session_state.vat_data['standard_rated_purchases'],
                                  st.session_state.vat_data['zero_rated_purchases'],
                                  st.session_state.vat_data['exempt_purchases'],
                                  st.session_state.vat_data['output_tax'],
                                  st.session_state.vat_data['input_tax'],
                                  st.session_state.vat_data['net_tax_payable']))
                        conn.commit()
                        
                        # Generate XML
                        company_info = pd.read_sql(f"""SELECT name, trn FROM companies 
                                                    WHERE id={selected_company_id}""", conn).iloc[0]
                        
                        xml_data = generate_vat_return_xml(
                            {'name': company_info['name'], 'trn': company_info['trn']},
                            st.session_state.vat_data,
                            st.session_state.vat_period
                        )
                        
                        # Generate PDF
                        pdf = FPDF()
                        pdf.add_page()
                        pdf.set_font("Arial", 'B', 16)
                        pdf.cell(0, 10, "VAT Return Summary", 0, 1, 'C')
                        pdf.set_font("Arial", '', 12)
                        pdf.cell(0, 10, f"Company: {company_info['name']}", 0, 1)
                        pdf.cell(0, 10, f"TRN: {company_info['trn']}", 0, 1)
                        pdf.cell(0, 10, f"Period: {st.session_state.vat_period}", 0, 1)
                        pdf.ln(10)
                        
                        # Add VAT data to PDF
                        pdf.set_font("Arial", 'B', 12)
                        pdf.cell(0, 10, "VAT Return Details", 0, 1)
                        pdf.set_font("Arial", '', 10)
                        
                        pdf.cell(100, 8, "Standard Rated Sales:", 1, 0)
                        pdf.cell(90, 8, f"AED {st.session_state.vat_data['standard_rated_sales']:,.2f}", 1, 1, 'R')
                        
                        pdf.cell(100, 8, "Zero Rated Sales:", 1, 0)
                        pdf.cell(90, 8, f"AED {st.session_state.vat_data['zero_rated_sales']:,.2f}", 1, 1, 'R')
                        
                        pdf.cell(100, 8, "Exempt Sales:", 1, 0)
                        pdf.cell(90, 8, f"AED {st.session_state.vat_data['exempt_sales']:,.2f}", 1, 1, 'R')
                        
                        pdf.cell(100, 8, "Standard Rated Purchases:", 1, 0)
                        pdf.cell(90, 8, f"AED {st.session_state.vat_data['standard_rated_purchases']:,.2f}", 1, 1, 'R')
                        
                        pdf.cell(100, 8, "Zero Rated Purchases:", 1, 0)
                        pdf.cell(90, 8, f"AED {st.session_state.vat_data['zero_rated_purchases']:,.2f}", 1, 1, 'R')
                        
                        pdf.cell(100, 8, "Exempt Purchases:", 1, 0)
                        pdf.cell(90, 8, f"AED {st.session_state.vat_data['exempt_purchases']:,.2f}", 1, 1, 'R')
                        
                        pdf.cell(100, 8, "Output Tax:", 1, 0)
                        pdf.cell(90, 8, f"AED {st.session_state.vat_data['output_tax']:,.2f}", 1, 1, 'R')
                        
                        pdf.cell(100, 8, "Input Tax:", 1, 0)
                        pdf.cell(90, 8, f"AED {st.session_state.vat_data['input_tax']:,.2f}", 1, 1, 'R')
                        
                        pdf.set_font("Arial", 'B', 10)
                        pdf.cell(100, 8, "Net VAT Payable:", 1, 0)
                        pdf.cell(90, 8, f"AED {st.session_state.vat_data['net_tax_payable']:,.2f}", 1, 1, 'R')
                        
                        pdf_data = pdf.output(dest='S').encode('latin1')
                        
                        # Update VAT return with generated documents
                        return_id = c.lastrowid
                        c.execute("""UPDATE vat_returns SET xml_data=?, pdf_data=? 
                                  WHERE id=?""", (xml_data, pdf_data, return_id))
                        conn.commit()
                        
                        log_activity(st.session_state.user['id'], "submit_vat_return", 
                                   f"Submitted VAT return for {st.session_state.vat_period}")
                        st.success("VAT return submitted successfully!")
                        del st.session_state.vat_data
                        del st.session_state.vat_period
                        st.rerun()
                    except Exception as e:
                        if conn:
                            conn.rollback()
                        st.error(f"Error submitting VAT return: {str(e)}")
                    finally:
                        if conn:
                            conn.close()
        
        with tab2:
            st.subheader("VAT Return History")
            
            conn = None
            try:
                conn = sqlite3.connect('data/tax_management.db')
                returns = pd.read_sql(f"""SELECT id, period, filing_date, status,
                                         net_tax_payable, fta_submission_id, payment_reference
                                         FROM vat_returns 
                                         WHERE company_id={selected_company_id}
                                         ORDER BY period DESC""", conn)
                
                if not returns.empty:
                    st.dataframe(returns)
                    
                    # Export returns
                    st.subheader("Export Returns")
                    csv = returns.to_csv(index=False)
                    st.download_button(
                        label="Download VAT Returns CSV",
                        data=csv,
                        file_name="vat_returns.csv",
                        mime="text/csv"
                    )
                    
                    # View return details
                    selected_return_id = st.selectbox("Select return to view details", 
                                                    returns['id'])
                    
                    if selected_return_id:
                        return_details = pd.read_sql(f"""SELECT * FROM vat_returns 
                                                      WHERE id={selected_return_id}""", conn).iloc[0]
                        
                        with st.expander("Return Details", expanded=True):
                            col1, col2 = st.columns(2)
                            with col1:
                                st.write(f"**Period:** {return_details['period']}")
                                st.write(f"**Filing Date:** {return_details['filing_date']}")
                                st.write(f"**Status:** {return_details['status']}")
                            with col2:
                                st.write(f"**Output Tax:** AED {return_details['output_tax']:,.2f}")
                                st.write(f"**Input Tax:** AED {return_details['input_tax']:,.2f}")
                                st.write(f"**Net Tax Payable:** AED {return_details['net_tax_payable']:,.2f}")
                            
                            if return_details['fta_submission_id']:
                                st.write(f"**FTA Submission ID:** {return_details['fta_submission_id']}")
                            if return_details['payment_reference']:
                                st.write(f"**Payment Reference:** {return_details['payment_reference']}")
                            
                            if return_details['pdf_data']:
                                st.download_button(
                                    label="Download VAT Return PDF",
                                    data=return_details['pdf_data'],
                                    file_name=f"vat_return_{return_details['period']}.pdf",
                                    mime="application/pdf"
                                )
                            
                            if return_details['xml_data']:
                                st.download_button(
                                    label="Download VAT Return XML",
                                    data=return_details['xml_data'],
                                    file_name=f"vat_return_{return_details['period']}.xml",
                                    mime="application/xml"
                                )
                else:
                    st.info("No VAT returns filed yet")
            except Exception as e:
                st.error(f"Error retrieving VAT returns: {str(e)}")
            finally:
                if conn:
                    conn.close()
    
    elif choice == "Corporate Tax":
        st.header("🏢 Corporate Tax Management")
        
        if not selected_company_id:
            st.warning("Please register a company to manage corporate tax")
            return
        
        if not company_data['corporate_tax_registered']:
            st.warning("This company is not registered for corporate tax. Update company profile to enable CT features.")
            return
        
        tab1, tab2 = st.tabs(["File Corporate Tax Return", "CT Return History"])
        
        with tab1:
            st.subheader("Prepare Corporate Tax Return")
            
            # Select tax year
            current_year = datetime.now().year
            tax_year = st.selectbox("Tax Year", 
                                  [f"{current_year-1}-{current_year}", 
                                   f"{current_year-2}-{current_year-1}"])
            
            if st.button("Calculate Corporate Tax"):
                conn = None
                try:
                    conn = sqlite3.connect('data/tax_management.db')
                    
                    # Calculate taxable income (simplified for demo)
                    # In a real system, this would involve proper accounting calculations
                    income = pd.read_sql(f"""SELECT SUM(amount) as total 
                                          FROM transactions 
                                          WHERE company_id={selected_company_id}
                                          AND type IN ('sale', 'income')
                                          AND date BETWEEN date('{tax_year[:4]}-06-01') 
                                          AND date('{tax_year[5:]}-05-31')""", conn).iloc[0]['total'] or 0.0
                    
                    expenses = pd.read_sql(f"""SELECT SUM(amount) as total 
                                            FROM transactions 
                                            WHERE company_id={selected_company_id}
                                            AND type IN ('purchase', 'expense')
                                            AND date BETWEEN date('{tax_year[:4]}-06-01') 
                                            AND date('{tax_year[5:]}-05-31')""", conn).iloc[0]['total'] or 0.0
                    
                    taxable_income = income - expenses
                    tax_payable = calculate_corporate_tax(taxable_income, company_data['free_zone'])
                    
                    # Prepare tax data
                    tax_data = {
                        'tax_year': tax_year,
                        'taxable_income': taxable_income,
                        'tax_rate': 0.09 if taxable_income > 375000 else 0.0,
                        'tax_payable': tax_payable,
                        'free_zone_deductions': 0.0 if not company_data['free_zone'] else max(0, taxable_income - 375000) * 0.09,
                        'tax_credits': 0.0,
                        'net_tax_payable': tax_payable
                    }
                    
                    # Display tax calculation
                    st.subheader("Corporate Tax Calculation")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Total Income:** AED {income:,.2f}")
                        st.write(f"**Total Expenses:** AED {expenses:,.2f}")
                        st.write(f"**Taxable Income:** AED {taxable_income:,.2f}")
                    with col2:
                        st.write(f"**Applicable Tax Rate:** {tax_data['tax_rate']*100:.1f}%")
                        if company_data['free_zone']:
                            st.write(f"**Free Zone Deductions:** AED {tax_data['free_zone_deductions']:,.2f}")
                        st.write(f"**Tax Payable:** AED {tax_payable:,.2f}")
                    
                    # Save to session for submission
                    st.session_state.tax_data = tax_data
                    
                except Exception as e:
                    st.error(f"Error calculating corporate tax: {str(e)}")
                finally:
                    if conn:
                        conn.close()
            
            # Submit corporate tax return
            if 'tax_data' in st.session_state:
                if st.button("Submit Corporate Tax Return"):
                    conn = None
                    try:
                        conn = sqlite3.connect('data/tax_management.db')
                        c = conn.cursor()
                        
                        # Insert corporate tax return
                        c.execute("""INSERT INTO corporate_tax_returns 
                                    (company_id, tax_year, filing_date, status,
                                     taxable_income, tax_rate, tax_payable,
                                     free_zone_deductions, tax_credits, net_tax_payable)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                 (selected_company_id, st.session_state.tax_data['tax_year'],
                                  datetime.now().strftime('%Y-%m-%d'), 'submitted',
                                  st.session_state.tax_data['taxable_income'],
                                  st.session_state.tax_data['tax_rate'],
                                  st.session_state.tax_data['tax_payable'],
                                  st.session_state.tax_data['free_zone_deductions'],
                                  st.session_state.tax_data['tax_credits'],
                                  st.session_state.tax_data['net_tax_payable']))
                        conn.commit()
                        
                        # Generate PDF
                        company_info = pd.read_sql(f"""SELECT name, trn, free_zone FROM companies 
                                                    WHERE id={selected_company_id}""", conn).iloc[0]
                        
                        pdf_data = generate_corporate_tax_pdf(
                            {'name': company_info['name'], 'trn': company_info['trn'], 'free_zone': company_info['free_zone']},
                            st.session_state.tax_data
                        )
                        
                        # Update corporate tax return with generated PDF
                        return_id = c.lastrowid
                        c.execute("""UPDATE corporate_tax_returns SET pdf_data=? 
                                  WHERE id=?""", (pdf_data, return_id))
                        conn.commit()
                        
                        log_activity(st.session_state.user['id'], "submit_corporate_tax", 
                                   f"Submitted corporate tax return for {st.session_state.tax_data['tax_year']}")
                        st.success("Corporate tax return submitted successfully!")
                        del st.session_state.tax_data
                        st.rerun()
                    except Exception as e:
                        if conn:
                            conn.rollback()
                        st.error(f"Error submitting corporate tax return: {str(e)}")
                    finally:
                        if conn:
                            conn.close()
        
        with tab2:
            st.subheader("Corporate Tax Return History")
            
            conn = None
            try:
                conn = sqlite3.connect('data/tax_management.db')
                returns = pd.read_sql(f"""SELECT id, tax_year, filing_date, status,
                                         taxable_income, tax_rate, tax_payable,
                                         net_tax_payable, fta_submission_id, payment_reference
                                         FROM corporate_tax_returns 
                                         WHERE company_id={selected_company_id}
                                         ORDER BY tax_year DESC""", conn)
                
                if not returns.empty:
                    st.dataframe(returns)
                    
                    # Export returns
                    st.subheader("Export Returns")
                    csv = returns.to_csv(index=False)
                    st.download_button(
                        label="Download CT Returns CSV",
                        data=csv,
                        file_name="corporate_tax_returns.csv",
                        mime="text/csv"
                    )
                    
                    # View return details
                    selected_return_id = st.selectbox("Select return to view details", 
                                                    returns['id'])
                    
                    if selected_return_id:
                        return_details = pd.read_sql(f"""SELECT * FROM corporate_tax_returns 
                                                      WHERE id={selected_return_id}""", conn).iloc[0]
                        
                        with st.expander("Return Details", expanded=True):
                            col1, col2 = st.columns(2)
                            with col1:
                                st.write(f"**Tax Year:** {return_details['tax_year']}")
                                st.write(f"**Filing Date:** {return_details['filing_date']}")
                                st.write(f"**Status:** {return_details['status']}")
                            with col2:
                                st.write(f"**Taxable Income:** AED {return_details['taxable_income']:,.2f}")
                                st.write(f"**Tax Rate:** {return_details['tax_rate']*100:.1f}%")
                                st.write(f"**Tax Payable:** AED {return_details['tax_payable']:,.2f}")
                            
                            if return_details['free_zone_deductions']:
                                st.write(f"**Free Zone Deductions:** AED {return_details['free_zone_deductions']:,.2f}")
                            if return_details['tax_credits']:
                                st.write(f"**Tax Credits:** AED {return_details['tax_credits']:,.2f}")
                            
                            st.write(f"**Net Tax Payable:** AED {return_details['net_tax_payable']:,.2f}")
                            
                            if return_details['fta_submission_id']:
                                st.write(f"**FTA Submission ID:** {return_details['fta_submission_id']}")
                            if return_details['payment_reference']:
                                st.write(f"**Payment Reference:** {return_details['payment_reference']}")
                            
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
                if conn:
                    conn.close()
    
    elif choice == "Financial Statements":
        st.header("📊 Financial Statements")
        
        if not selected_company_id:
            st.warning("Please register a company to view financial statements")
            return
        
        tab1, tab2, tab3 = st.tabs(["Income Statement", "Balance Sheet", "Cash Flow"])
        
        with tab1:
            st.subheader("Income Statement")
            
            # Select period
            col1, col2 = st.columns(2)
            with col1:
                period_type = st.selectbox("Period Type", ["Monthly", "Quarterly", "Annual"], key="inc_period")
            with col2:
                if period_type == "Monthly":
                    period = st.date_input("Select Month", value=datetime.now(), key="inc_month").strftime("%Y-%m")
                    start_date = datetime.strptime(period + "-01", "%Y-%m-%d")
                    end_date = (start_date + timedelta(days=32)).replace(day=1) - timedelta(days=1)
                elif period_type == "Quarterly":
                    quarter = st.selectbox("Select Quarter", ["Q1", "Q2", "Q3", "Q4"], key="inc_quarter")
                    year = st.selectbox("Year", [datetime.now().year, datetime.now().year-1], key="inc_year")
                    if quarter == "Q1":
                        start_date = datetime.strptime(f"{year}-01-01", "%Y-%m-%d")
                        end_date = datetime.strptime(f"{year}-03-31", "%Y-%m-%d")
                    elif quarter == "Q2":
                        start_date = datetime.strptime(f"{year}-04-01", "%Y-%m-%d")
                        end_date = datetime.strptime(f"{year}-06-30", "%Y-%m-%d")
                    elif quarter == "Q3":
                        start_date = datetime.strptime(f"{year}-07-01", "%Y-%m-%d")
                        end_date = datetime.strptime(f"{year}-09-30", "%Y-%m-%d")
                    else:
                        start_date = datetime.strptime(f"{year}-10-01", "%Y-%m-%d")
                        end_date = datetime.strptime(f"{year}-12-31", "%Y-%m-%d")
                else:
                    year = st.selectbox("Select Year", [datetime.now().year, datetime.now().year-1], key="inc_year_full")
                    start_date = datetime.strptime(f"{year}-01-01", "%Y-%m-%d")
                    end_date = datetime.strptime(f"{year}-12-31", "%Y-%m-%d")
            
            if st.button("Generate Income Statement"):
                conn = None
                try:
                    conn = sqlite3.connect('data/tax_management.db')
                    
                    # Calculate revenue
                    revenue = pd.read_sql(f"""SELECT SUM(amount) as total 
                                           FROM transactions 
                                           WHERE company_id={selected_company_id}
                                           AND type='sale'
                                           AND date BETWEEN '{start_date.strftime('%Y-%m-%d')}' 
                                           AND '{end_date.strftime('%Y-%m-%d')}'""", conn).iloc[0]['total'] or 0.0
                    
                    # Calculate cost of goods sold
                    cogs = pd.read_sql(f"""SELECT SUM(amount) as total 
                                        FROM transactions 
                                        WHERE company_id={selected_company_id}
                                        AND type='purchase'
                                        AND description LIKE '%inventory%'
                                        AND date BETWEEN '{start_date.strftime('%Y-%m-%d')}' 
                                        AND '{end_date.strftime('%Y-%m-%d')}'""", conn).iloc[0]['total'] or 0.0
                    
                    # Calculate expenses
                    expenses = pd.read_sql(f"""SELECT SUM(amount) as total 
                                            FROM transactions 
                                            WHERE company_id={selected_company_id}
                                            AND type='expense'
                                            AND date BETWEEN '{start_date.strftime('%Y-%m-%d')}' 
                                            AND '{end_date.strftime('%Y-%m-%d')}'""", conn).iloc[0]['total'] or 0.0
                    
                    # Calculate gross profit and net income
                    gross_profit = revenue - cogs
                    net_income = gross_profit - expenses
                    
                    # Display income statement
                    st.subheader(f"Income Statement for {period_type} ending {end_date.strftime('%Y-%m-%d')}")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**Revenue**")
                        st.write("Cost of Goods Sold")
                        st.write("**Gross Profit**")
                        st.write("Expenses")
                        st.write("**Net Income**")
                    with col2:
                        st.write(f"AED {revenue:,.2f}")
                        st.write(f"(AED {cogs:,.2f})")
                        st.write(f"AED {gross_profit:,.2f}")
                        st.write(f"(AED {expenses:,.2f})")
                        st.write(f"AED {net_income:,.2f}")
                    
                    # Generate PDF
                    pdf = FPDF()
                    pdf.add_page()
                    pdf.set_font("Arial", 'B', 16)
                    pdf.cell(0, 10, "Income Statement", 0, 1, 'C')
                    pdf.set_font("Arial", '', 12)
                    pdf.cell(0, 10, f"Company: {company_data['name']}", 0, 1)
                    pdf.cell(0, 10, f"Period: {period_type} ending {end_date.strftime('%Y-%m-%d')}", 0, 1)
                    pdf.ln(10)
                    
                    pdf.set_font("Arial", 'B', 12)
                    pdf.cell(100, 8, "Revenue", 1, 0)
                    pdf.cell(90, 8, f"AED {revenue:,.2f}", 1, 1, 'R')
                    
                    pdf.cell(100, 8, "Cost of Goods Sold", 1, 0)
                    pdf.cell(90, 8, f"(AED {cogs:,.2f})", 1, 1, 'R')
                    
                    pdf.set_font("Arial", 'B', 12)
                    pdf.cell(100, 8, "Gross Profit", 1, 0)
                    pdf.cell(90, 8, f"AED {gross_profit:,.2f}", 1, 1, 'R')
                    
                    pdf.set_font("Arial", '', 12)
                    pdf.cell(100, 8, "Expenses", 1, 0)
                    pdf.cell(90, 8, f"(AED {expenses:,.2f})", 1, 1, 'R')
                    
                    pdf.set_font("Arial", 'B', 12)
                    pdf.cell(100, 8, "Net Income", 1, 0)
                    pdf.cell(90, 8, f"AED {net_income:,.2f}", 1, 1, 'R')
                    
                    pdf_data = pdf.output(dest='S').encode('latin1')
                    
                    st.download_button(
                        label="Download Income Statement PDF",
                        data=pdf_data,
                        file_name=f"income_statement_{period_type}_{end_date.strftime('%Y%m%d')}.pdf",
                        mime="application/pdf"
                    )
                    
                except Exception as e:
                    st.error(f"Error generating income statement: {str(e)}")
                finally:
                    if conn:
                        conn.close()
        
        with tab2:
            st.subheader("Balance Sheet")
            
            # Select date
            as_of_date = st.date_input("As of Date", value=datetime.now(), key="balance_date")
            
            if st.button("Generate Balance Sheet"):
                conn = None
                try:
                    conn = sqlite3.connect('data/tax_management.db')
                    
                    # Calculate assets
                    cash = pd.read_sql(f"""SELECT SUM(amount) as total 
                                        FROM transactions 
                                        WHERE company_id={selected_company_id}
                                        AND type='income'
                                        AND description LIKE '%cash%'
                                        AND date <= '{as_of_date.strftime('%Y-%m-%d')}'""", conn).iloc[0]['total'] or 0.0
                    
                    # Calculate liabilities
                    liabilities = pd.read_sql(f"""SELECT SUM(amount) as total 
                                               FROM transactions 
                                               WHERE company_id={selected_company_id}
                                               AND type='expense'
                                               AND description LIKE '%payable%'
                                               AND date <= '{as_of_date.strftime('%Y-%m-%d')}'""", conn).iloc[0]['total'] or 0.0
                    
                    # Calculate equity (simplified)
                    equity = cash - liabilities
                    
                    # Display balance sheet
                    st.subheader(f"Balance Sheet as of {as_of_date.strftime('%Y-%m-%d')}")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**Assets**")
                        st.write("Cash")
                        st.write("**Total Assets**")
                    with col2:
                        st.write("")
                        st.write(f"AED {cash:,.2f}")
                        st.write(f"AED {cash:,.2f}")
                    
                    st.markdown("---")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**Liabilities**")
                        st.write("Accounts Payable")
                        st.write("**Total Liabilities**")
                    with col2:
                        st.write("")
                        st.write(f"AED {liabilities:,.2f}")
                        st.write(f"AED {liabilities:,.2f}")
                    
                    st.markdown("---")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**Equity**")
                        st.write("Retained Earnings")
                        st.write("**Total Equity**")
                    with col2:
                        st.write("")
                        st.write(f"AED {equity:,.2f}")
                        st.write(f"AED {equity:,.2f}")
                    
                    st.markdown("---")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**Total Liabilities & Equity**")
                    with col2:
                        st.write(f"AED {liabilities + equity:,.2f}")
                    
                    # Generate PDF
                    pdf = FPDF()
                    pdf.add_page()
                    pdf.set_font("Arial", 'B', 16)
                    pdf.cell(0, 10, "Balance Sheet", 0, 1, 'C')
                    pdf.set_font("Arial", '', 12)
                    pdf.cell(0, 10, f"Company: {company_data['name']}", 0, 1)
                    pdf.cell(0, 10, f"As of: {as_of_date.strftime('%Y-%m-%d')}", 0, 1)
                    pdf.ln(10)
                    
                    pdf.set_font("Arial", 'B', 12)
                    pdf.cell(0, 8, "Assets", 0, 1)
                    pdf.set_font("Arial", '', 12)
                    pdf.cell(100, 8, "Cash", 0, 0)
                    pdf.cell(90, 8, f"AED {cash:,.2f}", 0, 1, 'R')
                    
                    pdf.set_font("Arial", 'B', 12)
                    pdf.cell(100, 8, "Total Assets", 0, 0)
                    pdf.cell(90, 8, f"AED {cash:,.2f}", 0, 1, 'R')
                    pdf.ln(10)
                    
                    pdf.set_font("Arial", 'B', 12)
                    pdf.cell(0, 8, "Liabilities", 0, 1)
                    pdf.set_font("Arial", '', 12)
                    pdf.cell(100, 8, "Accounts Payable", 0, 0)
                    pdf.cell(90, 8, f"AED {liabilities:,.2f}", 0, 1, 'R')
                    
                    pdf.set_font("Arial", 'B', 12)
                    pdf.cell(100, 8, "Total Liabilities", 0, 0)
                    pdf.cell(90, 8, f"AED {liabilities:,.2f}", 0, 1, 'R')
                    pdf.ln(10)
                    
                    pdf.set_font("Arial", 'B', 12)
                    pdf.cell(0, 8, "Equity", 0, 1)
                    pdf.set_font("Arial", '', 12)
                    pdf.cell(100, 8, "Retained Earnings", 0, 0)
                    pdf.cell(90, 8, f"AED {equity:,.2f}", 0, 1, 'R')
                    
                    pdf.set_font("Arial", 'B', 12)
                    pdf.cell(100, 8, "Total Equity", 0, 0)
                    pdf.cell(90, 8, f"AED {equity:,.2f}", 0, 1, 'R')
                    pdf.ln(10)
                    
                    pdf.set_font("Arial", 'B', 12)
                    pdf.cell(100, 8, "Total Liabilities & Equity", 0, 0)
                    pdf.cell(90, 8, f"AED {liabilities + equity:,.2f}", 0, 1, 'R')
                    
                    pdf_data = pdf.output(dest='S').encode('latin1')
                    
                    st.download_button(
                        label="Download Balance Sheet PDF",
                        data=pdf_data,
                        file_name=f"balance_sheet_{as_of_date.strftime('%Y%m%d')}.pdf",
                        mime="application/pdf"
                    )
                    
                except Exception as e:
                    st.error(f"Error generating balance sheet: {str(e)}")
                finally:
                    if conn:
                        conn.close()
        
        with tab3:
            st.subheader("Cash Flow Statement")
            
            # Select period
            col1, col2 = st.columns(2)
            with col1:
                period_type = st.selectbox("Period Type", ["Monthly", "Quarterly", "Annual"], key="cash_period")
            with col2:
                if period_type == "Monthly":
                    period = st.date_input("Select Month", value=datetime.now(), key="cash_month").strftime("%Y-%m")
                    start_date = datetime.strptime(period + "-01", "%Y-%m-%d")
                    end_date = (start_date + timedelta(days=32)).replace(day=1) - timedelta(days=1)
                elif period_type == "Quarterly":
                    quarter = st.selectbox("Select Quarter", ["Q1", "Q2", "Q3", "Q4"], key="cash_quarter")
                    year = st.selectbox("Year", [datetime.now().year, datetime.now().year-1], key="cash_year")
                    if quarter == "Q1":
                        start_date = datetime.strptime(f"{year}-01-01", "%Y-%m-%d")
                        end_date = datetime.strptime(f"{year}-03-31", "%Y-%m-%d")
                    elif quarter == "Q2":
                        start_date = datetime.strptime(f"{year}-04-01", "%Y-%m-%d")
                        end_date = datetime.strptime(f"{year}-06-30", "%Y-%m-%d")
                    elif quarter == "Q3":
                        start_date = datetime.strptime(f"{year}-07-01", "%Y-%m-%d")
                        end_date = datetime.strptime(f"{year}-09-30", "%Y-%m-%d")
                    else:
                        start_date = datetime.strptime(f"{year}-10-01", "%Y-%m-%d")
                        end_date = datetime.strptime(f"{year}-12-31", "%Y-%m-%d")
                else:
                    year = st.selectbox("Select Year", [datetime.now().year, datetime.now().year-1], key="cash_year_full")
                    start_date = datetime.strptime(f"{year}-01-01", "%Y-%m-%d")
                    end_date = datetime.strptime(f"{year}-12-31", "%Y-%m-%d")
            
            if st.button("Generate Cash Flow Statement"):
                conn = None
                try:
                    conn = sqlite3.connect('data/tax_management.db')
                    
                    # Calculate cash from operations
                    cash_ops = pd.read_sql(f"""SELECT SUM(amount) as total 
                                            FROM transactions 
                                            WHERE company_id={selected_company_id}
                                            AND type IN ('sale', 'income', 'expense')
                                            AND date BETWEEN '{start_date.strftime('%Y-%m-%d')}' 
                                            AND '{end_date.strftime('%Y-%m-%d')}'""", conn).iloc[0]['total'] or 0.0
                    
                    # Calculate cash from investing (simplified)
                    cash_inv = pd.read_sql(f"""SELECT SUM(amount) as total 
                                            FROM transactions 
                                            WHERE company_id={selected_company_id}
                                            AND description LIKE '%investment%'
                                            AND date BETWEEN '{start_date.strftime('%Y-%m-%d')}' 
                                            AND '{end_date.strftime('%Y-%m-%d')}'""", conn).iloc[0]['total'] or 0.0
                    
                    # Calculate cash from financing (simplified)
                    cash_fin = pd.read_sql(f"""SELECT SUM(amount) as total 
                                            FROM transactions 
                                            WHERE company_id={selected_company_id}
                                            AND description LIKE '%loan%'
                                            AND date BETWEEN '{start_date.strftime('%Y-%m-%d')}' 
                                            AND '{end_date.strftime('%Y-%m-%d')}'""", conn).iloc[0]['total'] or 0.0
                    
                    # Calculate net cash flow
                    net_cash = cash_ops + cash_inv + cash_fin
                    
                    # Display cash flow statement
                    st.subheader(f"Cash Flow Statement for {period_type} ending {end_date.strftime('%Y-%m-%d')}")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**Cash from Operations**")
                        st.write("**Cash from Investing**")
                        st.write("**Cash from Financing**")
                        st.write("**Net Cash Flow**")
                    with col2:
                        st.write(f"AED {cash_ops:,.2f}")
                        st.write(f"AED {cash_inv:,.2f}")
                        st.write(f"AED {cash_fin:,.2f}")
                        st.write(f"AED {net_cash:,.2f}")
                    
                    # Generate PDF
                    pdf = FPDF()
                    pdf.add_page()
                    pdf.set_font("Arial", 'B', 16)
                    pdf.cell(0, 10, "Cash Flow Statement", 0, 1, 'C')
                    pdf.set_font("Arial", '', 12)
                    pdf.cell(0, 10, f"Company: {company_data['name']}", 0, 1)
                    pdf.cell(0, 10, f"Period: {period_type} ending {end_date.strftime('%Y-%m-%d')}", 0, 1)
                    pdf.ln(10)
                    
                    pdf.set_font("Arial", 'B', 12)
                    pdf.cell(100, 8, "Cash from Operations", 0, 0)
                    pdf.cell(90, 8, f"AED {cash_ops:,.2f}", 0, 1, 'R')
                    
                    pdf.cell(100, 8, "Cash from Investing", 0, 0)
                    pdf.cell(90, 8, f"AED {cash_inv:,.2f}", 0, 1, 'R')
                    
                    pdf.cell(100, 8, "Cash from Financing", 0, 0)
                    pdf.cell(90, 8, f"AED {cash_fin:,.2f}", 0, 1, 'R')
                    
                    pdf.set_font("Arial", 'B', 12)
                    pdf.cell(100, 8, "Net Cash Flow", 0, 0)
                    pdf.cell(90, 8, f"AED {net_cash:,.2f}", 0, 1, 'R')
                    
                    pdf_data = pdf.output(dest='S').encode('latin1')
                    
                    st.download_button(
                        label="Download Cash Flow Statement PDF",
                        data=pdf_data,
                        file_name=f"cash_flow_{period_type}_{end_date.strftime('%Y%m%d')}.pdf",
                        mime="application/pdf"
                    )
                    
                except Exception as e:
                    st.error(f"Error generating cash flow statement: {str(e)}")
                finally:
                    if conn:
                        conn.close()
    
    elif choice == "Reports":
        st.header("📈 Reports")
        
        if not selected_company_id:
            st.warning("Please register a company to view reports")
            return
        
        tab1, tab2, tab3 = st.tabs(["Sales Report", "Expense Report", "Tax Summary"])
        
        with tab1:
            st.subheader("Sales Report")
            
            # Filters
            with st.expander("Filters"):
                col1, col2 = st.columns(2)
                with col1:
                    start_date = st.date_input("From Date", 
                                             value=datetime.now() - timedelta(days=30),
                                             key="sales_start")
                with col2:
                    end_date = st.date_input("To Date", 
                                           value=datetime.now(),
                                           key="sales_end")
                
                group_by = st.selectbox("Group By", 
                                      ["Day", "Week", "Month", "Customer"],
                                      key="sales_group")
            
            if st.button("Generate Sales Report"):
                conn = None
                try:
                    conn = sqlite3.connect('data/tax_management.db')
                    
                    # Build query based on grouping
                    if group_by == "Day":
                        group_clause = "date"
                        format_str = "%Y-%m-%d"
                    elif group_by == "Week":
                        group_clause = "strftime('%Y-%W', date)"
                        format_str = "Week %W, %Y"
                    elif group_by == "Month":
                        group_clause = "strftime('%Y-%m', date)"
                        format_str = "%B %Y"
                    else:  # Customer
                        group_clause = "customer_trn"
                        format_str = None
                    
                    sales = pd.read_sql(f"""SELECT {group_clause} as period, 
                                          SUM(amount) as total_sales, 
                                          COUNT(*) as num_transactions
                                          FROM transactions 
                                          WHERE company_id={selected_company_id}
                                          AND type='sale'
                                          AND date BETWEEN '{start_date.strftime('%Y-%m-%d')}' 
                                          AND '{end_date.strftime('%Y-%m-%d')}'
                                          GROUP BY {group_clause}
                                          ORDER BY period""", conn)
                    
                    if not sales.empty:
                        # Format period for display
                        if group_by != "Customer":
                            sales['period'] = sales['period'].apply(lambda x: datetime.strptime(x, format_str.replace("%W", "%V")).strftime(format_str) if "%W" in format_str else datetime.strptime(x, format_str).strftime(format_str))
                        
                        st.subheader(f"Sales Report ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})")
                        
                        # Display summary
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            total_sales = sales['total_sales'].sum()
                            st.metric("Total Sales", f"AED {total_sales:,.2f}")
                        with col2:
                            avg_sale = total_sales / sales['num_transactions'].sum()
                            st.metric("Average Sale", f"AED {avg_sale:,.2f}")
                        with col3:
                            st.metric("Number of Transactions", sales['num_transactions'].sum())
                        
                        # Display chart
                        st.subheader("Sales Trend")
                        st.line_chart(sales.set_index('period')['total_sales'])
                        
                        # Display detailed data
                        st.subheader("Sales Details")
                        st.dataframe(sales)
                        
                        # Export report
                        st.subheader("Export Report")
                        csv = sales.to_csv(index=False)
                        st.download_button(
                            label="Download Sales Report CSV",
                            data=csv,
                            file_name="sales_report.csv",
                            mime="text/csv"
                        )
                    else:
                        st.info("No sales data found for the selected period")
                except Exception as e:
                    st.error(f"Error generating sales report: {str(e)}")
                finally:
                    if conn:
                        conn.close()
        
        with tab2:
            st.subheader("Expense Report")
            
            # Filters
            with st.expander("Filters"):
                col1, col2 = st.columns(2)
                with col1:
                    start_date = st.date_input("From Date", 
                                             value=datetime.now() - timedelta(days=30),
                                             key="expense_start")
                with col2:
                    end_date = st.date_input("To Date", 
                                           value=datetime.now(),
                                           key="expense_end")
                
                expense_category = st.selectbox("Expense Category", 
                                              ["All", "Rent", "Salaries", "Utilities", "Supplies", "Other"],
                                              key="expense_cat")
            
            if st.button("Generate Expense Report"):
                conn = None
                try:
                    conn = sqlite3.connect('data/tax_management.db')
                    
                    # Build query
                    query = f"""SELECT description, SUM(amount) as total_expenses
                              FROM transactions 
                              WHERE company_id={selected_company_id}
                              AND type='expense'
                              AND date BETWEEN '{start_date.strftime('%Y-%m-%d')}' 
                              AND '{end_date.strftime('%Y-%m-%d')}'"""
                    
                    if expense_category != "All":
                        query += f" AND description LIKE '%{expense_category}%'"
                    
                    query += " GROUP BY description ORDER BY total_expenses DESC"
                    
                    expenses = pd.read_sql(query, conn)
                    
                    if not expenses.empty:
                        st.subheader(f"Expense Report ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})")
                        
                        # Display summary
                        total_expenses = expenses['total_expenses'].sum()
                        st.metric("Total Expenses", f"AED {total_expenses:,.2f}")
                        
                        # Display chart
                        st.subheader("Expense Breakdown")
                        st.bar_chart(expenses.set_index('description')['total_expenses'])
                        
                        # Display detailed data
                        st.subheader("Expense Details")
                        st.dataframe(expenses)
                        
                        # Export report
                        st.subheader("Export Report")
                        csv = expenses.to_csv(index=False)
                        st.download_button(
                            label="Download Expense Report CSV",
                            data=csv,
                            file_name="expense_report.csv",
                            mime="text/csv"
                        )
                    else:
                        st.info("No expense data found for the selected period")
                except Exception as e:
                    st.error(f"Error generating expense report: {str(e)}")
                finally:
                    if conn:
                        conn.close()
        
        with tab3:
            st.subheader("Tax Summary Report")
            
            # Select period
            col1, col2 = st.columns(2)
            with col1:
                period_type = st.selectbox("Period Type", ["Monthly", "Quarterly", "Annual"], key="tax_period")
            with col2:
                if period_type == "Monthly":
                    period = st.date_input("Select Month", value=datetime.now(), key="tax_month").strftime("%Y-%m")
                elif period_type == "Quarterly":
                    quarter = st.selectbox("Select Quarter", ["Q1", "Q2", "Q3", "Q4"], key="tax_quarter")
                    year = st.selectbox("Year", [datetime.now().year, datetime.now().year-1], key="tax_year")
                    period = f"{year}-{quarter}"
                else:
                    year = st.selectbox("Select Year", [datetime.now().year, datetime.now().year-1], key="tax_year_full")
                    period = f"{year}"
            
            if st.button("Generate Tax Summary"):
                conn = None
                try:
                    conn = sqlite3.connect('data/tax_management.db')
                    
                    # Get VAT data
                    vat_data = pd.read_sql(f"""SELECT period, output_tax, input_tax, net_tax_payable
                                            FROM vat_returns 
                                            WHERE company_id={selected_company_id}
                                            AND period LIKE '{period}%'
                                            ORDER BY period""", conn)
                    
                    # Get corporate tax data
                    ct_data = pd.read_sql(f"""SELECT tax_year, taxable_income, tax_payable
                                           FROM corporate_tax_returns 
                                           WHERE company_id={selected_company_id}
                                           AND tax_year LIKE '{period}%'
                                           ORDER BY tax_year""", conn)
                    
                    if not vat_data.empty or not ct_data.empty:
                        st.subheader(f"Tax Summary for {period}")
                        
                        if not vat_data.empty:
                            st.write("**VAT Summary**")
                            st.dataframe(vat_data)
                            
                            # Calculate VAT totals
                            total_output_tax = vat_data['output_tax'].sum()
                            total_input_tax = vat_data['input_tax'].sum()
                            total_net_vat = vat_data['net_tax_payable'].sum()
                            
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric("Total Output Tax", f"AED {total_output_tax:,.2f}")
                            with col2:
                                st.metric("Total Input Tax", f"AED {total_input_tax:,.2f}")
                            with col3:
                                st.metric("Total Net VAT Payable", f"AED {total_net_vat:,.2f}")
                        
                        if not ct_data.empty:
                            st.write("**Corporate Tax Summary**")
                            st.dataframe(ct_data)
                            
                            # Calculate CT totals
                            total_taxable_income = ct_data['taxable_income'].sum()
                            total_ct_payable = ct_data['tax_payable'].sum()
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("Total Taxable Income", f"AED {total_taxable_income:,.2f}")
                            with col2:
                                st.metric("Total Corporate Tax Payable", f"AED {total_ct_payable:,.2f}")
                        
                        # Export report
                        st.subheader("Export Report")
                        if not vat_data.empty and not ct_data.empty:
                            combined = pd.concat([vat_data, ct_data])
                        elif not vat_data.empty:
                            combined = vat_data
                        else:
                            combined = ct_data
                        
                        csv = combined.to_csv(index=False)
                        st.download_button(
                            label="Download Tax Summary CSV",
                            data=csv,
                            file_name="tax_summary.csv",
                            mime="text/csv"
                        )
                    else:
                        st.info("No tax data found for the selected period")
                except Exception as e:
                    st.error(f"Error generating tax summary: {str(e)}")
                finally:
                    if conn:
                        conn.close()
    
    elif choice == "Settings":
        st.header("⚙️ User Settings")
        
        with st.form("user_settings"):
            st.subheader("Update Profile")
            
            conn = None
            try:
                conn = sqlite3.connect('data/tax_management.db')
                user = pd.read_sql(f"""SELECT full_name, phone, email FROM users 
                                    WHERE id={st.session_state.user['id']}""", conn).iloc[0]
                
                col1, col2 = st.columns(2)
                with col1:
                    full_name = st.text_input("Full Name", value=user['full_name'])
                with col2:
                    phone = st.text_input("Phone Number", value=user['phone'])
                
                email = st.text_input("Email", value=user['email'])
                
                submitted = st.form_submit_button("Update Profile")
                
                if submitted:
                    # Validate inputs
                    if phone and not validate_phone(phone):
                        st.error("Please enter a valid UAE phone number starting with +971")
                        return
                    
                    if not validate_email(email):
                        st.error("Please enter a valid email address")
                        return
                    
                    try:
                        c = conn.cursor()
                        c.execute("""UPDATE users SET full_name=?, phone=?, email=? 
                                  WHERE id=?""",
                                (full_name, phone, email, st.session_state.user['id']))
                        conn.commit()
                        
                        log_activity(st.session_state.user['id'], "update_profile", 
                                   "Updated user profile")
                        st.success("Profile updated successfully!")
                        st.rerun()
                    except Exception as e:
                        if conn:
                            conn.rollback()
                        st.error(f"Error updating profile: {str(e)}")
            except Exception as e:
                st.error(f"Error loading user data: {str(e)}")
            finally:
                if conn:
                    conn.close()
        
        with st.form("change_password"):
            st.subheader("Change Password")
            
            current_password = st.text_input("Current Password", type="password")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm New Password", type="password")
            
            submitted = st.form_submit_button("Change Password")
            
            if submitted:
                # Validate inputs
                if not current_password or not new_password or not confirm_password:
                    st.error("Please fill all fields")
                    return
                
                if new_password != confirm_password:
                    st.error("New passwords do not match")
                    return
                
                password_valid, password_msg = validate_password(new_password)
                if not password_valid:
                    st.error(password_msg)
                    return
                
                conn = None
                try:
                    conn = sqlite3.connect('data/tax_management.db')
                    c = conn.cursor()
                    
                    # Verify current password
                    c.execute("SELECT password FROM users WHERE id=?", (st.session_state.user['id'],))
                    db_password = c.fetchone()[0]
                    
                    if hash_password(current_password) != db_password:
                        st.error("Current password is incorrect")
                        return
                    
                    # Update password
                    new_hashed_password = hash_password(new_password)
                    c.execute("UPDATE users SET password=? WHERE id=?", 
                            (new_hashed_password, st.session_state.user['id']))
                    conn.commit()
                    
                    log_activity(st.session_state.user['id'], "change_password", 
                               "Changed password")
                    st.success("Password changed successfully!")
                    st.rerun()
                except Exception as e:
                    if conn:
                        conn.rollback()
                    st.error(f"Error changing password: {str(e)}")
                finally:
                    if conn:
                        conn.close()

# =============================================
# MAIN APP
# =============================================

def main():
    # Initialize session state
    if 'user' not in st.session_state:
        st.session_state.user = None
    if 'show_register' not in st.session_state:
        st.session_state.show_register = False
    
    # Check if user is logged in
    if st.session_state.user:
        if st.session_state.user['role'] == 'admin':
            admin_panel()
        else:
            user_dashboard()
    else:
        if st.session_state.show_register:
            register_page()
        else:
            login_page()

if __name__ == "__main__":
    main()