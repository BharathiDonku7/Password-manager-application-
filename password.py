from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from werkzeug.security import check_password_hash, generate_password_hash
from flask import flash, redirect, url_for
from flask_login import LoginManager
from flask import render_template
from flask import session
from flask_login import login_required, current_user
from flask import Flask
from flask_login import LoginManager
import os
import re
import base64

flask_app = Flask(__name__,template_folder="front-end")
flask_app.secret_key = b'!p9S5tL7oK3n@4b'

#creating a new table in database if not exists
def create_password_table():
    connection  = sqlite3.connect("DonkuDB.db") # creating a database connection
    cursor = connection.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwordmanager (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website_name TEXT,
            user_name TEXT,
            encrypted_password TEXT,
            salt BLOB     
        )
    ''')

    #Create a masterpassword table in database if not exists 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS masterpassword (
            masterpassword TEXT UNIQUE
        )
    ''')
    connection.commit()
    connection.close() # close the connection

# funvtion to derive secret  key from masterpassword using PBKDF2 
def derivesecretkey(masterpassword, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    secret_key = kdf.derive(masterpassword.encode())
    return secret_key

#Function to encrypting the text using AES
def encryption(information, secret_key):
    Initialization_Vector= os.urandom(16)
    encrypted = Cipher(algorithms.AES(secret_key), modes.CFB(Initialization_Vector), backend=default_backend())
    encryptor = encrypted.encryptor()
    encryptedtext = encryptor.update(information) + encryptor.finalize()
    return Initialization_Vector + encryptedtext

#Function to decrypting text data AES
def decryption(information, secret_key):
    Initialization_Vector = information[:16]
    encryptedtext = information[16:]
    encrypted = Cipher(algorithms.AES(secret_key), modes.CFB(Initialization_Vector), backend=default_backend())
    decryptor = encrypted.decryptor()
    text = decryptor.update(encryptedtext) + decryptor.finalize()
    return text

#Function to hash the masterpassword before storing in database
def hashingmasterpassword(masterpassword):
    return generate_password_hash(masterpassword)

# Function to check if the entered masterpassword matches the storedhash password
def checkingmasterpassword(masterpassword, stored_hash):
    return check_password_hash(stored_hash, masterpassword)

# Function to store userspassword in the database
def storingpasswodindatabase(website_name, user_name, encrypted_password, salt, masterpassword):
    connection = sqlite3.connect("DonkuDB.db")
    cursor = connection.cursor()
    # Converting binary data to Base64-encoded string
    encryptedpasswordstring = base64.b64encode(encrypted_password).decode('utf-8')
    # Check if a password entry already exists for the given websitename and username
    cursor.execute('SELECT encrypted_password FROM passwordmanager WHERE website_name = ? AND user_name = ?', (website_name, user_name))
    existingentry = cursor.fetchone()
    if existingentry: 
        # Derivekey using the retrieved salt
        secret_key = derivesecretkey(masterpassword, salt)
        previouspassword=base64.b64decode(existingentry[0])
        previouspasswordbytes = decryption(previouspassword, secret_key)
        previousdecryptedpassword = previouspasswordbytes.decode('utf-8', errors='replace')
        # Decrypt the newpassword
        newpassword_bytes = decryption(encrypted_password, secret_key)
        newpassword = newpassword_bytes.decode('utf-8', errors='replace')
        if previouspasswordbytes == newpassword_bytes:
            # If previous and new passwords match, display an error message
            connection.close()
            error_message = f"Error: Password '{newpassword}' is already  there in the database."
            return render_template('passwordmanager.html', error_message=error_message,alert_type='error')
        # If passwords don't match, update the password and salt
        else:
            cursor.execute('UPDATE passwordmanager SET encrypted_password = ?, salt = ? WHERE website_name = ? AND user_name = ?',
                       (encryptedpasswordstring, salt, website_name, user_name))
            connection.commit()
            connection.close()
            success_message = "Password updated successfully!"
            return render_template('passwordmanager.html', success_message=success_message,alert_type='success')
    else:
        # If no entry exists, insert a new password entry
        cursor.execute('INSERT INTO passwordmanager (website_name, user_name, encrypted_password, salt) VALUES (?, ?, ?, ?)',
                       (website_name, user_name, encryptedpasswordstring, salt))
        connection.commit()
        connection.close()
        success_message = "Password stored successfully!"
        return render_template('passwordmanager.html', success_message=success_message,alert_type='success')
      

# presents users with options to login or set up a password
@flask_app.route('/', methods=['GET'])
def initialpage():
    return render_template('welcomepage.html')

#handles form submission to check the master password
@flask_app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        masterpassword = request.form['masterpassword']
        connection = sqlite3.connect("DonkuDB.db")
        cursor = connection.cursor()

        # Retrieve the stored hashed masterpassword
        cursor.execute('SELECT masterpassword FROM masterpassword')
        stored_hashed_password = cursor.fetchone()

        if stored_hashed_password and checkingmasterpassword(masterpassword, stored_hashed_password[0]):
            # If the entered masterpassword matches the stored hash, set user_id in session
            session['logged_in'] = True
            connection.close()
            return redirect('/passwordmanager')
        else:
            # If the master password does not match, redirect to login with an error message
            connection.close()
            return render_template('loginpage.html', error='Invalid master password')
    else:
       
            # Your existing logic for handling GET requests (if needed) goes here...
            return render_template('loginpage.html')

# displays the password manager form or redirects to login if not logged in
@flask_app.route('/passwordmanager')
def index():
        return render_template('passwordmanager.html')
#set the masterpassword   
@flask_app.route('/setmasterpassword', methods=['GET', 'POST'])
def setmasterpassword():
    if request.method == 'POST':
        masterpassword = request.form['masterpassword']
        connection = sqlite3.connect("DonkuDB.db")
        cursor = connection.cursor()
        # Hash the master password before storing it
        hashedmasterpassword = hashingmasterpassword(masterpassword)
        # Check if the hashed master password already exists in the database
        cursor.execute('SELECT masterpassword FROM masterpassword WHERE masterpassword = ?', (hashedmasterpassword,))
        existing_password = cursor.fetchone()
        if existing_password:
            # If the hashed master password already exists, show an error message
            connection.close()
            error_message = 'Master password already exists in database. Please select  a different one.'
            return render_template('settingupmasterpassword.html', error=error_message)
        else:
            # Store the hashed master password in the database
            cursor.execute('INSERT INTO masterpassword (masterpassword) VALUES (?)', (hashedmasterpassword,))
            connection.commit()
            # Redirect to login after setting the master password
            connection.close()
            return redirect('/login')
    else:
        # Your existing logic for handling GET requests (if needed) goes here...
        return render_template('settingupmasterpassword.html')    
    
#logout out of the application
@flask_app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/')

#store the password in database
@flask_app.route('/storepassword', methods=['POST'])
def storepassword():
    website_name = request.form['website_name']
    user_name = request.form['user_name']
    user_password = request.form['password']   
    connection = sqlite3.connect("DonkuDB.db")
    cursor = connection.cursor() 
    # Retrieve the master password from the database
    cursor.execute('SELECT masterpassword FROM masterpassword')
    stored_master_password = cursor.fetchone()
    if stored_master_password:
        master_password = stored_master_password[0]
        # Store the master password in the session
        session['master_password'] = master_password
        # Retrieve the stored salt for the website and username
        cursor.execute('SELECT salt FROM passwordmanager WHERE website_name = ? AND user_name = ?', (website_name, user_name))
        stored_salt = cursor.fetchone()
        if not stored_salt:
            # If no salt exists, generate a new one
            salt = os.urandom(16)
        else:
            # If a salt exists, use the stored one
            salt = stored_salt[0]
        # Use the retrieved master password
        secret_key = derivesecretkey(master_password, salt)
        # Encrypt the password
        encrypted_password = encryption(user_password.encode(), secret_key)
        # Store the password in the database
        storingpasswodindatabase(website_name, user_name, encrypted_password, salt, master_password)
        connection.commit()
        connection.close()
        success_message = f" Your Password is stored successfully "
        return render_template('passwordmanager.html', success_message=success_message)
        

# Function to check password strength
def checkpasswordstrength(password):
    errors = []
    # Checking the  if the password length is at least 8 characters
    if len(password) < 8:
        errors.append("Password length is too short.")
    # Check if the password contains at least one uppercase letter
    if not any(char.isupper() for char in password):
        errors.append("password contains at least one uppercase character.")
    # Check if the password contains at least one lowercase letter
    if not any(char.islower() for char in password):
        errors.append("Password contains at least one lowercase letter.")
    # Check if the password contains at least one digit
    if not any(char.isdigit() for char in password):
        errors.append("Password contains at least one digit.")
    # Check if the password contains at least one special character
    special_characters = re.compile(r"[!@#$%^&*(),.?\":{}|<>]")
    if not special_characters.search(password):
        errors.append("Password  contains at least one special character.")
    return errors
# Retrieve password route - handles form submission to retrieve passwords
@flask_app.route('/retrievealldetails', methods=['POST'])
def retrievealldetails():
    masterpassword = request.form['masterpassword']
    action = request.form['action']  # Added to get the action for retrieving all details 
    connection = sqlite3.connect("DonkuDB.db")
    cursor = connection.cursor()
    # Retrieve the master password from the database
    cursor.execute('SELECT masterpassword FROM masterpassword')
    stored_master_password = cursor.fetchone()
    # Check if the action is to retrieve all details
    if action == 'retrieve_all':
        # Verify the master password
        if stored_master_password and checkingmasterpassword(masterpassword, stored_master_password[0]):
            cursor.execute('SELECT * FROM passwordmanager')
            all_passwords = cursor.fetchall()
            # Close the connection
            connection.close()
            # Render passwordmanager.html template with retrieved details passed as context
            return render_template('all_passwords.html', all_passwords=all_passwords)
        else:
            masterPswd_error_message = "Enter correct master password"
            connection.close()
            return render_template('passwordmanager.html', masterPswd_error_message=masterPswd_error_message)
    else:
        # Handle the case where an invalid action is submitted
        error_message = "Invalid action submitted."
        connection.close()
        return render_template('passwordmanager.html', error_message=error_message)

#retrieve the user details 
@flask_app.route('/retrieveuserdetails', methods=['POST'])
def retrieve_user_details():
    user_name = request.form['user_name']
    password = request.form['password']   
    # Connect to database and check user existence
    connection = sqlite3.connect("DonkuDB.db")
    cursor = connection.cursor()
    cursor.execute('SELECT encrypted_password, salt FROM passwordmanager WHERE user_name = ?', (user_name,))
    user_data = cursor.fetchone() 
    if user_data:
        encrypted_password, salt = user_data  
        # Fetch master password hash from the database
        cursor.execute('SELECT masterpassword FROM masterpassword')
        master_password_hash = cursor.fetchone()[0] 
        # Derive secret key using master password hash and salt
        secret_key = derivesecretkey(master_password_hash, salt) 
        # Decrypt stored password
        decrypted_password = decryption(base64.b64decode(encrypted_password), secret_key)
        print(decrypted_password )
        # Check if decrypted password matches entered password
        if decrypted_password.decode('utf-8') == password:
            # Authentication successful, redirect to dashboard or next page
            session['user_name'] = user_name
            return redirect('/display_details')
        else:
            # Authentication failed
            return render_template('loginpage.html', error_message="Invalid username or password")
    else:
        # User does not exist
        return render_template('loginpage.html', error_message="User does not exist")
#display the username,website,decryptedpassword
@flask_app.route('/display_details')
def display_details():
    # Check if the user is logged in
    if 'user_name' in session:
        user_name = session['user_name']     
        try:
            # Fetch user details from the database
            connection = sqlite3.connect("DonkuDB.db")
            cursor = connection.cursor()    
            # Fetch user details and master password hash
            cursor.execute('SELECT website_name, user_name, encrypted_password, salt FROM passwordmanager WHERE user_name = ?', (user_name,))
            user_details = cursor.fetchone()
            cursor.execute('SELECT masterpassword FROM masterpassword')
            master_password_hash = cursor.fetchone()[0]   
            if user_details:
                website_name, user_name, encrypted_password, salt = user_details               
                # Derive secret key using master password hash and salt
                secret_key = derivesecretkey(master_password_hash, salt)
                # Decrypt stored password
                decrypted_password = decryption(base64.b64decode(encrypted_password), secret_key)
                # Pass user details and decrypted password to the display_details.html template
                return render_template('display_details.html', website_name=website_name, user_name=user_name, decrypted_password=decrypted_password.decode('utf-8'))
            else:
                # User details not found in the database
                return "User details not found."
        except Exception as e:
            # Handle database errors
            return "An error occurred while fetching user details. Please try again later."
    else:
        # User is not logged in, redirect to the login page
        return redirect('/loginpage') 
# Run the application
if __name__ == '__main__':
    create_password_table()
    flask_app.run(debug=True)


