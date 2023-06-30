"""
An authentication (Sign-Up / Sign-In) system implemented as a website using Flask.
The authentication systems is dsigned in a scure way, encrpyting the data on th DB server (MySQL),
and applies security checks: secure password, input validation, password checking using
encryption and hash (salted hash), TLS, HTTPS.
The app allows a user to sign up, sign in, add data for a specific user, and reset password via email.
In addtion, the app allows to demonstrate stored XSS and SQLI attackes and defense.

	Project sources:
		* Base Flask template from https://www.geeksforgeeks.org/login-and-registration-project-using-flask-and-mysql/
		* HMAC tutorial from https://nitratine.net/blog/post/how-to-hash-passwords-in-python/
		* Convert hex to bytes (for get salt in bytes after saved as hex in DB) from https://java2blog.com/python-hex-to-bytes/
		* 200 most commonfrom Wikipedia: https://en.wikipedia.org/wiki/Wikipedia:10,000_most_common_passwords
		* HTTPS (TLS/SSL) tutorial: https://zeropointdevelopment.com/how-to-get-https-working-in-windows-10-localhost-dev-environment/
		* Disable HTML autoescaping: https://jinja.palletsprojects.com/en/3.1.x/templates/#autoescape-extension 
		* XSS attack: https://www.youtube.com/watch?v=UXtxfka2TuY

Nati Aharoni
"""


from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_mail import Mail, Message
import os
import hashlib
import codecs
import re
import random
import html
import password_configuration
import ssl
from dotenv import load_dotenv, dotenv_values


# Application configuration
app = Flask(__name__)

load_dotenv()

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('certificate/localhost.crt',
                        'certificate/localhost.key')

#Initialize basic variables
app.secret_key = os.getenv("APP_SECRET_KEY")

#Configurate MySQL DB details
#Fill your details in here:
app.config['MYSQL_HOST'] = os.getenv("MYSQL_HOST")
app.config['MYSQL_USER'] = os.getenv("MYSQL_USER")
app.config['MYSQL_PASSWORD'] = os.getenv("MYSQL_PASSWORD")
app.config['MYSQL_DB'] = os.getenv("MYSQL_DB")
mysql = MySQL(app)

#Configurate mail details
#Used in rest_password page
#In order to overcome the problem of logging into gmail acoount using python watch: https://www.youtube.com/watch?v=g_j6ILT-X0k
app.config['MAIL_SERVER'] = "smtp.gmail.com"
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

# ----------------- THE WEB PAGES ----------------- 

# -------- Login page --------
@app.route('/')
@app.route('/login', methods =['GET', 'POST'])
def login():
	#In case the user arrived here, will logout so he won't be able to approche logged-in users pages (by URL parameters)
	session.pop('loggedin', None)
	session.pop('id', None)
	session.pop('username', None)
	msg = ''
	#Fetch coniguration data
	conf_data = password_configuration.read_configuration()
	if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
		#Get the values the user entered
		username = request.form['username']
		password = request.form['password']
		#Get the user's detalis from DB
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		if(conf_data['enableSqli']):
			#To apply SQLI use the line below:
			cursor.execute("SELECT * FROM accounts WHERE username = '"+username+"'")
		else:
			#To prevent SQLI use the line below:
			cursor.execute('SELECT * FROM accounts WHERE username = %s', (username, ))
		account = cursor.fetchone()
		#If user exists
		if account:
			#Check if manager
			if (account['username'] == 'admin' & account['password']=='admin' & account['login_attempts'] == -1):
				msg = 'First admin login, please reset your password'
				return render_template('change_password_reset.html', msg=msg)	
			#Get salt for the hmac function, in order to save hash-encrypted password
			#the codecs.decode function turns a hex into bytes (needed for salt)
			salt = codecs.decode(account['curr_salt'], 'hex_codec')
			#Check if the password the user entered matches the one saved in DB
			if account['login_attempts'] < conf_data['loginAttemptsAllowed']:
				if account['password'] == hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000).hex():
					session['loggedin'] = True
					session['id'] = account['id']
					session['username'] = account['username']
					msg = 'Logged in successfully!'
					cursor.execute('UPDATE accounts SET login_attempts = %s  WHERE username = %s', (0, username, ))
					mysql.connection.commit()
					if account['admin'] == 'TRUE':
						return render_template('admin_page.html', msg = msg)
					else:
						return render_template('user_page.html', msg = msg)
				else:
					msg = 'Incorrect username / password!'
					cursor.execute('UPDATE accounts SET login_attempts = %s  WHERE username = %s', (account['login_attempts']+1, username, ))
					mysql.connection.commit()
					return render_template('login.html', msg = msg)
			else:
				msg = '3 failed logs, You have to reset your password'
		elif not username or not password:
			msg = 'Please fill out the form!'
		else:
			msg = 'Incorrect username/password!'
	return render_template('login.html', msg = msg)


# -------- user_page --------
# the page the user sees after a succsseful login
@app.route('/user_page', methods =['GET', 'POST'])
def user_page():
	if 'loggedin' in session:
		msg = ''
		return render_template('user_page.html', msg = msg)
	else:
		msg = 'You must be logged in to enter user page'
		return render_template('login.html', msg=msg)

# -------- admin_page --------
# the page the admin sees after a succsseful login
@app.route('/admin_page', methods =['GET', 'POST'])
def admin_page():
	if 'loggedin' in session:
		msg = ''
		return render_template('admin_page.html', msg = msg)
	else:
		msg = 'You must be logged in to enter user page'
		return render_template('login.html', msg=msg)

# -------- manage_pswd_config --------
# the page in which the admin sets the passwords configuration
@app.route('/manage_pswd_config', methods =['GET', 'POST'])
def manage_pswd_config():
	if 'loggedin' in session:
		msg = ''
		return render_template('manage_pswd_config.html', msg = msg)
	else:
		msg = 'You must be logged in to enter user page'
		return render_template('login.html', msg=msg)


# -------- Registration page --------
@app.route('/register', methods =['GET', 'POST'])
def register():
	#Fetch coniguration data
	conf_data = password_configuration.read_configuration()
	msg = ''
	if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form :
		#Get the values the user entered
		username = request.form['username']
		password = request.form['password']
		password_ver = request.form['password2']
		email = request.form['email']
		#Generate salt for the hmac function, in order to save hash-encrypted password
		salt = os.urandom(32)
		#Connection to DB
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		if(conf_data['enableSqli']):
			#To apply SQLI use the line below:
			cursor.execute("SELECT * FROM accounts WHERE username = '"+username+"'")
		else:
			#To prevent SQLI use the line below:
			cursor.execute('SELECT * FROM accounts WHERE username = %s', (username, ))
		account = cursor.fetchone()
		if account:
			msg = 'Account already exists!'
		#Password checks
		elif password != password_ver:
			msg = 'Entered passwords does not match!'
		elif conf_data['CheckCommonValues'] and password in password_configuration.get_common_passwords():
			msg = 'Weak password! (very common...)'
		elif len(password) < conf_data['passwordMinLength']:
			msg = 'Password is too short'
		elif not any (char.isdigit() for char in password):
			msg = 'You must use at least one digit in password'
		elif not any (char.isupper() for char in password):
			msg = 'You must use at least one upper-case char in password'
		elif not any (char.islower() for char in password):
			msg = 'You must use at least one lower-case char in password'
		elif not any (char in conf_data['mustToHaveChars'] for char in password):
			msg = 'You must use at least one special char in password'
		#Email check
		elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
			msg = 'Invalid email address!'
		#Details check
		elif not username or not password or not password_ver or not email:
			msg = 'Please fill out the form!'
		else:
			#In case all input details are valid
			#Generate a key for storing the salt-hashed password
			salt_hash_pass = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000).hex()
			cursor.execute('INSERT INTO accounts (username, password, email, login_attempts, password_hist1, password_hist2, password_hist3, curr_salt, salt_hist1 , salt_hist2, salt_hist3, admin) VALUES (%s,%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                           (username, salt_hash_pass, email, 0, salt_hash_pass, salt_hash_pass, salt_hash_pass, salt.hex(), salt.hex(), salt.hex(), salt.hex(), 'FALSE'))
			#salt = salt.hex()
			#salt = str(salt)
			#cursor.execute("INSERT INTO accounts (username = '"+username+"', password = '"+salt_hash_pass+"', email = '"+email+"', login_attempts = '0', password_hist1 ='"+salt_hash_pass+"', password_hist2 ='"+salt_hash_pass+"', password_hist3='"+salt_hash_pass+"', curr_salt='"+salt+"', salt_hist1='"+salt+"', salt_hist2='"+salt+"', salt_hist3='"+salt+"'")
			mysql.connection.commit()
			msg = 'You have successfully registered!'
			session['loggedin'] = True
			session['username'] = username
			return render_template('user_page.html', msg = msg)
	elif request.method == 'POST':
		msg = 'Please fill out the form!'
	return render_template('register.html', msg = msg)

# -------- change_password --------
# here the user can change his password
# accessible from user_pasge
@app.route('/change_password', methods =['GET', 'POST'])
def change_password():
	if 'loggedin' in session:
		#Fetch coniguration data
		conf_data = password_configuration.read_configuration()
		msg = ''
		if request.method == 'POST':
			#Get the values the user entered
			#username = request.form['username']
			username = session['username']
			new_password1 = request.form['new_password1']
			new_password2= request.form['new_password2']
			#Get the user's detalis from DB
			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
			cursor.execute('SELECT * FROM accounts WHERE username = %s', (username, ))
			account = cursor.fetchone()
			#Password checks
			if new_password1 != new_password2:
				msg = 'Entered passwords does not match!'
			elif conf_data['CheckCommonValues'] and new_password1 in password_configuration.get_common_passwords():
				msg = 'Weak password! (very common..)'
			elif len(new_password1) < conf_data['passwordMinLength']:
				msg = 'Password is too short'
			elif not any (char.isdigit() for char in new_password1):
				msg = 'You must use at least one digit in password'
			elif not any (char.isupper() for char in new_password1):
				msg = 'You must use at least one upper-case char in password'
			elif not any (char.islower() for char in new_password1):
				msg = 'You must use at least one lower-case char in password'
			elif not any (char in conf_data['mustToHaveChars'] for char in new_password1):
				msg = 'You must use at least one special-case char in password'
			elif check_if_in_passwords_history(account, new_password1):
				msg = 'You already used this password before'
				return render_template('change_password.html', msg = msg)
			else:
				new_salt = os.urandom(32)
				salt_hash_new_pass = hashlib.pbkdf2_hmac('sha256', new_password1.encode('utf-8'), new_salt, 100000).hex()
				#set vars for understandable SQL oreder
				new_pass = salt_hash_new_pass
				pass_hist1 = account['password']
				pass_hist2 = account['password_hist1']
				pass_hist3 = account['password_hist2']
				new_salt = new_salt.hex()
				salt_hist1 = account['curr_salt']
				salt_hist2 = account['salt_hist1']
				salt_hist3 = account['salt_hist2']

				cursor.execute('UPDATE accounts SET password = %s ,password_hist1 =%s, password_hist2 =%s, password_hist3 =%s, curr_salt=%s, salt_hist1  = %s, salt_hist2  = %s, salt_hist3  = %s WHERE username = % s',
				(new_pass, pass_hist1, pass_hist2, pass_hist3, new_salt, salt_hist1, salt_hist2, salt_hist3, username, ))
				mysql.connection.commit()
				msg = 'Password was changed successfully!'
				return render_template('user_page.html', msg = msg)
		return render_template('change_password.html', msg = msg)
	else:
		msg = 'You must be logged in to enter change password page'
		return render_template('login.html', msg=msg)


#function to check the user's password history
def check_if_in_passwords_history(account, password):
	#Fetch coniguration data
	conf_data = password_configuration.read_configuration()
	history_num_check = int(conf_data['passwordHistory'])
	for i in range(1, history_num_check+1):
		i_pswd_prefix = "password_hist" + str(i)
		i_salt_prefix = "salt_hist" + str(i)
		salt = codecs.decode(account[i_salt_prefix], 'hex_codec')		
		hash_new_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000).hex()
		past_pswd = account[i_pswd_prefix]
		if hash_new_password == past_pswd:
			return True
	return False


# -------- reset_password --------
# here the user can ask for a reset code via email in order to cahnge his password (in case it's forgotten)
@app.route('/reset_password', methods =['GET', 'POST'])
def reset_password():
	msg = ''
	if request.method == 'POST' and 'email' in request.form:
		username = request.form['username']
		email = request.form['email']
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM accounts WHERE email = % s AND username = %s', (email, username))
		account = cursor.fetchone()
		session['username'] = account['username']
		if account:
			#Generate a code with random value
			reset_pass = str(random.randrange(100000,999999))
			#Hash it using SHA-1 as intructed, and save the hashed code in DB
			hash_rst_pass = hashlib.sha1(reset_pass.encode('utf-8')).hexdigest()
			cursor.execute('UPDATE accounts SET reset_code = %s WHERE email = %s', (hash_rst_pass, email,))
			mysql.connection.commit()
			#Send email to user with the code
			email_info = Message('Password Reset', sender='naticoding@gmail.com', recipients=[email])
			email_info.body = 'Use this to reset your password:\n' + reset_pass
			mail.send(email_info)
			msg = 'Reset code was  sent to the email you entered'
			return render_template('reset_password_con.html', msg=msg)
		elif not username or not email:
			msg= 'Please fill the form!'
		else:
			msg = 'Invalid user/email address!'
	return render_template('reset_password.html', msg = msg)

# -------- reset_password_continue --------
# here the user fills the code he got in email
# in case of success, the user goes to 'change_password' page
@app.route('/reset_password_con', methods =['GET', 'POST'])
def reset_password_con():
	msg = ''
	if request.method == 'POST' and 'rst_code' in request.form:
		rst_code = request.form['rst_code']		
		hash_rst_pass = hashlib.sha1(rst_code.encode('utf-8')).hexdigest()
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM accounts WHERE reset_code = %s', (hash_rst_pass, ))
		account = cursor.fetchone()
		if account['reset_code'] == hash_rst_pass:
			msg = 'Correct reset code!\n Enter new password:'
			session['username'] = account['username']
			return render_template('change_password_reset.html', msg=msg)
		elif not rst_code:
			msg = 'Please put in the code'
		else:
			msg = 'Invalid reset code!'
	return render_template('reset_password.html', msg = msg)

# -------- change_password_reset --------
# here the user can change his password
# accessible from reset_password after reset code validation
@app.route('/change_password_reset', methods =['GET', 'POST'])
def change_password_reset():
	#Fetch coniguration data
	conf_data = password_configuration.read_configuration()
	msg = ''
	if request.method == 'POST':
		#Get the values the user entered
		username = session['username']
		new_password1 = request.form['new_password1']
		new_password2= request.form['new_password2']
		#Get the user's detalis from DB
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
		cursor.execute('SELECT * FROM accounts WHERE username = %s', (username, ))
		account = cursor.fetchone()
		#Password checks
		if new_password1 != new_password2:
			msg = 'Entered passwords does not match!'
		elif conf_data['CheckCommonValues'] and new_password1 in password_configuration.get_common_passwords():
			msg = 'Weak password! (very common..)'
		elif len(new_password1) < conf_data['passwordMinLength']:
			msg = 'Password is too short'
		elif not any (char.isdigit() for char in new_password1):
			msg = 'You must use at least one digit in password'
		elif not any (char.isupper() for char in new_password1):
			msg = 'You must use at least one upper-case char in password'
		elif not any (char.islower() for char in new_password1):
			msg = 'You must use at least one lower-case char in password'
		elif not any (char in conf_data['mustToHaveChars'] for char in new_password1):
			msg = 'You must use at least one special-case char in password'
		elif check_if_in_passwords_history(account, new_password1):
			msg = 'You already used this password before'
			return render_template('change_password_reset.html', msg = msg)
		else:
			new_salt = os.urandom(32)
			salt_hash_new_pass = hashlib.pbkdf2_hmac('sha256', new_password1.encode('utf-8'), new_salt, 100000).hex()
			#set vars for understandable SQL oreder
			new_pass = salt_hash_new_pass
			pass_hist1 = account['password']
			pass_hist2 = account['password_hist1']
			pass_hist3 = account['password_hist2']
			new_salt = new_salt.hex()
			salt_hist1 = account['curr_salt']
			salt_hist2 = account['salt_hist1']
			salt_hist3 = account['salt_hist2']

			cursor.execute('UPDATE accounts SET password = %s ,password_hist1 =%s, password_hist2 =%s, password_hist3 =%s, curr_salt=%s, salt_hist1  = %s, salt_hist2  = %s, salt_hist3  = %s, login_attempts=%s WHERE username = % s',
			(new_pass, pass_hist1, pass_hist2, pass_hist3, new_salt, salt_hist1, salt_hist2, salt_hist3, 0, username, ))
			mysql.connection.commit()
			msg = 'Password was changed successfully!'
			session['loggedin'] = True
			session['id'] = account['id']
			session['username'] = account['username']
			return render_template('user_page.html', msg = msg)
	return render_template('change_password_reset.html', msg = msg)

# -------- Logout page --------
@app.route('/logout')
def logout():
	session.pop('loggedin', None)
	session.pop('id', None)
	session.pop('username', None)
	return redirect(url_for('login'))


# -------- Add customer page --------
@app.route('/add_customer', methods =['GET', 'POST'])
def add_customer():
	msg = ''
	conf_data = password_configuration.read_configuration()
	if 'loggedin' in session:
		if request.method == 'POST' and 'username' in request.form and 'email' in request.form :
			#Get the values the user entered
			#This command allowes XSS
			if(conf_data['enableXSS']):
				username = request.form['username']
				email = request.form['email']
			else:
				#This command prevetns XSS
				username = html.escape(request.form['username'])
				email = html.escape(request.form['email'])
			#Connection to DB
			cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
			if(conf_data['enableSqli']):
				#This command allowes SQLI
				cursor.execute("SELECT * FROM customers WHERE cust_name = '"+username+"' AND cust_email ='"+email+"'")
			else:
				#This command prevetns SQLI
				cursor.execute("SELECT * FROM customers WHERE cust_name = %s AND cust_email = %s", (username, email,))
			account = cursor.fetchone()
			if account:
				msg = 'Account already exists!'
				return render_template('add_customer.html', msg = msg)
			#Email validation check
			elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
				msg = 'Invalid email address!'
			#Details check
			elif not username or not email:
				msg = 'Please fill out the form!'
			else:
				#In case all input details are valid
				cursor.execute('INSERT INTO customers (cust_name, cust_email, registered_by) VALUES (%s,%s, %s)',
								(username,  email, session['username'],))
				mysql.connection.commit()
				if(conf_data['enableXSS']):
					cursor.execute("SELECT * FROM customers WHERE cust_name = %s AND cust_email = %s", (username, email,))
					customer = cursor.fetchone()
					cust_name = customer['cust_name']
					cust_email = customer['cust_email']
					msg = f'Customer: {cust_name} with email: {cust_email} was added successfully!'
				else:
					msg = f'Customer: {username} with email: {email} was added successfully!'
				return render_template('add_customer.html', msg = msg)
		elif request.method == 'POST':
			msg = 'Please fill out the form!'
	else:
		msg = 'You must be logged in to enter change password page'
		return render_template('login.html', msg = msg) 
	return render_template('add_customer.html', msg = msg)




if __name__ == "__main__":
    app.run(ssl_context = context, debug=True)


