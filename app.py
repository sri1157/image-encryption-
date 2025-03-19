import os
import struct
import numpy as np
import mysql.connector
import re
from flask import Flask, request, send_file, render_template, session, redirect, url_for, flash
from PIL import Image
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2 import PasswordHasher
from smtplib import SMTP
from flask_mail import Mail, Message 

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Use a random secret key for production

# MySQL database configuration
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="virgo18",
    database="miniproject"
)
cursor = db.cursor()

# Password hasher
ph = PasswordHasher()

# Password validation functions
def validate_password(password):
    if (len(password) < 8 or
        not re.search(r"[A-Z]", password) or
        not re.search(r"[a-z]", password) or
        not re.search(r"[0-9]", password) or
        not re.search(r"[!@#$%^&*()_]", password)):
        return False
    return True

def validate_encryption_password(encryption_password):
    return len(encryption_password) >= 6

def is_username_or_email_taken(username, email):
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s OR email = %s", (username, email))
    return cursor.fetchone()[0] > 0

# Generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def save_rsa_keys(user_id, private_key, public_key):
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    cursor.execute("INSERT INTO userkeys (user_id, rsa_public_key, rsa_private_key) VALUES (%s, %s, %s)",
                   (user_id, public_key_bytes, private_key_bytes))
    db.commit()

def encrypt_rsa(public_key, aes_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_rsa(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def pad_data(data):
    pad_length = 16 - (len(data) % 16)
    return data + bytes([pad_length] * pad_length)

def unpad_data(data):
    pad_length = data[-1]
    return data[:-pad_length]

def generate_noise_image(shape, path):
    noise = np.random.randint(0, 256, shape, dtype=np.uint8)
    noise_image = Image.fromarray(noise)
    noise_image.save(path)

def encrypt_image(image_path, original_filename, user_id):
    image = Image.open(image_path)
    image_data = np.array(image)
    original_shape = image_data.shape
    original_shape_bytes = struct.pack('iii', *original_shape)

    aes_key = os.urandom(32)  # 256-bit key

    cursor.execute("SELECT rsa_private_key, rsa_public_key FROM userkeys WHERE user_id = %s", (user_id,))
    keys = cursor.fetchone()

    if keys is None:
        private_key, public_key = generate_rsa_keys()
        save_rsa_keys(user_id, private_key, public_key)
    else:
        private_key = serialization.load_pem_private_key(keys[0].encode('utf-8'), password=None, backend=default_backend())
        public_key = serialization.load_pem_public_key(keys[1].encode('utf-8'), backend=default_backend())

    encrypted_aes_key = encrypt_rsa(public_key, aes_key)
    iv = os.urandom(16)  # Random IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    flattened_data = image_data.flatten().astype(np.uint8)
    padded_data = pad_data(flattened_data.tobytes())
    encrypted_image = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_image_with_metadata = iv + encrypted_aes_key + original_shape_bytes + encrypted_image
    
    bin_file_path = f"static/uploads/user_{user_id}/{os.path.splitext(original_filename)[0]}_encrypted.bin"
    os.makedirs(os.path.dirname(bin_file_path), exist_ok=True)
    with open(bin_file_path, 'wb') as bin_file:
        bin_file.write(encrypted_image_with_metadata)

    encrypted_image_path = f"static/uploads/user_{user_id}/{os.path.splitext(original_filename)[0]}_encrypted_visual.png"
    generate_noise_image(image_data.shape, encrypted_image_path)

    cursor.execute("INSERT INTO images (user_id, file_path, bin_file_path, original_filename, upload_date) VALUES (%s, %s, %s, %s, NOW())",
                   (user_id, encrypted_image_path, bin_file_path, original_filename))
    db.commit()

    return encrypted_image_path

def decrypt_image(bin_file_path, user_id):
    with open(bin_file_path, 'rb') as bin_file:
        encrypted_bin_path = bin_file.read()

    iv = encrypted_bin_path[:16]
    encrypted_aes_key = encrypted_bin_path[16:16 + 256]
    original_shape_bytes = encrypted_bin_path[16 + 256:16 + 256 + 12]
    encrypted_image_content = encrypted_bin_path[16 + 256 + 12:]

    cursor.execute("SELECT rsa_private_key FROM userkeys WHERE user_id = %s", (user_id,))
    private_key_row = cursor.fetchone()

    if private_key_row is None:
        raise Exception("No RSA private key found for this user.")

    private_key_str = private_key_row[0].encode('utf-8')

    private_key = serialization.load_pem_private_key(
        private_key_str,
        password=None,
        backend=default_backend()
    )

    aes_key = decrypt_rsa(private_key, encrypted_aes_key)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_image_content) + decryptor.finalize()
    unpadded_data = unpad_data(decrypted_data)

    original_shape = struct.unpack('iii', original_shape_bytes)
    image_array = np.frombuffer(unpadded_data, dtype=np.uint8).reshape(original_shape)

    decrypted_image_path = f"static/uploads/decrypted_image.png"  # You might want to keep original filename or add a suffix
    Image.fromarray(image_array).save(decrypted_image_path)

    return decrypted_image_path

@app.route('/')
def first():
    return render_template('first.html')



import logging

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        encryption_password = request.form.get('encryption_password')

        # Validate inputs
        if not validate_password(password):
            flash("Password must be at least 8 characters long and contain uppercase letters, lowercase letters, numbers, and special characters.", "danger")
            return redirect(url_for('register'))  # Ensure redirect to the registration page

        if not validate_encryption_password(encryption_password):
            flash("Encryption password must be at least 6 characters long.", "danger")
            return redirect(url_for('register'))

        if is_username_or_email_taken(username, email):
            flash("Username or email already taken. Please choose another.", "danger")
            return redirect(url_for('register'))

        try:
            hashed_password = ph.hash(password)
            hashed_encryption_password = ph.hash(encryption_password)

            cursor.execute(
                "INSERT INTO users (username, email, password, encryption_password) VALUES (%s, %s, %s, %s)",
                (username, email, hashed_password, hashed_encryption_password)
            )
            db.commit()

            user_id = cursor.lastrowid

            private_key, public_key = generate_rsa_keys()
            save_rsa_keys(user_id, private_key, public_key)

            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            logging.error(f"Error during registration: {e}")
            flash("An error occurred. Please try again.", "danger")
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Query to retrieve the user's hashed password
        cursor.execute("SELECT user_id, password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        # Check if user exists and verify password
        if user and ph.verify(user[1], password):
            session['user_id'] = user[0]  # Store user_id in session
            flash("Login successful!", "success")
            return redirect(url_for('encrypt'))  # Redirect to user's data page after successful login
        else:
            flash("Invalid username or password.", "danger")
            return redirect(url_for('login'))  # Redirect to login page for re-entry

    return render_template('login.html')

@app.route('/encrypt')
def encrypt():
    return render_template('encrypt.html') 

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        flash("Please log in to upload images.", "danger")
        return redirect(url_for('encrypt'))

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        flash("No selected file.", "danger")
        return redirect(url_for('your_data'))

    encryption_password = request.form['encryption_password']

    # Get the user's stored encryption password
    cursor.execute("SELECT encryption_password FROM users WHERE user_id = %s", (session['user_id'],))
    user = cursor.fetchone()

    if user is None or not ph.verify(user[0], encryption_password):
        flash("Invalid encryption password.", "danger")
        return redirect(url_for('your_data'))

    original_filename = uploaded_file.filename
    uploaded_file.save(os.path.join('static/uploads', original_filename))

    image_path = os.path.join('static/uploads', original_filename)
    encrypted_image_path = encrypt_image(image_path, original_filename, session['user_id'])
    
    flash("Image uploaded and encrypted successfully! Go to Your Data to view the encrypted image ", "success")
    return redirect(url_for('encrypt'))

@app.route('/decrypt_route', methods=['POST'])
def decrypt_route():
    if 'user_id' not in session:
        flash("Please log in to decrypt images.", "danger")
        return redirect(url_for('encrypt'))

    bin_file_path = request.form['bin_file_path']
    encryption_password = request.form['encryption_password']

    # Get the user's stored encryption password
    cursor.execute("SELECT encryption_password FROM users WHERE user_id = %s", (session['user_id'],))
    user = cursor.fetchone()

    if user is None or not ph.verify(user[0], encryption_password):
        flash("Invalid encryption password.", "danger")
        return redirect(url_for('your_data'))

    decrypted_image_path = decrypt_image(bin_file_path, session['user_id'])
    session['decrypted_image_path'] = decrypted_image_path  # Store path in session
    flash("Image decrypted successfully!", "success")
    return redirect(url_for('your_data'))

@app.route('/your_data')
def your_data():
    if 'user_id' not in session:
        flash("Please log in to view your images.", "danger")
        return redirect(url_for('encrypt'))

    cursor.execute("SELECT file_path, bin_file_path, original_filename FROM images WHERE user_id = %s", (session['user_id'],))
    images = cursor.fetchall()

    # Check if there's a decrypted image path, but don't pop it here
    decrypted_image_path = session.get('decrypted_image_path')  # Just get the value, don't clear it here

    return render_template('your_data.html', images=images, decrypted_image_path=decrypted_image_path)

@app.route('/go_back', methods=['GET'])
def go_back():
    # Clear the decrypted image path when going back
    session.pop('decrypted_image_path', None)  # Clear the decrypted image path
    return redirect(url_for('your_data'))  # Redirect to your_data

@app.route('/delete_image', methods=['POST'])
def delete_image():
    if 'user_id' not in session:
        flash("Please log in to delete images.", "danger")
        return redirect(url_for('encrypt'))

    bin_file_path = request.form['bin_file_path']
    file_path = request.form['file_path']

    # Delete files from the filesystem
    try:
        os.remove(bin_file_path)  # Remove the binary file
        os.remove(file_path)  # Remove the encrypted image file
    except Exception as e:
        flash(f"Error deleting files: {e}", "danger")
        return redirect(url_for('your_data'))

    # Delete record from the database
    cursor.execute("DELETE FROM images WHERE user_id = %s AND bin_file_path = %s", (session['user_id'], bin_file_path))
    db.commit()

    # Clear decrypted image path if it was set
    if 'decrypted_image_path' in session:
        session.pop('decrypted_image_path', None)

    flash("Image deleted successfully!", "success")
    return redirect(url_for('your_data'))

@app.route('/download_decrypted', methods=['GET'])
def download_decrypted():
    if 'user_id' not in session:
        flash("Please log in to download decrypted images.", "danger")
        return redirect(url_for('index'))

    decrypted_image_path = session.get('decrypted_image_path')
    if decrypted_image_path and os.path.exists(decrypted_image_path):
        return send_file(decrypted_image_path, as_attachment=True)
    else:
        flash("No decrypted image available for download.", "danger")
        return redirect(url_for('your_data'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove user_id from the session
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

#About us page
@app.route('/About-us')
def About_us():
    # Get the referrer (previous page) to send back to that page
    referrer = request.referrer or url_for('home')  # Default to home if no referrer exists
    return render_template('About_us.html', referrer=referrer)

#Contact us page
@app.route('/Contact_us', methods=['GET', 'POST'])
def Contact_us():
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        # Compose the email message
        subject = f"Contact Us Form Submission from {name} ({email})"
        body = f"Name: {name}\nEmail: {email}\nMessage: {message}"

        try:
            # Create the message to send contact form data
            msg = Message(subject, recipients=["21E51A6257@hitam.org"])  # Replace with the destination email
            msg.body = body  # Set the body of the email as the contact message

            # Send the email
            mail.send(msg)

            # Flash a success message for the user
            flash("Thank you for contacting us! We will get back to you shortly.", 'success')

        except Exception as e:
            # If something goes wrong, flash an error message
            flash(f"Error sending message: {str(e)}", 'danger')

        # Redirect back to the contact us page (or a thank you page if needed)
        return redirect(request.referrer or url_for('home'))

    return render_template('Contact_us.html')

#feedback page
@app.route('/Feedback')
def Feedback():
    referrer = request.referrer or url_for('home')  # Default to home if no referrer exists
    return render_template('Feedback.html', referrer=referrer)
    

app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Using Gmail SMTP server
app.config['MAIL_PORT'] = 587  # Port for sending emails
app.config['MAIL_USE_TLS'] = True  # Use TLS for security
app.config['MAIL_USE_SSL'] = False  # Use SSL for security
app.config['MAIL_USERNAME'] = '21E51A6257@hitam.org'  # Your email address
app.config['MAIL_PASSWORD'] = '1234567890@V'  # Your email password
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'  # Default sender

mail = Mail(app)

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    # Get feedback data from form
    name = request.form.get('name')
    email = request.form.get('email')
    feedback = request.form.get('feedback')

    # Compose email message
    subject = f"Feedback from {name} ({email})"
    body = f"Name: {name}\nEmail: {email}\nFeedback: {feedback}"
    
    referrer = request.referrer or url_for('home')

    try:
        # Create the message to send feedback
        msg = Message(subject, recipients=["21E51A6257@hitam.org"])  # Replace with destination email
        msg.body = body  # Set the body of the email as the feedback

        # Send the email
        mail.send(msg)

        # Flash a success message for the user
        flash("Thank you for providing valuable feedback. We are committed to continuously improving and your insights play an important role in that process.", 'success')

    except Exception as e:
        # If something goes wrong, flash an error message
        flash(f"Error sending feedback: {str(e)}", 'danger')
        
    return render_template('Feedback.html', referrer=referrer)



if __name__ == '__main__':
    app.run(debug=True)