from werkzeug.security import generate_password_hash, check_password_hash
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response, abort, send_file, send_from_directory
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from cryptography.fernet import Fernet, InvalidToken
import os, io 
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import SubmitField
from sqlalchemy.exc import SQLAlchemyError
from flask_mail import Mail
import secrets
from flask_mail import Message


app = Flask(__name__)
app.config['SECRET_KEY'] = 'grhfgksddsadasdasdsddccdddddddnnnsilsdjfijseilsdjfl'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    pin = db.Column(db.String(6))  
    files = db.relationship('File', backref='user', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    encrypted_name = db.Column(db.String(100), nullable=False)
    encrypted_content = db.Column(db.LargeBinary, nullable=False)
    key = db.Column(db.String(255), nullable=False) 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    @property
    def size_in_mb(self):
        return len(self.encrypted_content) / (1024 * 1024)

class SharedDownloadForm(FlaskForm):
    key_file = FileField('Key File', validators=[FileRequired()])
    submit = SubmitField('Download')

    def __init__(self, name, encrypted_name, encrypted_content, key, user_id):
        self.name = name
        self.encrypted_name = encrypted_name
        self.encrypted_content = encrypted_content
        self.key = key
        self.user_id = user_id

class KeyUploadForm(FlaskForm):
    key_file = FileField('Key File', validators=[FileRequired()])
    submit = SubmitField('Submit Key')


ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp3', 'mp4'} 

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def base():
    
    return render_template('index.html')



@app.route('/home')
@login_required
def home():
    
    user_files = File.query.filter_by(user_id=current_user.id).all()
    
    success_message = request.args.get('success_message')
    return render_template('home.html', files=user_files, success_message=success_message)
    
    

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        pin = request.form['pin'] 

        # Check if the user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error_message = "User already exists. Please choose a different username."
            return render_template('register.html', error_message=error_message)

        # If the user doesn't exist, proceed with registration
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        encrypted_password = cipher_suite.encrypt(password.encode())

        hashed_password = generate_password_hash(password)
        user = User(username=username, email=email, password=hashed_password, pin=pin)
        db.session.add(user)
        db.session.commit()

        print('User registered successfully:', username)
        logging.info('User registered successfully')

        return redirect(url_for('login', success_message='Registration Successful'))

    return render_template('register.html')

@app.route('/services', methods=['GET','POST'])
@login_required
def services():
    return render_template('services.html')

@app.route('/service', methods=['GET','POST'])
def service():
    return render_template('service.html')


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)
            flash('You have been logged in!', 'success')
            return redirect(url_for('home', success_message='Login Successful'))

        else:
            error_message = "Invalid username or password. Please try again."
            return render_template('login.html', error_message=error_message)

    return render_template('login.html', login_error=True)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out!', 'success')
    return redirect(url_for('login'))

@app.route('/download_key/<int:file_id>', methods=['GET', 'POST'])
@login_required
def download_key(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        abort(403)
    if file:
        key_content = file.key
        return send_file(io.BytesIO(key_content), as_attachment=True, download_name=f'{file.name}.key')

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        try:
            uploaded_file = request.files['file']
            if uploaded_file.filename == '':
                flash('No file selected for upload', 'error')
                return redirect(request.url)
            
            filename = secure_filename(uploaded_file.filename)
            encrypted_filename = f'encrypted_{filename}'

            key = Fernet.generate_key()
            cipher_suite = Fernet(key)

            file_content = uploaded_file.read()
            encrypted_content = cipher_suite.encrypt(file_content)

            new_file = File(
                name=filename,
                encrypted_name=encrypted_filename,
                encrypted_content=encrypted_content,
                key=key,
                user_id=current_user.id
            )

            db.session.add(new_file)
            db.session.commit()

            flash('File uploaded and encrypted successfully!', 'success')

            return redirect(url_for('download_key', file_id=new_file.id))
        except Exception as e:
            print(f'An error occurred: {str(e)}', 'error')
            return redirect(request.url)

    return render_template('upload.html')

from flask import jsonify

@app.route('/delete_file/<int:file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    try:
        file = File.query.get(file_id)
        if file:
            db.session.delete(file)
            db.session.commit()
            return jsonify({'message': 'File deleted successfully'}), 200
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/downloadpage', methods=['GET', 'POST'])
@login_required
def downloadpage():
    files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('downloadpage.html', files=files)




@app.route('/download/<int:file_id>', methods=['GET', 'POST'])
@login_required
def download(file_id):
    file = File.query.get_or_404(file_id)

    key_upload_form = KeyUploadForm()

    if request.method == 'POST' and key_upload_form.validate_on_submit():
        uploaded_key = key_upload_form.key_file.data.read()
        cipher_suite = Fernet(file.key)

        try:
            
            decrypted_content = cipher_suite.decrypt(file.encrypted_content)
            if uploaded_key == file.key:
                response = make_response(decrypted_content)
                response.headers["Content-Disposition"] = f"attachment; filename={file.name}"
                response.headers["Content-Type"] = "application/octet-stream"

                return response
            else:
                error_message = "Invalid key. Please try again."

        except InvalidToken as e:
            flash('Invalid key', 'danger')

    return render_template('download.html', file=file, key_upload_form=key_upload_form, error_message=error_message)

@app.route('/upload-key/<int:file_id>', methods=['GET', 'POST'])
@login_required
def uploadkey(file_id):
    file = File.query.get_or_404(file_id)
    key_upload_form = KeyUploadForm()

    if request.method == 'POST' and key_upload_form.validate_on_submit():
        uploaded_key = key_upload_form.key_file.data.read()
        cipher_suite = Fernet(file.key)
        
        try:
            decrypted_content = cipher_suite.decrypt(file.encrypted_content)
            if uploaded_key == file.key:
                matching_files = [(file, decrypted_content)]
            else:
                # If uploaded key doesn't match the file's key, show error message
                flash('Wrong key provided', 'danger')
                return render_template('upload-key.html', key_upload_form=key_upload_form)
        except InvalidToken:
            # If decryption fails, show error message
            flash('Invalid key provided', 'danger')
            return render_template('upload-key.html', key_upload_form=key_upload_form)

        return render_template('download.html', matching_files=matching_files, key_upload_form=key_upload_form)

    return render_template('upload-key.html', key_upload_form=key_upload_form)

@app.route('/shared', methods=['GET', 'POST'])
@login_required
def shared():
    key_upload_form = KeyUploadForm()

    if request.method == 'POST' and key_upload_form.validate_on_submit():
        uploaded_key = key_upload_form.key_file.data.read()

        files = File.query.all()
        matching_files = []

        for file in files:
            cipher_suite = Fernet(file.key)
            try:
                decrypted_content = cipher_suite.decrypt(file.encrypted_content)
                if uploaded_key == file.key:
                    matching_files.append((file, decrypted_content))
                    break  
            except InvalidToken:
                continue

        if not matching_files:
            flash('No matching file found', 'danger')

        return render_template('download_shared.html', matching_files=matching_files, key_upload_form=key_upload_form)

    return render_template('shared.html', key_upload_form=key_upload_form)

@app.route('/reset_password', methods=['GET', 'POST'])
@login_required
def reset_password():
    if request.method == 'POST':
        pin = request.form['pin']

        # Verify the PIN
        if current_user.pin != pin:
            flash('Invalid PIN. Please try again.', 'error')
            error_message='Invaild Security Pin'
            return redirect(url_for('reset_password', error_message=error_message))

        return redirect(url_for('set_new_pass'))
    return render_template('reset_password.html')

@app.route('/set_new_pass', methods=['GET', 'POST'])
@login_required
def set_new_pass():
    if request.method == 'POST':
        new_pass = request.form['new_pass']
        
        # Encrypting the password
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        encrypted_password = cipher_suite.encrypt(new_pass.encode()).decode()  # Encrypt and decode to store as string
        
        # Hashing the password
        hashed_password = generate_password_hash(new_pass)

        try:
            user = User.query.filter_by(id=current_user.id).first()  # Assuming current_user is available
            user.password = hashed_password
            user.encrypted_password = encrypted_password  # Assuming there's a field 'encrypted_password' in User model
            db.session.commit()

            flash('Password reset successfully.', 'success')
            return redirect(url_for('home', success_message='Password Changed Successfully'))
        except SQLAlchemyError as e:
            flash('Error updating password: {}'.format(str(e)), 'error')
            db.session.rollback()

    return render_template('set_new_pass.html')


@app.route('/download_shared/<int:file_id>', methods=['GET','POST'])
@login_required
def download_shared(file_id):
    file = File.query.get_or_404(file_id)
    
    cipher_suite = Fernet(file.key)
    decrypted_content = cipher_suite.decrypt(file.encrypted_content)

    response = make_response(decrypted_content)
    response.headers["Content-Disposition"] = f"attachment; filename={file.name}"
    response.headers["Content-Type"] = "application/octet-stream"

    flash(f'Downloading {file.name} by {file.user.username}', 'success')
    return response

@app.route('/view_files')
@login_required
def view_files():
    files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('view_files.html', files=files)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/recover_key/<int:file_id>', methods=['GET', 'POST'])
@login_required
def recover_key(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        abort(403)
    
    if request.method == 'POST':
        pin = request.form['pin'] 
        
        
        if current_user.pin != pin:
            error_message = "Invalid pin. Please try again."
            return redirect(url_for('recover_key', file_id=file_id, error_message=error_message))
        else:
            # If PIN is valid, proceed with key recovery logic
            key = file.key  # Assuming you have a 'key' attribute in your 'File' model
            return redirect(url_for('download_key', file_id=file.id))
    
    # This will handle the GET request case
    return render_template('recover_key.html', file=file)

@app.route('/delete_account', methods=['POST'])  # Update to accept POST requests
@login_required
def delete_account():
    try:
        pin = request.form.get('pin')

        # Check if the security code matches the user's actual security code
        if pin != current_user.pin:
            flash('Incorrect security code. Account deletion failed.', 'error')
            return redirect(url_for('profile',error_message='Incorrect security code. Account deletion failed.'))

        # Delete the current user account
        db.session.delete(current_user)
        db.session.commit()
        
        # Log out the user after deleting the account
        logout_user()
        
        flash('Your account has been successfully deleted.', 'success')
        return redirect(url_for('login', success_message='Account deleted successfully'))
    except Exception as e:
        flash('An error occurred while deleting your account. Please try again later.', 'error')
        return redirect(url_for('profile'))

    

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        app.run(debug=True)