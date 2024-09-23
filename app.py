from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from flask_bcrypt import Bcrypt
import pyotp
import qrcode
import io
from base64 import b64encode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'
login_manager = LoginManager()
login_manager.init_app(app)
bcrypt = Bcrypt(app)

# Dummy user database
users = {}

# Generate RSA keys for digital signatures
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

class User(UserMixin):
    def __init__(self, email):
        self.id = email

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_email(self, email):
        if email.data in users:
            raise ValidationError('Email is already registered.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class MFAForm(FlaskForm):
    token = StringField('Token', validators=[DataRequired()])
    submit = SubmitField('Verify')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        totp_secret = pyotp.random_base32()
        users[email] = {'password': password, 'totp_secret': totp_secret}
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        if email in users and bcrypt.check_password_hash(users[email]['password'], password):
            user = User(email)
            login_user(user)
            return redirect(url_for('mfa'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/mfa', methods=['GET', 'POST'])
@login_required
def mfa():
    form = MFAForm()
    if form.validate_on_submit():
        token = form.token.data
        totp = pyotp.TOTP(users[current_user.id]['totp_secret'])
        if totp.verify(token):
            session['mfa_authenticated'] = True
            return redirect(url_for('protected'))
        else:
            flash('Invalid token. Please try again.', 'danger')
    return render_template('mfa.html', form=form)

@app.route('/protected')
@login_required
def protected():
    if not session.get('mfa_authenticated'):
        return redirect(url_for('mfa'))
    return 'Protected content'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('mfa_authenticated', None)
    return redirect(url_for('login'))

@app.route('/qrcode')
@login_required
def qrcode_route():
    totp = pyotp.TOTP(users[current_user.id]['totp_secret'])
    uri = totp.provisioning_uri(current_user.id, issuer_name="YourApp")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf)
    img_b64 = b64encode(buf.getvalue()).decode('utf-8')
    return f'<img src="data:image/png;base64,{img_b64}">'

@app.route('/sign', methods=['POST'])
@login_required
def sign_data():
    data = request.form['data']
    signature = private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signature_b64 = b64encode(signature).decode('utf-8')
    return {'signature': signature_b64}

@app.route('/verify', methods=['POST'])
@login_required
def verify_data():
    data = request.form['data']
    signature_b64 = request.form['signature']
    signature = b64decode(signature_b64)
    try:
        public_key.verify(
            signature,
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {'status': 'verified'}
    except Exception as e:
        return {'status': 'failed', 'reason': str(e)}

@app.route('/hash', methods=['POST'])
@login_required
def hash_data():
    data = request.form['data']
    hash_object = hashlib.sha256(data.encode())
    hash_hex = hash_object.hexdigest()
    return {'hash': hash_hex}

if __name__ == '__main__':
    app.run(debug=True)
