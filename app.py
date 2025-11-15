from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Inquiry

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///george_yachts.db'
db.init_app(app)

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Auth routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already taken!', 'error')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))

# Protected routes
@app.route('/dashboard')
@login_required
def dashboard():
    inquiries = Inquiry.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', inquiries=inquiries)

@app.route('/contact', methods=['GET', 'POST'])
@login_required
def contact():
    if request.method == 'POST':
        service = request.form['service']
        message = request.form['message']
        inquiry = Inquiry(user_id=current_user.id, service=service, message=message)
        db.session.add(inquiry)
        db.session.commit()
        flash('Inquiry submitted!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('contact.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)



from flask_mail import Mail, Message
from utils import generate_token, verify_token

# Flask-Mail setup
app.config['MAIL_SERVER'] = 'smtp.example.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@example.com'
app.config['MAIL_PASSWORD'] = 'your-password'
mail = Mail(app)

# Password reset routes
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_token(user.email)
            reset_url = url_for('reset_token', token=token, _external=True)
            msg = Message('Password Reset Request', sender='noreply@georgeyachts.com', recipients=[user.email])
            msg.body = f'''To reset your password, visit:
{reset_url}
This link expires in 1 hour.'''
            mail.send(msg)
            flash('Reset link sent to your email.', 'info')
        else:
            flash('Email not found.', 'error')
    return render_template('auth/reset_request.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    email = verify_token(token)
    if not email:
        flash('Invalid or expired token.', 'error')
        return redirect(url_for('reset_request'))

    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        user.set_password(request.form['password'])
        db.session.commit()
        flash('Password updated! Log in now.', 'success')
        return redirect(url_for('login'))

    return render_template('auth/reset_token.html', token=token)

# Admin routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied.', 'error')
        return redirect(url_for('home'))
    users = User.query.all()
    inquiries = Inquiry.query.all()
    return render_template('admin/dashboard.html', users=users, inquiries=inquiries)   

from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

# Flask-WTF form for CAPTCHA
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Register')

# Logging utility
def log_action(user_id, action, ip):
    log = Log(user_id=user_id, action=action, ip_address=ip)
    db.session.add(log)
    db.session.commit()

# Admin promotion route
@app.route('/admin/promote/<int:user_id>', methods=['GET', 'POST'])
@login_required
def promote_user(user_id):
    if not current_user.is_admin:
        flash('Access denied.', 'error')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.is_admin = not user.is_admin
        db.session.commit()
        action = f"Promoted/demoted user {user.username} (Admin={user.is_admin})"
        log_action(current_user.id, action, request.remote_addr)
        flash(action, 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin/promote.html', user=user)

# Updated login route with logging
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            log_action(user.id, "Logged in", request.remote_addr)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            log_action(None, f"Failed login attempt for {username}", request.remote_addr)
            flash('Invalid username or password.', 'error')

    return render_template('auth/login.html')