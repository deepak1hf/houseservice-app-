from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to something secure
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login page if user is not authenticated

from flask_login import UserMixin

# Mock data for services
services = {
    "home_cleaning": {"title": "Home Cleaning", "description": "Thorough cleaning of your home.", "price": "$100", "availability": "Available"},
    "plumbing": {"title": "Plumbing", "description": "Fix plumbing issues, leaks, etc.", "price": "$150", "availability": "Available"}
}

# Mock data for sub-service history
service_history = {
    "home_cleaning": [
        'Deep Cleaning - January 2024',
        'General Cleaning - December 2023',
        'Carpet Cleaning - November 2023'
    ],
    "plumbing": [
        'Pipe Fix - February 2024',
        'Drain Unclogging - January 2024',
        'Faucet Repair - December 2023'
    ]
}
class User(db.Model, UserMixin):  # Inherit UserMixin from Flask-Login
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # Role: Admin, Customer, Service Professional

    # Flask-Login expects these methods to be implemented:

    def is_active(self):
        return True  # Return True for all users, but you can implement this based on user status

    def is_authenticated(self):
        return True  # Return True if user is authenticated (can be based on session/permissions)

    def get_id(self):
        return str(self.id)  # Flask-Login uses this to get the user's ID (must return a string)

    def is_anonymous(self):
        return False  # Return False to indicate the user is not anonymous

# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Home route
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/services')
def services():
    # Replace with actual data for your services (could be fetched from a database)
    services_data = [
        {
            'name': 'Professional Home Cleaning',
            'image': 'static/images/Cleaning.jpg',
            'description': 'Our home cleaning service offers thorough, regular, or deep cleaning for any part of your house. We ensure a spotless, hygienic, and safe environment for you and your family.'
        },
        {
            'name': 'Expert Plumbing',
            'image': 'static/images/Plumbing.jpg',
            'description': 'From fixing leaks to full plumbing installations, our expert plumbers handle all types of plumbing needs. We guarantee fast, reliable, and professional service.'
        },
        {
            'name': 'Electrical Repairs',
            'image': 'static/images/Electrician.jpg',
            'description': 'Whether it’s a faulty light fixture or a complete rewiring project, our certified electricians offer expert electrical services to ensure your home is safe and functional.'
        }
    ]
    return render_template('services.html', services=services_data)  # Pass the services data to the template

# Custom 404 error handler
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404  # Ensure 404.html exists in templates

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)  # Log in the user

            # Redirect based on role
            if user.role == 'Admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'Service Professional':
                return redirect(url_for('professional_dashboard'))
            elif user.role == 'Customer':
                return redirect(url_for('customer_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        # Hash the password using the correct method
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create a new user
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

# Admin Dashboard
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'Admin':
        flash('You are not authorized to view this page', 'danger')
        return redirect(url_for('home'))

    users = User.query.all()  # Fetch all users from the database
    total_users = len(users)
    active_services = 5  
    pending_requests = 3  
    completed_tasks = 8  

    return render_template(
        'admin_dashboard.html', 
        users=users, 
        total_users=total_users, 
        active_services=active_services, 
        pending_requests=pending_requests,
        completed_tasks=completed_tasks
    )

# Professional Dashboard
@app.route('/professional_dashboard')
@login_required
def professional_dashboard():
    if current_user.role != 'Service Professional':
        flash('You are not authorized to view this page', 'danger')
        return redirect(url_for('home'))
    return render_template('professional_dashboard.html')

@app.route('/customer_dashboard')
@login_required  # This ensures the user must be logged in to access this page
def customer_dashboard():
    return render_template('customer_dashboard.html', user=current_user)


@app.route('/plumbing_service')
def plumbing_service():
    history = service_history['plumbing']
    return render_template('plumbing_service.html', history=history)

@app.route('/cleaning_service')
def cleaning_service():
    history = service_history['home_cleaning']
    return render_template('cleaning_service.html', history=history)


# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()  # Log out the current user
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# Error handling for undefined routes
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Create the database and tables inside the application context
if __name__ == '__main__':
    with app.app_context(): 
        db.create_all()  # Create database tables
    app.run(debug=True)
