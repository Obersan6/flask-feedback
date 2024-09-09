"""Flask app for flask-feedback."""

from flask import Flask, request, render_template, redirect, flash, session, url_for
from flask_debugtoolbar import DebugToolbarExtension
from models import db, connect_db, User, Feedback
from forms import RegisterUserForm, LoginForm, AddFeedbackForm, EditFeedbackForm
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

app.config['SECRET_KEY'] = 'abcd123'
app.config['DEBUG_TB_INTERCEPT_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Caccolino5@localhost/feedback'

debug = DebugToolbarExtension(app)

connect_db(app)

# Routes

# Homepage route
@app.route('/')
def homepage():
    return redirect('/register')

# User registration form route
@app.route('/register', methods=['GET', 'POST'])
def register_user():
    """
    GET request:
    - Shows a form that when submitted will register/create a user.
    - This form accepts: a username, password, email, first_name, and last_name. 
    - Using WTForms, to ensure that the password input hides the characters the user is typing.

    POST request:
    - Process the registration form by adding a new user. 
    - Then redirect to 'user_page' route ('/user/<username>').
    """
    form = RegisterUserForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data

        try:
            # New instance of a User with the classmethod 'register'
            new_user = User.register(username, password)
            new_user.email = email
            new_user.first_name = first_name
            new_user.last_name = last_name

            # Add user to the database
            db.session.add(new_user)
            db.session.commit()

            # Add user to the session
            session['username'] = new_user.username

            flash("Your account was successfully created.", "success")
            return redirect(url_for('user_page', username=new_user.username ))

        except IntegrityError:
            # Handle the case when the username or email already exists
            db.session.rollback()  # Rollback the session to clean the transaction
            flash("Username or email already taken. Please try again.", "danger")

    return render_template('register_form.html', form=form)

# User login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    GET request:
    - Show a form that when submitted will login a user. 
    - This form should accept: a 'username' and a 'password'. 
    - Uses WTForms to ensure that the password input hides the characters that the user is typing

    POST request:
    - Processes the login form, ensuring the user is authenticated and redirect4d to 'user_page' route ('/user/<username>'). 
    - If so, it adds some authorization: When a user logs in, takes them to the route '/users/<username'.
    """
    # Instance of the LoginForm class
    form = LoginForm()
    # Post request
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Call the User classmethod 'authenticate' from 'models.py' with that username & passord from the form
        user = User.authenticate(username, password)
        
        if user:
            # Add flash message to inform user succesfully logged in. Add to the session
            flash(f"Welcome back, {user.username}!")
            session['username'] = user.username
            return redirect(url_for('user_page', username=user.username ))
        else:
            form.username.errors = ['Invalid username or password'] # This comes from 'login.html'

    return render_template('login_form.html', form=form)

# The user's page route
@app.route('/user/<username>')
def user_page(username):
    """
    Makes sure that when we log a user in, then it displays a template that shows information about that user: - Everything except for their password.
    - Shows all of the feedback that the user has given: For each piece of feedback, there's a link to a form to edit the feedback and a button to delete the feedback.
    - It has a link that sends to a form to add more feedback.
    - A button to delete the user. 
    """
    # Check if user is logged in
    if 'username' not in session or session['username'] != username:
        flash('You must be logged in to view this page.')
        return redirect(url_for('login'))
    
    # Retrieve the user from the database
    user = User.query.filter_by(username=username).first()
    
    if not user:
        flash('User not found.')
        return redirect(url_for('login'))

    # Retrieve all the user's feedbacks 
    feedbacks = Feedback.query.filter_by(username=username).all()
    
    # Pass the user object to the template for rendering
    return render_template('user_page.html', user=user, feedbacks=feedbacks)

# Route that allows the user to add new feedback through a form
@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    """
    Display a form to add feedback.
    Only the user who is logged in can see this form.

    Add a new piece of feedback and redirect to '/users/<username>'
    Only a logged in user can add feedback.
    """
    # Check if user is logged in
    if 'username' not in session:
        flash('You must login to add a feedback.')
        return redirect(url_for('login'))
    
    # Check if the logged in user matches the username in the URL
    if session['username'] != username:
        flash('You are not authorized to view this page.')
        return redirect(url_for('login'))
    
    # Initialize the form
    form = AddFeedbackForm()

    # Check if it's a POST request and if the form has been submitted succesfully
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data

        try:
            # New Instance of feedback
            new_feedback = Feedback(title=title, content=content, username=username)

            # Add new_feedback to the db
            db.session.add(new_feedback)
            db.session.commit()

            flash('Feedback added successfully', 'success')
            return redirect(url_for('user_page', username=username))

        except IntegrityError:
            # Handle the case when the feedback could not be added
            db.session.rollback()       
            flash("An error occurred", "danger")  

    # Retrieve user from the db
    user = User.query.filter_by(username=username).first_or_404()

    return render_template('add_feedback.html', user=user, form=form)

# Route that allows the user to edit their feedback through a form
@app.route('/feedback/<int:feedback_id>/update', methods=['GET', 'POST'])
def edit_feedback(feedback_id):
    """
    Display a form to edit feedback.
    Only the user who has written feedback can see this form.

    POST request:
    - Updates a specific piece of feedback
    - Redirects to /users/<username>
    """
    
    # Check if user is logged in
    if 'username' not in session:
        flash('You must log in to edit feedback.')
        return redirect(url_for('login'))

    # Retrieve feedback from the db
    feedback = Feedback.query.get_or_404(feedback_id)  

    # Check if the logged-in user is the author of the feedback
    if session['username'] != feedback.username:
        flash('You are not authorized to edit this feedback.')
        return redirect(url_for('homepage'))

    # Initialize the form and populate it with existing feedback data
    form = EditFeedbackForm(obj=feedback)

    # Check if it's a POST request and if the form has been submitted successfully
    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data

        db.session.commit()

        return redirect(url_for('user_page', username=feedback.username))

    return render_template('edit_feedback.html', username=feedback.username, form=form, feedback=feedback)

# Route for the user to delete a feedback 
@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
def delete_feedback(feedback_id):
    """
    Delete a specific feedback.
    Only the user who has written that feedback can delete it.
    """
    # Check if user is logged in
    if 'username' not in session:
        flash('Please login first!')
        return redirect(url_for('login'))
    
     # Retrieve feedback from the db
    feedback = Feedback.query.get_or_404(feedback_id)
    
    # Check if the logged in user is the author of the feedback
    if session['username'] != feedback.username:
        flash('You are not authorized to delete this feedback.')
        return redirect(url_for('login'))
    
    # Delete the feedback
    db.session.delete(feedback)
    db.session.commit()

    return redirect(url_for('user_page', username=session['username']))

# Route to delete a user
@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    """
    Delete user and all their feedback from the db.
    Clear any user info in the session and redirect to '/'.
    Make sure the user who is logged in can delete their account.
    """
    # Condition if user is not logged in
    if 'username' not in session:
        flash("Please login first!")
        return redirect(url_for('login'))
    
    # Check if the logged-in user i the one trying to delete their account
    logged_in_user = session['username']
    if logged_in_user != username:
        flash("You do not have permission to delete this account.")
        return redirect(url_for('homepage'))
    
    # Get the user we want to delete
    user = User.query.get_or_404(username)

    # Delete all feedback associated with the user
    feedbacks = Feedback.query.filter_by(username=username).all()
    for feedback in feedbacks:
        db.session.delete(feedback)
    
    # Delete the user
    db.session.delete(user)
    db.session.commit()

    # Clear the user session
    session.pop('username', None)

    # Redirect to homepage
    return redirect(url_for('homepage'))  

# GET "/logout" : Clear any information from the session and redirect to "/"
@app.route('/logout', methods=['POST'])
def logout():
    """Logout the user by clearing session."""
    
    session.clear()  # Clear all session data
    flash("You have been logged out.", "success")
    return redirect('/')

