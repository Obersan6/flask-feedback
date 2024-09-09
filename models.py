"""Models for flask-feedback."""

from sqlalchemy import Column, Integer, String, Text, ForeignKey, table, func
from sqlalchemy.orm import relationship
from flask_sqlalchemy import SQLAlchemy
# from app import app
from flask_bcrypt import Bcrypt

db = SQLAlchemy()

# Initialize Bcrypt
bcrypt = Bcrypt()

def connect_db(app):
    """Connect to database."""
    db.app = app
    db.init_app(app)
    bcrypt.init_app(app) # Initialize bcrypt with the app

# Models

class User(db.Model):
    __tablename__ = 'users'

    username = db.Column(db.String(20), primary_key=True, unique=True)
    password = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)

    # Class method for 'register'
    @classmethod
    def register(cls, username, pwd):
        """Regiser user w/hashed password & return user."""

        hashed = bcrypt.generate_password_hash(pwd)
        # Turn bytestring into normal (unicode utf8) string
        hashed_utf8 = hashed.decode('utf8')

        # Return instance of user w/username & hashed pwd
        return cls(username=username, password=hashed_utf8)

    # Class method for 'authenticate'
    @classmethod
    def authenticate(cls, username, pwd):
        """
        Validate that user exists & password is correct.
        Return user if valid, else return False.
        """

        u = User.query.filter_by(username=username).first()

        if u and bcrypt.check_password_hash(u.password, pwd):
            return u
        else:
            return False
        

class Feedback(db.Model):
    """Creates a new feedback post for a user."""
    __tablename__ = 'feedbacks'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    # foreign key referencing 'username' column in 'users' table
    username = db.Column(db.String(20), db.ForeignKey('users.username'), nullable=False)
    # Set up relationship so feedbacks will be able to access the user, and the user their feedbacks (one-to-many relationship)
    user = db.relationship('User', backref='feedbacks')


    


    



