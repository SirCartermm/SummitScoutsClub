from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Create the Flask app instance
app = Flask(__name__)

# Configure the database URI (from .env)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///SummitScoutsClub.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Example route
@app.route('/')
def home():
    return "Hello, World!"

if __name__ == '__main__':
    app.run()