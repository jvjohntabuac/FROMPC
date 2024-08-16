import sqlite3
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FileField, TextAreaField
from wtforms.validators import InputRequired, Email, Length
import bcrypt
import base64
from io import BytesIO
from flask_wtf.csrf import CSRFProtect

# Initialize Flask app
app = Flask(__name__)

# Set secret key for session management and CSRF protection
app.secret_key = 'yHjLEqrN3b'

# Configure upload folder for storing images
UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Enable CSRF protection for the app
csrf = CSRFProtect(app)

# Function to establish a database connection
def get_db_connection():
    # Connect to SQLite database 'user_accounts.db'
    conn = sqlite3.connect('user_accounts.db')
    
    # Set the row factory to sqlite3.Row for dictionary-like access to columns
    conn.row_factory = sqlite3.Row
    return conn

# Function to authenticate a user based on username and password
def authenticate(username, password):
    # Establish a database connection
    conn = get_db_connection()
    
    # Query the database for the user's hashed password using their username
    user = conn.execute("SELECT password FROM Users WHERE username = ?", (username,)).fetchone()
    
    # Close the database connection
    conn.close()
    
    # If the user exists, verify the provided password against the stored hash
    if user:
        # Convert the hexadecimal string of the stored password back to bytes
        password_hash_bin = bytes.fromhex(user['password'])
        
        # Check if the provided password matches the stored hash
        if bcrypt.checkpw(password.encode('utf-8'), password_hash_bin):
            return True  # Authentication successful
    return False  # Authentication failed

# FlaskForm class for login
class LoginForm(FlaskForm):
    # Username input field, required
    uname = StringField('Username', validators=[InputRequired()])
    
    # Password input field, required
    psw = PasswordField('Password', validators=[InputRequired()])

# FlaskForm class for signup
class SignupForm(FlaskForm):
    # Email input field, required and must be a valid email
    email = StringField('Email', validators=[InputRequired(), Email()])
    
    # Username input field, required
    newuname = StringField('Username', validators=[InputRequired()])
    
    # Password input field, required and must be at least 6 characters long
    newpsw = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    
    # Confirm password input field, required
    confpsw = PasswordField('Confirm Password', validators=[InputRequired()])

# FlaskForm class for creating a post
class CreatePostForm(FlaskForm):
    # Content input field for text content of the post
    content = TextAreaField('Content')
    
    # File input field for uploading an image
    image = FileField('Image')
    
    # String input field for an optional image URL
    image_url = StringField('Image URL')

# FlaskForm class for updating a profile image
class UpdateProfileForm(FlaskForm):
    # File input field for uploading a profile image
    profile_image = FileField('Profile Image')

# Route for the login page
@app.route('/', methods=['GET', 'POST'])
def login():
    # Initialize the login form
    form = LoginForm()
    
    # Check if the form is submitted and validated
    if form.validate_on_submit():
        # Get the username and password from the form
        username = form.uname.data
        password = form.psw.data
        
        # Authenticate the user
        if authenticate(username, password):
            # Establish a database connection
            conn = get_db_connection()
            
            # Query the user's ID based on their username
            user = conn.execute('SELECT id FROM Users WHERE username = ?', (username,)).fetchone()
            
            # Close the database connection
            conn.close()
            
            # If the user is found, start a session
            if user:
                session['username'] = username
                session['user_id'] = user['id']
                flash('Login successful!')
                
                # Tracing output for debugging
                print('Successfully logged in with user_id:', session['user_id'])
                
                # Redirect to the home page
                return redirect(url_for('home'))
            else:
                # Flash an error if the user is not found
                flash('Login failed: User not found.')
                print('User not found in the database')
        else:
            # Flash an error if authentication fails
            flash('Login failed: Invalid username or password')
            print('Invalid username or password')
    
    # Render the login template with the form
    return render_template('login.html', form=form)

# Route for the signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Initialize the signup form
    form = SignupForm()
    
    # Check if the form is submitted and validated
    if form.validate_on_submit():
        # Get the email, username, and password from the form
        email = form.email.data
        username = form.newuname.data
        password = form.newpsw.data
        confirm_password = form.confpsw.data

        # Check if the passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('signup'))

        # Additional email validation logic
        if not validate_email(email):
            flash('Invalid email address.', 'error')
            return redirect(url_for('signup'))

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Convert the hashed password to a hexadecimal string for storage
        hashed_password_hex = hashed_password.hex()

        # Establish a database connection
        conn = get_db_connection()
        try:
            # Insert the new user into the Users table
            conn.execute("INSERT INTO Users (email, username, password) VALUES (?, ?, ?)", (email, username, hashed_password_hex))
            conn.commit()
            
            # Flash a success message and redirect to the login page
            flash('Account created successfully, please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            # Handle the case where the email or username already exists
            flash(f'Error: That email or username already exists. Details: {e}', 'error')
            print(f'IntegrityError: {e}')
        except sqlite3.Error as e:
            # Handle any other database errors
            flash(f'An unexpected error occurred: {e}', 'error')
            print(f'SQLite Error: {e}')
        finally:
            # Ensure the database connection is closed
            conn.close()
    
    # Render the signup template with the form
    return render_template('signup.html', form=form)

# Function to validate an email address
def validate_email(email):
    # Simple email validation logic (can be expanded)
    return '@' in email and '.' in email

# Route for the home page
@app.route('/home')
def home():
    # Ensure the user is logged in by checking the session
    if 'username' not in session:
        flash('You must be logged in to view the home page.')
        return redirect(url_for('login'))

    # Retrieve the user ID from the session
    user_id = session.get('user_id')
    
    # If the user ID is missing, redirect to logout
    if user_id is None:
        flash('User ID is not available in session.')
        return redirect(url_for('logout'))

    # Establish a database connection
    conn = get_db_connection()
    try:
        # Query the posts from the database with their like counts and whether the current user has liked them
        posts = conn.execute(
            '''SELECT p.id, p.content, p.image_url, p.created_at, u.username,
                      COALESCE(l.like_count, 0) AS like_count,
                      COALESCE(SUM(CASE WHEN l2.user_id = ? THEN 1 ELSE 0 END), 0) AS is_liked_by_current_user
               FROM Posts p
               JOIN Users u ON p.author_id = u.id
               LEFT JOIN (SELECT post_id, COUNT(*) AS like_count FROM PostLikes GROUP BY post_id) l ON p.id = l.post_id
               LEFT JOIN PostLikes l2 ON p.id = l2.post_id
               GROUP BY p.id, p.content, p.image_url, p.created_at, u.username, l.like_count
               ORDER BY p.created_at DESC''',
            (user_id,)
        ).fetchall()
    except sqlite3.OperationalError as e:
        # Handle any errors that occur while querying posts
        flash(f'An error occurred while querying posts: {e}')
        posts = []  # Ensure posts is always defined
    finally:
        # Ensure the database connection is closed
        conn.close()

    # Debugging information to print the session and posts
    print('Session:', session)
    print('Posts:', posts)

    # Render the home template with the username and posts
    return render_template('home.html', username=session['username'], posts=posts)


# Route for creating a new post
@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('You need to be logged in to post.')
        return redirect(url_for('login'))

    form = CreatePostForm()  # Instantiate the form for creating a post
    if form.validate_on_submit():  # Check if the form is submitted and valid
        content = form.content.data  # Get the content of the post from the form
        image = form.image.data  # Get the uploaded image from the form
        image_url = form.image_url.data  # Get the image URL from the form

        # Ensure that at least content or an image is provided
        if not content and not image and not image_url:
            flash('Either post content or an image must be provided.')
            return redirect(url_for('create_post'))

        # Process the image if one was uploaded
        if image and image.filename != '':
            # Convert the image to Base64 format
            image_stream = BytesIO(image.read())
            image_base64 = base64.b64encode(image_stream.getvalue()).decode('utf-8')
            # Create a data URL for the image
            image_url = f"data:image/jpeg;base64,{image_base64}"

        try:
            conn = get_db_connection()  # Open a connection to the database
            # Insert the new post into the Posts table
            conn.execute('''INSERT INTO Posts (author_id, content, image_url) 
                            VALUES (?, ?, ?)''', (session['user_id'], content, image_url))
            conn.commit()  # Commit the transaction
            flash('Your post has been created!')
            return redirect(url_for('home'))  # Redirect to the home page after creating the post
        except sqlite3.OperationalError as e:  # Handle any SQLite errors
            flash(f'An error occurred: {e}')
            return redirect(url_for('create_post'))  # Redirect to the create post page on error
        finally:
            conn.close()  # Ensure the database connection is closed

    return render_template('create_post.html', form=form)  # Render the create post page

# Route for displaying the user's profile page
@app.route('/profile')
def profile():
    # Check if the user is logged in
    if 'username' not in session:
        flash('You must be logged in to view the profile page.')
        return redirect(url_for('login'))

    conn = get_db_connection()  # Open a connection to the database
    # Get the user ID of the logged-in user
    user_id = conn.execute('SELECT id FROM Users WHERE username = ?', (session['username'],)).fetchone()['id']
    # Retrieve all posts created by the user
    posts = conn.execute('SELECT * FROM Posts WHERE author_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
    # Retrieve the user's details
    user = conn.execute('SELECT username, email FROM Users WHERE username = ?', (session['username'],)).fetchone()
    conn.close()  # Close the database connection

    # Render the profile page with the user's information and posts
    return render_template('profile.html', username=session['username'], posts=posts, user=user)

# Route for displaying the guide page
@app.route('/guide')
def guide():
    # Check if the user is logged in
    if 'username' not in session:
        flash('You must be logged in to view the guide.')
        return redirect(url_for('login'))
    return render_template('guide.html', username=session['username'])  # Render the guide page

# Route for displaying the DLC page with pagination
@app.route('/DLC')
def DLC():
    # Check if the user is logged in
    if 'username' not in session:
        flash('You must be logged in to view the DLC page.')
        return redirect(url_for('login'))

    # Get the current page number from the query parameters, default to 1
    page = request.args.get('page', 1, type=int)
    content = f'Blah{page}'  # Placeholder content based on the page number
    return render_template('DLC.html', content=content)  # Render the DLC page with content

# Route for deleting a post
@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    # Check if the user is logged in
    if 'username' not in session:
        flash('You must be logged in to perform this action.')
        return redirect(url_for('login'))

    conn = get_db_connection()  # Open a connection to the database
    # Delete the post with the given post_id
    conn.execute('DELETE FROM Posts WHERE id = ?', (post_id,))
    conn.commit()  # Commit the transaction
    conn.close()  # Close the database connection
    flash('Post deleted successfully', 'success')
    return redirect(url_for('profile'))  # Redirect to the profile page after deletion

# Route for liking a post
@app.route('/like_post', methods=['POST'])
def like_post():
    # Check if the user is logged in
    if 'user_id' not in session:
        return jsonify({'error': 'User not logged in'}), 403

    post_id = request.form.get('post_id')  # Get the post ID from the form
    user_id = session['user_id']  # Get the user ID from the session
    
    if not post_id:  # Validate the post ID
        return jsonify({'error': 'Invalid request'}), 400

    conn = get_db_connection()  # Open a connection to the database

    try:
        # Check if the user has already liked the post
        existing_like = conn.execute(
            'SELECT * FROM PostLikes WHERE post_id = ? AND user_id = ?',
            (post_id, user_id)
        ).fetchone()
        
        if existing_like:
            # Unlike the post by removing the like record
            conn.execute(
                'DELETE FROM PostLikes WHERE post_id = ? AND user_id = ?',
                (post_id, user_id)
            )
            action = 'removed'
        else:
            # Like the post by inserting a new like record
            conn.execute(
                'INSERT INTO PostLikes (post_id, user_id) VALUES (?, ?)',
                (post_id, user_id)
            )
            action = 'added'

        conn.commit()  # Commit the transaction

        # Get the updated like count for the post
        like_count = conn.execute(
            'SELECT COUNT(*) FROM PostLikes WHERE post_id = ?',
            (post_id,)
        ).fetchone()[0]

        # Return the updated like count and action (added or removed)
        return jsonify({'like_count': like_count, 'action': action})
    except sqlite3.Error as e:  # Handle any SQLite errors
        conn.rollback()  # Roll back the transaction on error
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()  # Ensure the database connection is closed

# Route for logging out the user
@app.route('/logout')
def logout():
    session.clear()  # Clear the session data
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))  # Redirect to the login page

# Run the Flask app if this script is executed directly
if __name__ == "__main__":
    app.run(debug=True)  # Start the Flask application in debug mode
