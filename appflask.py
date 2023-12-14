from flask import Flask, render_template, url_for, redirect
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from azure.cosmos import CosmosClient
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'

COSMOSDB_ENDPOINT = 'https://fgcyascecl.documents.azure.com:443/'
COSMOSDB_KEY = '8MSWmqzEVgffuuTM0Q51mQQu5tCDatEPJF5JVvAnm1PpEHwYSHvEaEUmxhSX0mMluzUrkFxvVtieACDbQoL5yQ=='
COSMOSDB_DATABASE = 'userregistration_id'
COSMOSDB_COLLECTION = 'usercontainer_id'

client = CosmosClient(COSMOSDB_ENDPOINT, COSMOSDB_KEY)
database = client.get_database_client(COSMOSDB_DATABASE)
collection = database.get_container_client(COSMOSDB_COLLECTION)

bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    user_data = User.query(user_id)
    if user_data:
        return User(username=user_data['username'], password=user_data['password'])
    return None

class User(UserMixin):
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.id = username  # Assuming username is unique

    @staticmethod
    def query(username):
        query = f"SELECT * FROM c WHERE c.username = '{username}'"
        items = list(collection.query_items(query=query, enable_cross_partition_query=True))
        return items[0] if items else None

    def get_id(self):
        return self.id

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query(username=username.data)
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

    def validate_username(self, username):
        user = User.query(username=username.data)
        if not user:
            raise ValidationError('Invalid username or password.')
        if not bcrypt.check_password_hash(user['password'], self.password.data):
            raise ValidationError('Invalid username or password.')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query(username=form.username.data)
        if user and bcrypt.check_password_hash(user['password'], form.password.data):
            login_user(User(username=user['username'], password=user['password']))
            return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch NFL schedule
    nfl_schedule_data = get_nfl_schedule()

    if 'error' in nfl_schedule_data:
        error_message = f"Error fetching NFL schedule data: {nfl_schedule_data['error']}"
        return render_template('dashboard.html', error_message=error_message)

    return render_template('dashboard.html', nfl_schedule_data=nfl_schedule_data)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = {'id': form.username.data, 'username': form.username.data, 'password': hashed_password}
        collection.create_item(body=new_user)
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

def get_nfl_schedule():
    url = "https://tank01-nfl-live-in-game-real-time-statistics-nfl.p.rapidapi.com/getNFLGamesForDate"
    querystring = {"week": "14", "seasonType": "reg", "season": "2023"}
    headers = {
        "X-RapidAPI-Key": "89c5fdbf61mshd77ba5175a194eep157f81jsnc0df7a68f45c",
        "X-RapidAPI-Host": "tank01-nfl-live-in-game-real-time-statistics-nfl.p.rapidapi.com"
    }

    response = requests.get(url, headers=headers, params=querystring)
    nfl_schedule_data = response.json()

    return nfl_schedule_data

if __name__ == "__main__":
    app.run(debug=False)