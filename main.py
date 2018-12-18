# matthew wolfgram
# si 364 001
# final project - edamam food api // nutrition information
# i used code from the user-authentication example

import os
import requests
import json
from flask import Flask, render_template, session, redirect, request, url_for, flash, request
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, PasswordField, BooleanField, SelectMultipleField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
import random
from flask_migrate import Migrate, MigrateCommand
from threading import Thread
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from werkzeug import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

# Configure base directory of app
basedir = os.path.abspath(os.path.dirname(__file__))

# Application configurations
app = Flask(__name__)
app.debug = True
app.use_reloader = True
app.static_folder = 'static' # what is this
app.config['SECRET_KEY'] = 'hardtoguessstring'
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("postgresql://localhost/edamam364") or "postgresql://localhost/edamam364"  # TODO: decide what your new database name will be, and create it in postgresql, before running this new application
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

## Statements for db setup (and manager setup if using Manager)
db = SQLAlchemy(app)
manager = Manager(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

# Login configurations setup
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app) # set up login manager

def make_shell_context():
	return dict(app=app, db=db, User=User)
manager.add_command("shell", Shell(make_context=make_shell_context))

################################ good above here ################################
## ***** how many get_or_creates? get/create recipe, get or create collection

##### model(s) setup #####

# TO DO : decide on edamam database structure, translate this to here and below, templates too!
# Set up association Table between search terms and recipes  --- map these out!

# Set up association Table between recipes (formerly s) and collections prepared by user
#user_collection = db.Table('user_collection',db.Column('_id', db.Integer, db.ForeignKey('s.id')),db.Column('collection_id',db.Integer, db.ForeignKey('personalCollections.id')))
user_collection = db.Table('user_collection',db.Column('recipe_id', db.Integer, db.ForeignKey('recipes.id')),db.Column('collection_id',db.Integer, db.ForeignKey('personalCollections.id')))

## ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Special model for users to log in
# *** user, recipe, personal collection for models
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    collection = db.relationship('PersonalCollection', backref='User')
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True


# Other models
# Similar to playlists... a user can create theirs
class PersonalCollection(db.Model): #how does this link to the db setup above?
    __tablename__ = "personalCollections"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    recipes = db.relationship('Recipe',secondary=user_collection,backref=db.backref('personalCollections',lazy='dynamic'),lazy='dynamic') #*****change

class Recipe(db.Model): #*****change to Recipe, put all of the info here, how to put in ??
    __tablename__ = "recipes"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128))
    source = db.Column(db.String(128))
    yield_servings = db.Column(db.Integer)
    ingredients = db.Column(db.String()) #what if it's a list?? how??
    diet_labels = db.Column(db.String()) #what if it's a list?? how??
    URL = db.Column(db.String(256))

    def __repr__(self):
        return "recipe: {}, yield: {}, ingredients: {}, diet_labels: {}, URL: {}".format(self.title, self.yield_servings, self.ingredients, self.diet_labels, self.URL)

## DB load functions
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) # returns User object or None


##### Set up Forms #####

class RegistrationForm(FlaskForm):
    email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
    username = StringField('Username:',validators=[Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
    password2 = PasswordField("Confirm Password:",validators=[Required()])
    submit = SubmitField('Register User')

    #Additional checking methods for the form
    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class RecipeSearchForm(FlaskForm): #***** recipe search form, add other recipe options
    search = StringField("Enter a food:", validators=[Required()])
    submit = SubmitField('Submit')

class CollectionCreateForm(FlaskForm):
    name = StringField('Collection Name',validators=[Required()])
    _picks = SelectMultipleField('Recipes to include') #***** recipes to include
    submit = SubmitField("Create Collection")

##### Helper functions

### For database additions / get_or_create functions

def get__by_id(id): #*****get recipe by id
    """returns  or None"""
    _obj = Recipe.query.filter_by(id=id).first()
    return _obj

def get_or_create_search_term(db_session, term, _list = []): #*****recipe_list, what does this translate to????????????????????????????????????
    searchTerm = db_session.query(Search).filter_by(term=term).first()
    if searchTerm:
        print("Found term") #replace terms with other stuff?????
        return searchTerm
    else:
        print("Added term")
        searchTerm = Search(term=term)
        for a in _list:
            recipe = get_or_create_(db_session, title = a[1], url = a[2]) #???????????????????????????????????????????
            searchTerm.Recipes.append(Recipe)
        db_session.add(searchTerm)
        db_session.commit()
        return searchTerm

def get_or_create_(db_session, title, url):
     = db_session.query().filter_by(title = title).first()
    if :
        return
    else:
         = (title = title, URL = url)
        db_session.add()
        db_session.commit()
        return

def get_or_create_personal_collection(db_session, name, _list, current_user): #add foodlist = [] or something?
    Collection = db_session.query(PersonalCollection).filter_by(name=name,user_id=current_user.id).first()
    if Collection: #rename n stuff
        return Collection
    else:
        Collection = PersonalCollection(name=name,user_id=current_user.id,recipes=[])
        for a in _list:
            Collection.recipes.append(a)
        db_session.add(Collection)
        db_session.commit()
        return Collection




##### Set up Controllers (view functions) #####

## Error handling routes
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

## Login routes
@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid username or password.')
    return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/register',methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,username=form.username.data,password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You can now log in!')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)

@app.route('/secret')
@login_required
def secret():
    return "Only authenticated users can do this! Try to log in or contact the site admin."


## Main routes
@app.route('/', methods=['GET', 'POST'])#****************************************************************************************
def index():
    all_recipes = []
    def collection(userq, diet_label = None, calorie_ct = None, excluded = None): #add the params

        payload = {'app_id': secrets.app_key,
                       'app_key': secrets.app_secret,
                       'q': userq,
                       'diet': diet_label,
                       'calories': calorie_ct,
                       'excluded': excluded}
        r = requests.get("https://api.edamam.com/search", params = payload)

        supermarket = r.json()
        #print(supermarket)
        for recipes in supermarket['hits']:
                for recipe in recipes:
                    try:
                        if recipes[recipe] != False:
                            dish = recipes[recipe]

                            label = dish['label']           #0 - dish name
                            source = dish['source']         #1 - name of original source
                            url = dish['url']               #2 - link to original source
                            batch_yield = dish['yield'] #change to float or something?                          #3 - yield
                            dietLabels = dish['dietLabels'] #what to do if there are none?                      #4 - one of “balanced”, “high-protein”, “high-fiber”, “low-fat”, “low-carb”, “low-sodium”
                            healthLabels = dish['healthLabels'] #what to do if there are none?                  #5 - vegan, alcohol-free, etc.
                            cautions = dish['cautions'] #what to do if there are none?                          #6 - milk, tree nuts, etc
                            ingredientLines = dish['ingredientLines'] #***you gotta take apart this list        #7 - all strings
                            caloric = dish['calories']                                                          #8 - into of calories

                            recipe_data = (label, source, url, int(batch_yield), dietLabels, healthLabels, cautions, ingredientLines, int(caloric))
                            all_recipes.append(recipe_data)
                            # **** what to do if lists are empty??? how to handle the separate elements??

                    except:
                        continue
        for x in all_recipes:
            print('------------')
            print(x)
            print('------------')
        return all_recipes
    return render_template('index.html', form=form, num_recipes=num_recipes) #*****rename this stuff in the index template

@app.route('/all_recipes') #****************************************************************************************
def see_all():
    all_recipes = [] # To be tuple list of title, genre
    recipes = Recipe.query.all()
    for a in recipes:
        all_recipes.append((a.title,a.URL))
    return render_template('all_recipes.html', all_recipes=all_recipes)

@app.route('/create__collection',methods=["GET","POST"])
@login_required
def create_():
    form = CollectionCreateForm()
    choices = []
    #populating your multi select picklist
    for a in Recipe.query.all():
        choices.append((a.id, a.title))
    form._picks.choices = choices

    if request.method == 'POST':
        recipes_selected = form._picks.data # list?
        print("RECIPES SELECTED", recipes_selected)
        _objects = [get__by_id(int(id)) for id in recipes_selected]
        print("RECIPES RETURNED", _objects)
        get_or_create_personal_collection(db.session,current_user=current_user,name=form.name.data,recipe_list=recipe_objects) # How to access user, here and elsewhere TODO
        return "Collection made"
    return render_template('create__collection.html',form=form) #remap these templates

if __name__ == '__main__':
    db.create_all() #creates models when you run the app
    app.run(use_reloader=True, debug=True)
