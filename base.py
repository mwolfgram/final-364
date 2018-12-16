# matthew wolfgram
# si 364 001
# final proj



import os
import requests
import json
from flask import Flask, render_template, session, redirect, request, url_for, flash
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, PasswordField, BooleanField, SelectMultipleField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
import random
from flask_migrate import Migrate, MigrateCommand  #delete these???
from threading import Thread
from werkzeug import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import secrets 

# Imports for login management
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user

# Configure base directory of app
basedir = os.path.abspath(os.path.dirname(__file__))

# Application configurations
app = Flask(__name__)
app.static_folder = 'static'
app.config['SECRET_KEY'] = 'hardtoguessstring'
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('DATABASE_URL') or "postgresql://localhost/edamam364"  # TODO: decide what your new database name will be, and create it in postgresql, before running this new application
# Lines for db setup so it will work as expected
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Set up Flask debug and necessary additions to app
manager = Manager(app)
db = SQLAlchemy(app) # For database use
migrate = Migrate(app, db) # For database use/updating
manager.add_command('db', MigrateCommand) # Add migrate command to manager

    # Login configurations setup
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app) # set up login manager

## Set up Shell context so it's easy to use the shell to debug
# Define function
def make_shell_context():
    return dict( app=app, db=db)
# Add function use to manager
manager.add_command("shell", Shell(make_context=make_shell_context))

##### Set up Models #####

# Set up association Table between search terms and articles  --- map these out!
tags = db.Table('tags',db.Column('search_id',db.Integer, db.ForeignKey('search.id')),db.Column('article_id',db.Integer, db.ForeignKey('articles.id')))

# Set up association Table between Articles and collections prepared by user
user_collection = db.Table('user_collection',db.Column('article_id', db.Integer, db.ForeignKey('articles.id')),db.Column('collection_id',db.Integer, db.ForeignKey('personalCollections.id')))

# Special model for users to log in
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
# Similar to playlists... a user can create his/ehr
class PersonalCollection(db.Model):
    __tablename__ = "personalCollections"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    articles = db.relationship('Article',secondary=user_collection,backref=db.backref('personalCollections',lazy='dynamic'),lazy='dynamic')

class Article(db.Model):
    __tablename__ = "articles"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128))
    articleURL = db.Column(db.String(256))

    def __repr__(self):
        return "{}, URL: {}".format(self.title,self.articleURL)

class Search(db.Model):
    __tablename__ = "search"
    id = db.Column(db.Integer, primary_key=True)
    term = db.Column(db.String(32),unique=True) # Only unique searches
    articles = db.relationship('Article',secondary=tags,backref=db.backref('search',lazy='dynamic'),lazy='dynamic')

    def __repr__(self):
        return "{} : {}".format(self.id, self.term)

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

class ArticleSearchForm(FlaskForm):
    search = StringField("Enter a search term:", validators=[Required()])
    submit = SubmitField('Submit')

class CollectionCreateForm(FlaskForm):
    name = StringField('Collection Name',validators=[Required()])
    article_picks = SelectMultipleField('Articles to include')
    submit = SubmitField("Create Collection")

##### Helper functions

### For database additions / get_or_create functions

def get_article_by_id(id):
    """returns article or None"""
    article_obj = Article.query.filter_by(id=id).first()
    return article_obj

def get_or_create_search_term(db_session, term, article_list = []):
    searchTerm = db_session.query(Search).filter_by(term=term).first()
    if searchTerm:
        print("Found term")
        return searchTerm
    else:
        print("Added term")
        searchTerm = Search(term=term)
        for a in article_list:
            article = get_or_create_article(db_session, title = a[1], url = a[2])
            searchTerm.articles.append(article)
        db_session.add(searchTerm)
        db_session.commit()
        return searchTerm

def get_or_create_article(db_session, title, url):
    article = db_session.query(Article).filter_by(title = title).first()
    if article:
        return article
    else:
        article = Article(title = title, articleURL = url)
        db_session.add(article)
        db_session.commit()
        return article

def get_or_create_personal_collection(db_session, name, article_list, current_user):
    articleCollection = db_session.query(PersonalCollection).filter_by(name=name,user_id=current_user.id).first()
    if articleCollection:
        return articleCollection
    else:
        articleCollection = PersonalCollection(name=name,user_id=current_user.id,articles=[])
        for a in article_list:
            articleCollection.articles.append(a)
        db_session.add(articleCollection)
        db_session.commit()
        return articleCollection




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
@app.route('/', methods=['GET', 'POST'])
def index():
    articles = Article.query.all()
    num_articles = len(articles)
    form = ArticleSearchForm()
    if form.validate_on_submit():
        if db.session.query(Search).filter_by(term=form.search.data).first():
            term = db.session.query(Search).filter_by(term=form.search.data).first()
            all_articles = []
            for i in term.articles.all():
                all_articles.append((i.title, i.articleURL))
            print(all_articles)
            return render_template('all_articles.html', all_articles = all_articles)
        else:
            # request articles for that search term
            # add the search term and articles to database
            baseURL = "https://www.buzzfeed.com/api/v2/feeds/"
            feed_name=form.search.data
            response = requests.get(baseURL + feed_name)
            #print("RESPONSE TEXT", response.text)
            articleInResponse = json.loads(response.text)['buzzes']
            articleFieldsRequired = []
            for a in articleInResponse:
                articleURL = "https://www.buzzfeed.com/"+a['canonical_path']
                article_tuple = (a['id'], a['title'], articleURL)
                if article_tuple not in articleFieldsRequired:
                    articleFieldsRequired.append(article_tuple)
            print("Article fields required:", articleFieldsRequired)
            searchterm = get_or_create_search_term(db.session, form.search.data, articleFieldsRequired)
            print(searchterm)
            return "Added to DB"
    return render_template('index.html', form=form, num_articles=num_articles)

@app.route('/all_articles')
def see_all():
    all_articles = [] # To be tuple list of title, genre
    articles = Article.query.all()
    for a in articles:
        all_articles.append((a.title,a.articleURL))
    return render_template('all_articles.html', all_articles=all_articles)

@app.route('/create_article_collection',methods=["GET","POST"])
@login_required
def create_article():
    form = CollectionCreateForm()
    choices = []
    #populating your multi select picklist
    for a in Article.query.all():
        choices.append((a.id, a.title))
    form.article_picks.choices = choices

    if request.method == 'POST':
        articles_selected = form.article_picks.data # list?
        print("ARTICLES SELECTED", articles_selected)
        article_objects = [get_article_by_id(int(id)) for id in articles_selected]
        print("ARTICLES RETURNED", article_objects)
        get_or_create_personal_collection(db.session,current_user=current_user,name=form.name.data,article_list=article_objects) # How to access user, here and elsewhere TODO
        return "Collection made"
    return render_template('create_article_collection.html',form=form)

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True) # NEW: run with this: python challenge_buzzfeed.py runserver
    # Also provides more tools for debugging
