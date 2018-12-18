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

all_recipes = []
def collection(userq, diet_label = None, calorie_ct = None, excluded = None):

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

    # if get_or_create_city(city, state, country) == True:            # ---- **** figure out how to transfer this lol uhhh
    #     #pass
    #     flash("!!!! this city already exists! enter another one! ")
    #return supermarket #change this after relevant data has been picked out successfully
collection('pie', 'balanced', '2000', 'blueberries')
