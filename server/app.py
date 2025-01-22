#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.before_request
def check_if_logged_in():
    if not session.get('user_id') \
    and request.endpoint in ['recipes']:
        return {'error': 'Unauthorized'}, 401
    
class Signup(Resource):

    def post(self):
        json = request.get_json()

        try:
            user = User(
                username=json['username'],
                image_url = json['image_url'],
                bio = json['bio']
            )
            user.password_hash = json['password']

            db.session.add(user)
            db.session.commit()
            return user.to_dict(), 201
        except:
            return {'error': 'User not valid'}, 422

class CheckSession(Resource):

    def get(self):
        
        user_id = session['user_id']
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            return user.to_dict(), 200
        
        return {'error': 'User is not logged in'}, 401

class Login(Resource):

    def post(self):
        json = request.get_json()

        username = json['username']
        user = User.query.filter_by(username=username).first()

        password = json['password']

        if not user:
            return {'error': 'Invalid username or password'}, 401

        if user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200

        return {'error': 'Invalid username or password'}, 401


class Logout(Resource):

    def delete(self):

        if not session['user_id']:
            return {'error': 'No active user'}, 401

        session['user_id'] = None
        return {}, 204

class RecipeIndex(Resource):

    def get(self):
        recipes = [recipe.to_dict() for recipe in Recipe.query.filter_by(user_id=session['user_id']).all()]
        return recipes, 200

    def post(self):
        data = request.get_json()

        try:
            new_recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete'],
                user_id=session['user_id']
            )

            db.session.add(new_recipe)
            db.session.commit()

            return new_recipe.to_dict(), 201
        except:
            return {'error': 'Recipe not valid'}, 422
        

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)