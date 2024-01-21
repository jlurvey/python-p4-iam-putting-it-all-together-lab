#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        json=request.get_json()

        if 'username' not in json or 'password' not in json or 'image_url' not in json or 'bio' not in json:
            return {'error': 'Missing required fields'}, 422

        user = User(
            username=json['username'],
            password_hash=json['password'],
            image_url=json['image_url'],
            bio=json['bio']
        )
        
        db.session.add(user)
        db.session.commit()
        session['user_id'] = user.id
        return user.to_dict(),201



class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            return user.to_dict(), 200
        return {'error': 'User not logged in'}, 401
    
class Login(Resource):
    def post(self):
        username = request.get_json()['username']
        user = User.query.filter(User.username == username).first()

        password = request.get_json()['password']

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        else:
            return {'error': 'Invalid username or password'}, 401



class Logout(Resource):
    def delete(self):
        user_id = session.get('user_id')

        if user_id is not None:
            # User is logged in, perform logout
            session['user_id'] = None
            return {}, 204
        else:
            # User is not logged in
            return {'error': 'User not logged in'}, 401


class RecipeIndex(Resource):
        def get(self):
            user_id = session.get('user_id')

            if user_id:
                # User is logged in, retrieve and return recipes data
                recipes = Recipe.query.all()
                recipes_data = []
                for recipe in recipes:
                    recipe_data = {
                        'title': recipe.title,
                        'instructions': recipe.instructions,
                        'minutes_to_complete': recipe.minutes_to_complete,
                        'user': {
                            'username': recipe.user.username,
                            'image_url': recipe.user.image_url,
                            'bio': recipe.user.bio
                        }
                    }
                    recipes_data.append(recipe_data)

                return recipes_data, 200
            else:
                # User is not logged in, return unauthorized error
                return {'error': 'Unauthorized. Please log in to view recipes.'}, 401
            
        def post(self):
            user_id = session.get('user_id')

            if user_id:
                # User is logged in, retrieve user object
                user = User.query.filter(User.id == user_id).first()

                # Get recipe data from JSON request
                json_data = request.get_json()
                title = json_data.get('title')
                instructions = json_data.get('instructions')
                minutes_to_complete = json_data.get('minutes_to_complete')

                # Validate recipe data
                try:
                    # Create a new recipe associated with the logged-in user
                    new_recipe = Recipe(
                        title=title,
                        instructions=instructions,
                        minutes_to_complete=minutes_to_complete,
                        user=user
                    )

                    # Add and commit the new recipe to the database
                    db.session.add(new_recipe)
                    db.session.commit()

                    # Prepare response data
                    recipe_data = {
                        'title': new_recipe.title,
                        'instructions': new_recipe.instructions,
                        'minutes_to_complete': new_recipe.minutes_to_complete,
                        'user': {
                            'username': user.username,
                            'image_url': user.image_url,
                            'bio': user.bio
                        }
                    }

                    return recipe_data, 201

                except IntegrityError as e:
                    # Handle IntegrityError (e.g., validation errors)
                    db.session.rollback()
                    return {'error': str(e)}, 422

            else:
                # User is not logged in, return unauthorized error
                return {'error': 'Unauthorized. Please log in to create recipes.'}, 401


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)