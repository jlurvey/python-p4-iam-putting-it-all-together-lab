#models.py

from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates
from sqlalchemy.exc import IntegrityError

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship(
        'Recipe', back_populates="user", cascade='all, delete-orphan')
    
    serialize_rules = ('-recipes.user',)

    @hybrid_property
    def password_hash(self):
        return self._password_hash

    @password_hash.setter
    def password_hash(self, plaintext):
        self._password_hash = bcrypt.generate_password_hash(plaintext)

    def authenticate(self, plaintext):
        if bcrypt.check_password_hash(self._password_hash, plaintext): 
            return True
        return False

    @validates('username')
    def validate_username(self, key, username):
        if not username:
            raise IntegrityError
        existing_username = User.query.filter(db.func.lower(
            User.username) == db.func.lower(username)).first()
        if existing_username and existing_username.id != self.id:
            raise IntegrityError
        return username
    
    def __repr__(self):
        return f'<User {self.id}, {self.username}, {self._password_hash}, {self.image_url}, {self.bio}>'

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', back_populates="recipes")

    @validates('title')
    def validate_title(self, key, title):
        if not title:
            raise IntegrityError("Title is required")
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions or len(instructions) < 50:
            raise IntegrityError
        return instructions

    def __repr__(self):
        return f'<Recipe {self.id}, {self.title}, {self.instructions}, {self.minutes_to_complete}>'