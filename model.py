from config import db
from werkzeug.security import generate_password_hash, check_password_hash

""" this file is for database models """


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(80), unique=True, nullable=False)
    insta_id = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        self.password = check_password_hash(self.password, password)

    def to_json(self):
        return {
            "id": self.id,
            "user_name": self.user_name,
            "insta_id": self.instagram_ID
        }
