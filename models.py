from config import db
from werkzeug.security import generate_password_hash, check_password_hash

""" this file is for database models """


class Users(db.Model):
    __tablename__ = 'Users'

    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    insta_user_account = db.relationship("Insta_info", back_populates="insta_account", lazy="dynamic")

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        self.password = check_password_hash(self.password, password)

    def to_json(self):
        return {
            "id": self.id,
            "user_name": self.user_name,
        }


class Insta_info(db.Model):
    __tablename__ = 'Insta_info'

    id = db.Column(db.Integer, primary_key=True)
    username_insta = db.Column(db.String(120), unique=True, nullable=False)
    password_insta = db.Column(db.String(120), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("Users.id"), nullable=False, unique=True)
    insta_account = db.relationship("Users", back_populates="insta_user_account")

    post = db.relationship("Post_insta", back_populates="instagram_posts", uselist=False)

    def to_json(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username_insta": self.username_insta,
        }


class Post_insta(db.Model):
    __tablename__ = 'Post_insta'

    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String(300), nullable=False)
    caption = db.Column(db.String(600), nullable=True, default="")

    user_id_account_instagram = db.Column(db.Integer, db.ForeignKey("Insta_info.id"), nullable=False, unique=True)
    instagram_posts = db.relationship("Insta_info", back_populates="post")

    def to_json(self):
        return {
            "id": self.id,
            "insta_id": self.insta_id,
            "user_id": self.user_id,
            "caption": self.caption,
            "path": self.path,
        }
