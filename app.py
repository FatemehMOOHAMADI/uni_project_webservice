from config import (app, db, Resource, api, request, jsonify, JWTManager, create_access_token, jwt_required,
                    get_jwt_identity, make_response, send_file)
from models import Users, generate_password_hash, check_password_hash, Post_insta
from flask_jwt_extended import get_jwt, set_access_cookies, unset_jwt_cookies
from instagrapi import Client
import PIL


class UserRegister(Resource):
    """
    register the users
    """

    def get(self):
        if request.accept_mimetypes.accept_html:
            app.logger.info("get the register.html")
            return send_file('register.html')
        else:
            app.logger.info("try post request")
            return {"message": "Use Post request"}

    def post(self):
        data = request.get_json()

        # ask for the users username for our service
        if 'user_name' not in data:
            return {"message": "your user name is missing"}, 400

        # check if the chosen username already exits in the database
        if Users.query.filter_by(user_name=data['user_name']).first():
            return {"message": "user already exists"}, 400

        # check if the user has input the instagram username and password fields
        if 'username_insta' not in data:
            return {"message": "you have missed to input your instagram id "}, 400

        if 'password_insta' not in data:
            return {"message": "you have missed to input your instagram password"}, 400

        # check for the password fields
        if 'password' not in data:
            return {"message": "your password is missing"}, 400

        if 'confirm' not in data:
            return {"message": "your password confirmation is missing"}, 400

        # check if the fields are empty
        if not data['user_name'] or data['user_name'] == "":
            return {"message": "please enter your user name"}, 400

        if not data['username_insta'] or data['username_insta'] == "":
            return {"message": "please enter your instagram username"}, 400

        if not data['password_insta'] or data['password_insta'] == "":
            return {"message": "please enter your instagram password"}, 400

        if not data['password'] or data['password'] == "":
            return {"message": "please enter your password"}, 400

        if not data['confirm'] or data['confirm'] == "":
            return {"message": "please confirm your password"}, 400

        # check if the password and confirm match
        if data['password'] != data['confirm']:
            return {"message": "your password doesn't match. try again!"}, 400

        # convert password to hash
        new_password_hash = generate_password_hash(data['password'])
        # save the username and password to the database
        new_user = Users(
            user_name=data['user_name'],
            username_insta=data['username_insta'],
            password_insta=data['password_insta'],
            password=new_password_hash)

        try:
            db.session.add(new_user)
            db.session.commit()

            app.logger.info("user registered successfully")
            return {"message": "user created"}, 201
        except Exception as e:
            app.logger.info(str(e))
            return {"message": str(e)}, 404


class UserLogin(Resource):
    """
    login the user
    """
    def get(self):
        if request.accept_mimetypes.accept_html:
            app.logger.info("getting login.html")
            return send_file('login.html')
        else:
            app.logger.info("try Post request")
            return {"message": "Use Post request"}

    def post(self):
        data = request.get_json()

        # check for the fields
        if 'user_name' not in data:
            return {"message": "user name missing"}, 400

        if 'password' not in data:
            return {"message": "password missing"}, 400

        user = Users.query.filter_by(user_name=data['user_name']).first()

        # check if the fields are empty
        if not data['user_name'] or data['user_name'] == "":
            return {"message": "please enter a valid user name"}, 404

        if not data['password'] or data['password'] == "" or not check_password_hash(user.password, data['password']):
            return {"message": "please enter a valid password"}, 400

        access_token = create_access_token(identity=str(user.id))

        response = make_response({
            "message": "you are logged in",
            "access token": access_token,
            "user_id": user.id
        }, 200)

        # Set cookies if needed
        response.set_cookie(
            'access_token_cookie',
            value=access_token,
            httponly=True,
            samesite='Lax'
        )

        app.logger.info("user logged in")
        return response


class UserLogout(Resource):
    """
    logout route
    """
    @jwt_required()
    def post(self):
        response = make_response({"message": "you are logged out"}, 200)

        unset_jwt_cookies(response)
        app.logger.info("user logged out")
        return response


# api routes
api.add_resource(UserRegister, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(UserLogout, '/logout')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)
