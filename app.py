from config import (app, db, Resource, api, request, session, jsonify, JWTManager, create_access_token, jwt_required,
                    get_jwt_identity, make_response)
from models import Users, generate_password_hash, check_password_hash, Insta_info, Post_insta
from flask_jwt_extended import get_jwt, set_access_cookies, unset_jwt_cookies
from instagrapi import Client
import PIL


class UserRegister(Resource):
    """
    register the users
    """

    def post(self):
        data = request.get_json()

        if 'user_name' not in data:
            return {"message": "your user name is missing"}, 400

        if Users.query.filter_by(user_name=data['user_name']).first():
            return {"message": "user already exists"}, 400

        # check for the fields
        if 'password' not in data:
            return {"message": "your password is missing"}, 400

        if 'confirm' not in data:
            return {"message": "your password confirmation is missing"}, 400

        # check if the fields are empty
        if not data['user_name'] or data['user_name'] == "":
            return {"message": "please enter your user name"}, 400

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
        new_user = Users(user_name=data['user_name'], password=new_password_hash)

        try:
            db.session.add(new_user)
            db.session.commit()

            return {"message": "user created"}, 201
        except Exception as e:
            return {"message": str(e)}, 404


class UserLogin(Resource):
    """
    login the user
    """

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

        return response


class InstaLogin(Resource):
    """
    connect to instagram account
    """

    @jwt_required()
    def post(self):
        # ask the user to input their instagram info
        data = request.get_json()

        if 'username_insta' not in data or 'password_insta' not in data:
            return {"message": "you have missed username or password"}, 400

        if not data['username_insta'] or data['username_insta'] == "":
            return {"message": "please enter your instagram username"}, 400

        if not data['password_insta'] or data['password_insta'] == "":
            return {"message": "please enter your instagram password"}

        try:
            current_user = get_jwt_identity()
            # query which account belong to the user
            exist_user_account = Insta_info.query.filter_by(
                username_insta=data['username_insta'],
                user_id=current_user
            ).first()

            if exist_user_account:
                return {"message": "user already exists"}, 400

            # make instance of client
            user = Client()

            # login the user to their instagram account
            user.login(data['username_insta'], data['password_insta'])
            get_user_info = jsonify(user.user_info_by_username(data['username_insta']))

            new_insta_user = Insta_info(
                username_insta=data['username_insta'],
                password_insta=data['password_insta'],
                user_id=current_user
            )

            db.session.add(new_insta_user)
            db.session.commit()

            return {
                "message": "user connected",
                "user info": get_user_info,
            }, 200

        except Exception as e:
            return {
                "message": "not successful",
                "error": str(e)
            }, 400


class UserLogout(Resource):
    """
    logout route
    """

    @jwt_required()
    def post(self):
        response = make_response({"message": "you are logged out"}, 200)

        unset_jwt_cookies(response)
        return response


# api routes
api.add_resource(UserRegister, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(InstaLogin, '/instalogin')
api.add_resource(UserLogout, '/logout')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)
