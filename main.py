from config import app, db
from model import Users, generate_password_hash, check_password_hash
from flask import request, render_template, jsonify, session
from functools import wraps


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return jsonify({"message": "Unutherized"}), 404
        return f(*args, **kwargs)

    return decorated_function


@app.route("/register", methods=["POST"])
def register():
    """
    this function registers the users
    :return: new_users
    """

    user_name = request.json.get("user_name")

    if not user_name:
        return jsonify({"message": "please enter your username"}), 400

    password = request.json.get("password")

    if not password:
        return jsonify({"message": "please enter your password"}), 400

    # confirm the password
    confirm = request.json.get("confirm")

    if not confirm:
        return jsonify({"message": "please confirm your password"}), 400

    if confirm != password:
        return jsonify({"message": "your password doesn't match"}), 404

    generate_hash_password = generate_password_hash(password)

    new_user = Users(user_name=user_name, password=generate_hash_password)

    # add the user to the database
    try:
        db.session.add(new_user)
        db.session.commit()
    except Exception as e:
        return jsonify({"message": str(e)}), 404

    return jsonify({"message": "user created"}), 200


@app.route("/login", methods=["POST"])
def login():
    """
    this function handles the users that are logged in
    :return: none
    """
    user_name = request.json.get("user_name")
    if not user_name:
        return jsonify({"message": "please enter your username"}), 400

    password = request.json.get("password")
    if not password:
        return jsonify({"message": "please enter your password"}), 400

    user = Users.query.filter_by(user_name=user_name).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "user not valid"}), 400

    session["user_id"] = user.id

    return jsonify({"message": "you are logged in"}), 200


@app.route("/", methods=["GET"])
def index():
    users = Users.query.all()
    json_user = list(map(lambda x: x.to_json(), users))
    return jsonify({"users": json_user})


@app.route("/logout")
@login_required
def logout():
    """
    logout
    :return:
    """
    session.clear()
    return jsonify({"message": "you are logged out"})


if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)
