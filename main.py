from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack
import requests

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt


import json
from os import environ as env
from werkzeug.exceptions import HTTPException
import logging

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode
import key
import constants
app = Flask(__name__)
client = datastore.Client()
app.secret_key = key.key
food_keys = ['name', 'price','ingredients']
restaurant_keys = ['name', 'address']
# Default Route

# Update the values of the following 3 variables
CLIENT_ID = 'uBmZb7sNadlurP5JTpdYh0H7ACnsE3AE'
CLIENT_SECRET = key.key
DOMAIN = 'dev-j6xiyw1cjonbunvv.us.auth0.com'
# For example
# DOMAIN = 'fall21.us.auth0.com'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://{DOMAIN}/.well-known/openid-configuration'

)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        return None
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        return None


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    user = datastore.entity.Entity(key=client.key(constants.USER))
    user.update({"user":token["id"]})
    client.put(user)
    return redirect("/")

@app.route('/')
def index():
    return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4))

# Get all users in data store
@app.route('/users', methods=['GET'])
def get_users():
    query = client.query(kind=constants.USER)
    results = list(query.fetch())
    for e in results:
        e["id"] = e.key.id
    return (json.dumps(results), 200)

# Get or create food
@app.route('/food', methods=['GET','POST'])
def food():
    if request.method == 'POST':
        payload = verify_jwt(request)
        # keys_present = [key for key in food_keys if key in content]
        # if keys_present != food_keys:
        #     return ({"Error": "The request object is missing at least one of the required attributes"},400)
        if payload is None:
            raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)
        content = request.get_json()
        new_food= datastore.entity.Entity(key=client.key(constants.FOOD))
        new_food.update({"name": content["name"], "price": content["price"],
            "ingredients ": content["ingredients"], "self_link": request.url})
        client.put(new_food)
        food_key = client.key(constants.FOOD,new_food.key.id)
        food = client.get(key=food_key)
        food.update({"self_link":request.url + "/" +str(new_food.key.id)})
        client.put(food)
        food["id"] = food.key.id
        return (json.dumps(food),201)
    elif request.method == 'GET':
        query = client.query(kind=constants.FOOD)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
        output = {"food": results}
        if next_url:
            output["next"] = next_url
        return json.dumps(output)
    return('Method not allowed',405)
@app.route('/food/<id>', methods=['GET','DELETE','PATCH','PUT'])
def get_food(id):
    if request.method == 'DELETE':
        payload = verify_jwt(request)
        if payload is None:
            raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)
        query = client.query(kind=constants.FOOD)
        results = list(query.fetch())
        for e in results:
            if int(id) == int(e.id):
                food_key = client.key(constants.FOOD, int(id))

        if(results is not None):   
            client.delete(food_key)
            return ('',204)
   
        else:
            return ('No food found ',403)
        
    if request.method == 'GET':
        query = client.query(kind=constants.FOOD)
        results = list(query.fetch())
        food_key = None
        if id is not None:
            for e in results:
                if int(id) == int(e.id):
                    food_key = client.key(constants.FOOD, int(id))

            if(results is not None): 
                
                return (json.dumps(client.get(key=food_key)),200)
            else:
                return ([],200)
        else:
            return ('Please enter a valid ID', 406)
    
    if request.method == 'PATCH' or request.method == 'PUT':
        payload = verify_jwt(request)
        if payload is None:
            raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)
        content = request.get_json()
        keys_present = [key for key in food_keys if key in content]
        if keys_present != food_keys:
            return ({"Error": "The request object is missing at least one of the required attributes"},400)
        query = client.query(kind=constants.FOOD)
        results = list(query.fetch())
        food_key = None
        for e in results:
            if int(id) == int(e.id):
                food_key = client.key(constants.FOOD, int(id))
        
        if(food_key is not None): 
            food = client.get(key=food_key)
            food.update({"name": content["name"], "price": content["price"],
          "ingredients": content["ingredients"]})
            food["id"] = food.key.id
            return (json.dumps(food),200)
        else:
            return ({"Error": "No boat with this boat_id exists"},404)

    return('Method not allowed',405)

@app.route('/restaurant', methods=['GET','POST'])
def restaurants():
    if request.method == 'POST':
        payload = verify_jwt(request)
        if payload is None:
            raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)
        content = request.get_json()
        new_restaurant= datastore.entity.Entity(key=client.key(constants.RESTAURANT))
        new_restaurant.update({"name": content["name"], "address": content["address"],"menu":[],
            "owner": payload["sub"], "self_link": request.url + "/"})
        
        client.put(new_restaurant)
        restaurant_key = client.key(constants.RESTAURANT,new_restaurant.key.id)
        restaurant = client.get(key=restaurant_key)
        restaurant.update({"self_link":request.url + "/" +str(new_restaurant.key.id)})
        client.put(restaurant)
        restaurant["id"] = restaurant.key.id
        return (json.dumps(restaurant),201)
    elif request.method == 'GET':
        payload = verify_jwt(request)
        query = client.query(kind=constants.RESTAURANT)
        # implement pagination
        #if no jwt is provided give all res
        if payload is None:
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = query.fetch(limit= q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))
            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None
            for e in results:
                e["id"] = e.key.id
            output = {"restaurants": results}
            if next_url:
                output["next"] = next_url
            return json.dumps(output)
        #get only restaurants from that owner
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        query.add_filter("owner", "=", payload["sub"])
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
        output = {"restaurants": results}
        if next_url:
            output["next"] = next_url
        return json.dumps(output)
    return('Method not allowed',405)

@app.route('/restaurant/<id>', methods=['GET','DELETE','PATCH','PUT'])
def get_restaurants(id):
    if request.method == 'DELETE':
        results = None
        payload = verify_jwt(request)
        if payload is None:
            raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)
        query = client.query(kind=constants.RESTAURANT)
        results = list(query.fetch())
        for e in results:
            if int(id) == int(e.id):
                restaurant_key = client.key(constants.RESTAURANT, int(id))
                result = e["owner"]
        if(results is not None):
            if result == payload["sub"]:
                    client.delete(restaurant_key)
                    return ('',204)
            else:
                return ('Not owner',403)
        else:
            return ('No boat found ',403)
    if request.method == 'GET':
        payload = verify_jwt(request)
        if payload is None:
            raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)
        query = client.query(kind=constants.RESTAURANT)
        results = None
        results = list(query.fetch())
        for e in results:
            if int(id) == int(e.id):
                restaurant_key = client.key(constants.RESTAURANT, int(id))
        
        if(results is not None): 
            return (json.dumps(client.get(key=restaurant_key)),200)
        else:
            return ([],200)
        
    if request.method == 'PATCH' or request.method == 'PUT' :
        payload = verify_jwt(request)
        content = request.get_json()
        keys_present = [key for key in restaurant_keys if key in content]
        if keys_present != restaurant_keys:
            return ({"Error": "The request object is missing at least one of the required attributes"},400)
        query = client.query(kind=constants.RESTAURANT)
        results = list(query.fetch())
        restaurant_key = None
        restaurant_owner = None
        for e in results:
            if int(id) == int(e.id):
                restaurant_key = client.key(constants.RESTAURANT, int(id))
                restaurant_owner = e["owner"]
        if restaurant_owner == payload["sub"]:
            if(restaurant_key is not None): 
                restaurant = client.get(key=restaurant_key)
                restaurant.update({"name": content["name"], "address": content["address"]})
                restaurant["id"] = restaurant.key.id
                return (json.dumps(restaurant),200)
            else:
                return ({"Error": "No request with this request_id exists"},404)
        else:
            return ('You are not the owner', 403)
    return('Method not allowed',405)

@app.route('/restaurant/<restaurant_id>/<food_id>', methods=['POST','DELETE'])
def add_menu_item(food_id,restaurant_id):
    if request.method == 'POST':
        restaurant_owner = None
        restaurant_key = None
        food_key = None
        payload = verify_jwt(request)
        if payload is None:
            raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)
        query = client.query(kind=constants.RESTAURANT)
        results = list(query.fetch())
        
        for e in results:
            if int(restaurant_id) == int(e.id):
                restaurant_key = client.key(constants.RESTAURANT, int(restaurant_id))
                restaurant_owner = e["owner"]
        query = client.query(kind=constants.FOOD)
        results = list(query.fetch())
        
        for e in results:
            if int(food_id) == int(e.id):
                food_key = client.key(constants.FOOD, int(food_id))

        if restaurant_owner == payload["sub"]:
            if(restaurant_key is not None and food_key is not None): 
                food = client.get(key=food_key)
                restaurant = client.get(key=restaurant_key)
                restaurant.update({"menu": [food["name"]]})
                food.update({"restaurants":[restaurant["name"]]})
                client.put(food)
                client.put(restaurant)
                return (json.dumps(restaurant),200)
            else:
                return ('restaurant or food not found', 404)
        else:
            return('You are not the restaurant owner', 403)
    if request.method == 'DELETE':
        payload = verify_jwt(request)
        if payload is None:
            raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)
        query = client.query(kind=constants.RESTAURANT)
        results = list(query.fetch())
        restaurant_key = None
        restaurant_owner = None
        for e in results:
            if int(restaurant_id) == int(e.id):
                restaurant_key = client.key(constants.RESTAURANT, int(restaurant_id))
                restaurant_owner = e["owner"]
        query = client.query(kind=constants.FOOD)
        results = list(query.fetch())
        food_key = None
        for e in results:
            if int(food_id) == int(e.id):
                food_key = client.key(constants.FOOD, int(food_id))
        if restaurant_owner == payload["sub"]:
            if(restaurant_key is not None and food_key is not None): 
                food = client.get(key=food_key)
                restaurant = client.get(key=restaurant_key)
                restaurant.update({"menu": restaurant["menu"].remove(food["name"])})
                food.update({"restaurants": food["restaurants"].remove(restaurant["name"])})
                client.put(food)
                client.put(restaurant)
                return (json.dumps(restaurant),200)
            else:
                return ('restaurant or food not found', 404)
        else:
            return('You are not the restaurant owner', 403)
    return('Method not allowed',405)
        
