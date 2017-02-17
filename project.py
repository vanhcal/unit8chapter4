from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User
# import Flask's version of session and name it login_session
# login_session works like a dictionary; we can store user's info for duration of their session
from flask import session as login_session
# use this to create a pseudo random string used to identify each session
import random, string
from oauth2client.client import flow_from_clientsecrets
# FlowExchangeError catches errors made exchanging access tokens
from oauth2client.client import FlowExchangeError
import httplib2
import json
# converts the return from a function into a real response object that can be sent to client
from flask import make_response
import requests

app = Flask(__name__)

# reference client_secrets.json file
CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu App"

#Connect to Database and create database session
engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Creating anti-forgery state tokens
# Store it in the session for later validation
@app.route('/login')
def showLogin():
  # 'state' is a variable 32 characters long, a mix of uppercase and digits
  state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
  # store state in the login_session object under the name state
  login_session['state'] = state
  # see what current state looks like
  return render_template('login.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
  # confirm that the token the client sends to the server matches token from server to client (to ensure it's the user making the request)
  # no further authentication will occur if there is a mismatch
  if request.args.get('state') != login_session['state']:
    response = make_response(json.dumps('Invalid state parameter'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  # if the token does match  
  code = request.data

  try:
    # Upgrade the one-time authorization code into a credentials object
    # add client_secrets info to oauth_flow
    oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
    # specify that this is one-time flow message that server will be sending off
    oauth_flow.redirect_uri = 'postmessage'
    # initiate the exchange, which exchanges authorization code into credentials object
    credentials = oauth_flow.step2_exchange(code)
  # if error, send response as json object  
  except FlowExchangeError:
    response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response

  # check that access token is valie
  access_token = credentials.access_token
  # store access_token to this url, which can verify whether this is a valid token
  url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
  # create json get request containing url and access token, which is stored in 'result'
  h = httplib2.Http()
  result = json.loads(h.request(url, 'GET')[1])

  # If there was an error in the access token info, send error and abort
  # if this IF statement isn't true, we know we have a working access token
  if result.get('error') is not None:
    response = make_response(json.dumps(result.get('error')), 500)
    response.headers['Content-Type'] = 'application/json'
    return response
    # But is it the right access token? verify that the account is used for the intended user
    # compare credentials token to id returned by google api server; if they don't match, return error
  gplus_id = credentials.id_token['sub']
  if result['user_id'] != gplus_id:
    response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  # if client ids do not match, the app is trying to use a client id that does not belong to it
  if result['issued_to'] != CLIENT_ID:
    response = make_response(json.dumps("Token's client ID does not match app's."), 401)
    print "Token's client ID does not match app's."
    response.headers['Content-Type'] = 'application/json'
    return response

  # Check to see if user is already logged in
  stored_access_token = login_session.get('access_token')
  stored_gplus_id = login_session.get('gplus_id')
  if stored_access_token is not None and gplus_id == stored_gplus_id:
    response = make_response(json.dumps('Current user is already connected.'), 200)
    response.headers['Content-Type'] = 'application/json'
    return response

  # if none of these if statements are true, we have a valid access token, and user is able to successfully log into server. store the access token in the session for later use 
  login_session['provider'] = 'google'
  login_session['access_token'] = credentials.access_token
  login_session['gplus_id'] = gplus_id

  # get user info
  userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
  params = {'access_token': credentials.access_token, 'alt':'json'}
  answer = requests.get(userinfo_url, params=params)
  data = answer.json()

  # store the data we're interested in
  login_session['username'] = data['name']
  login_session['picture'] = data['picture']
  login_session['email'] = data['email']

  # see if user exists, if they don't make a new account
  user_id = getUserID(login_session['email'])
  if not user_id:
    # create new user in our db and pass in the login session
    user_id = createUser(login_session)
  # take result and store in login_session under user_id
  login_session['user_id'] = user_id

  # create a response that knows the user's name
  output = ''
  output += '<h1>Welcome, '
  output += login_session['username']
  output += '!</h1>'
  output += '<img src="'
  output += login_session['picture']
  output += '"style="width:300px; height:300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
  flash("you are now logged in as %s" % login_session['username'])
  print "done!"
  return output

# Disconnect -- revoke a current user's token and reset their login_session
@app.route("/gdisconnect")
def gdisconnect():
  access_token = login_session['access_token']
  # Again, grab credentials from login object
  # Only disconnect a connected user. If the credentials is empty, we don't have a user to disconnect from the app
  if access_token is None:
    response = make_response(json.dumps('Current user not connected.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response 
  # grab the URL for revoking tokens; store google's response in "result" object
  url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
  h = httplib2.Http()
  result = h.request(url, 'GET') [0]
  # something other than a 200 response indicates an unsuccessful disconnect
  if result['status'] != '200':
    # if we get back something besides 200, then for whatever reason, the given token was invalid
    response = make_response(json.dumps('Failed to revoke token for given user.'), 400)
    response.headers['Content-Type'] = 'application/json'
    return response 

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
  # verify the value of STATE to protect against cross-site forgery attacks
  if request.args.get('state') != login_session['state']:
    response = make_response(json.dumps('Invalid state parameter.'), 401)
    response.headers['Content-Type'] = 'application/json'
    return response
  access_token = request.data
  print "access token received %s" % access_token

  # Exchange client token for long-lived server-side token
  # Send app secret and app id to facebook, to verify server identity
  app_id = json.loads(open('fb_client_secrets.json', 'r').read()) ['web']['372022926513956']
  app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['0ba36c72430a046262196e6cfb8400b4']
  url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)
  h = httplib2.Http()
  result = h.request(url, 'GET')[1]

  # User token to get user info from API
  # includes expires field that indicates how long token is valid 
  userinfo_url = "https://graph.facebook.com/v2.4/me"
  # strip expire tag from access token, since we don't need it to make apiu calls 
  token = result.split("&")[0]

  # if the token works, we should be able to make api calls with new token
  url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
  h = httplib2.Http()
  result = h.request(url, 'GET')[1]
  # print "url sent for API access: %s" %
  # print "API JSON result: %s" % result
  # populate login session
  data = json.loads(result)
  login_session['provider'] = 'facebook'
  login_session['username'] = data["name"]
  login_session['email'] = data["email"]
  login_session['facebook_id'] = data["id"]

  # The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
  stored_token = token.split("=")[1]
  login_session['access_token'] = stored_token

  # use a separate api call to retrieve profile picture
  url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
  h = httplib2.Http()
  result = h.request(url, 'GET')[1]
  data = json.loads(result)

  login_session['picture'] = data["data"]["url"]

  # use same code as google login to retrieve a user or create a new one
  user_id = getUserID(login_session['email'])
  if not user_id:
    user_id = createUser(login_session)
  login_session['user_id'] = user_id

  output = ''
  output += '<h1>Welcome, '
  output += login_session['username']
  output += '!<h1>'
  output += '<img src ="'
  output += login_session['picture']
  output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

  flash("Now logged in as %s" % login_session['username'])
  return output

# reject the login token when the user is ready to log out
@app.route('/fbdisconnect')
def fbdisconnect():
  facebook_id = login_session['facebook_id']
  # access token must be included to successfully logout
  access_token = login_session['access_token']
  url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
  h = httplib2.Http()
  result = h.request(url, 'DELETE')[1]
  return "You have been logged out"

# create a new method for disconnecting regardless of provider
@app.route('/disconnect')
def disconnect():
  if 'provider' in login_session:
    if login_session['provider'] == 'google':
      gdisconnect()
      del login_session['gplus_id']
      del login_session['credentials']
    if login_session['provider'] == 'facebook':
      fbdisconnect()
      del login_session['facebook_id']
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['user_id']
    del login_session['provider']
    flash("You have successfully been logged out.")
    return redirect(url_for('showRestaurants'))
  else:
    flash("You were not logged in")
    redirect(url_for('showRestaurants'))


#JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
  restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
  return jsonify(MenuItems=[i.serialize for i in items])

@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
  Menu_Item = session.query(MenuItem).filter_by(id = menu_id).one()
  return jsonify(Menu_Item = Menu_Item.serialize)

@app.route('/restaurant/JSON')
def restaurantsJSON():
  restaurants = session.query(Restaurant).all()
  return jsonify(restaurants= [r.serialize for r in restaurants])


#Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
  restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
  # if user is logged in, show the template that has option to add restaurants. otherwise, show public restaurants template
  if 'username' not in login_session:
    return render_template('publicrestaurants.html', restaurants = restaurants)
  else: 
    return render_template('restaurants.html', restaurants = restaurants)

#Create a new restaurant
@app.route('/restaurant/new/', methods=['GET','POST'])
def newRestaurant():
  # make sure that all users coming to site are logged in
  # decide which pages we want to be public facing, and which should be logged-in-only
  if 'username' not in login_session:
    return redirect('/login')
  if request.method == 'POST':
    newRestaurant = Restaurant(name = request.form['name'], user_id = login_session['user_id'])
    session.add(newRestaurant)
    flash('New Restaurant %s Successfully Created' % newRestaurant.name)
    session.commit()
    return redirect(url_for('showRestaurants'))
  else:
      return render_template('newRestaurant.html')

# Edit a restaurant
@app.route('/restaurant/<int:restaurant_id>/edit/', methods = ['GET', 'POST'])
def editRestaurant(restaurant_id):
  if 'username' not in login_session:
    return redirect('/login')
  editedRestaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if request.method == 'POST':
    if request.form['name']:
      editedRestaurant.name = request.form['name']
      flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
      return redirect(url_for('showRestaurants'))
  else:
    return render_template('editRestaurant.html', restaurant = editedRestaurant)

# Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods = ['GET','POST'])
def deleteRestaurant(restaurant_id):
  if 'username' not in login_session:
    return redirect('/login')
  # if user tries to access url that they're not authorized for, flash this message
  if restaurantToDelete.user_id != login_session['user_id']:
    return "<script>function myFunction() {alert('You are not authorized to delete this restaurant. Please create your own restaurant in order to delete.');}</script><body onload='myFunction()''>"
  if request.method == 'POST':
    session.delete(restaurantToDelete)
    flash('%s Successfully Deleted' % restaurantToDelete.name)
    session.commit()
    return redirect(url_for('showRestaurants', restaurant_id = restaurant_id))
  else:
    return render_template('deleteRestaurant.html',restaurant = restaurantToDelete)

# Show a restaurant menu; protect each menu based on the user who created it
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
  restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  creator = getUserInfo(restaurant.user_id)
  items = session.query(MenuItem).filter_by(restaurant_id = restaurant_id).all()
  # if user isn't logged in or isn't the original creator, render the public menu....
  if 'username' not in login_session or creator.id != login_session['user_id']:
    return render_template('publicmenu.html', items = items, restaurant = restaurant, creator = creator)
  # otherwise render the original menu
  else:
    return render_template('menu.html', items = items, restaurant = restaurant, creator = creator)

# Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/',methods=['GET','POST'])
def newMenuItem(restaurant_id):
  if 'username' not in login_session:
    return redirect('/login')
  restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if request.method == 'POST':
      newItem = MenuItem(name = request.form['name'], description = request.form['description'], price = request.form['price'], course = request.form['course'], restaurant_id = restaurant_id, user_id = restaurant.user_id)
      session.add(newItem)
      session.commit()
      flash('New Menu %s Item Successfully Created' % (newItem.name))
      return redirect(url_for('showMenu', restaurant_id = restaurant_id))
  else:
      return render_template('newmenuitem.html', restaurant_id = restaurant_id)

# Edit a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET','POST'])
def editMenuItem(restaurant_id, menu_id):
  if 'username' not in login_session:
    return redirect('/login')
  editedItem = session.query(MenuItem).filter_by(id = menu_id).one()
  restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  if request.method == 'POST':
    if request.form['name']:
        editedItem.name = request.form['name']
    if request.form['description']:
        editedItem.description = request.form['description']
    if request.form['price']:
        editedItem.price = request.form['price']
    if request.form['course']:
        editedItem.course = request.form['course']
    session.add(editedItem)
    session.commit() 
    flash('Menu Item Successfully Edited')
    return redirect(url_for('showMenu', restaurant_id = restaurant_id))
  else:
      return render_template('editmenuitem.html', restaurant_id = restaurant_id, menu_id = menu_id, item = editedItem)

# Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods = ['GET','POST'])
def deleteMenuItem(restaurant_id,menu_id):
  if 'username' not in login_session:
    return redirect('/login')
  restaurant = session.query(Restaurant).filter_by(id = restaurant_id).one()
  itemToDelete = session.query(MenuItem).filter_by(id = menu_id).one() 
  if request.method == 'POST':
      session.delete(itemToDelete)
      session.commit()
      flash('Menu Item Successfully Deleted')
      return redirect(url_for('showMenu', restaurant_id = restaurant_id))
  else:
      return render_template('deleteMenuItem.html', item = itemToDelete)


# take email and return user ID, if user is stored in db
def getUserID(email):
  try:
    user = session.query(User).filter_by(email = email).one()
    return user.id
  except:
    return None

# when user id is passed in, return the user object
def getUserInfo(user_id):
  user = session.query(User).filter_by(id = user_id).one()
  return user

# Take a login session as input, and create a new user in db; populate all fields from login session
def createUser(login_session):
  newUser = User(name = login_session['username'], email = login_session['email'], picture = login_session['picture'])
  session.add(newUser)
  session.commit()
  user = session.query(User).filter_by(email = login_session['email']).one()
  # return user id of new user created
  return user.id  


if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
