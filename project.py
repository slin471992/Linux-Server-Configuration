from flask import Flask, render_template
from flask import request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc, desc, func
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

# Login with google account


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'

    flash("You are now logged in with Google as %s" %
          login_session['username'])
    print "done!"
    return output


# log out google account
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# Log in with facebook account


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly
    # logout, let's strip out the information before the equals sign in our
    # token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'

    flash("You are now logged in with Facebook as %s" %
          login_session['username'])
    return output


# Log out of facebook account
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            # del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']

        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))


@app.route("/catalog/<string:category_name>/JSON/")
def menuItemJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    category_id = category.id
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/catalog/JSON/')
def showCatalogJSON():
    catalog = session.query(Category).all()
    return jsonify(catalog=[c.serialize for c in catalog])


# Show all categories
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    catalog = session.query(Category).order_by(asc(Category.name))
    # retreive latest added items
    items = session.query(Item).order_by(desc(Item.created)).limit(10)

    if 'username' not in login_session:
        return render_template("publiccatalog.html", catalog=catalog, items=items)
    else:
        return render_template('login_catalog.html', catalog=catalog, items=items)


# Create a new category


@app.route('/catalog/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        error = "Please login to create a new category"
        return render_template("error_login.html", error=error)
        # return redirect('/login')
    if request.method == 'POST':
        if request.form['name']:
            newCategory = Category(
                name=request.form['name'], user_id=login_session['user_id'])
            session.add(newCategory)
            flash('New Category %s Successfully Created' % newCategory.name)
            session.commit()
            return redirect(url_for('showCatalog'))
        else:
            error = "Please enter a category name"
            return render_template('newCategory.html', error=error)
    else:
        return render_template('newCategory.html')


# Edit a category


@app.route('/catalog/<string:category_name>/edit/', methods=['GET', 'POST'])
def editCategory(category_name):
    editedCategory = session.query(
        Category).filter_by(name=category_name).one()

    if 'username' not in login_session:
        # return redirect('/login')
        error = "Please login to edit the category"
        return render_template("error_login.html", error=error)

    if editedCategory.user_id != login_session['user_id']:
        return "<script>function myFunction() \
                    {alert('You are not authorized to edit this category.');}\
                    </script><body onload='myFunction()''>"
        # error = "You are not arthorized to edit this category"
        # return render_template("login_items.html", )
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            flash('Category %s Successfully Edited' % editedCategory.name)
            return redirect(url_for('showCatalog'))

    else:
        return render_template('editCategory.html', category=editedCategory)


# Delete a Category


@app.route('/catalog/<string:category_name>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_name):
    categoryToDelete = session.query(
        Category).filter_by(name=category_name).one()
    if 'username' not in login_session:
        # return redirect('/login')
        error = "Please login to delete the category"
        return render_template("error_login.html", error=error)

    if categoryToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction()\
                    {alert('You are not authorized to delete this category.');}\
                    </script><body onload='myFunction()''>"

    if request.method == 'POST':
        if request.form["action"] == "delete":
            # delete the category
            session.delete(categoryToDelete)
            session.commit()

            # delete the items in the category
            items = session.query(Item).filter_by(
                category_id=categoryToDelete.id)
            for item in items:
                session.delete(item)
                session.commit()

            flash('Category %s Successfully Deleted' % categoryToDelete.name)

            return redirect(url_for('showCatalog', category_name=category_name))
        else:
            return redirect(url_for('showItems', category_name=category_name))
    else:
        return render_template('deleteCategory.html', category=categoryToDelete)


# List all item of a category
@app.route("/catalog/<string:category_name>/")
@app.route("/catalog/<string:category_name>/items/")
def showItems(category_name):
    catalog = session.query(Category).order_by(asc(Category.name))
    category = session.query(Category).filter_by(name=category_name).one()
    category_id = category.id
    items = session.query(Item).filter_by(
        category_id=category_id).all()

    # get the number of items of a category
    number = session.query(Item).filter_by(
        category_id=category_id).count()

    if 'username' not in login_session:
        return render_template("publicitems.html", catalog=catalog,
                               category=category, items=items, number=number)
    else:
        return render_template('login_items.html', catalog=catalog,
                               category=category, items=items, number=number)


@app.route("/catalog/<string:category_name>/<string:item_name>/")
def showDescription(category_name, item_name):
    item = session.query(Item).filter_by(
        name=item_name).one()

    if 'username' not in login_session:
        return render_template("publicdescription.html", item=item)

    else:
        return render_template("login_description.html", item=item)


# Create a new item
@app.route('/catalog/<string:category_name>/new/', methods=['GET', 'POST'])
def newItem(category_name):
    category = session.query(Category).filter_by(name=category_name).one()

    if 'username' not in login_session:
        # return redirect('/login')
        error = "Please login to add a new item"
        return render_template("error_login.html", error=error)

    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() \
                    {alert('You are not authorized to add items to this category.');}\
                    </script><body onload='myFunction()''>"

    if request.method == 'POST':
        if request.form["action"] == "save":
            newItem = Item(name=request.form['name'], description=request.form['description'],
                           category=category, user_id=category.user_id)
            session.add(newItem)
            session.commit()
            flash('New Item %s Successfully Created' % (newItem.name))
            return redirect(url_for('showItems', category_name=category.name))
        else:
            return redirect(url_for('showItems', category_name=category.name))

    else:
        return render_template('newItem.html', category_name=category.name)


# Edit an item


@app.route('/catalog/<string:category_name>/<string:item_name>/edit', methods=['GET', 'POST'])
def editItem(category_name, item_name):
    if 'username' not in login_session:
        # return redirect('/login')
        error = "Please login to edit an item"
        return render_template("error_login.html", error=error)

    editedItem = session.query(Item).filter_by(name=item_name).one()
    category = session.query(Category).filter_by(name=category_name).one()

    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction()\
                    {alert('You are not authorized to edit items to this category.');}\
                    </script><body onload='myFunction()''>"

    if request.method == 'POST':
        if request.form["action"] == "save":
            if request.form['name']:
                editedItem.name = request.form['name']
            if request.form['description']:
                editedItem.description = request.form['description']
            # if request.form['category']:
            #     editedItem.category = request.form['category']

            session.add(editedItem)
            session.commit()
            flash('Item Successfully Edited')
            return redirect(url_for('showDescription',
                                    category_name=category_name, item_name=editedItem.name))

        else:
            return redirect(url_for('showDescription',
                                    category_name=category_name, item_name=item_name))
    else:
        return render_template('edit_item.html', category_name=category_name, item=editedItem)


# Delete an item


@app.route('/catalog/<string:category_name>/<string:item_name>/delete', methods=['GET', 'POST'])
def deleteItem(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')

    category = session.query(Category).filter_by(name=category_name).one()
    itemToDelete = session.query(Item).filter_by(name=item_name).one()

    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction()\
                    {alert('You are not authorized to delete items to this category.');}\
                    </script><body onload='myFunction()''>"

    if request.method == 'POST':
        if request.form["action"] == "delete":
            name = itemToDelete.name
            session.delete(itemToDelete)
            session.commit()
            flash('Item %s Successfully Deleted' % name)
            return redirect(url_for('showItems', category_name=category_name))
        else:
            return redirect(url_for('showDescription',
                                    category_name=category_name, item_name=item_name))
    else:
        return render_template('deleteItem.html', item=itemToDelete)


# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
