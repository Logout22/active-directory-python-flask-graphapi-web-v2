from flask import Flask, redirect, url_for, session, request, jsonify, render_template
from flask_oauthlib.client import OAuth, OAuthException

# from flask_sslify import SSLify

from logging import Logger
import uuid

app = Flask(__name__)
# sslify = SSLify(app)
app.debug = True
app.secret_key = 'development'
oauth = OAuth(app)

consumer_key = 'Register your app at apps.dev.microsoft.com'
consumer_secret = 'Register your app at apps.dev.microsoft.com'
# Put your consumer key and consumer secret into a config file
# and don't check it into github!!
microsoft = oauth.remote_app(
	'microsoft',
	consumer_key=consumer_key,
	consumer_secret=consumer_secret,
	request_token_params={'scope': 'offline_access User.Read'},
	base_url='https://graph.microsoft.com/v1.0/',
	request_token_url=None,
	access_token_method='POST',
	access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
	authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
)

refresh_token = None

@app.route('/')
def index():
	return render_template('hello.html')

@app.route('/login', methods = ['POST', 'GET'])
def login():

	if 'microsoft_token' in session:
		return redirect(url_for('me'))

	# Generate the guid to only accept initiated logins
	guid = uuid.uuid4()
	session['state'] = guid

	return microsoft.authorize(callback=url_for('authorized', _external=True), state=guid)
	
@app.route('/logout', methods = ['POST', 'GET'])
def logout():
	session.pop('microsoft_token', None)
	session.pop('state', None)
	return redirect(url_for('index'))

def store_credentials(response):
	global refresh_token
	print("Response: " + str(response))
	# Okay to store this in a local variable, encrypt if it's going to client
	# machine or database. Treat as a password.
	session['microsoft_token'] = (response['access_token'], '')
	refresh_token = response['refresh_token']

	return redirect(url_for('me'))

@app.route('/login/authorized')
def authorized():
	response = microsoft.authorized_response()

	if response is None:
		return "Access Denied: Error=%s" % (
			request.get('error_description')
		)
		
	# Check response for state
	if str(session['state']) != str(request.args['state']):
		raise Exception('State has been messed with, end authentication')

	return store_credentials(response)

def refresh():
	print("Refreshing")
	data = {'grant_type': 'refresh_token', 'refresh_token': refresh_token, 'client_id': consumer_key,
			'client_secret': consumer_secret}
	response = microsoft.post(microsoft.access_token_url, data=data)
	if response is None:
		return "Refresh failed"
	return store_credentials(response.data)

@app.route('/me')
def me():
	me = microsoft.get('me')
	if 'error' in me.data.keys() and me.data['error']['code'] == 'InvalidAuthenticationToken':
		return refresh()
	return render_template('me.html', me=str(me.data))

@microsoft.tokengetter
def get_microsoft_oauth_token():
	return session.get('microsoft_token')

if __name__ == '__main__':
	app.run()
