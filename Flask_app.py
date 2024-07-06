from flask import Flask, redirect, url_for, session, request, render_template_string
from authlib.integrations.flask_client import OAuth
import panel as pn
from bokeh.server.server import Server
from tornado.ioloop import IOLoop
import json
import threading
from werkzeug.urls import url_quote


app = Flask(__name__)
app.secret_key = 'flask_app'  # Replace with a secure random key

# Load OAuth credentials from JSON file
with open('client_flask_app.json') as f:
    google_secrets = json.load(f)['web']

# Configure OAuth with Google
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=google_secrets['client_id'],
    client_secret=google_secrets['client_secret'],
    authorize_url=google_secrets['auth_uri'],
    authorize_params=None,
    access_token_url=google_secrets['token_uri'],
    access_token_params=None,
    refresh_token_url=None,
    client_kwargs={'scope': 'email'},
)

# HTML templates
index_html = '''
<!doctype html>
<html>
<head><title>Home</title></head>
<body>
    <h1>Welcome to the Flask App</h1>
    <a href="/login"><button>Login with Google</button></a>
</body>
</html>
'''

post_login_html = '''
<!doctype html>
<html>
<head><title>Post Login</title></head>
<body>
    <h1>Welcome, you are now logged in!</h1>
    <a href="/dashboard"><button>See Dashboard</button></a>
    <a href="/logout"><button>Logout</button></a>
</body>
</html>
'''

@app.route('/')
def index():
    if 'google_token' in session:
        return redirect(url_for('post_login'))
    return render_template_string(index_html)

@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/logout')
def logout():
    session.pop('google_token', None)
    return redirect(url_for('index'))

@app.route('/callback')
def authorize():
    token = google.authorize_access_token()
    if token is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_token'] = token
    return redirect(url_for('post_login'))

@app.route('/post_login')
def post_login():
    if 'google_token' in session:
        return render_template_string(post_login_html)
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'google_token' in session:
        return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Dashboard</title>
        </head>
        <body>
            <h1>Welcome to your Dashboard!</h1>
            <iframe src="http://localhost:5006/panel" width="100%" height="600" style="border:none;"></iframe>
            <a href="/logout"><button>Logout</button></a>
        </body>
        </html>
        """)
    return redirect(url_for('login'))

def modify_doc(doc):
    pn_panel = pn.pane.Markdown("Welcome to your Dashboard!")
    dashboard_page = pn.template.FastListTemplate(main=pn_panel)
    dashboard_page.server_doc(doc)

def bk_worker():
    server = Server({'/panel': modify_doc}, io_loop=IOLoop(), allow_websocket_origin=["localhost:5000"])
    server.start()
    server.io_loop.start()

thread = threading.Thread(target=bk_worker)
thread.start()

if __name__ == '__main__':
    app.run(debug=True)
