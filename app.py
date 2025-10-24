import os
from flask import Flask, render_template, session, redirect, url_for, request
from flask_oidc import OpenIDConnect
from functools import wraps

app = Flask(__name__)

# --- 1. Configuration ---
app.config.update({
    'SECRET_KEY': 'a_very_secret_key_change_this_for_production',
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_COOKIE_SECURE': False,
    'OIDC_CALLBACK_ROUTE': '/oidc/callback',
    'OIDC_SCOPES': ['openid', 'email', 'profile', 'roles'] # Request 'roles' scope
})

# Initialize OpenID Connect
oidc = OpenIDConnect(app)


# --- 2. Custom Decorator for Role-Based Access ---

def admin_required(f):
    """
    A decorator to ensure a user is an admin.
    Must be used *after* @oidc.require_login.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not oidc.user_loggedin:
            return redirect(url_for('login', next=request.url))

        # The correct method is 'user_getinfo(scopes)'
        # This fetches claims from the UserInfo endpoint
        user_info = oidc.user_getinfo(['roles']) 
        
        # Check for 'roles' key and if 'admin' is in the list
        if 'roles' not in user_info or 'admin' not in user_info['roles']:
            # Fallback: Check the ID token directly if not in userinfo
            roles_from_id_token = oidc.user_getfield('roles')
            if not roles_from_id_token or 'admin' not in roles_from_id_token:
                 # --- UPDATED LINE ---
                 # Render a proper 403 Error Page
                 return render_template('403.html'), 403
            
        return f(*args, **kwargs)
    return decorated_function


# --- 3. Application Routes ---

@app.route('/')
def index():
    """Home page, accessible to all."""
    return render_template('index.html', oidc=oidc)


@app.route('/login')
@oidc.require_login
def login():
    """Triggers the OIDC login."""
    return redirect(url_for('profile'))


@app.route('/profile')
@oidc.require_login  # Protects this page
def profile():
    """Displays user profile information fetched from the IdP."""
    
    try:
        user_info_payload = oidc.user_getinfo(['email', 'profile', 'openid'])
    except Exception as e:
        print(f"Could not fetch user info: {e}")
        # Fallback to ID token if userinfo fails
        user_info_payload = {
            'sub': oidc.user_getfield('sub'),
            'email': oidc.user_getfield('email'),
            'name': oidc.user_getfield('name'),
            'preferred_username': oidc.user_getfield('preferred_username')
        }

    user_info = {
        'id': user_info_payload.get('sub'),
        'email': user_info_payload.get('email'),
        'name': user_info_payload.get('name'),
        'preferred_username': user_info_payload.get('preferred_username')
    }
    
    return render_template('profile.html', user=user_info)


# --- UPDATED ADMIN ROUTE ---
@app.route('/admin')
@oidc.require_login
@admin_required  # This decorator is applied *after* the login check
def admin_page():
    """An admin-only page."""
    # Get the admin's user info to display
    admin_user = oidc.user_getinfo(['name', 'email'])
    
    # You can add real data here later
    mock_stats = {
        'total_users': 1,
        'active_sessions': 1,
        'failed_logins': 0
    }
    
    return render_template('admin.html', user=admin_user, stats=mock_stats)


@app.route('/logout')
def logout():
    """Logs the user out of the local session and the IdP session."""
    oidc.logout()
    
    try:
        # Use .get() for safer dictionary access
        end_session_endpoint = oidc.client_secrets.get('web', {}).get('end_session_endpoint')
        if end_session_endpoint:
            logout_url = f"{end_session_endpoint}?post_logout_redirect_uri={url_for('index', _external=True)}"
            return redirect(logout_url)
        else:
            print("Warning: 'end_session_endpoint' not found in client_secrets.json. Redirecting to home.")
            return redirect(url_for('index'))
    except KeyError:
        print("Warning: Error reading client_secrets.json. Redirecting to home.")
        return redirect(url_for('index'))


# --- 4. Run the App ---

if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)

