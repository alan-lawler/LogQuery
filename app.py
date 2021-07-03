import dash
import dash_bootstrap_components as dbc
import dash_auth

app = dash.Dash(__name__, suppress_callback_exceptions=True, external_stylesheets=[dbc.themes.FLATLY])
server = app.server

app.title = 'LogQuery'

VALID_USERNAME_PASSWORD_PAIRS = {
    'user': 'pass'
}
auth = dash_auth.BasicAuth(
    app,
    VALID_USERNAME_PASSWORD_PAIRS
)
