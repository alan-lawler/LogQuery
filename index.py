import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output
from app import app
from apps import dashboard, search, threat_intel, upload


app.layout = html.Div([
    dcc.Location(id='url', refresh=False),
    html.Div(id='page-content')
])


# Callback to load dash app based on pathname
@app.callback(Output('page-content', 'children'),
              Input('url', 'pathname'))
def display_page(pathname):
    if pathname == '/apps/home':
        return dashboard.layout
    elif pathname == '/apps/search':
        return search.layout
    elif pathname == '/apps/threat_intel':
        return threat_intel.layout
    elif pathname == '/apps/upload':
        return upload.layout
    else:
        return dashboard.layout


# starts application using port
if __name__ == '__main__':
    app.run_server(debug=False, host='0.0.0.0', ssl_context='adhoc')
