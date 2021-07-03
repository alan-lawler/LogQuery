import dash_core_components as dcc
import dash_bootstrap_components as dbc
import dash_html_components as html
from dash.dependencies import Input, Output, State
import dash_table
import pandas as pd
import requests
from app import app
import base64
import io

layout = html.Div([
    # Navbar from Dash bootstrap
    dbc.NavbarSimple(
        children=[
            dbc.NavItem(dbc.NavLink("Dashboard", href="/apps/dashboard")),
            dbc.NavItem(dbc.NavLink("Threat Intel", href="/apps/threat_intel")),
            dbc.NavItem(dbc.NavLink("Search", href="/apps/search")),
            dbc.NavItem(dbc.NavLink("Bulk Upload", href="/apps/upload")),
        ],
        brand="LogQuery",
        brand_href="#",
        color="primary",
        dark=True,
    ),
    dcc.Upload(
        id='upload-data',
        children=html.Div([
            'Drag and Drop or ',
            html.A('Select Files')
        ]),
        style={
            'width': '100%',
            'height': '60px',
            'lineHeight': '60px',
            'borderWidth': '1px',
            'borderStyle': 'dashed',
            'borderRadius': '5px',
            'textAlign': 'center',
            'margin': '10px'
        },
        # Allow multiple files to be uploaded
        multiple=True
    ),
    html.Div(id='output-data-upload'),
])


def threat_lookup(ip):
    endpoint = f'https://api.ipregistry.co/{ip}?key=se9q6mprd3lm5f'
    r = requests.get(endpoint)
    response = r.json()
    country = response['location']['country']['name']
    abuse = response['security']['is_abuser']
    anon = response['security']['is_anonymous']
    attacker = response['security']['is_attacker']
    bogon = response['security']['is_bogon']
    cloud = response['security']['is_cloud_provider']
    tor = response['security']['is_tor']
    tor_exit = response['security']['is_tor_exit']

    return pd.Series([country, bogon, abuse, attacker, tor, tor_exit, cloud, anon])


def parse_contents(contents, filename, date):
    content_type, content_string = contents.split(',')

    decoded = base64.b64decode(content_string)
    try:
        names = ['IP', 'Country', 'Bogon', 'Abuser', 'Attacker', 'Tor IP', 'Tor Exit Node', 'Cloud', 'Anonymous']
        df = pd.read_csv(
            io.StringIO(decoded.decode('utf-8')), names=names, header=None, nrows=100)
        df[['Country', 'Bogon', 'Abuser', 'Attacker', 'Tor IP', 'Tor Exit Node', 'Cloud', 'Anonymous']] = df['IP']\
            .apply(threat_lookup)
        df.astype(str)
    except Exception as e:
        print(e)
        return html.Div([
            'There was an error processing this file.'
        ])

    return html.Div([
        dash_table.DataTable(
            data=df.to_dict('records'),
            columns=[{'name': i, 'id': i} for i in df.columns],
            fixed_rows={'headers': True},
            style_header={
                'backgroundColor': 'rgb(230, 230, 230)',
                'fontWeight': 'bold'
            },
            style_cell_conditional=[
                {'if': {'column_id': 'IP'},
                 'width': '10%', 'textAlign': 'left'},
                {'if': {'column_id': 'Country'},
                 'width': '10%', 'textAlign': 'left'},
                {'if': {'column_id': 'Bogon'},
                 'width': '10%', 'textAlign': 'left'},
                {'if': {'column_id': 'Abuser'},
                 'width': '10%', 'textAlign': 'left'},
                {'if': {'column_id': 'Attacker'},
                 'width': '10%', 'textAlign': 'left'},
                {'if': {'column_id': 'Tor IP'},
                 'width': '10%', 'textAlign': 'left'},
                {'if': {'column_id': 'Tor Exit Node'},
                 'width': '10%', 'textAlign': 'left'},
                {'if': {'column_id': 'Cloud'},
                 'width': '10%', 'textAlign': 'left'},
                {'if': {'column_id': 'Anonymous'},
                 'width': '10%', 'textAlign': 'left'}
            ],
            style_data_conditional=[
                {'if': {'row_index': 'odd'},
                 'backgroundColor': 'rgb(248, 248, 248)'},
            ]
        )
    ])


@app.callback(Output('output-data-upload', 'children'),
              Input('upload-data', 'contents'),
              State('upload-data', 'filename'),
              State('upload-data', 'last_modified'))
def update_output(list_of_contents, list_of_names, list_of_dates):
    if list_of_contents is not None:
        children = [
            parse_contents(c, n, d) for c, n, d in
            zip(list_of_contents, list_of_names, list_of_dates)]
        return children
