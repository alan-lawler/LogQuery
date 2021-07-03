import dash_core_components as dcc
import dash_bootstrap_components as dbc
import dash_html_components as html
from dash.dependencies import Input, Output, State
from app import app
import plotly.graph_objects as go
import requests

token = mapbox_access_token = open("/home/ubuntu/mapbox/.mapbox_token").read()

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
    html.Section([
        html.Div([
            html.H4('Enter an IP address:'),
            html.Hr(),
            dcc.Input(id="ip_lookup", type="text", value='199.249.230.170'),
        ]),
        html.Button(
            id='submit-button-ip',
            n_clicks=0,
            children='Submit'
        ),
    ], className='menu'),
    html.Section([
        html.Div([], id="output-test"),
        html.Br(),
    ], className='threat-container')
])


def threat_lookup(ip):
    endpoint = f'https://api.ipregistry.co/{ip}?key=API KEY'
    r = requests.get(endpoint)
    response = r.json()
    asn = response['connection']['asn']
    org = response['connection']['organization']
    city = response['location']['city']
    country = response['location']['country']['name']
    lat = response['location']['latitude']
    lon = response['location']['longitude']
    tz = response['time_zone']['abbreviation']
    abuse = response['security']['is_abuser']
    anon = response['security']['is_anonymous']
    attacker = response['security']['is_attacker']
    bogon = response['security']['is_bogon']
    cloud = response['security']['is_cloud_provider']
    proxy = response['security']['is_proxy']
    threat = response['security']['is_threat']
    tor = response['security']['is_tor']
    tor_exit = response['security']['is_tor_exit']

    return asn, org, city, country, lat, lon, tz, abuse, anon, attacker, bogon, cloud, proxy, threat, tor, tor_exit


@app.callback(
    Output("output-test", "children"),
    [Input('submit-button-ip', 'n_clicks')],
    [State('ip_lookup', 'value')]
)
def update_output(n_clicks, ip_address):
    asn, org, city, country, lat, lon, tz, abuse, anon, attacker, bogon, cloud, proxy, threat, tor, tor_exit \
        = threat_lookup(ip_address)

    fig = go.Figure(go.Scattermapbox(
        lat=[lat],
        lon=[lon],
        mode='markers',
        marker=go.scattermapbox.Marker(
            size=14
        ),
        text=ip_address,
    ))

    fig.update_layout(
        mapbox={
            'accesstoken': token,
            'style': "basic", 'zoom': 0.7},
        showlegend=False)

    return html.Div([
        html.Br(),
        html.H4(f'{ip_address}'),
        html.H5(f'ASN: {asn}'),
        html.H5(f'City:  {city}'),
        html.H5(f'Country:  {country}'),
        html.H5(f'Org: {org}'),
        html.H5(f'Time Zone: {tz}'),
        html.Br(),
        html.H4('Threat Data:'),
        html.H5(f'Bogon: {bogon}'),
        html.H5(f'Abuser: {abuse}'),
        html.H5(f'Attacker: {attacker}'),
        html.H5(f'Tor IP: {tor}'),
        html.H5(f'Tor Exit Node: {tor_exit}'),
        html.H5(f'Cloud Provider: {cloud}'),
        html.H5(f'Anonymous Service Provider: {anon}'),
        dcc.Graph(id='map', figure=fig)
    ])
