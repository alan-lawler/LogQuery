import dash_core_components as dcc
import dash_bootstrap_components as dbc
import dash_html_components as html
from dash.dependencies import Input, Output
import dash_daq as daq
import dash_table
import pandas as pd
import datetime
from app import app
import numpy as np

filename = str(datetime.date.today())

names = ['Date', 'Time', 'Source', 'Destination', 'Dest Port', 'Protocol', 'Action', 'Category', 'Country']
df = pd.read_csv('/home/ubuntu/capstone/src/' + filename + '.csv', names=names, header=None)
df = df.tail(12)

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
    html.Img(style={'height': '10%', 'width': '10%'}),
    # Dash DataTable
    dash_table.DataTable(
        id='dashboard',
        columns=[{'presentation': 'markdown', 'id': c, 'name': c} for c in df.columns],
        fixed_rows={'headers': True},
        # style_table={'height': 2200, 'width': 1500, 'margin-right': 'auto', 'margin-left': 'auto'},
        # Sets text alignment for table header and column width
        style_cell_conditional=[
            {'if': {'column_id': 'Date'},
             'width': '10%', 'textAlign': 'left'},
            {'if': {'column_id': 'Time'},
             'width': '10%', 'textAlign': 'left'},
            {'if': {'column_id': 'Source'},
             'width': '10%', 'textAlign': 'left'},
            {'if': {'column_id': 'Destination'},
             'width': '10%', 'textAlign': 'left'},
            {'if': {'column_id': 'Dest Port'},
             'width': '10%', 'textAlign': 'left'},
            {'if': {'column_id': 'Protocol'},
             'width': '10%', 'textAlign': 'left'},
            {'if': {'column_id': 'Action'},
             'width': '10%', 'textAlign': 'left'},
            {'if': {'column_id': 'Category'},
             'width': '10%', 'textAlign': 'left'},
            {'if': {'column_id': 'Country'},
             'width': '10%', 'textAlign': 'left'}
        ],
        style_data_conditional=[
            {'if': {'row_index': 'odd'},
                'backgroundColor': 'rgb(248, 248, 248)'},
            # Highlights rows red if category == vpn
            {'if': {'filter_query': '{Category} = "vpn"'},
                'backgroundColor': 'red', 'color': 'white'},
            # Highlights rows red if category == proxy
            {'if': {'filter_query': '{Category} = "proxy"'},
             'backgroundColor': 'red', 'color': 'white'},
            # Highlights rows red if category == tor
            {'if': {'filter_query': '{Category} = "tor"'},
             'backgroundColor': 'red', 'color': 'white'}
        ],
        style_header={
            'backgroundColor': 'rgb(230, 230, 230)',
            'fontWeight': 'bold'
        }

    ),
    # Dash interval code to update table every 1 second
    dcc.Interval(
        id='interval-component',
        interval=1 * 1000,  # in milliseconds == 1 second
        n_intervals=0,
    ),
    html.Br(),
    html.Div([
        daq.PowerButton(
            id='power',
            on=True,
            label='Start / Stop',
            labelPosition='bottom',
            color='green'
        )
    ])
])


# Callback to update table with last 12 rows in dataframe every one second
@app.callback(
    Output('dashboard', 'data'),
    [Input('interval-component', 'n_intervals')]
)
def update_dashboard(n):
    df = pd.read_csv('/home/ubuntu/capstone/src/' + filename + '.csv', names=names, header=None)
    df = df.tail(12)
    if n > 0:
        df = df.tail(12)  # loads dataframe with the last 12 logs
        df = df.replace(np.nan, '', regex=True)  # removes null values
    return df.to_dict('records')


# Callback to start or stop updating dashboard
@app.callback(
    Output('interval-component', 'max_intervals'),
    [Input('power', 'on')]
)
def stop_interval(state):
    if state is True:
        max_intervals = -1  # if -1, interval has no limit
    else:
        max_intervals = 0  # if 0, interval stops

    return max_intervals
