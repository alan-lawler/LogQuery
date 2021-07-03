import dash_core_components as dcc
import dash_bootstrap_components as dbc
import dash_html_components as html
from dash.dependencies import Input, Output, State
import dash_table
import pandas as pd
from datetime import datetime
from app import app
import numpy as np
import glob
import datetime as dt
import re

today = dt.date.today()

names = ['Date', 'Time', 'Source', 'Destination', 'Dest Port', 'Protocol', 'Action', 'Category', 'Country']
df = pd.DataFrame(columns=names)

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
    html.Br(),
    dcc.DatePickerRange(
        id='dates',
        min_date_allowed=datetime(2021, 3, 27),
        max_date_allowed=today,
        start_date=today,
        end_date=today,
    ),
    dcc.Input(id="source", type="text", placeholder="Source"),
    dcc.Input(id="dest", type="text", placeholder="Destination"),
    dcc.Input(id="dest_port", type="text", placeholder="Dest Port"),
    dcc.Input(id="action", type="text", placeholder="Action"),
    dcc.Input(id="category", type="text", placeholder="Category"),
    dcc.Input(id="country", type="text", placeholder="Country"),
    html.Button(
        id='submit-button',
        n_clicks=0,
        children='Submit'
        # style={'fontSize': 24, 'marginLeft': '30px'}
    ),
    html.Br(),
    html.Br(),
    dash_table.DataTable(
        id='search-table',
        columns=[{'presentation': 'markdown', 'id': c, 'name': c} for c in df.columns],
        page_size=18,
        # data=df.to_dict('records'),
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
    html.Br(),
])


@app.callback(
    Output('search-table', 'data'),
    [Input('submit-button', 'n_clicks')],
    [State('dates', 'start_date'),
     State('dates', 'end_date'),
     State('source', 'value'),
     State('dest', 'value'),
     State('dest_port', 'value'),
     State('action', 'value'),
     State('category', 'value'),
     State('country', 'value')
     ])
def update_table(n_clicks, start_date, end_date, source, dest, dest_port, action, category, country):
    files = glob.glob('/home/ubuntu/capstone/src/*.csv')

    dfs = [pd.read_csv(fp, names=names, header=None) for fp in files]
    df = pd.concat(dfs)
    df = df.replace(np.nan, '', regex=True)  # removes null values
    df['Dest Port'] = df['Dest Port'].apply(str)

    if source is None or source == '':
        source = df['Source'].str.contains('.+')
    else:
        source = df['Source'].str.contains('^' + source)

    if dest is None or dest == '':
        dest = df['Destination'].str.contains('.+')
    else:
        dest = df['Destination'].str.contains('^' + dest)

    if dest_port is None or dest_port == '':
        dest_port = df['Dest Port'].str.contains('.+')
    else:
        dest_port = df['Dest Port'].isin([str(dest_port)])

    if action is None or action == '':
        action = df['Action'].str.contains('.+')
    else:
        action = df['Action'].str.contains(action.title())

    if category is None or category == '':
        category = df['Category'].str.contains('.+')
    else:
        category = df['Category'].str.contains(category.lower())

    if country is None or country == '':
        country = df['Country'].str.contains('.+')
    elif len(country) != 2:
        country = None
    else:
        country = df['Country'].str.contains(country.upper())

    data = df[
        (df['Date'] >= start_date) & (df['Date'] <= end_date) &
        source & dest & dest_port & action & category & country
        ]

    return data.to_dict('records')
