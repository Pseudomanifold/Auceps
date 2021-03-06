#!/usr/bin/env python3
#
# make_choropleth_map.py: uses `Plotly` to create a choropleth map of
# the origin of the nefarious incidents, taken from a log file.

import iso3166
import sys

import numpy as np
import pandas as pd

import plotly.offline as po
import plotly.plotly as py
import plotly.graph_objs as go


if __name__ == '__main__':
    df = pd.read_csv(sys.argv[1])

    # Convert from two-character abbreviations to three-character
    # abbreviations because `Plotly` cannot handle them.
    locations = list(map(
        lambda x: iso3166.countries.get(x).alpha3, df['code'].values))

    data = [ dict(
        type = 'choropleth',
        locations = locations,
        z = np.log10(df['count']),
        text = df['name'],
        colorscale = [[0.00, "rgb(247, 247, 247)"],\
                      [0.25, "rgb(204, 204, 204)"],\
                      [0.50, "rgb(150, 150, 150)"],\
                      [0.75, "rgb( 99,  99,  99)"],\
                      [1.00, "rgb( 37,  37,  37)"]],
        autocolorscale = False,
        reversescale = False,
        colorbar = dict(
            autotick = True,
            title = dict(
                text='<b>Incidents (log-10)</b>'),
            ),
            titleside = 'bottom',
      ) ]

    layout = dict(
        title = '<b>Failed ssh access attempts</b>',
        font = dict(family='Raleway', size=20),
        margin = 5,
        geo = dict(
            showframe = False,
            showcoastlines = True,
            projection = dict(
                type = 'Mercator'
            )
        )
    )

    figure = dict(data=data, layout=layout)
    py.iplot(figure, validate=False, filename='ssh-incidents')
