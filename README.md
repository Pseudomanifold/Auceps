# Auceps: Analysing `auth.log` log files

This is a simple script for analysing `auth.log`. It tabulates IP
addresses and user names that are involved in failed login attempts
via `ssh`&nbsp;(although the script could be easily extended to cover
other services, as well). Moreover, it creates a CSV file for subsequent
[choropleth map](https://en.wikipedia.org/wiki/Choropleth_map) plotting.

## Usage

    $ pipenv shell
    $ ./auceps.py /var/log/auth*
    $ ./make_choropleth_map.py /tmp/countries.csv

For the choropleth map creation, you need to have a valid
[plotly](https://plot.ly) account.

## Example

See [my blog post on analysing nefarious ssh access attempts](http://bastian.rieck.me/blog/posts/2019/ssh_incidents) for more details.
