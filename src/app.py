# -*- coding: utf-8 -*-
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import yaml
from flask import redirect, request, jsonify, render_template, url_for, \
    make_response, flash
from flask import Flask
import click
import requests
import math
import toolforge
from flask_jsonlocale import Locales
from flask_mwoauth import MWOAuth
from SPARQLWrapper import SPARQLWrapper, JSON
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

app = Flask(__name__, static_folder='../static')

# Load configuration from YAML file
__dir__ = os.path.dirname(__file__)
app.config.update(
    yaml.safe_load(open(os.path.join(__dir__, os.environ.get(
        'FLASK_CONFIG_FILE', 'config.yaml')))))
locales = Locales(app)
_ = locales.get_message

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)

class Wiki(db.Model):
    _sitematrix = None
    id = db.Column(db.Integer, primary_key=True)
    dbname = db.Column(db.String(255))
    url_ = db.Column(db.String(255))
    featured_articles_category = db.Column(db.String(255))
    template = db.Column(db.String(255))
    summary = db.Column(db.String(255))
    bytes_per_link_avg = db.Column(db.Integer)
    bytes_per_link_max = db.Column(db.Integer)
    tolerance = db.Column(db.Integer)
    minimum_length = db.Column(db.Integer)
    articles = db.relationship('SuggestedArticle', backref='suggested_article', lazy=True)

    def _get_wiki_data(self):
        try:
            conn = toolforge.connect('meta')
        except:
            return {
                "sitename": self.dbname,
                "dbname": self.dbname,
                "url": None # TODO: Fix
            }
        with conn.cursor() as cur:
            cur.execute('select * from wiki where dbname=%s', (self.dbname, ))
            data = cur.fetchall()[0]
        return {
            "sitename": data[2],
            "url": data[3],
            "dbname": data[0]
        }

    @property
    def root_url(self):
        return "%s/w" % self.url

    @property
    def url(self):
        if self.url_:
            return self.url_
        sm = self._get_wiki_data()
        self.url_ = sm['url']
        db.session.commit()
        return self.url_
    
    @property
    def name(self):
        sm = self._get_wiki_data()
        return '%s (%s)' % (sm['sitename'], sm['dbname'])

class SuggestedArticle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    page_id = db.Column(db.Integer)
    bytes_per_link = db.Column(db.Integer)
    probability = db.Column(db.Integer)
    wiki_id = db.Column(db.Integer, db.ForeignKey('wiki.id'), nullable=False)

    @property
    def wiki(self):
        return Wiki.query.filter_by(id=self.wiki_id).first()

    @property
    def wiki_root_url(self):
        return self.wiki.root_url

    @property
    def page_title(self):
        r = mwoauth.request({
            "action": "query",
            "format": "json",
            "pageids": self.page_id
        }, url=self.wiki_root_url)
        return r['query']['pages'][str(self.page_id)]['title']

    def as_json(self):
        return {
            "id": self.id,
            "page_id": self.page_id,
            "page_title": self.page_title,
            "probability": self.probability
        }

mwoauth = MWOAuth(
    consumer_key=app.config.get('CONSUMER_KEY'),
    consumer_secret=app.config.get('CONSUMER_SECRET'),
    base_url=app.config.get('OAUTH_MWURI'),
    return_json=True
)
app.register_blueprint(mwoauth.bp)

def logged():
    return mwoauth.get_current_user() is not None

def get_user():
    if logged():
        return User.query.filter_by(username=mwoauth.get_current_user()).first()
    return None

@app.context_processor
def inject_base_variables():
    return {
        "logged": logged(),
        "username": mwoauth.get_current_user(),
        "is_admin": get_user().is_admin
    }

@app.before_request
def force_login():
    if not logged() and '/login' not in request.url and '/oauth-callback' not in request.url:
        return render_template('login.html')

@app.before_request
def db_check_user():
    if logged():
        user = get_user()
        if user is None:
            user = User(username=mwoauth.get_current_user())
            db.session.add(user)
            db.session.commit()
        else:
            if not user.is_active:
                return render_template('permission_denied.html')

@app.before_request
def db_admin_permissions():
    if logged() and '/admin' in request.url and not get_user().is_admin:
        return render_template('permission_denied.html')

@app.route('/')
def index():
    if request.args.get('wiki'):
        w = Wiki.query.filter_by(dbname=request.args.get('wiki')).first()
        return render_template('tool.html', wiki=w)
    return render_template('index.html', wikis=Wiki.query.all())

@app.route('/suggest-article.json')
def suggest_article():
    last_id = request.args.get('last_id', 0)
    wiki = Wiki.query.filter_by(dbname=request.args.get('wiki')).first()
    res = SuggestedArticle.query.filter(db.and_(
        SuggestedArticle.id > last_id,
        SuggestedArticle.wiki_id == wiki.id
    )).order_by('id').first().as_json()
    res['page_html'] = mwoauth.request({
        "action": "parse",
        "format": "json",
        "pageid": res['page_id'],
        "disableeditsection": 1,
        "disabletoc": 1
    }, url=wiki.root_url)['parse']['text']['*']
    return jsonify(res)

@app.route('/report-article/<int:page_id>/needs-more-links', methods=['POST'])
def report_article_needs_more_links(page_id):
    sa = SuggestedArticle.query.filter_by(page_id=page_id).first()
    r = mwoauth.request({
        "action": "query",
        "format": "json",
        "meta": "tokens"
    }, url=sa.wiki_root_url)
    print(r)
    token = r['query']['tokens']['csrftoken']
    r = mwoauth.request({
        "action": "edit",
        "prependtext": '{{%s}}\n' % sa.wiki.template,
        "nocreate": 1,
        "summary": sa.wiki.summary,
        "pageid": page_id,
        "token": token
    }, url=sa.wiki_root_url)
    db.session.delete(sa)
    db.session.commit()
    return jsonify({
        "status": "ok",
        "page_id": page_id,
        "mw_response": r
    })

@app.route('/admin')
def admin_home():
    return render_template('admin/index.html')

@app.route('/admin/wikis', methods=['GET', 'POST'])
def admin_wikis():
    conn = toolforge.connect('meta')
    with conn.cursor() as cur:
        cur.execute('select * from wiki where is_closed=0')
        matrix = cur.fetchall()
    if request.method == 'POST':
        wiki = Wiki(
            dbname=request.form.get('dbname'),
            featured_articles_category=request.form.get('featured-category')
        )
        db.session.add(wiki)
        db.session.commit()
        return redirect(url_for('admin_wikis'))
    return render_template('admin/wikis.html', wikis=Wiki.query.all(), sitematrix=matrix)

@app.route('/admin/wikis/<int:id>/delete', methods=['POST'])
def admin_wiki_delete(id):
    w = Wiki.query.filter_by(id=id).first()
    db.session.delete(w)
    db.session.commit()
    flash(_('wiki-deleted'), 'success')
    return redirect(url_for('admin_wikis'))

@app.route('/admin/wikis/<int:id>/edit', methods=['GET', 'POST'])
def admin_wiki_edit(id):
    w = Wiki.query.filter_by(id=id).first()
    if request.method == 'POST':
        w.featured_articles_category = request.form.get('featured-category')
        w.minimum_length = request.form.get('minimum-length')
        w.template = request.form.get('template')
        w.summary = request.form.get('summary')
        db.session.commit()
        return redirect(request.url)
    return render_template('admin/wiki.html', wiki=w)

@app.route('/admin/wikis/<int:id>/metrics', methods=['POST'])
def admin_wiki_metrics(id):
    w = Wiki.query.filter_by(id=id).first()
    w.bytes_per_link_avg = request.form.get('avg-bytes-per-link')
    w.bytes_per_link_max = request.form.get('max-bytes-per-link')
    w.tolerance = request.form.get('tolerance')
    db.session.commit()
    flash(_('wiki-metrics-edited'), 'success')
    return redirect(url_for('admin_wiki_edit', id=id))

def floor(x, decimals=0):
    multiplier = 10 ** decimals
    return math.floor(x * multiplier) / multiplier

@app.cli.command('suggest-articles')
@click.option('--wiki', required=True)
@click.option('--limit', default=50)
def suggest_articles(wiki, limit):
    w = Wiki.query.filter_by(dbname=wiki).first()
    conn = toolforge.connect(wiki)
    with conn.cursor() as cur:
        treshold = floor(w.bytes_per_link_avg, 2)
        cur.execute(
            '''select page_id, page_title, page_len/count(*) as bytes_per_link from pagelinks
            join page on page_id=pl_from where page_len>%s and page_namespace=0
            group by page_id having bytes_per_link>%s
            limit %s;''' ,
            (w.minimum_length, treshold, limit)
        )
        data = cur.fetchall()
    for row in data:
        bpl_min = w.bytes_per_link_avg
        bpl_max = w.bytes_per_link_max + w.tolerance
        if row[2] < bpl_min:
            probability = 0
        elif row[2] > bpl_max:
            probability = 100
        else:
            probability = (row[2] - bpl_min)/bpl_max * 100
        s = SuggestedArticle(
            page_id=row[0],
            bytes_per_link=row[2],
            probability=probability,
            wiki_id=w.id
        )
        db.session.add(s)
        db.session.commit()

if __name__ == "__main__":
    app.run(threaded=True)
