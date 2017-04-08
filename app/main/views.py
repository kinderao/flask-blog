from flask import render_template
from . import main
from flask_login import login_required


@main.route('/')
def index():
    return render_template('base.html')


@main.route('/secret')
@login_required
def secret():
    return 'Only authenticate users can allowed'
