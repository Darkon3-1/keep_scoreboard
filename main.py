from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'this_is_my_super_secret_key_right_now'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

db = SQLAlchemy(app)
all_flags = [
    'add',
    'all',
    'flags',
    'here'
]

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    flags = db.relationship('Flag', backref='user', lazy='dynamic')

    def __repr__(self):
        return self.username

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Flag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    flag = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return self.flag

@app.get('/', defaults={'path': ''})
@app.get('/<path:path>')
def index(path):
    possible_route = ['login', 'logout', 'register', 'submit_flag', 'scoreboard']
    if path in possible_route:
        return render_template(f'{path}.html')
    
    return render_template('index.html')


@app.post('/register')
def register():
    username = request.form['username']
    password = request.form['password']
    if User.query.filter_by(username=username).first():
        flash('Username already taken.', 'error')
        return redirect(url_for('register'))
    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    flash('Registration successful.', 'success')
    session['username'] = username
    return redirect('/submit-flag')


@app.post('/login')
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        session['username'] = username
        flash('Login successful.', 'success')
        return redirect(url_for('submit_flag'))
    else:
        flash('Invalid username or password.', 'error')
        return redirect('/login')

@app.get('/logout')
def logout():
    del session['username']
    return redirect('/')


@app.post('/submit_flag')
def submit_flag():
    if 'username' not in session:
        flash('You must login first.', 'error')
        return redirect(url_for('login'))
    username = session['username']
    user = User.query.filter_by(username=username).first()
    flag = request.form['flag']
    if flag not in all_flags:
        flash('Wrong flag.', 'error')
        return redirect('/submit_flag')
    if user.flags.filter_by(flag=flag).first():
        flash(f'Flag already submitted by {username}.', 'error')
        return redirect(url_for('submit_flag'))
    flag = Flag(flag=flag, user_id=user.id)
    db.session.add(flag)
    db.session.commit()
    flash('NICE! Flag submitted.', 'success')
    return redirect('/submit_flag')


@app.route('/scoreboard')
def scoreboard():
    users = User.query.all()
    user_scores = [(user, len(user.flags.all())) for user in users]
    user_scores.sort(key=lambda x: (-x[1], x[0].username))
    return render_template('scoreboard.html', user_scores=user_scores)

def run():
    create_tables()
    app.run(debug=True)

def create_tables():
    with app.app_context():
        db.create_all() 

if __name__ == '__main__':
    run()