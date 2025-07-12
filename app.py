import csv
from io import StringIO
from flask import Response
from flask import Flask, render_template, redirect, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

from flask_migrate import Migrate
migrate = Migrate(app, db)

# Hardcoded admin credentials
ADMIN_CREDENTIALS = {
    "email": "admin@swap.com",
    "password": "admin123"
}

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(200))
    location = db.Column(db.String(100))
    availability = db.Column(db.String(100))
    is_public = db.Column(db.Boolean, default=True)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Skill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(50))
    type = db.Column(db.String(10))  # 'offered' or 'wanted'
    user = db.relationship('User', backref='skills')

class SwapRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    skill_offered = db.Column(db.String(50))
    skill_requested = db.Column(db.String(50))
    status = db.Column(db.String(20), default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    rating = db.Column(db.Integer)  # 1 to 5
    feedback = db.Column(db.Text)

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        password_hash = generate_password_hash(request.form['password'])
        user = User(
            name=request.form['name'],
            email=request.form['email'],
            password=password_hash,
            location=request.form.get('location'),
            availability=request.form.get('availability'),
            is_public=bool(request.form.get('is_public'))
        )
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if email == ADMIN_CREDENTIALS["email"] and password == ADMIN_CREDENTIALS["password"]:
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            return "Invalid admin credentials", 403

    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    all_users = User.query.all()
    all_swaps = SwapRequest.query.all()

    return render_template('admin_dashboard.html', users=all_users, swaps=all_swaps)


@app.route('/admin_skills')
def admin_skills():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    all_skills = Skill.query.all()
    return render_template('admin_skills.html', skills=all_skills)

@app.route('/admin_delete_skill/<int:skill_id>')
def admin_delete_skill(skill_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    skill = Skill.query.get_or_404(skill_id)
    db.session.delete(skill)
    db.session.commit()
    return redirect(url_for('admin_skills'))

@app.route('/admin_toggle_ban/<int:user_id>')
def admin_toggle_ban(user_id):
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    user = User.query.get_or_404(user_id)
    user.is_banned = not user.is_banned
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_announcement', methods=['GET', 'POST'])
def admin_announcement():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    latest = Announcement.query.order_by(Announcement.created_at.desc()).first()

    if request.method == 'POST':
        message = request.form['message']
        new_announcement = Announcement(message=message)
        db.session.add(new_announcement)
        db.session.commit()
        return redirect(url_for('admin_announcement'))

    return render_template('admin_announcement.html', latest=latest)

@app.route('/admin/download_users')
def download_users():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    users = User.query.all()

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'Name', 'Email', 'Location', 'Availability', 'Public?', 'Banned?'])

    for u in users:
        cw.writerow([u.id, u.name, u.email, u.location, u.availability, u.is_public, u.is_banned])

    output = Response(si.getvalue(), mimetype='text/csv')
    output.headers["Content-Disposition"] = "attachment; filename=users_report.csv"
    return output

@app.route('/admin/download_swaps')
def download_swaps():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    swaps = SwapRequest.query.all()

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['From User ID', 'To User ID', 'Skill Offered', 'Skill Requested', 'Status', 'Date', 'Rating', 'Feedback'])

    for s in swaps:
        cw.writerow([
            s.from_user_id, s.to_user_id,
            s.skill_offered, s.skill_requested,
            s.status, s.created_at,
            s.rating or "", s.feedback or ""
        ])

    output = Response(si.getvalue(), mimetype='text/csv')
    output.headers["Content-Disposition"] = "attachment; filename=swaps_report.csv"
    return output

@app.route('/delete_swap/<int:swap_id>', methods=['POST'])
def delete_swap(swap_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    swap = SwapRequest.query.get_or_404(swap_id)

    # Ensure only sender can delete, and only if pending
    if swap.from_user_id != session['user_id'] or swap.status != 'pending':
        return "Unauthorized or already processed", 403

    db.session.delete(swap)
    db.session.commit()
    return redirect(url_for('swap_requests'))

@app.context_processor
def inject_announcement():
    latest = Announcement.query.order_by(Announcement.created_at.desc()).first()
    return dict(global_announcement=latest)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            return 'Invalid credentials'
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    user_skills = Skill.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html', user=user, user_skills=user_skills)

@app.route('/add_skill', methods=['POST'])
def add_skill():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    skill = Skill(
        user_id=session['user_id'],
        name=request.form['name'],
        type=request.form['type']
    )
    db.session.add(skill)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/browse')
def browse():
    users = User.query.filter_by(is_public=True).all()
    return render_template('browse.html', users=users, session_user_id=session.get('user_id'))
@app.route('/request_swap', methods=['GET', 'POST'])
def request_swap():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    from_user_id = session['user_id']
    to_user_id = request.args.get('to_user_id') or request.form.get('to_user_id')

    if not to_user_id:
        return "Target user not specified", 400

    from_user = User.query.get(from_user_id)
    to_user = User.query.get(to_user_id)

    if not from_user or not to_user:
        return "User not found", 404

    if request.method == 'POST':
        offered_skill = request.form.get('offered_skill')
        wanted_skill = request.form.get('wanted_skill')
        message = request.form.get('message', '')

        if not offered_skill or not wanted_skill:
            return "Missing skill selection", 400

        new_request = SwapRequest(
            from_user_id=from_user_id,
            to_user_id=to_user_id,
            skill_offered=offered_skill,
            skill_requested=wanted_skill,
            status='pending'
        )
        db.session.add(new_request)
        db.session.commit()
        return redirect(url_for('dashboard'))

    offered_skills = [s.name for s in from_user.skills if s.type == 'offered']
    wanted_skills = [s.name for s in to_user.skills if s.type == 'wanted']

    return render_template(
        'request_swap.html',
        from_user=from_user,
        to_user=to_user,
        offered_skills=offered_skills,
        wanted_skills=wanted_skills
    )

@app.route('/swap_requests')
def swap_requests():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    received = SwapRequest.query.filter_by(to_user_id=user_id).all()
    sent = SwapRequest.query.filter_by(from_user_id=user_id).all()

    return render_template('swap_requests.html', received=received, sent=sent)

@app.route('/update_request/<int:request_id>/<string:action>')
def update_request(request_id, action):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    swap = SwapRequest.query.get_or_404(request_id)

    if swap.to_user_id != session['user_id']:
        return "Unauthorized", 403

    if action == 'accept':
        swap.status = 'accepted'
    elif action == 'reject':
        swap.status = 'rejected'

    db.session.commit()
    return redirect(url_for('swap_requests'))

    return render_template(
        'request_swap.html',
        from_user=from_user,
        to_user=to_user,
        offered_skills=offered_skills,
        wanted_skills=wanted_skills
    )

@app.route('/give_feedback/<int:request_id>', methods=['GET', 'POST'])
def give_feedback(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    swap = SwapRequest.query.get_or_404(request_id)

    if swap.from_user_id != session['user_id'] or swap.status != 'accepted':
        return "Unauthorized or invalid swap", 403

    if request.method == 'POST':
        swap.rating = int(request.form['rating'])
        swap.feedback = request.form['feedback']
        db.session.commit()
        return redirect(url_for('swap_requests'))

    return render_template('feedback.html', swap=swap)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("📦 Database recreated with all columns!")
    app.run(debug=True)
