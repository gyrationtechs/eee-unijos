import os
import secrets
# from PIL import Image pip install Pillow
from datetime import datetime
from flask import Flask, render_template, url_for, flash, redirect, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, SubmitField, DateTimeField
from wtforms.fields.html5 import DateField
from wtforms.validators import InputRequired, Email, Length, EqualTo, ValidationError, DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView

#install flask security to authenticate admin users -- pip install flask_security


app = Flask(__name__)
app.config['SECRET_KEY'] = '927f9b175bfa8a197354f63daf1cfb38'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
Bootstrap(app)
login_manager = LoginManager(app)
#login_manager.init_app(app)
login_manager.login_view = 'login' 
login_manager.login_message_category = 'info'


student_courses = db.Table('student_courses',
                    db.Column('student_id', db.Integer, db.ForeignKey('student.id')),
                    db.Column('course_id', db.Integer, db.ForeignKey('course.id'))
    )


class Authentication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    auth_code = db.Column(db.String(15), unique=True, nullable=False)


class Student(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    profile = db.Column(db.String(20), nullable=False, default='profile.jpg')
    department = db.Column(db.String(60), nullable=False, default='Electrical Electronics Engineering')
    dob = db.Column(db.String(60))
    address = db.Column(db.String(255), default='University of Jos')
    level = db.Column(db.Integer, default='100')
    gender = db.Column(db.String(20))
    posts = db.relationship('Post', backref='author', lazy=True)
    courses = db.relationship('Course', secondary=student_courses, backref=db.backref('courses', lazy='dynamic'))
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"Student('{self.first_name}', '{self.last_name}', '{self.username}', '{self.email}', '{self.department}', '{self.level}', {self.password}')"


@login_manager.user_loader
def load_user(student_id):
    return Student.query.get(int(student_id))



class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_code = db.Column(db.String(15))
    course_title = db.Column(db.String(100))
    semester = db.Column(db.String(15), default='1')
    credit_unit = db.Column(db.String(15))
        


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False) 

    def __repr__(self):
        return f"Student('{self.title}', '{self.date_posted}')"


class MyModelView(ModelView):
    def not_auth(self):
        return abort(403)

    def is_accessible(self):
        if current_user.is_admin == True:
            return current_user.is_authenticated

        elif current_user != current_user.is_authenticated:
            return abort(403)
        else:
            return abort(403)

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))


class MyAdminIndexView(AdminIndexView):
    def not_auth(self):
        return abort(403)


    def is_accessible(self):
        if current_user.is_admin == True:
            return current_user.is_authenticated
        elif current_user != current_user.is_authenticated:
            return abort(403)
        else:
            return abort(403)


    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))


admin = Admin(app, index_view=MyAdminIndexView())
admin.add_view(MyModelView(Student, db.session))
admin.add_view(MyModelView(Post, db.session))
admin.add_view(MyModelView(Authentication, db.session))
admin.add_view(MyModelView(Course, db.session))


class LoginForm(FlaskForm):
    username = StringField('Mat No (eg uj/2014/en/0002)', validators=[InputRequired(), Length(min=12, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')
    submit = SubmitField('Login')


class AuthForm(FlaskForm):
    code = StringField('Enter Authentication Code', validators=[InputRequired(), Length(min=12, max=15)])
    submit = SubmitField('Validate')


class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[InputRequired(), Length(min=2, max=50)])
    last_name = StringField('Last Name', validators=[InputRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[InputRequired(), Length(max=120), Email(message = 'Invalid Email')])
    username = StringField('Mat No (eg uj/2014/en/0002)', validators=[InputRequired(), Length(min=12, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    department = StringField('Department', validators=[InputRequired(), Length(min=2, max=80)])
    dob = DateField('Date of Birth', format='%Y-%m-%d') #, validators=[InputRequired()])
    address = StringField('Address', validators=[InputRequired(), Length(min=2, max=50)])
    level = StringField('Level', validators=[InputRequired(), Length(min=2, max=50)])
    gender = StringField('Gender', validators=[InputRequired(), Length(min=2, max=50)])
    submit = SubmitField('Register')

    def validate_username(self, username):
        student = Student.query.filter_by(username=username.data).first()
        if student:
            raise ValidationError('Student already exists for that username. Please check your matric number correctly')

    def validate_email(self, email):
        student = Student.query.filter_by(email=email.data).first()
        if student:
            raise ValidationError('That email is choosen. Please choose a different one')


class AdminForm(FlaskForm):
    first_name = StringField('First Name', validators=[InputRequired(), Length(min=2, max=50)])
    last_name = StringField('Last Name', validators=[InputRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[InputRequired(), Length(max=120), Email(message = 'Invalid Email')])
    username = StringField('Username', validators=[InputRequired(), Length(min=12, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        student = Student.query.filter_by(username=username.data).first()
        if student:
            raise ValidationError('Student already exists for that username. Please check your matric number correctly')

    def validate_email(self, email):
        student = Student.query.filter_by(email=email.data).first()
        if student:
            raise ValidationError('That email is choosen. Please choose a different one')


class UpdateAccountForm(FlaskForm):
    first_name = StringField('First Name', validators=[InputRequired(), Length(min=2, max=50)])
    last_name = StringField('Last Name', validators=[InputRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[InputRequired(), Length(max=120), Email(message = 'Invalid Email')])
    username = StringField('Mat No (eg uj/2014/en/0002)', validators=[InputRequired(), Length(min=12, max=15)])
    department = StringField('Department', validators=[InputRequired(), Length(min=3, max=100)])
    level = StringField('Level', validators=[InputRequired(), Length(min=3, max=10)])
    picture = FileField('Update Profile Photo', validators=[FileAllowed(['jpg', 'png'])])
    department = StringField('Department', validators=[InputRequired(), Length(min=2, max=80)])
    dob = DateField('Date of Birth', format='%Y-%m-%d')
    address = StringField('Address', validators=[InputRequired(), Length(min=2, max=50)])
    level = StringField('Level', validators=[InputRequired(), Length(min=2, max=50)])
    gender = StringField('Gender', validators=[InputRequired(), Length(min=2, max=50)])
    submit = SubmitField('Update')


    def validate_username(self, username):
        if username.data != current_user.username:
            student = Student.query.filter_by(username=username.data).first()
            if student:
                raise ValidationError('Student already exists for that username. Please check your matric number correctly')


    def validate_email(self, email):
        if email.data != current_user.email:        
            student = Student.query.filter_by(email=email.data).first()
            if student:
                raise ValidationError('That email is choosen. Please choose a different one')


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Create Post')


class CourseForm(FlaskForm):
    course_code = StringField('Course Code', validators=[DataRequired()])
    course_title = StringField('Course Title', validators=[DataRequired()])
    semester = StringField('Semester', validators=[DataRequired()])
    credit_unit = StringField('Credit Unit', validators=[DataRequired()])
    submit = SubmitField('Add Course')


class CourseUpdateForm(FlaskForm):
    course_code = StringField('Course Code', validators=[DataRequired()])
    course_title = StringField('Course Title', validators=[DataRequired()])
    semester = StringField('Semester', validators=[DataRequired()])
    credit_unit = StringField('Credit Unit', validators=[DataRequired()])
    submit = SubmitField('Update Course')


@app.route('/')
@app.route('/home')
def home(): 
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        student = Student.query.filter_by(username=form.username.data).first()
        if student:
            if check_password_hash(student.password, form.password.data):
                login_user(student, remember=form.remember.data)
                next_page = request.args.get('next')
                flash(f'Login Successful for {form.username.data}!', 'success')
                if current_user.is_admin == True:
                    return redirect(url_for('admin_profile'))
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        flash('Invalid Login Details. Please check username or password', 'danger')
        return redirect(url_for('login'))
        
    return render_template('login.html', title='Login', form=form)


@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = AuthForm()
    if form.validate_on_submit():
        auth = Authentication.query.filter_by(auth_code=form.code.data).first()
        if auth:
            return redirect(url_for('register'))
        flash('Invalid Authentication Code. Please try again', 'danger')
        return redirect(url_for('auth'))
        
    return render_template('auth.html', title='Authentication', form=form)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_student = Student(first_name=form.first_name.data, 
                            last_name=form.last_name.data, 
                            username=form.username.data, 
                            email=form.email.data,
                            department=form.department.data,
                            dob=form.dob.data,
                            address=form.address.data,
                            level=form.level.data,
                            gender=form.gender.data,
                            password=hashed_password)
        db.session.add(new_student)
        db.session.commit()
        flash(f'Account Created for {form.username.data}! Please login and Update your profile', 'success')
        return redirect(url_for('home'))
    return render_template('register.html', title='Signup', form=form)


@app.route('/add_admin', methods=['GET', 'POST'])
@login_required
def add_admin():
    if current_user.is_admin == True:
        if current_user.is_authenticated:
            return redirect(url_for('home'))
        form = AdminForm()
        if form.validate_on_submit():
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            admin = Student(first_name=form.first_name.data, 
                        last_name=form.last_name.data, 
                        username=form.username.data, 
                        email=form.email.data,
                        password=hashed_password,
                        is_admin=True)
            db.session.add(admin)
            db.session.commit()
            flash(f'New Admin Account Created', 'success')
            return redirect(url_for('admin_profile'))
    if current_user != current_user.is_authenticated:
            return abort(403)
    else:
        return abort(403)
    return render_template('add_admin.html', title='Add Admin', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    #user_id = Student.query.filter_by(username=current_user.username)
    x = 1
    while x <= 10:
        x += 1
    courses = Course.query.filter(Course.courses.any(username=current_user.username)).all()
    profile = url_for('static', filename='images/' + current_user.profile)
    return render_template('dashboard.html', courses=courses, title='Dashboard', x=x, profile=profile)


@app.route('/admin_profile', methods=['GET', 'POST'])
@login_required
def admin_profile():
    if current_user.is_admin == True:
        profile = url_for('static', filename='images/' + current_user.profile)
        return render_template('admin_profile.html', title='Dashboard', profile=profile)
    return abort(403)


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/images', picture_fn)
    
    # output_size = (125, 125)
    # i = Image.open(form_picture)
    # i.thumbnail(output_size)
    # i.save(picture_path)

    form_picture.save(picture_path)
    return picture_fn


@app.route('/dashboard/edit', methods=['GET', 'POST'])
@login_required
def edit():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.profile = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.department = form.department.data
        current_user.level = form.level.data
        #current_user.dob = form.dob.data
        current_user.address = form.address.data
        current_user.gender = form.gender.data
        db.session.commit()
        flash('Your account has been updated', 'success')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.department.data = current_user.department
        form.level.data = current_user.level
        #form.dob.data = current_user.dob
        form.address.data = current_user.address
        form.gender.data = current_user.gender
    profile = url_for('static', filename='images/' + current_user.profile)
    return render_template('edit.html', title='Dashboard', profile=profile, form=form)


@app.route('/about')
def about():
    return render_template('about.html', title='About')


@app.route('/courses', methods=['GET', 'POST'])
@login_required
def courses():
    return render_template('courses.html', title='Course Registration')


@app.route('/contact')
def contact():
    return render_template('contact.html', title='Contact')


@app.route('/forum')
def forum():
    posts = Post.query.all()
    return render_template('forum.html', title='EEE Forum', posts=posts)


@app.route('/forum/<int:post_id>')
def forum_content(post_id):
    post = Post.query.get_or_404(post_id)
    user_id = Post.query.get(post.author.username)
    return render_template('forum_content.html', title='EEE Forum', user_id=user_id, post=post)


@app.route('/forum/<int:post_id>/update', methods=['GET', 'POST'])
@login_required
def forum_update(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content

    elif form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Your post has been Updated', 'success')
        return redirect(url_for('forum'))

    return render_template('forum_update.html', title='EEE Forum', form=form, post=post)


@app.route('/forum/<int:post_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been Deleted', 'success')
    return redirect(url_for('forum'))



@app.route('/forget')
def forget():
    return render_template('forget.html', title='Forget Password')


@app.route('/forum/new', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created', 'success')
        return redirect(url_for('forum'))
    return render_template('new_post.html', title='Create Post', form=form)


@app.route('/add_course', methods=['GET', 'POST'])
@login_required
def add_course():
    form = CourseForm()
    if form.validate_on_submit():
        course = Course(course_code=form.course_code.data, 
                    course_title=form.course_title.data, 
                    semester=form.semester.data,
                    credit_unit=form.credit_unit.data)
                    #courses=current_user.username)
        db.session.add(course)
        course.courses.append(current_user)
        db.session.commit()
        flash('Your Course has been Added', 'success')
        return redirect(url_for('add_course'))
    return render_template('add_course.html', title='Add Course', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)