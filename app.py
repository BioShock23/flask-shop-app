from database_setup import Categories, Items, Users, Base, OAuth

import os
from functools import wraps
from passlib.hash import sha256_crypt

from flask import (Flask, render_template, flash, redirect,
                   url_for, session, request, jsonify)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import (current_user, LoginManager,)
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from wtforms import (Form, StringField, TextAreaField,
                     PasswordField, SelectField, validators)
from wtforms_alchemy import ModelForm


app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(12)
project_dir = os.path.dirname(os.path.abspath(__file__))
database_file = "sqlite:///{}".format(os.path.join(project_dir, "flaskshop.db"))
app.config['SQLALCHEMY_DATABASE_URI'] = database_file

db = SQLAlchemy(app)

# Создание движка БД
engine = create_engine(database_file)
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

migrate = Migrate(app, db)
login_manager = LoginManager(app)
storage = SQLAlchemyStorage(OAuth, db.session, user=current_user)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


# Класс формы регистраци
class RegisterForm(Form):
    name = StringField('Имя', [validators.Length(min=1, max=50)])
    username = StringField('Логин', [validators.Length(min=4, max=25)])
    password = PasswordField('Пароль', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Пароли не совпадают')
    ])
    confirm = PasswordField('Подтвердите пароль')


# Форма логина
class LoginForm(Form):
    username = StringField('Логин', [validators.Length(min=3, max=25)])
    password = PasswordField('Пароль', [validators.DataRequired()])


class CategoryForm(ModelForm):
    def get_session():
        return db.session

    class Meta:
        model = Categories
        only = ['name']


# Форма товара
class ItemForm(Form):
    name = StringField('Название', [validators.Length(min=1, max=200)])
    detail = TextAreaField('Описание', [validators.Length(min=3)])
    category = SelectField('Категория', [validators.DataRequired()])


# Проверка на авторизацию
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session or current_user.is_authenticated:
            return f(*args, **kwargs)
        else:
            flash('Вы не авторизованы', 'danger')
            return redirect(url_for('login'))
    return wrap


@app.route('/catalog.json')
def get_current_catalog():
    catalog = db.session.query(Categories).all()
    results = {'Category': list()}

    for category in catalog:
        items = db.session.query(Items) \
            .filter(Items.category == category.name).all()
        category_data = {
            'id': category.id,
            'name': category.name,
            'items': [item.serialize for item in items]
        }
        results['Category'].append(category_data)

    return jsonify(results)


@app.route('/<string:category>/<string:name>/JSON')
def get_single_item(category, name):

    singleitem = db.session.query(Items).filter(Items.name == name)

    return jsonify(Item=[i.serialize for i in singleitem.all()])


# Выход
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('Вы вышли', 'success')
    return redirect(url_for('login'))


# Домашняя страница
@app.route("/")
def home():
    return render_template('home.html')


# О нас
@app.route("/about")
def about():
    return render_template('about.html')


# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():

    form = RegisterForm(request.form)

    try:
        if request.method == 'POST' and form.validate():
            name = form.name.data
            username = form.username.data
            password = sha256_crypt.encrypt(str(form.password.data))

            new_user = Users(name=name, username=username, password=password)
            db.session.add(new_user)
            db.session.commit()

            flash('Вы зарегистрированы и можете войти!', 'success')

            return redirect(url_for('home'))
    except:
        flash('Такой логин уже существует', 'danger')
        return redirect(url_for('register'))

    return render_template('register.html', form=form)


# Вход
@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm(request.form)

    if request.method == 'POST' and form.validate():
        username = form.username.data
        password_post = form.password.data

        try:
            user = db.session.query(Users) \
                .filter(Users.username == username).first()
            if sha256_crypt.verify(password_post, user.password) \
                    and username == user.username:
                session['logged_in'] = True
                session['username'] = username

                flash('Вы вошли', 'success')
                return redirect(url_for('home'))

            else:
                error = 'Invalid login'
                return render_template('login.html', error=error, form=form)

        except:
            error = 'Invalid login'
            return render_template('login.html', error=error, form=form)

    else:
        return render_template('login.html', form=form)


# Каталог
@app.route("/catalog")
def catalog():
    username = session.get('username')
    catalog = db.session.query(Categories).order_by(Categories.name)
    latestitems = db.session.query(Items) \
        .order_by(Items.creation_time.desc()).limit(10)
    user_id = db.session.query(Users.id) \
        .filter(Users.username == username).scalar()
    return render_template('catalog.html', catalog=catalog,
                           latestitems=latestitems, user_id=user_id)


# Страница категории
@app.route("/<string:name>")
def category(name):

    catalog = db.session.query(Categories.name).filter(Categories.name == name)

    category = db.session.query(Items).filter(Items.category == name)

    countitems = db.session.query(Items).filter(Items.category == name).count()

    return render_template('category.html', category=category,
                           catalog=catalog, countitems=countitems)


# Страница товара
@app.route("/<string:category>/<string:name>/")
def item(name, category):

    singleitem = db.session.query(Items).filter(Items.name == name)

    return render_template('item.html', singleitem=singleitem)


# Добавление категории
@app.route('/add_category', methods=['GET', 'POST'])
@is_logged_in
def add_category():

    form = CategoryForm(request.form)
    username = session.get('username')
    user = db.session.query(Users).filter(Users.username == username).first()
    user_id = user.id

    if request.method == 'POST' and form.validate():

        name = form.name.data
        newcategory = Categories(name=name, user_id=user_id)
        db.session.add(newcategory, user_id)
        db.session.commit()
        flash('Категория создана', 'success')
        return redirect(url_for('catalog'))
    return render_template('add_category.html', form=form)


# Удаление категории
@app.route('/delete_cat/<string:id>', methods=['POST'])
@is_logged_in
def delete_cat(id):
    result = db.session.query(Categories).filter(Categories.id == id).first()
    db.session.delete(result)
    db.session.commit()
    flash('Категория удалена', 'success')
    return redirect(url_for('catalog'))


# Изменение категории
@app.route('/edit_cat/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_cat(id):
    category = db.session.query(Categories).filter(Categories.id == id).first()
    form = CategoryForm(request.form)
    form.name.data = category.name

    if request.method == 'POST' and form.validate():
        newname = request.form['name']
        app.logger.info(newname)
        category.name = newname
        db.session.commit()
        flash('Категория обновлена', 'success')
        return redirect(url_for('catalog'))
    return render_template('edit_cat.html', form=form)


# Добавление товара
@app.route('/add_item', methods=['GET', 'POST'])
@is_logged_in
def add_item():
    form = ItemForm(request.form)
    username = session.get('username')
    categories = db.session.query(Categories)
    user = db.session.query(Users).filter(Users.username == username).first()
    user_id = user.id
    form.category.choices = [(c.name, c.name) for c in categories]
    if request.method == 'POST' and form.validate():
        name = form.name.data
        detail = form.detail.data
        category = form.category.data
        selected_category_id = categories.filter(Categories.name == category).first().id
        newitem = Items(name=name,
                        detail=detail,
                        category=category,
                        category_id = selected_category_id,
                        user_id=user_id)
        db.session.add(newitem)
        db.session.commit()
        flash('Товар создан', 'success')
        return redirect(url_for('catalog'))
    return render_template('add_item.html', form=form, categories=categories,
                           user_id=user_id)


# Удаление товара
@app.route('/delete_item/<string:id>', methods=['POST'])
@is_logged_in
def delete_item(id):
    delitem = db.session.query(Items).filter(Items.id == id).first()
    db.session.delete(delitem)
    db.session.commit()
    flash('Товар удалён', 'success')
    return redirect(url_for('catalog'))


# Изменение товара
@app.route('/edit_item/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_item(id):
    item = db.session.query(Items).filter(Items.id == id).first()
    categories = db.session.query(Categories)
    form = ItemForm(request.form)
    form.category.choices = [(c.name, c.name) for c in categories]
    form.name.data = item.name
    form.detail.data = item.detail
    form.name.default = item.name
    form.detail.default = item.detail
    form.category.default = item.category
    form.process()
    if request.method == 'POST' and form.validate():
        newcategory = request.form['category']
        newname = request.form['name']
        newdetail = request.form['detail']
        app.logger.info(newcategory, newname, newdetail)
        item.category = newcategory
        item.name = newname
        item.detail = newdetail
        db.session.commit()
        flash('Товар обновлён', 'success')
        return redirect(url_for('catalog'))
    return render_template('edit_item.html', form=form)


if __name__ == "__main__":
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run()
