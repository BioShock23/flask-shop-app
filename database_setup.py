import os.path
import datetime
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin


Base = declarative_base()


class Items(Base):

    __tablename__ = 'items'

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(String(250), nullable=False)
    detail = Column(String(500))
    category = Column(String(100))
    category_id = Column(Integer, ForeignKey('categories.id'))
    creation_time = Column(DateTime, default=datetime.datetime.now)
    modification_time = Column(DateTime, onupdate=datetime.datetime.now)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'detail': self.detail,
            'category': self.category
        }


class Categories(Base):
    __tablename__ = 'categories'

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    items = relationship("Items", cascade="all, delete")
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)


class Users(Base):

    __tablename__ = 'users'

    id = Column(Integer, autoincrement=True, primary_key=True)
    name = Column(String(100), nullable=False)
    username = Column(String(30), nullable=False, unique=True)
    password = Column(String(100), nullable=True)
    register_date = Column(DateTime, default=datetime.datetime.now)
    github_id = Column(Integer, nullable=True, unique=True)


class OAuth(OAuthConsumerMixin, Base):
    user_id = Column(Integer, ForeignKey(Users.id))
    user = relationship(Users)


project_dir = os.path.dirname(os.path.abspath(__file__))
database_file = "sqlite:///{}".format(os.path.join(project_dir, "flaskshop.db"))

engine = create_engine(database_file)
Base.metadata.create_all(engine)
