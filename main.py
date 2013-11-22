import os
import re
import random
import hashlib
import hmac
from string import letters

from utils import *

import webapp2
import jinja2

import logging

from google.appengine.ext import db
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.api import mail
from google.appengine.api import images

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)



def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val, remember):
        cookie_val = make_secure_val(val)
        if(remember):
            self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))
        else:
            self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; expires=datetime.datetime.now() + datetime.timedelta(weeks=4); Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user, remember = False):
        self.set_secure_cookie('user_id', str(user.key().id()), remember)

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

class MainPage(BaseHandler):
  def get(self):
      params=dict(user=self.user)
      logging.error(self.user)
      self.render('main.html', **params)



##### user stuff
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    email = db.StringProperty(required = True)
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)

    item_want = db.ListProperty(db.Key)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def by_email(cls, email):
        u = cls.all().filter('email =', email).get()
        return u

    @classmethod
    def register(cls, name, pw, email):
        pw_hash = make_pw_hash(email, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, email, pw):
        u = cls.by_email(email)
        if u and valid_pw(email, pw, u.pw_hash):
            return u

class Item(db.Model):
    category = db.StringProperty()
    expire_date = db.DateProperty()
    added_date = db.DateTimeProperty(auto_now_add=True)
    item_ownner = db.ReferenceProperty(User, collection_name='item_owns')
    description = db.StringProperty()
    blob = blobstore.BlobReferenceProperty()
    thumbnail = db.StringProperty()

class Comment(db.Model):
    writer = db.ReferenceProperty(User, collection_name='comments')
    item = db.ReferenceProperty(Item, collection_name='comments')
    content = db.TextProperty()
    added_date = db.DateTimeProperty(auto_now_add=True)

class Signup(BaseHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.domain = self.request.get('domain')
        self.email = self.username + self.domain
        
        self.password = pw_generator()

        logging.error(self.password)

        params = dict(username = self.username,
                      domain = self.domain)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_email(self.email)
        if u:
            msg = 'That user already exists.'
            params = dict( error_username = msg )
            self.render('signup-form.html', **params)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            registration_msg = 'Your password is %s' % self.password
            message = mail.EmailMessage(sender='Exchange-JP Team <xingxiaoxiong@gmail.com>',
                                        to=self.email,
                                        subject='Welcome to Exchange-JP',
                                        body=registration_msg)
            message.send()

            #self.login(u)
            self.redirect('/login')

class Login(BaseHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        email_username = self.request.get('email_username')
        domain = self.request.get('domain')
        password = self.request.get('password')
        remember = self.request.get('remember')

        u = User.login(email_username+domain, password)

        logging.error( email_username+domain )
        logging.error( password )
        if u:
            if (remember):
                self.login(u, True)
            else:
                self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            params = dict( error = msg )
            self.render('login-form.html', **params)

class Logout(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)

