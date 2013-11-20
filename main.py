import datetime
import os
import logging

from utils import *

import webapp2
import jinja2

from google.appengine.ext import db
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.api import mail
from google.appengine.api import images

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


class User(db.Model):
    email = db.StringProperty(required=True)
    username = db.StringProperty()
    register_time = db.DateTimeProperty(auto_now_add=True)
    password = db.StringProperty(required=True)
#    items_holds = db.ListProperty(db.Key)
#    items_wanted = db.ListProperty(db.Key) 
    @property
    def members(self):
        return Item.all().filter('item_wanter', self.key())

class Item(db.Model):
    category = db.StringProperty()
    expire_date = db.DateProperty()
    added_date = db.DateTimeProperty(auto_now_add=True)
    item_holder = db.ReferenceProperty(User, collection_name='item_owns')
    item_wanter = db.ListProperty(db.Key)
    item_wanter_name = db.ListProperty(str)
    description = db.StringProperty()
    blob = blobstore.BlobReferenceProperty()
    thumbnail = db.StringProperty()
    comments = db.ListProperty(str)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BaseHandler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

class Main(BaseHandler):
    def get(self):
        email = self.request.cookies.get('email', None)
        username = None
        if not email:
            self.redirect('/signin')
        else:
            username = str((email.split('@'))[0])

        q = Item.all()
        q.order('-added_date')
        items = q.fetch(5)
        
        
        upload_url = blobstore.create_upload_url('/upload')
        params = dict(user=username, upload_url=upload_url, items = items)
        
        self.render('index2.html', **params)
        
class Signout(BaseHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'email=None; Expires=Thu, 01-Jan-1970 00:00:00 GMT')
        self.redirect('/')

class Signin(BaseHandler):
    def get(self):
        self.render("signin-form.html")

    def post(self):
        have_error = False
        email = self.request.get('email')
        pwd = self.request.get('password')
        params = dict(email = email, password = pwd)
        user = None
        key = None

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True
        elif not valid_password(pwd):
            params['error_password'] = "Invalid password."
            have_error = True
        else:
            q =  db.Query(User).filter('email =', email)
            user = q.fetch(1)
            if user:
                if pwd != user[0].password:
                    params['error_password']= "Password incorrect!"
                    have_error = True
            else:
                params['error_email'] = "User doesn't exist."
                have_error = True
        
        if have_error:
            self.render('signin-form.html', **params)
        else:
            self.response.headers.add_header('Set-Cookie', 'email=%s, key=%s; expires=datetime.datetime.now() + datetime.timedelta(weeks=4)'% (str(email), user[0].key()))
            #self.redirect('/welcome?username=' + (email.split('@'))[0])
            self.redirect('/')

class Signup(BaseHandler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        domain = self.request.get('domain')
        params = dict(username = username, domain=domain)

        if not valid_username(username):
            params['error_username'] = "That's not a valid email."
            have_error = True
        elif db.Query(User).filter('username =', username).count(1)==1:
            params['error_username'] = "User already exists."
            have_error = True

        
        if have_error:
            self.render('signup.html', **params)
        else:
            pwd = id_generator()
            user = User(username = username, email = username+domain, password = pwd)
            user.put()
            registration_msg = 'Your password is %s' % pwd
            print registration_msg
            print username+domain
            message = mail.EmailMessage(sender='Exchange-JP Team <xingxiaoxiong@gmail.com>',
                                        to=username+domain,
                                        subject='Welcome to Exchange-JP',
                                        body=registration_msg)
            message.send()
            self.redirect('/signin')

class UploadHandler(blobstore_handlers.BlobstoreUploadHandler):
    def post(self):
#        email = self.request.cookies.get('email', None)
#        q =  db.Query(User).filter('email =', email)
#        user = q.fetch(1)
        key = self.request.cookies.get('key', None)
        user = User.get(key)

        description = self.request.params['description']
        logging.error('this is a log')
        logging.error(description)
        category = self.request.params['category']
        for blob_info in self.get_uploads('upload'):
            item = Item(category = category,
                        description=description,
                        item_holder = user,
                        blob=blob_info.key(),
                        thumbnail = images.get_serving_url(blob_info.key(), size=128))
            item.put()
        self.redirect('/')
        
class Manage(BaseHandler):
    def get(self):
#        email = self.request.cookies.get('email', None)
#        q =  db.Query(User).filter('email =', email)
#        user = q.fetch(1)

        key = self.request.cookies.get('key', None)
        user = User.get(key)
        
        if not user:
            self.redirect('/')

        items = user.item_owns
        params = dict(user=user.username, items=items)
        
        self.render('manage.html', **params)

    def post(self):
#        email = self.request.cookies.get('email', None)
#        q =  db.Query(User).filter('email =', email)
#        user = q.fetch(1)

        key = self.request.cookies.get('key', None)
        user = User.get(key)

        have_error = False

        items = user.item_owns
        params = dict(user=user.username, items=items)

        oldpwd = self.request.get('oldpassword')
        newpwd = self.request.get('newpassword')
        confirmpwd = self.request.get('confirmpassword')
        if (not valid_password(oldpwd)) or (not valid_password(newpwd)) or (not valid_password(confirmpwd)):
            have_error = True
            error_pwd = 'Please input valid password.'
        elif oldpwd != user.password:
            have_error = True
            error_pwd = 'Old password doesn\'t match.'
        elif newpwd != confirmpwd:
            have_error = True
            error_pwd = 'New password doesn\'t match.'
        else:
            user.password = newpwd
            user.put()
        
        logging.error(user.password)
        if have_error:
            self.render('manage.html', **params)

        self.redirect('signin')
            
class Iwant(BaseHandler):
    def get(self):
        userkey = self.request.cookies.get('key', None)
        itemkey = self.request.get('itemkey')

        userk = User.get(userkey).key()

        item = Item.get(itemkey)
        item.item_wanter.append(userk)
        item.item_wanter_name.append(User.get(userkey).username)
        item.put()

        self.redirect('/')

class Iquit(BaseHandler):
    def get(self):
        userkey = self.request.cookies.get('key', None)
        itemkey = self.request.get('itemkey')

        userk = User.get(userkey).key()
        item = Item.get(itemkey)
        item.item_wanter.remove(userk)
        item.item_wanter_name.remove(User.get(userkey).username)
        item.put()

        self.redirect('/')
        
class Addcomment(BaseHandler):
    def post(self):
        userkey = self.request.cookies.get('key', None)
        itemkey = self.request.get('itemkey')
        comment = self.request.get('comment')

        username = User.get(userkey).username
        fullcomment = comment + '-----------' + username
        item = Item.get(itemkey)
        item.comments.append(fullcomment)
        item.put()

        self.redirect('/')
    
class Welcome(BaseHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/signin', Signin),
                               ('/welcome', Welcome),
                               ('/signout', Signout),
                               ('/upload', UploadHandler),
                               ('/manage', Manage),
                               ('/iwant', Iwant),
                               ('/iquit', Iquit),
                               ('/addcomment', Addcomment),
                               ('/', Main)],
                              debug=True)
