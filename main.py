
import webapp2

import os 
import re
import jinja2
import cgi 
from google.appengine.ext import db
from google.appengine.api import memcache
from string import letters
import time
import datetime
import hashlib
import hmac
import random
import string
import urllib2
import json
from xml.dom import minidom
import logging

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
    autoescape =True)

Secret="secre-`11kdk`1-3opjdvkldfnl05"

#return a hash string, usually very long
def hash_str(s):
    #return hashlib.md5(s).hexdigest()
    return hmac.new(Secret,s).hexdigest()

#return a format of 's|hash string'
def make_secure_val(val):
    return "%s|%s"% (val,hmac.new(Secret,val).hexdigest())

#decode, h is the full format of 's|hash string'
def check_secure_val(h):
    #value is the s
    val = h.split('|')[0]
    #if the full input is equal to verified hash string
    if h == make_secure_val(val):
        return val


class Handler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.out.write(*a,**kw)
    def render_str(self,template,**params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))

    def set_user_cookie(self,user):#set the cookie from the input to Set-Cookie
        hasheduser = make_secure_val(str(user.key().id()))
        self.response.headers.add_header('Set-Cookie','user_id=%s;Path=/'%hasheduser)
        #self.redirect("/welcome")

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    def render_json(self,d):
        jtxt=json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        
        self.write(jtxt)

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name,pw,salt=None):
    if not salt:
        salt = make_salt()
    h=hashlib.sha256(name+pw+salt).hexdigest()
    return "%s|%s" %(h,salt)

def valid_pw(name,pw,h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name,pw,salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    username = db.StringProperty(required = True)
    #store a hashed_password instead
    password = db.StringProperty(required =True)

    email = db.StringProperty(required=False)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())


class Post(db.Model):
	title = db.StringProperty(required=True)
	content = db.StringProperty(required=True,multiline=True)
	created = db.DateProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	

def getuser(cookie):
    user_id_formatted_cookie = cookie
    if user_id_formatted_cookie:
        userid=check_secure_val(user_id_formatted_cookie)
        if userid:
            user = User.get_by_id(int(userid))
            username = str(user.username)
        else:
            user=""

        return user

class EditPage(Handler):
        def get(self,url_title):
            user = getuser(self.request.cookies.get("user_id"))
            if not user:
                #self.write("bla")
                self.render('signup.html',message="Please sign up to start editing")
            else:
                title = url_title.split('/')[1]
                if not title:
                    title = "default"
                p = Post.all().filter("title =",title).order('-last_modified').get()
                if p:
                    content =p.content
                else:
                    content=""
                self.render("edit.html",title = title,user=user,content=content)


        def post(self,url_title):
                title = url_title.split('/')[1]
                content = self.request.get("content")
                user = getuser(self.request.cookies.get('user_id'))

                if not title:
                    title = "default"

                if content:
                        newentry=Post(title=title,content=content)
                        newkey = newentry.put()
                        self.render("view.html",content=content,user=user)
            #one last problem here,
            #when posted, it should go back to localhost:8080/12
                else:
                        error = "Please don't leave your memo blank"
                        self.render("edit.html",title=title,error=error,user=user)

class HistPage(Handler):
    def get(self,url_title):
         user = getuser(self.request.cookies.get("user_id"))
         title = url_title.split('/')[1]
         #self.write(title)
         if not title:
            title = "default"
         posts = db.GqlQuery("SELECT * FROM Post Where title = '%s' ORDER BY last_modified DESC "%title)
         self.render("history.html",posts=posts,title=title,user=user)
         #self.render("history.html",posts=posts,user=user)


class WikiPage(Handler):
	def get(self,url_title):

            user = getuser(self.request.cookies.get('user_id'))

            if url_title=="/":

                posts = Post.all().filter('title =',"default").order('-last_modified').get()
                if not posts:
                    content = "Welcome to BagelWiki! You can put anything in the url and start editing!"
                    defaultentry=Post(title='default',content=content)
                    self.render("view.html",content = content,user=user)
                else:
                    #p = Post.all().filter("title =","default").order('-last_modified').get()
                    self.render("view.html",content = posts.content,user=user)

                # #initialize for the first time.



                # p = Post.all().filter("title =","default").order('-last_modified').get()
                # #default_content = "Welcome to BagelWiki! You can put anything in the url and start editing! Have fun"
                # self.render("view.html",content = p.content,user=user)
            else:
                title = url_title.split('/')[1]
                #logging.error("here the title is "+title)
                p = Post.all().filter("title =",title).order('-last_modified').get()#order by date descending
                if p:
                    self.render("view.html",title=title,content=p.content,user=user)
                    logging.error(p.content)
                else:
                    self.redirect('_edit'+url_title)


class Signup(Handler):
    def get(self):

        self.render("signup.html")

    def post(self):


        getusername = self.request.get('username')
        getpassword = self.request.get('password')
        getverify = self.request.get('verify')
        getemail = self.request.get('email')

        correct = True
        usernameErrMsg=""
        passwordErrMsg=""
        verifyErrMsg=""
        emailErrMsg=""

        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        PASS_RE = re.compile(r"^.{3,20}$")
        EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")

        user_id_formatted_cookie = self.request.cookies.get('user_id')

        u = User.all().filter('username =',getusername).get()

        if u:
            usernameErrMsg="Username not available"
            getusername=""
            correct=False

        elif (not getusername) or "  " in getusername or not USER_RE.match(getusername):
            usernameErrMsg ="Please enter a valid user name"
            getusername = ""
            correct=False

        if not getpassword or not PASS_RE.match(getpassword):
            passwordErrMsg = "Please enter a password"
            correct=False
        if not getverify:
            verifyErrMsg = "Please retype yoru password"
            correct=False
        elif getpassword != getverify:

            verifyErrMsg = "Password are not the same"
            correct=False

        if getemail:
            if not EMAIL_REGEX.match(getemail):
                emailErrMsg = "Please enter a vaid email address"
                getemail = ""
                correct= False
        if not correct:
            self.render("signup.html",username=getusername,password="",verify="",email=getemail,
                uerror=usernameErrMsg,perror=passwordErrMsg,verror=verifyErrMsg,eerror=emailErrMsg)
        else:
            #hashed the password 

            hash_password= make_pw_hash(getusername,getpassword)

            u = User(username=getusername,password=hash_password,email=getemail)
            u.put()

            #rewrite this

            self.set_user_cookie(u)
            self.redirect('/')


class Login(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        getusername = self.request.get("username")
        getpassword = self.request.get("password")
        #when user enters a password, it matches the database
        
        u = User.all().filter('username =',getusername).get()
        if u and valid_pw(getusername,getpassword,u.password):
            #self.render("welcome.html",username=getusername)
            self.set_user_cookie(u)
            self.redirect('/')

        else:
            error="Invalid login"
            self.render('login.html',error=error)

class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/'%'')
        self.redirect('/')

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_history' + PAGE_RE,HistPage),
                               ('/_edit' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage),
                               ],
                              debug=True)
