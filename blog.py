import os
import re
import random
import hashlib
import hmac     # Bcrypt best
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

# template and jinja2 declarations
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# my secret to use for hashing passwords, along with regex used for form validations
secret = 'eghrkjvChdJhf.XDUuUyLFYdhJ'
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PW_RE = re.compile("^.{3,20}$")
EMAIL_RE = re.compile("^[\S]+@[\S]+.[\S]+$")


# functions for hashing and validating passwords and salts
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


# functions for validating form inputs
def valid_username(username):
    return USER_RE.match(username)


def valid_password(password):
    return PW_RE.match(password)


def valid_email(email):
    if email == "":
        return True
    return EMAIL_RE.match(email)


# global function to render html...used in blog db declaration
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# blog db declaration
class Blog(db.Model):
    """
    Class Blog:  Datastore entity type for blog posts

    Attributes:
        title (str): title of blog
        user (str):  author of blog
        blog (str):  blog entry
        created (datetime):  datetime blog was created
        last_modified (datetime):  datetime blog was last modified
        likes_list (list(int)):  list of user_IDs that have "liked" the blog

    """

    title = db.StringProperty(required=True)
    user = db.StringProperty()
    blog = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes_list = db.ListProperty(item_type=int)

    def render(self,
               current_user,
               add_a_comment=False,
               delete_request=False,
               comment_error='',
               comment_id=-1,
               max_comments=3):
        return render_str("single_post.html",
                          blog=self,
                          comments=BlogComment.all().ancestor(self).order('-created'),
                          current_user=current_user,
                          add_a_comment=add_a_comment,
                          comment_error=comment_error,
                          delete_request=delete_request,
                          comment_id=comment_id,
                          num_comments=min(max_comments, BlogComment.all().ancestor(self).count()))

    # determines if a user can like or unlike a blog post
    def likable(self, current_user):
        if current_user == self.user:
            return 0
        elif int(current_user) in self.likes_list:
            return -1
        else:
            return 1


# comment db declaration
class BlogComment(db.Model):
    comment = db.TextProperty(required=True)
    author_id = db.StringProperty(required=True)
    author_name = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


# user db declaration
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=users_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# leveraging templates to build base handler class
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
                'Set-Cookie',
                '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login_cookie(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout_cookie(self):
        self.set_secure_cookie('user_id', '')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# create logic to render each page
class MainPage(Handler):
    def get(self):
        current_user = self.read_secure_cookie('user_id')
        self.set_secure_cookie('blog_id', '')
        blogs = Blog.all().order('-created')
        self.render('front_page.html', blogs=blogs, current_user=current_user)


class SubmissionPage(Handler):
    def get(self, title="", blog=""):
        this_cookie = self.read_secure_cookie('blog_id')
        if self.user:
            if this_cookie:
                post = Blog.get_by_id(int(this_cookie))
                title = post.title
                blog = post.blog
            self.render('submission.html', title=title, blog=blog)
        else:
            self.redirect('/login')

    def post(self):
        title = self.request.get("title")
        blog = self.request.get("blog")
        if self.user:
            if title and blog:
                this_cookie = self.read_secure_cookie('blog_id')
                current_user = self.read_secure_cookie('user_id')
                # if an existing entry and current user is author
                if this_cookie != '' and Blog.get_by_id(int(this_cookie)).user == current_user:
                    b = Blog.get_by_id(int(this_cookie))
                    b.title = title
                    b.blog = blog
                    b.put()
                    self.redirect('/blog/%s' % this_cookie)
                # else a new entry
                else:
                    b = Blog(title=title, blog=blog, user=self.read_secure_cookie('user_id'))
                    b.put()
                    self.redirect('/blog/%s' % str(b.key().id()))
            else:
                error = "subject and content please!"
                self.render('submission.html', title=title, blog=blog, error=error)
        else:
            self.redirect('/login')


class NewOutputPage(Handler):
    def get(self, blog_id):
        current_user = self.read_secure_cookie('user_id')
        if current_user and current_user != '':
            key = db.Key.from_path('Blog', int(blog_id))
            blog = db.get(key)
            self.set_secure_cookie('blog_id', blog_id)
            self.render('post_output.html',
                        blog=blog,
                        current_user=current_user,
                        add_a_comment=False,
                        comment_error='',
                        comment_id=-1)
        else:
            self.redirect('/login')


class Register(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        is_valid = True
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")

        params = dict(username=self.username, email=self.email)

        if not valid_username(self.username):
            params['username_error'] = "That's not a valid username."
            is_valid = False
        if not valid_password(self.password):
            params['password_error'] = "That's not a valid password."
            is_valid = False
        elif self.password != self.verify:
            params['dup_pw_error'] = "Your passwords didn't match."
            is_valid = False

        if not valid_email(self.email):
            params['email_error'] = "That's not a valid email."
            is_valid = False

        if not is_valid:
            self.render('signup.html', **params)
        else:
            # make sure user doesn't already exist
            u = User.by_name(self.username)
            if u:
                msg = "That user already exists."
                self.render('signup.html', username_error=msg)
            else:
                u = User.register(self.username, self.password, self.email)
                u.put()

                self.login_cookie(u)
                self.redirect('/welcome')


class Welcome(Handler):
    def get(self):
        self.set_secure_cookie('blog_id', '')
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login_cookie(u)
            self.redirect('/welcome')
        else:
            msg = "Invalid login."
            self.render('login.html', error=msg)


class Logout(Handler):
    def get(self):
        self.logout_cookie()
        self.set_secure_cookie('blog_id', '')
        self.redirect('/signup')


class Delete(Handler):
    def get(self):
        if self.user:
            this_cookie = int(self.read_secure_cookie('blog_id'))
            current_user = self.read_secure_cookie('user_id')
            b = Blog.get_by_id(this_cookie)
            delete_request = True
            comment_error = ''
            if b.user != current_user:
                comment_error = 'You cannot delete this post.  It is not your to delete!  ' \
                                'Stopping messing with my cookies!'
                delete_request = False
            self.render('post_output.html',
                        blog=b,
                        current_user=current_user,
                        add_a_comment=False,
                        delete_request=delete_request,
                        comment_error=comment_error,
                        comment_id=-1)
        else:
            self.redirect('/login')

    def post(self):
        this_cookie = int(self.read_secure_cookie('blog_id'))
        current_user = self.read_secure_cookie('user_id')
        b = Blog.get_by_id(this_cookie)
        if self.user and b.user == current_user:
            Blog.get_by_id(this_cookie).delete()
            self.set_secure_cookie('blog_id', '')
            self.redirect('/blog/?')
        else:
            self.redirect('/login')


class Like(Handler):
    def get(self, blog_id):
        key = db.Key.from_path('Blog', int(blog_id))
        b = db.get(key)
        current_user = self.read_secure_cookie('user_id')
        if self.user and b.likable(current_user) == 1:
            b.likes_list.append(int(current_user))
            b.put()
            self.set_secure_cookie('blog_id', blog_id)
            self.render('post_output.html', current_user=current_user, blog=b)
        else:
            self.redirect('/login')


class Unlike(Handler):
    def get(self, blog_id):
        key = db.Key.from_path('Blog', int(blog_id))
        b = db.get(key)
        current_user = self.read_secure_cookie('user_id')
        if self.user and b.likable(current_user) == -1:
            b.likes_list.remove(int(current_user))
            b.put()
            self.set_secure_cookie('blog_id', blog_id)
            self.render('post_output.html', current_user=current_user, blog=b)
        else:
            self.redirect('/login')


class AddComment(Handler):
    def get(self, blog_id):
        key = db.Key.from_path('Blog', int(blog_id))
        current_user = self.read_secure_cookie('user_id')
        b = db.get(key)
        if self.user and b.user != current_user:
            self.render('post_output.html',
                        blog=b,
                        current_user=current_user,
                        add_a_comment=True)
        else:
            self.redirect('/login')

    def post(self, blog_id):
        key = db.Key.from_path('Blog', int(blog_id))
        current_user = self.read_secure_cookie('user_id')
        b = db.get(key)
        if self.user and b.user != current_user:
            comment = self.request.get("comment")
            if comment:
                c = BlogComment(comment=comment,
                                author_id=current_user,
                                author_name=User.by_id(int(current_user)).name,
                                parent=b)
                c.put()
                self.redirect('/blog/%s' % str(b.key().id()))
            else:
                comment_error = "no comment to add!"
                self.render('post_output.html',
                            blog=b,
                            current_user=current_user,
                            add_a_comment=True,
                            comment_error=comment_error)
        else:
            self.redirect('/login')


class EditComment(Handler):
    def get(self, comment_id, blog_id):
        current_user = self.read_secure_cookie('user_id')
        blog_key = db.Key.from_path('Blog', int(blog_id))
        b = db.get(blog_key)
        key = db.Key.from_path('BlogComment', int(comment_id))
        c_id = key.id()
        c = BlogComment.get_by_id(c_id, b)
        # checks in include...
        # 1. does user exist,
        # 2. commenter not author of post,
        # 3.  editing commenter is comment's author
        if self.user and b.user != current_user and c.author_id == current_user:
            self.set_secure_cookie('blog_id', blog_id)
            self.render('post_output.html',
                        blog=b,
                        current_user=current_user,
                        comment_error='',
                        comment_id=c_id)
        else:
            self.redirect('/login')

    def post(self, comment_id, blog_id):
        current_user = self.read_secure_cookie('user_id')
        blog_key = db.Key.from_path('Blog', int(blog_id))
        b = db.get(blog_key)
        key = db.Key.from_path('BlogComment', int(comment_id))
        c_id = key.id()
        c = BlogComment.get_by_id(c_id, b)
        if self.user and b.user != current_user and c.author_id == current_user:
            comment = self.request.get("comment")
            if comment:
                c.comment = comment
                c.put()
                self.redirect('/blog/%s' % str(b.key().id()))
            else:
                comment_error = "no comment to add!"
                self.render('post_output.html',
                            blog=b,
                            current_user=current_user,
                            add_a_comment=True,
                            comment_error=comment_error)
        else:
            self.redirect('/login')


class DeleteComment(Handler):
    def get(self, comment_id, blog_id):
        current_user = self.read_secure_cookie('user_id')
        blog_key = db.Key.from_path('Blog', int(blog_id))
        b = db.get(blog_key)
        key = db.Key.from_path('BlogComment', int(comment_id))
        c_id = key.id()
        c = BlogComment.get_by_id(c_id, b)
        # checks in include...
        # 1. does user exist,
        # 2. commenter not author of post,
        # 3.  editing commenter is comment's author
        if self.user and b.user != current_user and c.author_id == current_user:
            BlogComment.get_by_id(key.id(), parent=b).delete()
            self.redirect('/blog/%s' % str(b.key().id()))
        else:
            self.redirect('/login')


# generate instance
app = webapp2.WSGIApplication([('/blog/?', MainPage),
                                ('/', MainPage),
                               ('/blog/newpost', SubmissionPage),
                               ('/blog/([0-9]+)', NewOutputPage),
                               ('/signup', Register),
                               ('/welcome', Welcome),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/deletepost', Delete),
                               ('/blog/like/([0-9]+)', Like),
                               ('/blog/unlike/([0-9]+)', Unlike),
                               ('/blog/comment/([0-9]+)', AddComment),
                                ('/blog/editcomment/([0-9]+)-([0-9]+)', EditComment),
                                ('/blog/deletecomment/([0-9]+)-([0-9]+)', DeleteComment)
                               ],
                              debug=True)
