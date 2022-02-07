"""
Insta485 index (main) view.

URLs include:
/
"""
import os
import pathlib
import hashlib
import uuid
import arrow
import flask
import insta485

# /


@insta485.app.route('/', methods=['GET'])
def show_index():
    """Display / route."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    # Connect to database
    connection = insta485.model.get_db()
    # Query database
    logname = flask.session['username']

    # find postids of posts posted by logname and users logname is following
    cur = connection.execute(
        "SELECT posts.postid, posts.owner, posts.created "
        "FROM posts "
        "WHERE owner IN "
        "(SELECT username2 FROM following WHERE username1 = ?) "
        "OR owner = ?"
        "ORDER BY postid DESC",
        (logname, logname)
    )
    post_data = cur.fetchall()
    posts_list = []

    connection = insta485.model.get_db()
    cur = connection.execute(
        "SELECT posts.filename "
        "FROM posts "
        "INNER JOIN following ON posts.owner = following.username2 "
        "WHERE following.username1 = ? "
        "OR posts.owner = ? ",
        (logname, logname,)
    )
    file = cur.fetchall()

    # find num of likes
    for post in post_data:
        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT posts.filename "
            "FROM posts "
            "INNER JOIN following ON posts.owner = following.username2 "
            "WHERE following.username1 = ? "
            "AND posts.postid = ? "
            "OR posts.owner = ? "
            "AND posts.postid = ? ",
            (logname, post['postid'], logname, post['postid'],)
        )
        file = cur.fetchone()

        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT users.filename "
            "FROM users "
            "INNER JOIN posts ON users.username = posts.owner "
            "INNER JOIN following ON posts.owner = following.username2 "
            "WHERE following.username1 = ? "
            "AND posts.postid = ? "
            "OR posts.owner = ? "
            "AND posts.postid = ? ",
            (logname, post['postid'], logname, post['postid'],)
        )
        user_file = cur.fetchone()

        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT COUNT(*) "
            "FROM likes "
            "INNER JOIN posts ON likes.postid = posts.postid "
            "WHERE posts.postid = ? ",
            # posts[0] previously
            (post['postid'],)
        )
        likes_data = cur.fetchall()

        connection = insta485.model.get_db()

        cur = connection.execute(
            "SELECT COUNT(*) "
            "FROM likes "
            "WHERE owner = ? "
            "AND postid = ? ",
            (logname, post['postid'])
        )
        liked_check = cur.fetchall()
        logname_likes = False
        if liked_check[0]['COUNT(*)'] != 0:
            logname_likes = True
        # posts.append(likes_data[0]['COUNT(*)')

        # find comments and owners of comments
        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT comments.owner, comments.text, comments.created "
            "FROM comments "
            "INNER JOIN posts ON comments.postid = posts.postid "
            "WHERE posts.postid = ?",
            (post['postid'],)
        )
        comments_data = cur.fetchall()
        comment_list = []
        for comment in comments_data:
            comment_list.append({"owner": comment['owner'],
                                 "text": comment['text']})
        posts_list.append({"postid": post['postid'],
                           "owner": post['owner'],
                           "owner_img_url": user_file['filename'],
                           "img_url": file['filename'],
                           "timestamp": arrow.get(post['created']).humanize(),
                           "likes": likes_data[0]['COUNT(*)'],
                           "comments": comment_list,
                           "logname_likes": logname_likes
                           })

    # Add database info to context
    context = {"logname": logname,
               "posts": posts_list}
    return flask.render_template("index.html", **context)


@ insta485.app.route('/users/<username>/', methods=['GET'])
def show_users(username):
    """Display /users/<user_url_slug>."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    # connect to database
    connection = insta485.model.get_db()

    # abort(404) if username DNE
    cur = connection.execute(
        "SELECT COUNT(*) "
        "FROM users "
        "WHERE username = ? ",
        ([username])
    )
    status = cur.fetchall()
    if status[0]["COUNT(*)"] == 0:
        flask.abort(404)

    # query
    logname = flask.session['username']

    # Find if user follows logname
    cur = connection.execute(
        "SELECT COUNT(*) "
        "FROM following "
        "WHERE username1 = ? "
        "AND username2 = ? ",
        (logname, username)
    )
    following_status = cur.fetchall()
    if following_status[0]["COUNT(*)"] == 0:
        logname_follows_username = False
    else:
        logname_follows_username = True

    # Find number of posts
    cur = connection.execute(
        "SELECT COUNT(*) "
        "FROM posts "
        "WHERE owner = ? ",
        ([username])
    )
    num_posts = cur.fetchall()

    # Find number of followers
    cur = connection.execute(
        "SELECT COUNT(*) "
        "FROM following "
        "WHERE username2 = ? ",
        ([username])
    )
    num_followers = cur.fetchall()

    # Find number of following
    cur = connection.execute(
        "SELECT COUNT(*) "
        "FROM following "
        "WHERE username1 = ? ",
        ([username])
    )
    num_following = cur.fetchall()

    # Find full name
    cur = connection.execute(
        "SELECT fullname "
        "FROM users "
        "WHERE username = ? ",
        ([username])
    )
    full_name = cur.fetchall()

    # A small image for each post
    cur = connection.execute(
        "SELECT postid, filename "
        "FROM posts "
        "WHERE owner = ? "
        "ORDER BY postid DESC ",
        ([username])
    )
    posts_data = cur.fetchall()

    # add database info to context

    # make list for
    posts_list = []
    for post in posts_data:
        posts_list.append({
            "postid": post['postid'],
            "img_url": post['filename']
        })

    context = {"logname": logname,
               "username": username,
               "logname_follows_username": logname_follows_username,
               "fullname": full_name[0]['fullname'],
               "following": num_following[0]['COUNT(*)'],
               "followers": num_followers[0]['COUNT(*)'],
               "total_posts": num_posts[0]['COUNT(*)'],
               "posts": posts_list
               }
    return flask.render_template("user.html", **context)


@ insta485.app.route('/users/<username>/followers/', methods=['GET'])
def show_followers(username):
    """Display /users/<user_url_slug>/followers."""
    # Connect to database
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))

    connection = insta485.model.get_db()

    # Abort 404 if username DNE
    # abort(404) if username DNE
    cur = connection.execute(
        "SELECT COUNT(*) "
        "FROM users "
        "WHERE username =  ?",
        ([username])
    )
    status = cur.fetchall()
    if status[0]['COUNT(*)'] == 0:
        flask.abort(404)

    # Query database

    # : Add into context

    logname = flask.session['username']
    cur = connection.execute(
        "SELECT following.username1, users.filename "
        "FROM following "
        "INNER JOIN users ON following.username1=users.username "
        "WHERE username2= ? ",
        ([username])
    )
    peoplefollowers = cur.fetchall()
    followers = []

    # Returns a list of people that follow you saved in "followers";

    for follower in peoplefollowers:
        cur = connection.execute(
            "SELECT COUNT(*) "
            "FROM Following "
            "WHERE username2 = ? "
            "AND username1 = ?",
            (follower['username1'], logname),
        )
        result = cur.fetchall()
        count = 0
        for person in result:
            if person['COUNT(*)'] != 0:
                count = 1
        if count == 1:
            followers.append({"username": follower['username1'],
                             "logname_follows_username": True,
                              "user_img_url": follower['filename']
                              })
        else:
            followers.append({"username": follower['username1'],
                             "logname_follows_username": False,
                              "user_img_url": follower['filename']
                              })

    context = {"followers": followers,
               "username": username,
               "logname": logname}
    return flask.render_template("followers.html", **context)


@ insta485.app.route('/users/<username>/following/', methods=['GET'])
def show_following(username):
    """Display /users/<user_url_slug>/following."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))

    # Connect to database
    connection = insta485.model.get_db()

    # abort(404) if username DNE
    cur = connection.execute(
        "SELECT COUNT(*) "
        "FROM users "
        "WHERE username =  ?",
        ([username])
    )
    status = cur.fetchall()
    if status[0]["COUNT(*)"] == 0:
        flask.abort(404)

    # Query database
    logname = flask.session['username']
    cur = connection.execute(
        "SELECT following.username2, users.filename "
        "FROM following "
        "INNER JOIN users ON following.username2=users.username "
        "WHERE username1 = ? ",
        ([username])
    )
    peoplefollowed = cur.fetchall()
    following_list = []
    for follow in peoplefollowed:
        cur = connection.execute(
            "SELECT COUNT(*) "
            "FROM following "
            "WHERE username1 = ? "
            "AND username2 = ? ",
            (logname, follow['username2'])
        )
        result = cur.fetchall()
        count = 0
        for person in result:
            if person['COUNT(*)'] != 0:
                count = 1
        if count == 1:
            following_list.append({"username": follow['username2'],
                                   "logname_follows_username": True,
                                   "user_img_url": follow['filename']})
        else:
            following_list.append({"username": follow['username2'],
                                   "logname_follows_username": False,
                                   "user_img_url": follow['filename']})

    context = {"following": following_list,
               "username": username,
               "logname": logname}
    return flask.render_template("following.html", **context)


@ insta485.app.route('/posts/<postid>/', methods=['GET'])
def show_post(postid):
    """Display /posts/<postid_url_slug>."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))

    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))

    # Connect to database
    connection = insta485.model.get_db()

    # Query into database
    logname = flask.session['username']
    # Find owner and owner_img

    connection = insta485.model.get_db()
    cur = connection.execute(
        "SELECT posts.owner, users.filename "
        "FROM posts "
        "INNER JOIN users ON posts.owner = users.username "
        "WHERE postid = ? ",
        ([postid])
    )
    owner = cur.fetchone()

    # Find timestamp and img
    connection = insta485.model.get_db()
    cur = connection.execute(
        "SELECT created, filename "
        "FROM posts "
        "WHERE postid = ? ",
        ([postid])
    )
    created = cur.fetchall()

    # Find number of likes
    connection = insta485.model.get_db()
    cur = connection.execute(
        "SELECT COUNT(*) "
        "FROM likes "
        "WHERE postid = ? ",
        ([postid])
    )
    num_likes = cur.fetchall()

    connection = insta485.model.get_db()
    cur = connection.execute(
        "SELECT owner, text, commentid "
        "FROM comments "
        "WHERE postid = ? ",
        ([postid])
    )
    comments_list = cur.fetchall()

    connection = insta485.model.get_db()
    cur = connection.execute(
        "SELECT COUNT(*) "
        "FROM likes "
        "WHERE owner = ? "
        "AND postid = ? ",
        (logname, postid)
    )
    liked_check = cur.fetchall()
    logname_likes = False
    if liked_check[0]['COUNT(*)'] != 0:
        logname_likes = True

    comment_list = []
    for comment in comments_list:
        comment_list.append({"owner": comment['owner'],
                            "text": comment['text'],
                             "commentid": comment['commentid']})

    context = {"logname": logname,
               "postid": postid,
               "owner": owner['owner'],
               "owner_img_url": owner['filename'],
               "img_url": created[0]['filename'],
               "timestamp": arrow.get(created[0]['created']).humanize(),
               "likes": num_likes[0]['COUNT(*)'],
               "comments": comment_list,
               "logname_likes": logname_likes
               }
    return flask.render_template("posts.html", **context)


@ insta485.app.route('/explore/', methods=['GET'])
def show_explore():
    """Display /explore."""
    if 'username' not in flask.session:
        return flask.redirect(flask.url_for('show_login'))

    # Connect to database
    connection = insta485.model.get_db()

    # Query into database
    logname = flask.session['username']
    cur = connection.execute(
        "SELECT users.username, users.filename "
        "FROM users "
        "INNER JOIN following ON "
        "users.username = following.username2 "
        "WHERE following.username1 = ? ",
        ([logname])
    )
    following_list = cur.fetchall()
    cur = connection.execute(
        "SELECT username, filename "
        "FROM users "
        "WHERE username != ? ",
        ([logname])
    )
    not_following = cur.fetchall()
    cur = connection.execute(
        "SELECT username, filename "
        "FROM users "
        "WHERE username != ? ",
        ([logname])
    )
    people = cur.fetchall()
    for follow in people:
        for person in following_list:
            if follow['username'] == person['username']:
                not_following.remove(follow)

    follow_list = []
    for follow in not_following:
        follow_list.append({
            "username": follow['username'],
            "user_img_url": follow['filename']
        })

    # Add database info to context
    context = {"logname": logname,
               "not_following": follow_list

               }
    return flask.render_template("explore.html", **context)


@ insta485.app.route('/accounts/login/', methods=['GET'])
def show_login():
    """Display /accounts/login."""
    if 'username' in flask.session:
        return flask.redirect(flask.url_for('show_index'))
    return flask.render_template("login.html")


@ insta485.app.route('/accounts/logout/', methods=['POST'])
def show_logout():
    """Display /accounts/logout."""
    flask.session.clear()
    return flask.redirect(flask.url_for('show_login'))


@ insta485.app.route('/accounts/create/', methods=['GET'])
def show_create():
    """Display /accounts/create."""
    # Connect to database
    if flask.session.get('username'):
        return flask.redirect(flask.url_for('show_edit'))
    return flask.render_template("create.html")


@ insta485.app.route('/accounts/delete/', methods=['GET'])
def show_delete():
    """Display /accounts/delete."""
    logname = flask.session['username']

    context = {"logname": logname}
    return flask.render_template("delete.html", **context)


@ insta485.app.route('/accounts/edit/', methods=['GET'])
def show_edit():
    """Display /accounts/edit."""
    # Connect to database
    connection = insta485.model.get_db()

    logname = flask.session['username']
    cur = connection.execute(
        "SELECT filename, fullname, email "
        "FROM users "
        "WHERE username = ? ",
        ([logname])
    )
    user_data = cur.fetchall()

    context = {"logname": logname,
               "user_img_url": user_data[0]['filename'],
               "fullname": user_data[0]['fullname'],
               "email": user_data[0]['email']
               }
    return flask.render_template("edit.html", **context)


@ insta485.app.route('/accounts/password/', methods=['GET'])
def show_password():
    """DISPLAY /accounts/password."""
    logname = flask.session['username']
    context = {"logname": logname}
    return flask.render_template("password.html", **context)


# POST methods
@ insta485.app.route('/likes/', methods=['POST'])
def likes():
    """Display /."""
    url = flask.request.args.get('target')
    logname = flask.session['username']

    # If the operation is like
    if flask.request.form['operation'] == 'like':
        postid = flask.request.form['postid']
        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT COUNT(*) "
            "FROM likes "
            "WHERE postid = ? "
            "AND owner = ? ",
            (postid, logname),
        )
        liked = cur.fetchall()
        # If user has already liked post, abort 409
        if liked[0]['COUNT(*)'] != 0:
            flask.abort(409)
        connection = insta485.model.get_db()
        # Create like for postid
        connection.execute(
            "INSERT INTO likes (owner, postid) "
            "VALUES (?, ?) ",
            (logname, postid)
        )

    # If the operation is unlike
    elif flask.request.form['operation'] == 'unlike':
        postid = flask.request.form['postid']
        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT COUNT(*) "
            "FROM likes "
            "WHERE postid = ? "
            "AND owner = ? ",
            (postid, logname),
        )
        liked = cur.fetchall()
        # If user has not liked post yet, abort 409
        if liked[0]['COUNT(*)'] == 0:
            flask.abort(409)
        # Delete like for postid
        connection = insta485.model.get_db()
        connection.execute(
            "DELETE FROM likes "
            "WHERE postid = ? "
            "AND owner = ? ",
            (postid, logname),
        )

    # Redirect to URL
    if url:
        return flask.redirect(url)
    return flask.redirect(flask.url_for('show_index'))


def hash_password(password):
    """Hash the password."""
    algorithm = 'sha512'
    salt = uuid.uuid4().hex
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + password
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([algorithm, salt, password_hash])
    return password_db_string


@ insta485.app.route('/comments/', methods=['POST'])
def comments():
    """Display function."""
    logname = flask.session['username']

    # If the operation is create
    if flask.request.form['operation'] == 'create':
        text = flask.request.form['text']
        postid = flask.request.form['postid']
        # Check if it is an empty comment
        if text == "":
            flask.abort(400)

        connection = insta485.model.get_db()
        connection.execute(
            "INSERT INTO comments (owner, postid, text) "
            "VALUES (?, ?, ?) ",
            (logname, postid, text)
        )

    # If operation is delete
    elif flask.request.form['operation'] == 'delete':
        commentid = flask.request.form['commentid']
        # Check if logman owns comment they are trying to delete
        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT COUNT(*) "
            "FROM comments "
            "WHERE commentid = ? "
            "AND owner = ? ",
            (commentid, logname,)
        )
        comment_check = cur.fetchall()
        # If logname does not own comment, abort 403
        if not comment_check:
            flask.abort(403)
        # Delete comment
        connection = insta485.model.get_db()
        connection.execute(
            "DELETE FROM comments WHERE commentid = ? AND owner = ? ",
            (commentid, logname,)
        )

    # Redirect to URL
    if 'target' in flask.request.args:
        return flask.redirect(flask.request.args['target'])
    return flask.redirect(flask.url_for('show_index'))


@ insta485.app.route('/posts/', methods=['POST'])
def posts():
    """Display function."""
    logname = flask.session['username']

    # If the operation is create
    if flask.request.form['operation'] == 'create':
        # unpack flask object
        fileobj = flask.request.files['file']
        filename = fileobj.filename
        # if the file is empty, abort 400
        if not fileobj:
            flask.abort(400)
        # Compute base name (filename without directory).
        # We use a UUID to avoid
        # clashes with existing files, and
        # ensure that the name is compatible with the
        # filesystem.
        stem = uuid.uuid4().hex
        suffix = pathlib.Path(filename).suffix
        uuid_basename = f"{stem}{suffix}"
        # Save to disk
        path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
        # : ^^ double check if this is the right file path!
        fileobj.save(path)

        # add filename to database
        connection = insta485.model.get_db()
        connection.execute(
            "INSERT INTO posts(filename, owner) "
            "VALUES (?, ?) ",
            (uuid_basename, logname)
        )

    # If the operation is delete
    elif flask.request.form['operation'] == 'delete':
        postid = flask.request.form['postid']
        # Check if logman owns post they are trying to delete
        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT COUNT(*) "
            "FROM posts "
            "WHERE postid = ? "
            "AND owner = ? ",
            (postid, logname)
        )
        post_check = cur.fetchall()
        # If logname does not own post, abort 403
        if post_check[0]['COUNT(*)'] == 0:
            flask.abort(403)

        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT filename "
            "FROM posts "
            "WHERE postid = ?",
            (postid)
        )
        filename = cur.fetchall()
        path = insta485.app.config["UPLOAD_FOLDER"]/filename[0]['filename']
        os.remove(path)
        connection = insta485.model.get_db()
        connection.execute(
            "DELETE FROM posts "
            "WHERE postid = ? ",
            ([postid])
        )

# Redirect to URL
    if 'target' in flask.request.args:
        return flask.redirect(flask.request.args['target'])
    return flask.redirect("/users/"+logname+"/")


@ insta485.app.route('/following/', methods=['POST'])
def following():
    """Display function."""
    logname = flask.session['username']
    username = flask.request.form['username']

    # If the operation is follow
    if flask.request.form['operation'] == 'follow':
        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT COUNT(*) FROM following "
            "WHERE username1 = ? AND username2 = ? ",
            (logname, username)
        )
        # If a user tries to follow a user already followed, abort 409
        following_status = cur.fetchall()
        if following_status[0]['COUNT(*)'] != 0:
            flask.abort(409)
        # create new following in database
        connection = insta485.model.get_db()
        connection.execute(
            "INSERT INTO following(username1, username2) "
            "VALUES (?, ?) ",
            (logname, username)
        )
    # If the operation is unfollow
    else:
        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT COUNT(*) FROM following "
            "WHERE username1 = ? AND username2 = ? ",
            (logname, username)
        )
        # If a user tries to unfollow someone not followed
        following_status = cur.fetchall()
        if following_status[0]['COUNT(*)'] == 0:
            flask.abort(409)
            # delete following in database
        connection = insta485.model.get_db()
        connection.execute(
            "DELETE FROM following "
            "WHERE username1 = ? AND username2 = ? ",
            (logname, username)
        )

    # Redirect to URL
    if 'target' in flask.request.args:
        return flask.redirect(flask.request.args['target'])
    return flask.redirect(flask.url_for('show_index'))


@ insta485.app.route('/accounts/', methods=['POST'])
def accounts():
    """Display function."""
    # If the operation is login
    if flask.request.form['operation'] == 'login':
        username = flask.request.form['username']
        password = flask.request.form.get('password')
        if not username or not password:
            flask.abort(400)
        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT password "
            "FROM users "
            "WHERE username = ? ",
            (username,)
        )
        correct_password = cur.fetchall()
        if not correct_password:
            flask.abort(403)
        if not pass_check(password, correct_password[0]['password']):
            flask.abort(403)
        flask.session.clear()
        flask.session['username'] = flask.request.form['username']

    # If the operation is create
    if flask.request.form['operation'] == 'create':
        username = flask.request.form['username']
        password = flask.request.form['password']
        fullname = flask.request.form['fullname']
        email = flask.request.form['email']
        # unpack flask object
        fileobj = flask.request.files['file']
        filename = fileobj.filename

        # filesystem.
        stem = uuid.uuid4().hex
        suffix = pathlib.Path(filename).suffix
        uuid_basename = f"{stem}{suffix}"
        # if any of the fields are empty, abort 400
        if username == "" or password == "" or fullname == "":
            flask.abort(400)
        if email == "" or uuid_basename == "":
            flask.abort(400)
        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT COUNT(*) "
            "FROM users "
            "WHERE username = ? ",
            ([username])
        )
        users_check = cur.fetchall()
        # users_check[0]['COUNT(*)'] = connection.fetchall()
        # if user already exists, abort 409
        if users_check[0]['COUNT(*)'] != 0:
            flask.abort(409)
        # insert new user into database
        # Compute hashed password using SHAS-512
        algorithm = 'sha512'
        salt = uuid.uuid4().hex
        hash_obj = hashlib.new(algorithm)
        password_salted = salt + password
        hash_obj.update(password_salted.encode('utf-8'))
        password_hash = hash_obj.hexdigest()
        password_db_string = "$".join([algorithm, salt, password_hash])
        connection = insta485.model.get_db()
        connection.execute(
            "INSERT INTO users(username, fullname, email, filename, password) "
            "VALUES (?, ?, ?, ?, ?) ",
            (username, fullname, email,
             uuid_basename, password_db_string)
        )
        # Save to disks
        path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
        # : ^^ double check if this is the right file path!
        fileobj.save(path)
        flask.session.clear()
        flask.session['username'] = username

    # If the operation is follow

    if flask.request.form['operation'] == 'delete':
        logname = flask.session['username']
        # If user not logged in, abort 403
        if not flask.session['username']:
            flask.abort(403)
        # Delete all post files uploaded by user
        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT filename "
            "FROM posts "
            "WHERE owner = ? ",
            ([logname])
        )
        delete_posts = cur.fetchall()
        for slay_c in delete_posts:
            path = insta485.app.config["UPLOAD_FOLDER"]/slay_c['filename']
            os.remove(path)
        # Delete user icon
        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT filename "
            "FROM users "
            "WHERE username = ? ",
            ([logname])
        )
        delete_icon = cur.fetchall()
        path = insta485.app.config["UPLOAD_FOLDER"]/delete_icon[0]['filename']
        os.remove(path)
        # Delete user's all related entries in all tables in database
        connection = insta485.model.get_db()
        connection.execute(
            "DELETE FROM users "
            "WHERE username = ? ",
            ([logname])
        )
        connection.commit()
        flask.session.clear()

    # If the operation is edit account
    if flask.request.form['operation'] == 'edit_account':
        if not flask.session['username']:
            flask.abort(403)

        logname = flask.session['username']
        # If fullname or email
        # fields are empty, abort
        if not flask.request.form['fullname']:
            flask.abort(400)
        if not flask.request.form['email']:
            flask.abort(400)

        # If no photo file is included
        if not flask.request.files['file']:
            connection = insta485.model.get_db()
            # Update only the user's name and email
            fullname = flask.request.form['fullname']
            email = flask.request.form['email']
            connection.execute(
                "UPDATE users "
                "SET fullname = ?, email = ? "
                "WHERE username = ? ",
                ([fullname, email, logname])
            )

        # If photo file is include
        else:
            fullname = flask.request.form['fullname']
            email = flask.request.form['email']
            # unpack flask object
            fileobj = flask.request.files['file']
            filename = fileobj.filename
            # Compute base name (filename without directory).
            # We use a UUID to avoid
            # clashes with existing files, and ensure
            # that the name is compatible with the
            # filesystem.
            stem = uuid.uuid4().hex
            suffix = pathlib.Path(filename).suffix
            uuid_basename = f"{stem}{suffix}"
            # If not logged in, abort
            # Get old icon filename from database and delete from path
            connection = insta485.model.get_db()
            cur = connection.execute(
                "SELECT filename "
                "FROM users "
                "WHERE username = ? ",
                ([logname])
            )
            old_icon = cur.fetchall()
            path = insta485.app.config["UPLOAD_FOLDER"] / \
                old_icon[0]['filename']
            os.remove(path)
            # Add the new icon file to the database
            path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
            fileobj.save(path)
            # Update the user's name, email, and photo
            connection = insta485.model.get_db()
            connection.execute(
                "UPDATE users "
                "SET fullname = ?, email = ?, filename = ? "
                "WHERE username = ? ",
                (fullname, email, uuid_basename, logname)
            )

    # If the operation is update password
    if flask.request.form['operation'] == 'update_password':
        # If not logged in, abort
        if not flask.session['username']:
            flask.abort(403)
        logname = flask.session['username']
        # If any of the field are empty, abort
        if not flask.request.form['password']:
            flask.abort(400)
        if not flask.request.form['new_password1']:
            flask.abort(400)
        if not flask.request.form['new_password2']:
            flask.abort(400)

        password = flask.request.form['password']
        new_password1 = flask.request.form['new_password1']
        new_password2 = flask.request.form['new_password2']
        # Verify password against user's password hash
        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT password "
            "FROM users "
            "WHERE username = ? ",
            ([logname])
        )
        user_password = cur.fetchall()
        algorithm, salt, curpasshash = user_password[0]['password'].split('$')
        hash_obj = hashlib.new(algorithm)
        password_salted = salt + password
        hash_obj.update(password_salted.encode('utf-8'))
        newpasshash = hash_obj.hexdigest()

        if not curpasshash == newpasshash:
            print('aborted')
            flask.abort(403)
            # if (user_password[0]['password'] != password):
            # "aborted"
            # flask.abort(403)
            # Verify both new passwords match
        if new_password1 != new_password2:
            flask.abort(401)

        # Compute hashed password using SHAS-512
        algorithm = 'sha512'
        salt = uuid.uuid4().hex
        hash_obj = hashlib.new(algorithm)
        password_salted = salt + new_password1
        hash_obj.update(password_salted.encode('utf-8'))
        password_hash = hash_obj.hexdigest()
        password_db_string = "$".join([algorithm, salt, password_hash])
        connection = insta485.model.get_db()
        # Update the hashed password entry
        connection.execute(
            "UPDATE users "
            "SET password = ? "
            "WHERE username = ? ",
            (password_db_string, logname)
        )

    # Redirect to URL
    if 'target' in flask.request.args:
        return flask.redirect(flask.request.args['target'])
    return flask.redirect(flask.url_for('show_index'))

# Static File Permissions


@ insta485.app.route('/uploads/<filename>', methods=['GET'])
def show_file(filename):
    """Display function."""
    if 'username' not in flask.session:
        flask.abort(403)
    if not os.path.exists(insta485.app.config['UPLOAD_FOLDER']/filename):
        flask.abort(404)
    return flask.send_from_directory(insta485.app.config['UPLOAD_FOLDER'],
                                     filename, as_attachment=True)


def pass_check(new, database):
    """Display pass_check."""
    algorithm, salt, curpasshash = database.split('$')
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + new
    hash_obj.update(password_salted.encode('utf-8'))
    newpasshash = hash_obj.hexdigest()
    return newpasshash == curpasshash
