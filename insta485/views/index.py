"""
Insta485 index (main) view.
URLs include:
/
"""
import flask
import insta485
from flask import request
import os
import pathlib
import uuid
import hashlib

# /


@insta485.app.route('/', methods=['GET'])
def show_index():
    """Display / route."""
    if "username" not in flask.session:
        return flask.redirect(flask.url_for('show_login'))
    # Connect to database
    connection = insta485.model.get_db()
    # Query database
    logname = flask.session['username']

    # find postids of posts posted by logname and users logname is following
    cur = connection.execute(
        "SELECT posts.postid, posts.owner, users.filename, posts.filename, posts.created "
        "FROM posts "
        "INNER JOIN following ON posts.owner = following.username2 "
        "INNER JOIN users ON posts.owner = users.username "
        "WHERE following.username1 = ? "
        "OR posts.owner = ? ",
        ([logname], [logname])
    )
    post_data = cur.fetchall()
    posts = []
    # TODO loop

    # find num of likes
    for post in post_data:
        cur = connection.execute(
            "SELECT COUNT(*) "
            "FROM likes "
            "INNER JOIN posts ON likes.postid = posts.postid "
            "WHERE posts.postid = ?",
            ([post[0]])
        )
        likes_data = cur.fetchall()
        post.append(likes_data[0]["COUNT(*)"])

        # find comments and owners of comments
        cur = connection.execute(
            "SELECT comments.owner, comments.text, comments.created "
            "FROM comments "
            "INNER JOIN posts ON comments.postid = posts.postid "
            "WHERE posts.postid = ?",
            ([post[0]])
        )
        comments_data = cur.fetchall()
        post.append([])
        for comment in comments_data:
            post[6].append({"owner": comment[0],
                            "text": comment[1]})
        posts.append({"postid": post[0],
                      "owner": post[1],
                      "owner_img_url": post[2],
                      "img_url": post[3],
                      "timestamp": post[4],
                      "likes": post[5],
                      "comments": post[6]})

    # Add database info to context
    context = {"logname": logname,
               "posts": posts}
    return flask.render_template("index.html", **context)


@insta485.app.route('/users/<username>/', methods=['GET'])
def show_users(username):
    """Display /users/<user_url_slug>"""

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
    if (status[0]["COUNT(*)"] == 0):
        flask.abort(404)

    # query
        logname = flask.session['username']

    # Find if user follows logname
    cur = connection.execute(
        "SELECT COUNT(*) "
        "FROM following "
        "WHERE username1 = ? "
        "AND username2 = ? ",
        ([logname], [username])
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
        "WHERE owner = ? ",
        ([username])
    )
    posts = cur.fetchall()

    # add database info to context

    # make list for
    posts_list = []
    for post in posts:
        posts_list.append({
            "postid": post['postid'],
            "img_url": post['filename']
        })

    context = {"logname": logname,
               "username": username,
               "logname_follows_username": logname_follows_username,
               "fullname": full_name[0]['fullname'],
               "following": num_following['COUNT(*)'],
               "followers": num_followers['COUNT(*)'],
               "total_posts": num_posts['COUNT(*)'],
               "posts": posts_list
               }
    return flask.render_template("user.html", **context)


@insta485.app.route('/users/<username>/followers/', methods=['GET'])
def show_followers(username):
    """Display /users/<user_url_slug>/followers"""

    # Connect to database

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
    if (status[0]['COUNT(*)'] == 0):
        flask.abort(404)

    # Query database

    # TODO: Add into context

    logname = flask.session['username']
    cur = connection.execute(
        "SELECT following.username2, users.filename "
        "FROM following "
        "INNER JOIN users ON following.username2=users.username "
        "WHERE username1= ? ",
        ([username])
    )
    peoplefollowers = cur.fetchall()
    followers = []

    # Returns a list of people that follow you saved in "followers";

    for follower in peoplefollowers:
        cur = connection.execute(
            "SELECT username2 "
            "FROM Following "
            "WHERE username2 = ? "
            "AND username1 = ?",
            ([follower[0]], [logname]),
        )
        if cur.rowcount != 0:
            followers.append({"username": follower[0]['following.username2'],
                             "logname_follows_username": True,
                              "user_image_url": follower[0]['users.filename']
                              })
        else:
            followers.append({"username": follower[0]['following.username2'],
                             "logname_follows_username": False,
                              "user_image_url": follower[0]['users.filename']
                              })

    context = {"followers": followers,
               "logname": logname}
    return flask.render_template("followers.html", **context)


@insta485.app.route('/users/<username>/following/', methods=['GET'])
def show_following(username):
    """Display /users/<user_url_slug>/following"""

    # Connect to database
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
    if (status[0]["COUNT(*)"] == 0):
        flask.abort(404)

    # Query database

    # TODO: Add into context
    logname = flask.session['username']
    cur = connection.execute(
        "SELECT following.username1, users.filename "
        "FROM following "
        "INNER JOIN users ON following.username1=users.username "
        "WHERE username2 = ? ",
        ([username])
    )
    # TODO: Finish the rest of the following
    peoplefollowed = cur.fetchall()
    following = []

    for following in peoplefollowed:
        cur = connection.execute(
            "SELECT username2 "
            "FROM following "
            "WHERE username2 = ? "
            "AND username1 = ?",
            ([following[0]], [logname])
        )
        if cur.rowcount() != 0:
            following.append({"username": following[0]['following.username1'],
                              "logname_follows_username": True,
                              "user_image_url": following[0]['users.filename']})
        else:
            following.append({"username": following[0]['following.username1'],
                              "logname_follows_username": False,
                              "user_image_url": following[1]['users.filename']})

    context = {"following": following,
               "logname": logname}
    return flask.render_template("following.html", **context)


@insta485.app.route('/posts/<postid>/', methods=['GET'])
def show_post(postid):
    """Display /posts/<postid_url_slug>"""

    # Connect to database
    connection = insta485.model.get_db()

    # Query into database
    logname = flask.session['username']
    # Find owner and owner_img
    cur = connection.execute(
        "SELECT posts.owner, users.filename "
        "FROM posts "
        "INNER JOIN users ON posts.owner = users.username, WHERE postid = ? ",
        ([postid])
    )
    owner = cur.fetchall()

    # Find timestamp and img
    cur = connection.execute(
        "SELECT created, filename "
        "FROM posts "
        "WHERE postid = ? ",
        ([postid])
    )
    created = cur.fetchall()

    # Find number of likes
    cur = connection.execute(
        "SELECT COUNT(*) "
        "FROM likes "
        "WHERE postid = ? ",
        ([postid])
    )
    num_likes = cur.fetchall()

    cur = connection.execute(
        "SELECT owner, text "
        "FROM comments "
        "WHERE postid = ? ",
        ([postid])
    )
    comments = cur.fetchall()
    comment_list = []
    for comment in comments:
        comment_list.append({"owner": comment['owner'],
                            "text": comment['text']})

    context = {"logname": logname,
               "postid": postid,
               "owner": owner[0]['posts.owner'],
               "owner_img_url": owner[0]['users.filename'],
               "img_url": created[0]['filename'],
               "timestamp": created[0]['created'],
               "likes": num_likes[0]['COUNT(*)'],
               "comments": comment_list
               }
    return flask.render_template("posts.html", **context)


@insta485.app.route('/explore', methods=['GET'])
def show_explore():
    """Display /explore"""

    # Connect to database
    connection = insta485.model.get_db()

    # Query into database
    logname = flask.session['username']
    cur = connection.execute(
        "SELECT users.username, users.filename "
        "FROM users "
        "INNER JOIN following ON "
        "following.username2=users.username "
        "WHERE username1 != ? ",
        ([logname])
    )
    not_following = cur.fetchall()
    follow_list = []
    for follow in not_following:
        follow_list.append({
            "username": follow['users.username'],
            "user_img_url": follow['users.filename']
        })

    # Add database info to context
    context = {"logname": logname,
               "not_following": follow_list
               # [
               #  {"username": not_following[0]['users.username'],
               #    "user_img_url": not_following[1]['users.filename']}
               # ]
               }
    return flask.render_template("explore.html", **context)


@insta485.app.route('/accounts/login/', methods=['GET'])
def show_login():
    """Display /accounts/login"""

    connection = insta485.model.get_db()
    if flask.session['username']:

        # THE CODE BELOW IS PROBALY UNNECESSARY

        #        logname = flask.session['username']
        #        cur = connection.execute(
        #            "SELECT username",
        #            "FROM users",
        #            "WHERE username = ?",
        #            (logname)
        #        )
        #        username = cur.fetchall()
        #        if cur.row_count() != 0:
        #            logged_in = True
        #        else:
        #            logged_in = False
        #
        return flask.redirect(flask.url_for('show_index'))
    else:
        return flask.render_template("login.html")


@insta485.app.route('/accounts/create/', methods=['GET'])
def show_create():
    """Display /accounts/create"""

    # Connect to database
    connection = insta485.model.get_db()
    if flask.session['username']:
        return flask.redirect(flask.url_for('show_edit'))
    else:
        return flask.render_template("create.html")


@insta485.app.route('/accounts/delete/', methods=['GET'])
def show_delete():
    """Display /accounts/delete"""
    logname = flask.session['username']

    context = {"logname": logname}
    return flask.render_template("delete.html", **context)


@insta485.app.route('/accounts/edit', methods=['GET'])
def show_edit():
    """Display /accounts/edit"""

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
               "fullname": user_data[1]['fullname'],
               "email": user_data[2]['email']
               }
    return flask.render_template("edit.html", **context)


@insta485.app.route('/accounts/password/', methods=['GET'])
def show_password():
    """DISPLAY /accounts/password"""

    logname = flask.session['username']
    context = {"logname": logname}
    return flask.render_template("password.html", **context)


# POST methods
@insta485.app.route('/likes/', methods=['POST'])
def likes():
    """Display /"""
    url = request.args.get('target')
    logname = flask.session['username']

    # If the operation is like
    if flask.request.form['operation'] == 'like':
        postid = flask.request.form['postid']
        connection = insta485.mode.get_db()
        connection.execute(
            "SELECT COUNT(*) "
            "FROM likes "
            "WHERE postid = ? "
            "AND user = ? ",
            ([postid], [logname])
        )
        liked = connection.fetchall()
        # If user has already liked post, abort 409
        if (liked[0]['COUNT(*)'] == 0):
            flask.abort(409)
        connection = insta485.model.get_db()
        # Create like for postid
        connection.execute(
            "INSERT INTO likes (owner, postid) "
            "VALUES (?, ?) ",
            ([logname], [postid])
        )

    # If the operation is unlike
    elif flask.request.form['operation'] == 'unlike':
        postid = flask.request.form['postid']
        connection = insta485.mode.get_db()
        connection.execute(
            "SELECT COUNT(*) "
            "FROM likes "
            "WHERE postid = ? "
            "AND user = ? ",
            ([postid], [logname])
        )
        liked = connection.fetchall()
        # If user has not liked post yet, abort 409
        if (liked[0]['COUNT(*)'] != 0):
            flask.abort(409)
        # Delete like for postid
        connection = insta485.model.get_db()
        connection.execute(
            "DELETE FROM likes "
            "WHERE postid = ? "
            "AND owner = ? ",
            ([postid], [logname])
        )

    # Redirect to URL
    if url:
        return flask.redirect(url)
    else:
        return flask.redirect("/")


@insta485.app.route('/comments/', methods=['POST'])
def comments():
    url = request.args.get('target')
    logname = flask.session['username']
    postid = flask.request.form['postid']
    commentid = flask.request.form['commentid']
    text = flask.request.form['text']

    # If the operation is create
    if flask.request.form['operation'] == 'create':
        # Check if it is an empty comment
        if text == "":
            flask.abort(400)

        connection = insta485.model.get_db()
        connection.execute(
            "INSERT INTO comments (owner, commentid) "
            "VALUES (?, ?, ?) ",
            ([logname], [commentid], [text])
        )

    # If operation is delete
    elif flask.request.form['operation'] == 'delete':
        # Check if logman owns comment they are trying to delete
        connection = insta485.model.get_db()
        connection.execute(
            "SELECT COUNT(*) "
            "FROM comments "
            "WHERE commentid = ? "
            " AND owner = ? ",
            ([commentid], [logname])
        )
        comment_check = connection.fetchall()
        # If logman does not own comment, abort 403
        if comment_check[0]['COUNT(*)'] == 0:
            flask.abort(403)
        # Delete comment
        connection = insta485.model.get_db()
        connection.execute(
            "DELETE FROM comments ",
            "WHERE commentid = ?",
            ([commentid])
        )

    # Redirect to URL
    if url:
        return flask.redirect(url)
    else:
        return flask.redirect("/")


@insta485.app.route('/posts/', methods=['POST'])
def posts():
    url = request.args.get('target')
    logname = flask.session['username']
    postid = flask.request.form['postid']
    # unpack flask object
    fileobj = request.files['file']
    filename = fileobj.filename

    # If the operation is create
    if flask.request.form['operation'] == 'create':
        # if the file is empty, abort 400
        if os.path.getsize(fileobj) <= 0:
            flask.abort(400)

        # Compute base name (filename without directory).  We use a UUID to avoid
        # clashes with existing files, and ensure that the name is compatible with the
        # filesystem.
        stem = uuid.uuid4().hex
        suffix = pathlib.Path(filename).suffix
        uuid_basename = f"{stem}{suffix}"
        # Save to disk
        path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
        # TODO: ^^ double check if this is the right file path!
        fileobj.save(path)

        # add filename to database
        connection = insta485.model.get_db()
        connection.execute(
            "INSERT INTO posts(filename, owner) "
            "VALUES (?, ?) ",
            ([uuid_basename], [logname])
        )

    # If the operation is delete
    elif flask.request.form['operation'] == 'delete':
        # Check if logman owns post they are trying to delete
        connection = insta485.model.get_db()
        connection.execute(
            "SELECT COUNT(*) "
            "FROM posts "
            "WHERE postid = ? "
            "AND owner = ? ",
            ([postid], [logname])
        )
        post_check = connection.fetchall()
        # If logname does not own post, abort 403
        if post_check[0]['COUNT(*)'] == 0:
            flask.abort(403)
        # Delete image file and everything related (automatically ON DELETE CASCADE)
        connection = insta485.model.get_db()
        connection.execute(
            "DELETE FROM posts "
            "WHERE postid = ? ",
            ([postid])
        )
# Redirect to URL
    if url:
        return flask.redirect(url)
    else:
        return flask.redirect("/users/" + logname)


@insta485.app.route('/following/', methods=['POST'])
def following():
    url = request.args.get('target')
    logname = flask.session['username']
    username = flask.request.form['username']
    # TODO: is username correct?? ^^

    # If the operation is follow
    if flask.request.form['operation'] == 'follow':
        connection = insta485.model.get_db()
        connection.execute(
            "SELECT COUNT(*) "
            "FROM following "
            "WHERE username1 = ? "
            "AND username2 = ? ",
            ([logname], [username])
        )
        # If a user tries to follow a user already followed, abort 409
        following_status = connection.fetchall()
        if following_status[0]['COUNT(*)'] != 0:
            flask.abort(409)
        # create new following in database
        connection = insta485.model.get_db()
        connection.execute(
            "INSERT INTO following(username1, username2) "
            "VALUES (?, ?) ",
            ([logname], [username])
        )
    # If the operation is unfollow
    elif flask.request.form['operation'] == 'unfollow':
        connection = insta485.model.get_db()
        connection.execute(
            "SELECT COUNT(*) "
            "FROM following "
            "WHERE username1 = ? ",
            ([logname]),
            "AND username2 = ? ",
            ([username])
        )
        # If a user tries to unfollow someone not followed
        following_status = connection.fetchall()
        if following_status[0]['COUNT(*)'] == 0:
            flask.abort(409)
            # delete following in database
        connection = insta485.model.get_db()
        connection.execute(
            "DELETE FROM following(username1, username2) "
            "VALUES (?, ?) ",
            ([logname], [username])
        )

    # Redirect to URL
        if url:
            return flask.redirect(url)
        else:
            return flask.redirect("/")


@ insta485.app.route('/accounts/', methods=['POST'])
def accounts():
    url = request.args.get('target')

    #  username = flask.request.form['username']
    # password = flask.request.form['password']
    # fullname = flask.request.form['fullname']
    # email = flask.request.form['email']
    # new_password1 = flask.request.form['new_password1']
    # new_password2 = flask.request.form['new_password2']
    # unpack flask object
    # fileobj = request.files['file']
    # filename = fileobj.filename
    # # Compute base name (filename without directory).  We use a UUID to avoid
    # # clashes with existing files, and ensure that the name is compatible with the
    # # filesystem.
    # stem = uuid.uuid4().hex
    # suffix = pathlib.Path(filename).suffix
    # uuid_basename = f"{stem}{suffix}"

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
            ([username])
        )
        correct_password = cur.fetchall()
        if cur.rowcount == 0 or correct_password[0]['password'] != password:
            flask.abort(403)
        flask.session['username'] = username

    # If the operation is create
    if flask.request.form['operation'] == 'create':
        username = flask.request.form['username']
        password = flask.request.form['password']
        fullname = flask.request.form['fullname']
        email = flask.request.form['email']
        # unpack flask object
        fileobj = flask.request.files['file']
        filename = fileobj.filename
        # Compute base name (filename without directory).  We use a UUID to avoid
        # clashes with existing files, and ensure that the name is compatible with the
        # filesystem.
        stem = uuid.uuid4().hex
        suffix = pathlib.Path(filename).suffix
        uuid_basename = f"{stem}{suffix}"
        # if any of the fields are empty, abort 400
        if username == "" or password == "" or fullname == "" or email == "" or uuid_basename == "":
            flask.abort(400)
        connection = insta485.model.get_db()
        cur = connection.execute(
            "SELECT COUNT(*) "
            "FROM users "
            "WHERE username = ? ",
            ([username])
        )
        users_check = cur.fetchall()
        #users_check[0]['COUNT(*)'] = connection.fetchall()
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
        # TODO: ^^ double check if this is the right file path!
        fileobj.save(path)

    # If the operation is follow

    if flask.request.form['operation'] == 'delete':
        logname = flask.session['username']
        # If user not logged in, abort 403
        if not flask.session['username']:
            flask.abort(403)
        # Delete all post files uploaded by user
        connection = insta485.model.get_db()
        connection.execute(
            "SELECT filename "
            "FROM post "
            "WHERE owner = ? ",
            ([logname])
        )
        delete_posts = connection.fetchall()
        for x in delete_posts[0]['filename']:
            for y in x:
                path = insta485.app.config["UPLOAD_FOLDER"]/y
                os.remove(path)
        # Delete user icon
        connection = insta485.model.get_db()
        connection.execute(
            "SELECT filename "
            "FROM users "
            "WHERE username = ? ",
            ([logname])
        )
        delete_icon = connection.fetchall()
        path = insta485.app.config["UPLOAD_FOLDER"]/delete_icon[0]['filename']
        os.remove(path)
        # Delete user's all related entries in all tables in database
        connection = insta485.model.get_db()
        connection.execute(
            "DELETE FROM users(username, fullname, email, filename, password) ",
            "WHERE username = ? ",
            ([logname])
        )

    # If the operation is edit account
    if flask.request.form['operation'] == 'edit_account':
        fullname = flask.request.form['fullname']
        email = flask.request.form['email']
        # unpack flask object
        fileobj = flask.request.files['file']
        filename = fileobj.filename
        # Compute base name (filename without directory).  We use a UUID to avoid
        # clashes with existing files, and ensure that the name is compatible with the
        # filesystem.
        stem = uuid.uuid4().hex
        suffix = pathlib.Path(filename).suffix
        uuid_basename = f"{stem}{suffix}"
        # If not logged in, abort
        if not flask.session['username']:
            flask.abort(403)

        logname = flask.session['username']
        # If fullname or email fields are empty, abort
        if fullname == "" or email == "":
            flask.abort(400)

        # If no photo file is included
        if os.path.getsize(fileobj) <= 0:
            connection = insta485.model.get_db()
            # Update only the user's name and email
            connection.execute(
                "UPDATE users "
                "SET fullname = ?, email = ? "
                "WHERE username = ? ",
                ([fullname, email, logname])
            )

        # If photo file is include
        else:
            # Get old icon filename from database and delete from path
            connection = insta485.model.get_db()
            connection.execute(
                "SELECT filename "
                "FROM users "
                "WHERE username = ? ",
                ([logname])
            )
            old_icon = connection.fetchall()
            path = insta485.app.config["UPLOAD_FOLDER"]/old_icon[0]['filename']
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
                ([fullname], [email], [uuid_basename], [logname])
            )

    # If the operation is update password
    if flask.request.form['operation'] == 'update_password':
        password = flask.request.form['password']
        new_password1 = flask.request.form['new_password1']
        new_password2 = flask.request.form['new_password2']
        # If not logged in, abort
        if not flask.session['username']:
            flask.abort(403)
        logname = flask.session['username']
        # If any of the field are empty, abort
        if password == "" or new_password1 == "" or new_password2 == "":
            flask.abort(400)
        # Verify password against user's password hash
        connection = insta485.model.get_db()
        connection.execute(
            "SELECT password "
            "FROM users "
            "WHERE username = ? ",
            ([logname])
        )
        user_password = cur.fetchall()
        if (user_password[0]['password'] != password):
            flask.abort(403)
        # Verify both new passwords match
        if new_password1 != new_password2:
            flask.abort(401)
        # Compute hashed password using SHAS-512
        algorithm = 'sha512'
        salt = uuid.uuid4().hex
        hash_obj = hashlib.new(algorithm)
        password_salted = salt + password
        hash_obj.update(password_salted.encode('utf-8'))
        password_hash = hash_obj.hexdigest()
        password_db_string = "$".join([algorithm, salt, password_hash])
        connection = insta485.model.get_db()
        # Update the hashed password entry
        connection.execute(
            "UPDATE users "
            "SET password = ? "
            "WHERE username = ? ",
            ([password_db_string], [logname])
        )

    # Redirect to URL
    if url:
        return flask.redirect(url)
    else:
        return flask.redirect(flask.url_for('show_index'))

# Static File Permissions


@insta485.app.route('/uploads/<filename>/', methods=['POST'])
def show_file(filename):
    if not flask.session['username']:
        flask.abort(403)
    connection = insta485.model.get_db()
    cur = connection.execute(
        "SELECT filename "
        "FROM users "
        "WHERE filename = ?",
        ([filename])
    )
    if cur.rowcount == 0:
        flask.abort(404)
