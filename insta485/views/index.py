"""
Insta485 index (main) view.
URLs include:
/
"""
import flask
import insta485
from flask import request

# /


@insta485.app.route('/', methods=['GET'])
def show_index():
    """Display / route."""

    # Connect to database
    connection = insta485.model.get_db()

    # Query database
    logname = "awdeorio"
    cur = connection.execute(
        "SELECT username, fullname "
        "FROM users "
        "WHERE username != ?",
        (logname),
    )
    users = cur.fetchall()

    cur = connection.execute(
        "SELECT postid, filename, owner, created "
        "FROM posts "
        "SELECT filename"

    )
    posts = cur.fetchall()
    # Add database info to context
    context = {"users": users}
    return flask.render_template("index.html", **context)


@insta485.app.route('/users/<username>', methods=['GET'])
def show_users(username):
    """Display /users/<user_url_slug>"""

    # connect to database
    connection = insta485.model.get_db()

    # abort(404) if username DNE
    cur = connection.execute(
        "SELECT username "
        "FROM users "
        "WHERE username = ?"
        (username)
    )
    status = cur.fetchall()
    if (status == 0):
        flask.abort(404)

    # query
    logname = "awdeorio"

    # Find if user follows logname
    cur = connection.execute(
        "SELECT COUNT(*) "
        "FROM following "
        "WHERE username1 = ?"
        (username)
        " AND username2 = ?"
        (logname)
    )
    following_status = cur.fetchall()
    if following_status == 0:
        username_follows_logname = False
    else:
        username_follows_logname = True

    # Find number of posts
    cur = connection.execute(
        "SELECT COUNT(*) "
        "FROM posts "
        "WHERE owner == ?"
        (username)
    )
    num_posts = cur.fetchall()

    # Find number of followers
    cur = connection.execute(
        "SELECT COUNT(*) "
        "FROM following "
        "WHERE username2 == ?"
        (username)
    )
    num_followers = cur.fetchall()

    # Find number of following
    cur = connection.execute(
        "SELECT COUNT(*) "
        "FROM following "
        "WHERE username1 == ?"
        (username)
    )
    num_following = cur.fetchall()

    # Find full name
    cur = connection.execute(
        "SELECT fullname "
        "FROM users "
        "WHERE username == ?"
        (username)
    )
    full_name = cur.fetchall()

    # A small image for each post
    cur = connection.execute(
        "SELECT postid, filename "
        "FROM posts "
        "WHERE owner == ?"
        (username)
    )
    posts = cur.fetchall()

    # add database info to context

    context = {"logname": logname,
               "username": username,
               "logname_follows_username": logname_follows_username,
               "fullname": full_name,
               "following": num_following,
               "followers": num_followers,
               "total_posts":}


@insta485.app.route('/users/<username>/followers', methods=['GET'])
def show_followers(username):
    """Display /users/<user_url_slug>/followers"""

    # Connect to database

    connection = insta485.model.get_db()

    # Abort 404 if username DNE
    # abort(404) if username DNE
    cur = connection.execute(
        "SELECT username "
        "FROM users "
        "WHERE username =  ?"
        (username)
    )
    status = cur.fetchall()
    if (status == 0):
        flask.abort(404)

    # Query database

    # TODO: Add into context

    logname = "awdeorio"
    cur = connection.execute(
        "SELECT following.username2, users.filename ",
        "FROM following",
        "INNER JOIN users ON following.username2=users.username"
        "WHERE username1= ?",
        (username)
    )
    peoplefollowers = cur.fetchall()
    followers = []

    # Returns a list of people that follow you saved in "followers";

    for follower in peoplefollowers:
        cur = connection.execute(
            "SELECT username2 ",
            "FROM FOLLOWING",
            "WHERE username2 = ?",
            "AND username1 = ?",
            (follower[0], logname),
        )
        if cur.rowcount() != 0:
            followers.append({"username": follower[0],
                             "logname_follows_username": True,
                              "user_image_url": follower[1]
                              })
        else:
            followers.append({"username": follower[0],
                             "logname_follows_username": False,
                              "user_image_url": follower[1]
                              })

    context = {"followers": followers,
               "logname": logname}
    return flask.render_template("following.html", **context)


@insta485.app.route('/users/<username>/following', methods=['GET'])
def show_following(username):
    """Display /users/<user_url_slug>/following"""

    # Connect to database
    connection = insta485.model.get_db()

    # Abort 404 if username DNE
    # abort(404) if username DNE
    cur = connection.execute(
        "SELECT username "
        "FROM users "
        "WHERE username =  ?"
        (username)
    )
    status = cur.fetchall()
    if (status == 0):
        flask.abort(404)

    # Query database

    # TODO: Add into context
    logname = "awdeorio"
    cur = connection.execute(
        "SELECT username1 ",
        "FROM following",
        "WHERE username2 = ?",
        (username)
    )
    # TODO: Finish the rest of the following


@insta485.app.route('/posts/<postid>', methods=['GET'])
def show_post(postid):
    """Display /posts/<postid_url_slug>"""

    # Connect to database
    connection = insta485.model.get_db()

    # Query into database
    logname = "awdeorio"
    cur = connection.execute(
        "SELECT commentid ",
        "FROM comments",
        "WHERE owner = ?",
        (logname)
    )
    # ^v Btton stuff so far, dont know if we need

    cur = connection.execute(
        "SELECT COUNT(*) ",
        "FROM posts",
        "WHERE postid = ?"
        (postid)
        "AND owner = ?"
        (logname)
    )

    # Find owner,timestamp of post
    cur = connection.execute(
        "SELECT owner, created ",
        "FROM posts",
        "WHERE postid = ?",
        (postid)
    )

    # Find number of likes
    cur = connection.execute(
        "SELECT COUNT(*) ",
        "FROM likes",
        "WHERE postid = ?",
        (postid)
    )
    num_likes = cur.fetchall()

    cur = connection.execute(
        "SELECT owner, text "
        "FROM comments "
        "WHERE postid = ?"
        (postid)
    )


@insta485.app.rout('/explore', methods=['GET'])
def show_explore():
    """Display /explore"""

    # Connect to database
    connection = insta485.model.get_db()

    # Query into database
    logname = "awdeorio"
    cur = connection.execute(
        "SELECT users.username, users.filename "
        "FROM users "
        "INNER JOIN following ON "
        "following.username2=users.username "
        "WHERE username1 != ?"
        (logname)
    )


@insta485.app.rout('/explore', methods=['GET'])
def show_explore():
    """Display /explore"""

    # Connect to database
    connection = insta485.model.get_db()


# POST methods
@insta485.app.route('/likes', methods=['POST'])
def likes():
    """Display /"""
    # grab data from the request form and save into variables
    # edit the database
    # redirect done by the webpage
    if request.form['operation'] == 'like':
