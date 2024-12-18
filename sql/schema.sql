PRAGMA foreign_keys = ON;
CREATE TABLE users(
  username VARCHAR(20) NOT NULL,
  fullname VARCHAR(40) NOT NULL,
  email VARCHAR(40) NOT NULL,
  filename VARCHAR(64) NOT NULL,
  password VARCHAR(256) NOT NULL,
  created DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(username)
);
CREATE TABLE posts(
  postid INTEGER PRIMARY KEY AUTOINCREMENT,
  filename VARCHAR(64) NOT NULL,
  owner VARCHAR(20) NOT NULL,
  created DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(owner) REFERENCES users(username)
  CONSTRAINT posts_delete
    FOREIGN KEY (owner)
    REFERENCES users(username)
    ON DELETE CASCADE
);
CREATE TABLE following(
  username1 VARCHAR(20) NOT NULL,
  username2 VARCHAR(20) NOT NULL,
  created DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(username1, username2),
  -- FOREIGN KEY (username1) REFERENCES users(username),
  -- FOREIGN KEY (username2) REFERENCES users(username),
  -- FOREIGN KEY(username1) REFERENCES users(username) ON DELETE CASCADE,
  -- FOREIGN KEY(username2) REFERENCES users(username) ON DELETE CASCADE
  CONSTRAINT fk_key
    FOREIGN KEY (username1) 
    REFERENCES users (username)
    ON DELETE CASCADE
  CONSTRAINT fk_key_2
    FOREIGN KEY (username2)
    REFERENCES users (username)
    ON DELETE CASCADE
);
CREATE TABLE comments(
  commentid INTEGER PRIMARY KEY AUTOINCREMENT,
  owner VARCHAR(20) NOT NULL,
  postid INTEGER,
  text VARCHAR(1024) NOT NULL,
  created DATETIME DEFAULT CURRENT_TIMESTAMP,
  -- FOREIGN KEY(owner) REFERENCES users(username),
  -- FOREIGN KEY(postid) REFERENCES posts(postid),
  CONSTRAINT fk_comments
    FOREIGN KEY(owner) 
    REFERENCES users(username) 
    ON DELETE CASCADE
  CONSTRAINT fk_comments_2
    FOREIGN KEY(postid) 
    REFERENCES posts(postid)
    ON DELETE CASCADE
);
CREATE TABLE likes (
  likeid INTEGER PRIMARY KEY AUTOINCREMENT,
  owner VARCHAR(20) NOT NULL,
  postid INTEGER,
  created DATETIME DEFAULT CURRENT_TIMESTAMP,
  -- FOREIGN KEY (owner) REFERENCES users(username),
  -- FOREIGN KEY(postid) REFERENCES posts(postid),
  CONSTRAINT likes_owner_delete
    FOREIGN KEY(owner) 
    REFERENCES users(username)
    ON DELETE CASCADE
  CONSTRAINT likes_postid_delete
    FOREIGN KEY(postid)
    REFERENCES posts(postid)
    ON DELETE CASCADE
);

