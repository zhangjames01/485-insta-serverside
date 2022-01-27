PRAGMA foreign_keys = ON;
CREATE TABLE users(
  username VARCHAR(20) NOT NULL,
  fullname VARCHAR(40) NOT NULL,
  email VARCHAR(40) NOT NULL,
  filename VARCHAR(64) NOT NULL,
  password VARCHAR(256) NOT NULL,
  created DATETIME,
  PRIMARY KEY(username)
);
CREATE TABLE posts(
  postid int AUTO_INCREMENT,
  filename VARCHAR(64) NOT NULL,
  owner VARCHAR(20) NOT NULL,
  created DATETIME,
  PRIMARY KEY(postid),
  FOREIGN KEY(owner) REFERENCES users(username)
  CONSTRAINT posts_delete
    FOREIGN KEY (owner)
    REFERENCES users(username)
    ON DELETE CASCADE
);
CREATE TABLE following(
  username1 VARCHAR(20) NOT NULL,
  username2 VARCHAR(20) NOT NULL,
  created DATETIME,
  PRIMARY KEY(username1, username2),
  -- FOREIGN KEY (username1) REFERENCES users(username),
  -- FOREIGN KEY (username2) REFERENCES users(username),
  FOREIGN KEY(username1, username2) REFERENCES users(username, username) ON DELETE CASCADE
  -- CONSTRAINT username2_delete FOREIGN KEY(username2) REFERENCES users(username) ON DELETE CASCADE
);
CREATE TABLE comments(
  commentid int AUTO_INCREMENT,
  owner VARCHAR(20) NOT NULL,
  postid int NOT NULL,
  text VARCHAR(1024) NOT NULL,
  created DATETIME,
  PRIMARY KEY(commentid),
  -- FOREIGN KEY(owner) REFERENCES users(username),
  -- FOREIGN KEY(postid) REFERENCES posts(postid),
  FOREIGN KEY(owner) REFERENCES users(username) ON DELETE CASCADE,
  FOREIGN KEY(postid) REFERENCES posts(postid) ON DELETE CASCADE
);
CREATE TABLE likes (
  likeid int AUTO_INCREMENT,
  owner VARCHAR(20) NOT NULL,
  postid int NOT NULL,
  created DATETIME,
  PRIMARY KEY(likeid),
  FOREIGN KEY (owner) REFERENCES users(username),
  FOREIGN KEY(postid) REFERENCES posts(postid),
  CONSTRAINT likes_owner_delete
    FOREIGN KEY (owner)
    REFERENCES users(username)
    ON DELETE CASCADE,
  CONSTRAINT likes_postid_delete
    FOREIGN KEY (postid)
    REFERENCES posts(postid)
    ON DELETE CASCADE
);

