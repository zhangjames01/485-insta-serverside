PRAGMA foreign_keys = ON;
INSERT INTO users(username, fullname, email, filename, password)
VALUES ('awdeorio', 'Andrew DeOrio', 'awdeorio@umich.edu', 'e1a7c5c32973862ee15173b0259e3efdb6a391af.jpg', 'password');
VALUES ('jflinn', 'Jason Filnn', 'jflinn@umich.edu', '505083b8b56c97429a728b68f31b0b2a089e5113.jpg', 'password');
VALUES ('michjc', 'Michael cafarella', 'michjc@umich.edu', '5ecde7677b83304132cb2871516ea50032ff7a4f.jpg', 'password');
VALUES ('jag', 'H.V. Jagadish', 'jag@umich.edu', '73ab33bd357c3fd42292487b825880958c595655.jpg', 'password');

INSERT INTO posts(filename, owner)
VALUES ('122a7d27ca1d7420a1072f695d9290fad4501a41.jpg', 'awdeorio');
VALUES ('ad7790405c539894d25ab8dcf0b79eed3341e109.jpg', 'jflinn');
VALUES ('9887e06812ef434d291e4936417d125cd594b38a.jpg', 'awdeorio');
VALUES ('2ec7cf8ae158b3b1f40065abfb33e81143707842.jpg', 'jag');

INSERT INTO following(username1, username2)
VALUES ('awdeorio', 'jflinn');
VALUES ('awdeorio', 'michjc');
VALUES ('jflinn', 'awdeorio');
VALUES ('jflinn', 'michjc');
VALUES ('michjc', 'awdeorio');
VALUES ('michjc', 'jag');
VALUES ('jag', 'michjc');

INSERT INTO comments(owner, postid, text)
VALUES ('awdeorio', '3', '#chickensofinstagram');
VALUES ('jflinn', '3', 'I <3 chickens');
VALUES ('michjc', '3', 'Cute overload!');
VALUES ('awdeorio', '2', 'Sick #crossword');
VALUES ('jflinn', '1', 'Walking the plank #chickensofinstagram');
VALUES ('awdeorio', '1', 'This was after trying to teach them to do a #crossword');
VALUES ('jag', '4', 'Saw this on the diag yesterday!');

INSERT INTO likes(owner, postid)
VALUES ('awdeorio', '1');
VALUES ('michjc', '1');
VALUES ('jflinn', '1');
VALUES ('awdeorio', '2');
VALUES ('michjc', '2');
VALUES ('awdeorio', '3');