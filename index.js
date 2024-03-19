require("./utils.js");
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mySQL = require("mysql2");
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;

const freedb_host = process.env.FREEDB_HOST;
const freedb_database = process.env.FREEDB_DATABASE;
const freedb_port = process.env.FREEDB_PORT;
const freedb_user = process.env.FREEDB_USER;
const freedb_password = process.env.FREEDB_PASSWORD;

const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

var members = mySQL.createPool({
                host: freedb_host,
                user: freedb_user,
                password: freedb_password,
                database: freedb_database
              });

app.use(express.urlencoded({ extended: false }));
app.use(express.static(__dirname + "/public"));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}.i0p5mcg.mongodb.net/${mongodb_database}`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

app.get('/', (req, res) => {
    var html = ``;

    if(!req.session.authenticated)
    {
        html += `
        <a href="signup"><button>Sign up</button></a>
        <br>
        <a href="login"><button>Log in</button></a>`;
        
    }
    else
    {
        html += `
        Hello, ` + req.session.name + `!
        <br><br>
        <a href="groups"><button>Go to Chatrooms</button></a>
        <br>
        <a href="logout"><button>Log out</button></a>`;
    }

    res.send(html);
});

app.get('/signup', (req, res) => {
    var html = `
    <form action='/signupSubmit' method='post'>
    create user
    <br>
    <input name='username' type='text' placeholder='username'>
    <br>
    <input name='password' type='password' placeholder='password'>
    <br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/signupSubmit', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;

    const nameSchema = Joi.string().required().pattern(new RegExp('^[a-zA-Z0-9_]*$'));
    const passSchema = Joi
    .string()
    .min(8) // Minimum length of 8 characters
    .pattern(new RegExp('(?=.*[A-Z])')) // At least one uppercase letter
    .pattern(new RegExp('(?=.*[!@#$%^&*()_+-=[\\]{};,.?])'));

    if((nameSchema.validate(username)).error != null)
    {
        res.send(`
        Your username is invalid.
        <br><br>
        <a href="/signup">Try again</a>
        `);
        return;
    }
    else if (passSchema.validate(password).error != null) {
        res.send(`
        Password must be at least 8 characters long, with at least one uppercase letter, one number, and one symbol.
        <br><br>
        <a href="/signup">Try again</a>
        `);
        return;
    }
    else
    {
        var hashedPassword = await bcrypt.hash(password, saltRounds);

        var query = 'INSERT INTO members (username, password) VALUES (?, ?)';
        members.query(query, [username, hashedPassword], (err, result) => {
            if (err){
                throw err;
            }

            console.log('Account created!');
            req.session.member_id = result.insertId;
            console.log(req.session.member_id);
            req.session.authenticated = true;
            req.session.name = username;
            req.session.cookie.maxAge = expireTime;
            res.redirect("/groups");
            return;
        });
    }
});

app.get('/login', (req, res) => {

    if (req.session.authenticated) {
        res.redirect('/groups');
        return;
    }

    var html = `
    log in
    <form action='/loginSubmit' method='post'>
    <input name='username' type='text' placeholder='username'>
    <br>
    <input name='password' type='password' placeholder='password'>
    <br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/loginSubmit', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;

    var failResponce = `
        Invalid username/password combination.
        <br><br>
        <a href="/login">Try again</a>
        `;

    const nameSchema = Joi.string().required();
    const passSchema = Joi.string().required();

    var validationResult = nameSchema.validate(username);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send(failResponce);
        return;
    }

    var validationResult = passSchema.validate(password);
    if(validationResult.error != null)
    {
        console.log(validationResult.error);
        res.send(failResponce);
        return;
    }

    var query = 'SELECT member_id,username,password FROM members WHERE username = ?';
    members.query(query, [username], (err, result) => {
      if (err) throw err;

      if (result.length > 0) {
        if (bcrypt.compareSync(password, result[0].password)) {
                req.session.authenticated = true;
                req.session.name = result[0].username;
                req.session.member_id = result[0].member_id;
                req.session.cookie.maxAge = expireTime;

                res.redirect('/groups');
                return;
        }
        else {
        console.log("Incorrect password");
        }
      } else {
        console.log('Username does not exist.');
      }
      res.send(failResponce);
      return;
    });
});

app.get('/groups', async (req, res) => {

    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    var html = `
    <a2>Hello, ` + encodeHTML(req.session.name) + `.
    <br><br>
    <a2>Your Chats</2>
    <br><br>`

    var query = `SELECT room.* 
    FROM room, room_member
    WHERE room_member.room_id = room.room_id
    AND room_member.member_id = ?
    `;

    var result = await members.promise().query(query, [req.session.member_id]);
    if (result[0].length > 0) {
        for(var i = 0; i < result[0].length; i++)
        {
            var str = await pullRoomDetails(req, result[0][i]);
            html += str;

            //CANT ACCESS result[] FROM INNER QUERY BECAUSE OF COURSE YOU CANT AAAAAA
        }
        html += `
        <br><br>
        <a href="/createGroup"><button>New Group</button></a>
        <br>
        <a href="/logout"><button>Sign out</button></a>
        `;
        res.send(html);
        return result;
        
    } else {
        html += "You do not currently have any active chatrooms.";
        html += `
        <br><br>
        <a href="/createGroup"><button>New Group</button></a>
        <br>
        <a href="/logout"><button>Sign out</button></a>
        `;
      res.send(html);
      return result;
      }
});

async function pullRoomDetails(req, roomData) {
    var html = ``;
    var subquery = `
            select ru.room_member_id, (select count(message_id)
            from message, room_member as ru2
            where message.room_member_id = ru2.room_member_id
            and ru2.room_id = ${roomData.room_id}
            and message.message_id > COALESCE(ru.last_read_id, 0)) as unread
            from room_member as ru
            where ru.room_id = ${roomData.room_id} and ru.member_id = ?
            `;
    var subresult = await members.promise().query(subquery, [req.session.member_id]);

    html += `${roomData.name} <a>Unread:</a>`;

    if(subresult[0].length > 0) {
        html += `<a>${subresult[0][0].unread}</a>`
    }
    else {
        html += `<a>0</a>`;
    }
    html += `<a href="/chatroom?room=${roomData.room_id}"><button>Enter Room</button></a><br>`;
    return html;
}

app.get('/createGroup', async (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    var id = req.query.room;

    var html = `
    <link rel="stylesheet" type="text/css" href="css/registerGroup.css" />`;

    var query = ``;

    if(id != undefined)
    {
        if(await checkRoomAuth(req) == false) {
        res.redirect("/");
        return;
        }
        html += `<form action='/registerGroup?room=${id}' method='post'>`;
        query = `SELECT member_id,username FROM members WHERE member_id not in
        (select rm.member_id
        from room_member as rm
        where rm.room_id = ?)`;

    }
    else {
        id = req.session.member_id;
        html += `
        <form action='/registerGroup' method='post'>
        <div>
        <a>Group Name: </a>
        <input name='groupname' type='text' placeholder='Group Name'>
        </div>
        <br>
        `;

        query = 'SELECT member_id,username FROM members WHERE member_id != ?';
    }

    members.query(query, [id], (err, result) => {
      if (err) throw err;

      if (result.length > 0) {
        html += `
        <a>Users to add:</a>
        <div class="container">`;

        for(var i = 0; i < result.length; i++)
        {
            html += `<input type="checkbox" value="${result[i].member_id}" name="users"/>${encodeHTML(result[i].username)}<br />`;
        }

        html += `</div>
        <br><br>
        <button action="submit">Submit</button>`;
      } else {
        html += "There are currently no users to add to this room.";
      }

      html += `
    <br>
    </form>
    <a href="groups"><button action="">Cancel</button></a>
    `;
      res.send(html);
      return;
    });
});

app.post('/registerGroup', async (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }
    var name = req.body.groupname;
    var users = req.body.users;
    var id = req.query.room;

    const nameSchema = Joi.string().required().pattern(new RegExp('^[a-zA-Z0-9_]*$'));
    if(id === undefined && nameSchema.validate(name))
    {
        console.log(name);
        var query = 'INSERT INTO room (name) VALUES (?)';
        members.query(query, [name], (err, result) => {
            if (err) throw err;

            console.log(result);
            var id = result.insertId;
            console.log("Created room: " + id);
            console.log(users);

            var subquery = 'INSERT INTO room_member (member_id, room_id) VALUES (?,?)';
            members.query(subquery, [req.session.member_id, id], (err, result) => {
            if (err) throw err;
            console.log(`Added userid ${req.session.member_id} to room ${id}`);
            });

            if(users != undefined)
            {
                for(var i = 0; i < users.length; i++)
                {
                    var subquery = 'INSERT INTO room_member (member_id, room_id) VALUES (?,?)';
                    members.query(subquery, [users[i], id], (err, result) => {
                    if (err) throw err;
                    console.log(`Added userid ${users[i]} to room ${id}`);
                    });
                }
            }
          res.redirect('/');
          return;
        });
    }
    else if(id !== undefined) {
        if(users != undefined)
            {
                for(var i = 0; i < users.length; i++)
                {
                    var subquery = 'INSERT INTO room_member (member_id, room_id) VALUES (?,?)';
                    members.query(subquery, [users[i], id], (err, result) => {
                    if (err) throw err;
                    console.log(`Added userid ${users[i]} to room ${id}`);
                    });
                }
                res.redirect('/');
                return;
            }
            else {
                console.log("Error: Unable to add users to group.");
            res.redirect('/');
            return;
            }
    }
    else
    {
        console.log("Error: group name is invalid.");
        res.redirect('/');
        return;
    }
});

app.get('/chatroom', async (req, res) => {

    if(await checkRoomAuth(req) == false) {
        res.send(`Error: You do not have access to this chatroom. <br><br><a href="/groups"><button>Back</button></a>`);
        return;
    }

    var id = req.query.room;

    var html = `
    <link rel="stylesheet" type="text/css" href="css/chatroom.css" />
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet"
    integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"
    integrity="sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP+IlRH9sENBO0LRn5q+8nbTov4+1p"
    crossorigin="anonymous"></script>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.2/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    <a href="/groups"><button>Back</button></a><a id="add" href="/creategroup?room=${id}"><button>Add Users</button></a><br><br>
    `;

    var msgQuery = 
    `select distinct msg.message_id, msg.text, msg.sent_date, rom.member_id
    from message as msg, room_member as rom where
    msg.room_member_id in 
    (select rm.room_member_id
        from room_member as rm
        where rm.room_id = ?
        and rm.member_id = rom.member_id)
    order by msg.sent_date asc
    `;
    var result = await members.promise().query(msgQuery, [id]);

    html += `
    <div class="container" id="messages-go-here">
    `

    var reactionQuery = `select message.message_id, reaction.emoji_id, count(reaction.emoji_id) as count, emoji.image 
    from message_reaction as reaction, message, emoji 
    where reaction.message_id = message.message_id and reaction.emoji_id = emoji.emoji_id 
    and message.room_member_id in 
    (select ru.room_member_id from room_member as ru where ru.room_id = ?) 
    group by message.message_id, reaction.emoji_id`;

    var reactions = await members.promise().query(reactionQuery, [id]);

    if(result[0].length > 0)
    {
        for(var i = 0; i < result[0].length; i++)
        {
            html += await processMessage(req, result[0][i], result[0][i].message_id, reactions[0]);
        }
    }
    else
    {
        html += `
        <div class="card no-chatrooms">
        <div class="card-body d-flexbox justify-content-center text-center">
        <div>
        There are currently no messages.
        </div>
        </div>
        </div>`;
    }

    html += `
    </div>
    `;

    if(result[0].length > 0)
    {
        var readQuery = `
        update room_member
        set last_read_id = ?
        where member_id = ? and room_id = ?
        `;
    members.query(readQuery, [result[0][result[0].length - 1].message_id, req.session.member_id, id]);
    }

    html += `
    <form id="message" class="fixed-bottom" method="post" action="/sendmessage?room=${id}">
      <div class="form-row">
        <div class="form-group d-inline-flex chat-box">
          <input type="text" name="messageBox" class="form-control" id="inputMessage" placeholder="Your message...">
        </div>
        <div class="d-inline-flex send-button">
          <button class="btn btn-primary w-100">Send</button>
        </div>
      </div>
    </form>
    `;

    html += `
    <div class="modal fade" id="exampleModal" tabindex="-1" role="dialog" aria-labelledby="exampleModalLabel" aria-hidden="true">
    <div class="modal-dialog" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="exampleModalLabel">Add Reaction</h5>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>
      <div class="modal-body">`

      html += await getEmojiDisplay();

      html +=`</div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>
    `;

    html += `<script src="/js/emoji.js"></script>`;
    res.send(html);
});

app.post("/sendmessage", async (req,res) => {
    if(await checkRoomAuth(req) == false) {
        res.redirect("/");
        return;
    }

    var id = req.query.room;
    var query = `
            select ru.room_member_id
            from room_member as ru
            where ru.room_id = ? and ru.member_id = ?
            `;
    var result = await members.promise().query(query, [id, req.session.member_id]);
    if(result[0].length <= 0) {
        res.redirect(`/chatroom?room=${id}`);
        return;
    }
    var rmID = result[0][0].room_member_id;

    var message = req.body.messageBox;

    if (message == null || message == "") {
        res.redirect(`/chatroom?room=${id}`);
        return;
    }

    var insertQuery = 'INSERT INTO message (room_member_id, text) VALUES (?, ?)';
    var result = await members.promise().query(insertQuery, [rmID, message]);
    console.log("Sent!")
    console.log("Status:\n" + JSON.stringify(result, null, 4))

    res.redirect(`/chatroom?room=${id}`);
});

async function processMessage(req, message, id, reactions) {
    var html = ``;
        html +=
        `
        <div class="${message.member_id != req.session.member_id ? "received-message" : "sent-message"}">
            <div class="card">
                <div class="card-body">
                    <p class="message-body">${message.text}</p>
                </div>`;
        
        html += await processEmojis(message, id, reactions);

        html += `</div>
            <p class="text-muted sent-time"><small class="text-muted time">Sent: ${message.sent_date}</small></p>
        </div>
        `;
    return html;
}

async function processEmojis(message, id, reactions) {
    var currentEmojis = `select reaction.emoji_id, count(reaction.emoji_id) as count, emoji.image from message_reaction as reaction, emoji where reaction.message_id = ? and reaction.emoji_id = emoji.emoji_id group by emoji_id`

    var currentResult = reactions;

    var html = `<div class="emojis">`;

    for(var i = 0; i < currentResult.length; i++) {
        if(message.message_id != currentResult[i].message_id) {
            continue;
        }
        var img = currentResult[i];
        html += `
        <div class="rounded-div d-flex justify-content-center align-items-center position-relative">
        <img class="icon" src="/icons/${img.image}.png"></img>
        <span class="number-badge position-absolute">${img.count}</span>
        </div>
        `;
    }
    
    html += `
        <button class="rounded-div d-flex justify-content-center align-items-center position-relative" data-toggle="modal" data-target="#exampleModal" onclick="selectMessage(${id})">
        <img class="btnicon" src="/icons/plus.png"></img>
        </button></div>
        `;

    return html;
}

async function getEmojiDisplay() {
    var emojis = "select * from emoji";
    var result = await members.promise().query(emojis);

    html = '';
    for(var i = 0; i < result[0].length; i++)
    {
        html += `
        <button class="rounded-div d-flex justify-content-center align-items-center position-relative selectable" onclick="selectEmoji(${i+1})">
        <img class="icon" src="/icons/${result[0][i].image}.png"></img>
        </button>
        `;
    }
    return html;
}

async function checkRoomAuth(req) {
    if (!req.session.authenticated) {
        console.log("Failed to validate session");
        return false;
    }

    var id = req.query.room;

    var query = `
            select ru.room_member_id
            from room_member as ru
            where ru.room_id = ? and ru.member_id = ?
            `;
    var result = await members.promise().query(query, [id, req.session.member_id]);
    if(result[0].length <= 0) {
        console.log("Permission Denied");
        return false;
    }

    console.log("Authorized");
    return true;
}

app.get('/react', async (req, res) => {

    if (!req.session.authenticated) {
        console.log("Failed to validate session");
        res.redirect('back');
        return false;
    }

    var message = req.query.message;
    var emoji = req.query.emoji;

    if(message === undefined || emoji === undefined) {
        console.log("Undefined message or reaction.");
        res.redirect('back');
        return;
    }

    var insertQuery = 'INSERT INTO message_reaction (message_id, emoji_id, user_id) VALUES (?, ?, ?)';
    var deleteQuery = 'DELETE FROM message_reaction where message_id = ? and emoji_id = ? and user_id = ?'
    var checkQuery = 'SELECT react.* from message_reaction as react where react.message_id = ? and react.emoji_id = ? and react.user_id = ?';

    var checkResult = await members.promise().query(checkQuery, [message, emoji, req.session.member_id]);

    if(checkResult[0].length > 0) {
        await members.promise().query(deleteQuery, [message, emoji, req.session.member_id]);
    }
    else {
        await members.promise().query(insertQuery, [message, emoji, req.session.member_id]);
    }


    res.redirect('back');
})

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
})

function encodeHTML(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 