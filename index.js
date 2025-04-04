/**
 * Requirements:
 * Express for the server, modemon for dev environment, helmet for conent security policy or XSS
 */


//Solution 1
//User enter data -> browser process data -> Server sanatize data.
const {JSDOM } = require('jsdom')
const {window } = new JSDOM('') //Required for domppurify
const DOMPurify = require('dompurify')(window) // This will sanitize user generated content


//Solution 2
const helmet = require('helmet') //Same domain policy
const sqlite3 = require('sqlite3').verbose(); // For implementing sql injection.


//Express
const express = require('express') //We need to install express using npm
const app = express()


//Solution number 2 for XSS making sure to accept what resources to be allowed to be loaded on the webpage.
//For example we can prevent scripts to be accepted from users.
// app.use(helmet.contentSecurityPolicy({
//     directives: {
//         defaultSrc: ["'self'"],
//         scriptSrc: ["'self'"],
//         styleSrc: ["'self'"]
//     },
// }))




//Default route
app.get('/', function(req, res) {
    res.send(`<h4>XSS Cross-site scripting</h4>
    <p id='p'>Insecure route: This following like will work fine, You can use helmet to test the following links. Enabling helmet should secure /insecure/?name...</p>
    <a href='/insecure?name=leen&lastname=bajunaid'>http:localhost:3000/insecure?name=leen&lastname=bajunaid</a>
    <hr>
    <p>Insecure route: This following link will work and execute the script alert. To turn this off there are two solutions, either using DOMPurify or helmet.</p>
    <a href='/insecure?name=<script>alert("GO")</script>&lastname=<script>alert("TEST")</script>'>This link contains a script, once clicked an alert should popup.</a>
    <hr>
    <p>For solution 2 the following urls will be executed but this time the route will use a secure route wehere it sanatize user input.</p>
    <a href='/secure?name=Leen&lastname=bajunaid'>http://localhost:3000/secure?name=Leen&lastname=bajunaid</a>
    <hr>
    <p>The following link will use a script but wouldn't execute becuase we have implemented DOMPurify to validate the input. This should work without Enabling helment.</p>
    <a href='/secure?name=<script>alert("GO")</script>&lastname=<script>alert("TEST")</script>'>This link contains a script, but it wouldn't execute.</a>
    <hr>
    <h4>SQL Injection Examples.</h4>
    <p>First we will show all users in the database, let us assume that we are admin when we access this link. /secure/users</p>
    <a href='/secure/users'>http://localhost:3000/secure/users</a>
    <hr>
    <p>The following link will get user input as an ID of a specific user. i.e /secure/user/2</p>
    <p>Here it validates the user input and make usre it doesn't contain any sql expression that may cause some sort of an injection.</p>
    <a href='/secure/user/2'>http://localhost:3000/secure/user/2</a>
    <p>However, it wouldn't care if there is an sql injection such as getting an input i.e 1 OR 1 = 1. Normaly this will work and should return all users. <br><code>SQL VALID STATEMENT will return true: SELECT * FROM users WHERE id = 1 OR 1 = 1</code> We should be worried about this kind of input.</p>
    <p>Since we managed to implement a secure way to get user input we shouldn't worry about this, on this secure url.</p>
    <a href='/secure/user/1%20OR%201=1'>http://localhost:3000/secure/user/1%20OR%201=1</a><span>Trying to sql inject. But fails.</span>
    <hr>
    <p>We will use the insecure url to show that it normally works fine on this url </p>
    <a href='/insecure/user/2'>http://localhost:3000/insecure/user/2</a>
    <p>Here we will show you how the same sql injection we did on the secure url, but now we will do it on an insecure url</p>
    <a href='/insecure/user/1%20OR%201=1'>http://localhost:3000/insecure/user/1%20OR%201=1</a><span>This sql inject successfully, because of how we implemented it, which disregard the input validation.</span>
    <hr>
    `)
})

/////LINKS TO TEST///// Insecure route for non helmet.
//http:localhost:3000/insecure?name=leen&lastname=bajunaid
//http://localhost:3000/insecure?name=<script>alert("goo")</script>&lastname=<script>alert("hello")</script>
app.get('/insecure', function(req, res) { //this is a get request
    let username = req.query.name
    let lastname = req.query.lastname
    res.send("Hi from not secure request " + username + " LastName: " + lastname)
})


//Solution 1 Santization using DOMPurify
////LINSK TO TEST/////
//http://localhost:3000/secure?name=<script>alert("goo")</script>&lastname=<script>alert("hello")</script>
app.get('/secure', function(req, res) {
    let username = req.query.name
    res.send("Hi from secure request " + DOMPurify.sanitize(username))
})




/**
 * SQL Injection is a different type of attack where maalicious SQL statements are inserted into input fields.
 * To protect against SQL injection, you should use parameterized queries or prepared statements when interacting
 * With database.
 */


//Connect to database
const db = new sqlite3.Database(':memory:')

//Create user table
db.serialize(function() {
    db.run('CREATE TABLE users (id INT, name TEXT)')
    const insert = db.prepare('INSERT INTO users VALUES (?,?)')
    insert.run(1, 'LEEN ALI')
    insert.run(2, 'REEM')
    insert.run(3, 'SADEEM')
    insert.run(4, 'LYAN')
    insert.finalize()
})


//List users // Pretend that you are admin
////LINKS/////
//http://localhost:3000/secure/users
app.get('/secure/users', function(req, res) {
    db.all('SELECT * from users', function(err, rows) {
        if(err) {
            return res.status(500).json({error: err.message})
        }
        res.json({users: rows})
    })
})

//route to fetch data from database for a sepcific user by id
///LINKS///
//http://localhost:3000/secure/user/2
app.get('/secure/user/:id', function(req, res) {
    const userId = req.params.i
    //This db.get does not uses userId without validation.
    db.get('SELECT * FROM users WHERE id = ?', [userId], function(err, row) {
        if(err) {
            return res.status(500).json({error: err.message})
        }
        if(!row) {
            return res.status(404).json({error: 'User not found'})
        }
        res.json({user: row})
    })
})

//insecure access to one of the users, passing a true sql statement as an id
// http://localhost:3000/insecure/user/1%20OR%201=1
app.get('/insecure/user/:id', function(req, res) {
    const userId = req.params.id

    const sql = "SELECT * FROM users WHERE id = " + userId //Concactation
    //SELECT * FROM users WHERE id = 1 OR 1 = 1

    db.all(sql, function(err, rows){
        if(err) {
            return res.status(500).json({error: err.message})
        }
        res.json({users: rows})
    })
})

app.listen(3000, function() { //here it runs the server on a specific port number.
    console.log('Server is running at http://localhost:'+ 3000)
})