## Demonstration how the web application firewall works.

### What we have implemented to to make this works on our website.
- express | to use a server for demostration.
- helmet | to make sure the website does not execute any scripts or styles outside of the domain name. Prevent corss-site scripting.
- DOMPurify, JSDOM | Both are required to also prevent scripts entered in from users to the browser. Sanatize User Input. This is similar to the main goal to helmet.
- sqlite3 | Used to demonstrate sql injection and how to prevent sql injections.

#### Solution 1 helmet (prevent scripts injection)
Direction to use content security policy. Preventing users to execute any scripts or import any styles.
It helps secure Express apps by setting HTTP response headers.
Link: github.com/helmetjs/helmet

Try commenting the following code and uncommenting to see how it prevents these attacks.

```
...
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"]
    },
}))
...
```
Test URLs
```

http:localhost:3000/insecure?name=leen&lastname=bajunaid
http://localhost:3000/insecure?name=<script>alert("goo")</script>&lastname=<script>alert("hello")</script>

```
We are using inseure paths just to show that it wouldn't matter if there was an injection, helmet will still be able to prevent it from executing.

#### Solution 2 DOMPurify to sanatize input (prevent script injection)
> Requirements before using DOMPurify library.
> The URLs to test DOMPurify is the one that used in a different path /secure/
```
const {JSDOM } = require('jsdom')
const {window } = new JSDOM('') //Required for domppurify
const DOMPurify = require('dompurify')(window) // This will sanitize user generated content
```

Test URLs
```

http:localhost:3000/insecure?name=leen&lastname=bajunaid
http://localhost:3000/secure?name=<script>alert("goo")</script>&lastname=<script>alert("hello")</script>

```
This URL wouldn't execute the script because its using DOMPurify.sanitize(user_input)


### SQL and SQL injection
> We need to import required libraries.
```
const sqlite3 = require('sqlite3').verbose(); // For implementing sql and show how to do an sql injection and how to prevent it.
```
We need to setup database and create our test table.
```
 
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
```

> **NOTE:** In a secure way we have a special path that will let any user to access or display all registered users. Let us assume that only admin users can access it. 

```
http://localhost:3000/secure/users
```

#### Access specific user. Can be done by anyone. 
> !IMPORTANT But through these urls, we shouldn't be able to access all users.

```
http://localhost:3000/secure/user/2
http://localhost:3000/secure/user/1%20OR%201=1 //This url wouldn't work because of the way the function is implemented.
```

We can display single user using the url shown above, this will display a user with id number 2. The code that was implemented was also preventing sql injection attack. Here is a samlpe of the code.

```
app.get('/secure/user/:id', function(req, res) {
    const userId = req.params.id
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
```

This way we make sure input data are specified and does not contain any invalid charactors.

#### Access specific user. Can be done by anyone. 
> !IMPORTANT But is weak and anyone can do an SQL injection.
```
http://localhost:3000/insecure/user/2 //Will display only 1 user.
http://localhost:3000/insecure/user/1%20OR%201=1 //This url will work because of the way the function is implemented. It will display all users.

WE ARE USING
1 OR 1=1
```
Example the following sql command should return everything on that table.
```SELECT * FROM users WHERE id = 1 OR 1 = 1```


An attacker might inject this into a parameterized query or a user input field, exploiting the lack of proper input validation or parameterization.
The 1 = 1 part is a tautology (always true), so the entire WHERE clause becomes true for every row.

The purpose of this attack is to manipulate the logic of the SQL query to bypass authentication or retrieve unauthorized data.
By injecting OR 1=1, the attacker is essentially saying, "Return all rows where either the given condition is true or 1 is always equal to 1 (which is always true)."
This type of attack is possible when user inputs are not properly validated or sanitized, allowing malicious users to inject arbitrary SQL code.


preventing 
a8lways use parameterized queries or prepared statements to prevent SQL injection. 


Because of the way that the methods was implemented. 

```
app.get('/insecure/user/:id', function(req, res) {
    const userId = req.params.id

    const sql = "SELECT * FROM users WHERE id = " + userId
    db.all(sql, function(err, rows){
        if(err) {
            return res.status(500).json({error: err.message})
        }
        res.json({users: rows})
    })
})
```
It does not validate or check user input.