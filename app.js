// importation 
const express = require('express');
const mysql = require('mysql');
const dotenv = require ('dotenv');
const bcrypt = require('bcryptjs'); // pour crypter les mdp
const jwt = require('jsonwebtoken')

dotenv.config({ path: './.env' });

const app = express();

// connection avc la 
const db = mysql.createConnection({
    host: process.env.database_host,
    user: process.env.database_user,
    password: process.env.database_password,
    database: process.env.DATABASE,
    port: process.env.port    
})

db.connect((error) => {
    if(error) {
        console.log(error);
    } else {
        console.log("my sql connected...");
    }
})

app.use(express.json())

// fonction qui génère/créer le token:
function generate_token(user) {
    const payload = {
        id: user.id,
        email: user.email,
        role: user.role
    }
    const options = {
        expiresIn: process.env.jwt_expires_in
    }
    // jwt.sign = créer le token
    return jwt.sign(payload, process.env.jwt_secret, options)
}

// next = envoie le token à la prochaine étape
function verify_token(req, res, next){
    const token = req.headers.authorization
    if (!token){
        return res.status(401).json({ error: 'access denied. token missing.'})
    }
    jwt.verify(token, process.env.jwt_secret, (error, decoded) => {
        if (error){
            return res.status(401).json({ error: 'invalid token.' })
        }
            req.user = decoded
            next()
    })
}

/* fonction permettant le créer un utilisateur:
--> créer une nouvelle page*/
app.post('/user', (req, res) => {
    const {name, password, role, email} = req.body
    bcrypt.hash(password, 10, (error, hashedPassword) => {
        if(error) {
            console.log(error)
            res.status(500).json({ error: 'operation failed' })
        } else {
            const new_user = { name, password: hashedPassword, role, email }
            db.query('INSERT INTO users SET ?', new_user, (error, result) => {
                if(error) {
                    console.log(error)
                    res.status(500).json({ error: 'operation failed' })
                } else {
                    const user = { id: result.insertId, ...new_user }
                    const token = generate_token(user)
                    res.status(201).json({
                        message: 'user created successfully',
                        token: token,
                    })
                }
            })
        }
    })
})

// login 
app.post('/login', (req, res) => {
    const {email, password} = req.body;
    db.query('SELECT * FROM users WHERE email = ?', email, (error, result) => {
        if(error){
            console.log(error);
            res.status(500).json({error: 'failed to login'})
        } else if(result.length === 0){
            res.status(401).json({ error: 'invalid email or password' })
        } else {
            const user = result[0]
            bcrypt.compare(password, user.password, (error, isMatch) => {
                if(error){
                    console.log(error)
                    res.status(500).json({ error: 'failed to login' })
                } else if(isMatch){
                    const token = generate_token(user)
                    res.status(200).json({
                        message: 'login sucessfull',
                        token: token,
                    })
                } else {
                    res.status(401).json({ error: 'invalid email or password' })
                }
            })
        }
    }) 
})

// récupérer tous les users
app.get('/users', (req, res) => {
    db.query('SELECT * FROM users', (error, results) => {
        if(error){
            console.log(error);
            res.status(500).json({ error: 'failed to receive users'});
        } else {
            res.status(200).json(results)
        }
    })
})

// récupérer un seul user
app.get('/user/:id', (req, res) => {
    const user_id = req.params.id
    console.log(user_id);
    db.query('SELECT * FROM users WHERE id = ?', user_id, (error, results) => {
        if(error){
            console.log(error);
            res.status(500).json({ error: 'failed to receive the user'})
        } else if (results.length === 0){
            res.status(404).json({ error: 'user not found'});
        } else {
            res.status(200).json(results[0]);
        }
    })
})

// update 
app.put('/user/:id', (req, res) => {
    const user_id = req.params.id
    const { name, password, role, email} = req.body;
    const update_user = { name, password, role, email }
    db.query(
        'UPDATE users SET ? WHERE id = ?',
        [update_user, user_id],
        (error, result) => {
            if(error){
                console.log(error);
                res.status(500).json({ error: 'failed to update the user'})
            } else if (result.affedctedRows === 0) {
                res.status(404).json({ error: 'user not found'});
            } else {
                res.status(200).json({ message: 'user updated successfully'})
            }
        }
    )
})

// delete 
app.delete('/user/:id', (req, res) => {
    const user_id = req.params.id
    db.query(
        'DELETE FROM users WHERE id = ?', user_id, (error, result) => {
            if(error){
                console.log(error);
                res.status(500).json({ error: 'failed to delete the user'})
            } else if (result.affedctedRows === 0) {
                res.status(404).json({ error: 'user not found'});
            } else {
                res.status(200).json({ message: 'user deleted successfully'})
            }
        }
    )
})

// notre serveur sera sur le port 3306:
const port =  process.env.PORT || 3306;
app.listen(port, () => {
    console.log(`Notre application est démarrrée sur : http://localhost:${port}`)
})