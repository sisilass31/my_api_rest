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

// fonction qui génère le token:
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
            db.query('insert into user set?', new_user, (error, result) => {
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
// notre serveur sera sur le port 3306:
const port =  process.env.PORT || 3306;

app.listen(port, () => {
    console.log(`Notre application est démarrrée sur : http://localhost:${port}`)
})