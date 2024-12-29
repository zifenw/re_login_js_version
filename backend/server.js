const express = require("express"); 
const mysql = require("mysql");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const cors = require("cors");

const app = express();
app.use(bodyParser.json());
app.use(cors());

// MySQL数据库连接
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "root",
    database: "lo_db",
});

db.connect((err) => {
    if (err) {
        console.error("Database connection failed:", err.stack);
        return;
    }
    console.log("Connected to database.");
});

// 登录处理
app.post("/login", (req, res) => {
    const { name, pass } = req.body;
    const query = "SELECT pass_hash FROM tuser WHERE name = ?";
    db.query(query, [name], (err, result) => {
        if (err) return res.status(500).send("Database error");
        if (result.length === 0) return res.status(400).send("Username not exist");

        const hash = result[0].pass_hash;
        bcrypt.compare(pass, hash, (err, isMatch) => {
            if (err) return res.status(500).send("Error verifying password");
            if (isMatch) {
                res.status(200).send({ message: "Login successful", username: name });
            } else {
                res.status(400).send("Password error");
            }
        });
    });
});

// 注册处理
app.post("/register", (req, res) => {
    const { name, email, pass } = req.body;
    const queryCheck = "SELECT * FROM tuser WHERE name = ?";
    db.query(queryCheck, [name], (err, result) => {
        if (err) return res.status(500).send("Database error");
        if (result.length > 0) return res.status(400).send("Username already exists");

        if (pass.length < 6) return res.status(400).send("Password must be at least 6 characters");

        bcrypt.hash(pass, 10, (err, hash) => {
            if (err) return res.status(500).send("Error hashing password");

            const queryInsert = "INSERT INTO tuser (name, email, pass_hash) VALUES (?, ?, ?)";
            db.query(queryInsert, [name, email, hash], (err, result) => {
                if (err) return res.status(500).send("Error saving user");
                res.status(200).send("Registration successful");
            });
        });
    });
});

// 动态 HTML 页面生成
app.get("/user", (req, res) => {
    const uname = req.query.uname;
    if (!uname) return res.status(400).send("Missing 'uname' query parameter");

    const query = "SELECT * FROM tuser WHERE name = ?";
    db.query(query, [uname], (err, result) => {
        if (err) return res.status(500).send("Database error");
        if (result.length === 0) return res.status(404).send("User not found");

        const user = result[0];
        const html = `
            <html> 
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>User Info</title>
                    <style>
                        *{
                            padding: 0;
                            margin: 0;
                        }
                        body{
                            width: 100vw;
                            height: 100vh;
                            background-image: url(./image/4.png);
                            background-size: cover;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            color: white;
                        }
                    </style>
                </head>
                <body>
                    <h1>Hi <span style="color:red;">${user.name}</span>,</h1>
                    <p>Your email is: <span style="color:yellow;">${user.email}</span></p>
                    <a href="./index.html" style="color:cyan;">BACK</a>
                </body>
            </html>
        `;
        res.send(html);
    });
});

app.listen(3000, () => {
    console.log("Server is running on port 3000");
});
