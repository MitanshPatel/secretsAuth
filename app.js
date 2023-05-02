//git cmds
//git init
//git status
//git add .
//git commit -m ""
//git remote add origin https://github.com/MitanshPatel/secretsAuth.git
//git push -u origin master

require('dotenv').config()     //to create .env file and save api keys and not get declared in github
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
//const md5 = require("md5");        //bcrypt is better for security
const bcrypt = require("bcrypt");
const saltRounds = 10;

//console.log(process.env.SECRET);

mongoose.connect("mongodb://0.0.0.0:27017/userDB", {useNewUrlParser: true});   //   ... to host locally
const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

const userSchema = new mongoose.Schema({        //obj created frm mongoose schema class for encryption
    email: String,
    password: String
});

//this is low level encryption, use md5(hash) instead
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });     //documentation of mongoose-encrypt

const User = new mongoose.model("User", userSchema);

app.get("/", function(req,res){
    res.render("home");
});

app.get("/login", function(req,res){
    res.render("login");
});

app.get("/register", function(req,res){
    res.render("register");
});

app.post("/register", function(req,res){

    bcrypt.hash(req.body.password, saltRounds) 
    .then(function(hash){                 //if above bcrypt fetches the data, then only run this
        const newUser = new User({
            email: req.body.username,
            password: hash                //md5(req.body.password) if md5 module used
        });
        newUser.save()                //encryption will encrypt when save and decrypt when find
        .then(function(){
            console.log("successfully registered");
            res.render("secrets");
        })
        .catch(function(err){
            console.log(err);
        })
    })
    .catch(function(err){
        console.log(err);
    })
});

app.post("/login", function(req,res){
    const username = req.body.username;
    const password = req.body.password;        //md5(req.body.password) if md5 used

    User.findOne({email: username})
    .then(function(foundUser){
        bcrypt.compare(req.body.password, foundUser.password)
        .then(function(result){
            if(result == true){
                res.render("secrets");
            }
        })
    })
    .catch(function(err){
        console.log(err);
    })
});

app.listen(3000,function(){
    console.log("Successfully started on port 3000");
})