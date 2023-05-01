require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");

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


userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });     //documentation of mongoose-encrypt

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
    const newUser = new User({
        email: req.body.username,
        password: req.body.password
    });
    newUser.save()                //encryption will encrypt when save and decrypt when find
    .then(function(){
        console.log("successfully registered");
        res.render("secrets");
    })
    .catch(function(err){
        console.log(err);
    })
});

app.post("/login", function(req,res){
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({email: username})
    .then(function(foundUser){
        if(foundUser){
            if(foundUser.password === password){
                res.render("secrets");
            }
        }
    })
    .catch(function(err){
        console.log(err);
    })
});

app.listen(3000,function(){
    console.log("Successfully started on port 3000");
})