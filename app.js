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
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require("express-session");  //cookies, using passport
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
var GoogleStrategy = require('passport-google-oauth20').Strategy;  //for google auth option
const findOrCreate = require("mongoose-findorcreate");

//console.log(process.env.SECRET);



const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({          //for cookies
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://0.0.0.0:27017/userDB", {useNewUrlParser: true});   //   ... to host locally


const userSchema = new mongoose.Schema({        //obj created frm mongoose schema class for encryption
    email: String,
    password: String,
    googleId: String,
    secret: String
});

//this is low level encryption, use md5(hash) instead
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });     //documentation of mongoose-encrypt, using .env file

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());


//FOR COOKIES n PASSPORT
// passport.serializeUser(User.serializeUser());    //serialize means to create cookie
// passport.deserializeUser(User.deserializeUser());  //deserialize means to destroy cookie and reveal the previous session mssg

//FOR COOKIES PASSPORT GOOGLE AUTH
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
});
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
});

passport.use(new GoogleStrategy({         //for google auth, code from passport docs
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",   //just cuz google+ got deprecated
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req,res){
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", {scope: ["profile"]}, { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/");
});

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

app.get("/login", function(req,res){
    res.render("login");
});

app.get("/register", function(req,res){
    res.render("register");
});

app.get("/secrets", function(req,res){
    // //if the user has authenticated/registered/login, then only access the /secrets route, else u cant
    // if(req.isAuthenticated()){
    //     res.render("secrets");
    // }
    // else{
    //     res.redirect("/login");
    // }

    //to display all secrets 
    User.find({"secret": {$ne: null}})     //if secrets domain is not equal to null
    .then(function(foundUsers){
        if(foundUsers){
            res.render("secrets", {usersWithSecrets: foundUsers})
            //console.log(foundUsers);
        }
    })
    .catch(function(err){
        console.log(err);
    })
});

app.get("/submit", function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
})

app.get("/logout",function(req,res){
    req.logOut(function(err){      //passport still needs callback func
        if(err){                   //destroys the cookie, cant access /secrets anymore without login
            console.log(err);
        }
    });
    res.redirect("/");
});

app.post("/register", function(req,res){
    //USING PASSPORT for COOKIES
    User.register({username: req.body.username}, req.body.password)
    .then(function(user){
        passport.authenticate("local")(req,res,function(){
            res.redirect("/secrets");
        })
    })
    .catch(function(err){
        console.log(err);
    })

    //FOR BCRYPT HASH
    // bcrypt.hash(req.body.password, saltRounds) 
    // .then(function(hash){                 //if above bcrypt fetches the data, then only run this
    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash                //md5(req.body.password) if md5 module used
    //     });
    //     newUser.save()                //encryption will encrypt when save and decrypt when find
    //     .then(function(){
    //         console.log("successfully registered");
    //         res.render("secrets");
    //     })
    //     .catch(function(err){
    //         console.log(err);
    //     })
    // })
    // .catch(function(err){
    //     console.log(err);
    // })
});

app.post("/login", function(req,res){
    //FOR PASSPORT AND COOOKIES
    const user = new User({
        username : req.body.username,
        password : req.body.password
    });

    req.login(user,function(err){        //this is a callback function, not using .then.catch(async await)
        if (err) { 
            console.log(err);
            res.redirect("/login");
        } 
        else {
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            })
          
        }
    })
    //FOR BCRYPT HASH
    // const username = req.body.username;
    // const password = req.body.password;        //md5(req.body.password) if md5 used

    // User.findOne({email: username})
    // .then(function(foundUser){
    //     bcrypt.compare(req.body.password, foundUser.password)
    //     .then(function(result){
    //         if(result == true){
    //             res.render("secrets");
    //         }
    //     })
    // })
    // .catch(function(err){
    //     console.log(err);
    // })
});

app.post("/submit", function(req,res){
    const submittedSecret = req.body.secret;
    //console.log(req.user);   //shows the details of login
    User.findById(req.user.id)       
    .then(function(foundUser){
        if(foundUser){
            foundUser.secret = submittedSecret;
            foundUser.save()
            .then(function(){
                res.redirect("/secrets");
                console.log("saved")
            })
            .catch(function(err){
                console.log(err);
            })
        }
    })
    .catch(function(err){
        console.log(err);
    })
});

app.listen(3000,function(){
    console.log("Successfully started on port 3000");
})