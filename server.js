//======      requiring  =======
if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}
const express = require("express");
const app = express();

const bcrypt = require("bcrypt");
const passport = require("passport");

const flash = require("express-flash");
const session = require("express-session");
const methodOverride = require("method-override");

//const methodOverride = require("method-override");
//====== initialize Users =======
const users = [];

//======initializePassport=======
const initializePassport = require("./passport-config");
initializePassport(
  passport,
  (email) => users.find((user) => user.email == email),
  (id) => users.find((user) => user.id === id)
);

//============="ejs"==============
app.set("view-engine", "ejs");

//========="midel wares"==========
//const bodyParser = require("body-parser");
//app.use(express.urlencoded({ extended: false }));
app.use(express.json()); // for parsing application/json
app.use(express.urlencoded({ extended: false })); // for parsing
app.use(flash());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride("_method"));
//============="/"=================
app.get("/", checkAuthenticated, (req, res) => {
  res.render("index.ejs", { name: req.user.name });
});

//=============login===============
app.get("/login", checkNotAuthenticated, (req, res) => {
  res.render("login.ejs");
});

app.post(
  "/login",
  checkNotAuthenticated,
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

//============register==============
app.get("/register", checkNotAuthenticated, (req, res) => {
  res.render("register.ejs", { name: "--" });
});

app.post(
  "/register",
  CheckPasswordStrength,
  checkNotAuthenticated,
  checkNotRegistred,
  async (req, res) => {
    try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      users.push({
        id: Date.now().toString(),
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword,
      });
      res.redirect("/login");
    } catch {
      res.redirect("/register");
    }
    console.log(users);
  }
);
//=============logOut===============
app.delete("/logout", (req, res) => {
  req.logOut();
  res.redirect("/login");
});
//============checkPoints or not============
function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  next();
}
function checkNotRegistred(req, res, next) {
  let registred = users.find(
    (user) => user.email == req.body.email || user.name == req.body.name
  );

  if (registred) {
    console.log("is registred");
    return res.redirect("/register");
  }
  console.log("registring");
  next();
}

function CheckPasswordStrength(req, res, next) {
  var passw = new RegExp(
    "^(((?=.*[a-z])(?=.*[A-Z]))|((?=.*[a-z])(?=.*[0-9]))|((?=.*[A-Z])(?=.*[0-9])))(?=.{6,})"
  );

  if (req.body.password.match(passw)) {
    console.log("good password...");
    next();
    return;
  } else {
    console.log("weak password...!");
    return res.redirect("/register");
  }
}
/*
RegEx	Description
^	The password string will start this way
(?=.*[a-z])	The string must contain at least 1 lowercase alphabetical character
(?=.*[A-Z])	The string must contain at least 1 uppercase alphabetical character
(?=.*[0-9])	The string must contain at least 1 numeric character
(?=.*[!@#$%^&*])	The string must contain at least one special character, but we are escaping reserved RegEx characters to avoid conflict
(?=.{8,})	The string must be eight characters or longer
*/
//================listening========================
app.listen(3000);
console.log("listning_..._");
