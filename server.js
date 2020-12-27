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
//============checkAuthenticated or not============
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

  var stregth = CheckPassword(req.body.password);
  if (registred || stregth) {
    console.log("is registred");
    return res.redirect("/register");
  }
  console.log("registring");
  next();
}

function CheckPassword(inputtxt) {
  var passw = /^[A-Za-z]\w{7,14}$/;

  if (inputtxt.match(passw)) {
    console.log("good password...");
    return false;
  } else {
    console.log("weak password...!");
    return true;
  }
}

//================listening========================
app.listen(3000);
console.log("listning_..._");
