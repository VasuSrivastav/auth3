import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import dotenv from 'dotenv';
import session from 'express-session';
import passport from "passport";
import { Strategy } from "passport-local";

dotenv.config();


const app = express();
const port = 3000;
const saltRounds = 10;

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    cookie:{maxAge: 1000*60*60*24},
  })
);


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));


app.use(passport.initialize());
app.use(passport.session());



const config = { 

  user: process.env.USER,
  password: process.env.PASSWORD,
  host: process.env.HOST,
  // port: process.env.PORT,
  port: 21471,
  database: process.env.DATABASE,
  ssl: {
      rejectUnauthorized: true,
      // ca: fs.readFileSync('./ca.pem').toString(),
      ca: process.env.CA,
  },
};
const db = new pg.Client(config);
db.connect();
// const db = new pg.Client({
//   user: "postgres",
//   host: "localhost",
//   database: "secrets",
//   password: "123456",
//   port: 5432,
// });
// db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", (req, res) => {
  // console.log(req.user);
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

// app.post("/login", passport.authenticate("local", {
//   successRedirect: "/secrets",
//   failureRedirect: "/login",

// }))
app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.render("extra.ejs", { errmessage: "Wrong password or username" });
    }
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      return res.redirect("/secrets");
    });
  })(req, res, next);
});



app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM userbt WHERE email = $1", [
      email,
    ]);
    if (checkResult.rows.length > 0) {
      // res.send("Email already exists. Try logging in.");
      res.render("extra.ejs",{errmessage:"Email already exists. Try logging in."});
    } else {
      // const hashedPassword = await bcrypt.hash(password, saltRounds);
      bcrypt.hash(password, saltRounds, async function(err, hash) {
        if (err) {
          console.log("not register error:",err);
        }
        else {
          const result = await db.query(
            "INSERT INTO userbt (email, password) VALUES ($1, $2) RETURNING * ;",
            [email, hash]
          );
          // console.log(result.rows);
          // res.render("secrets.ejs");
          // res.send("Registered now logging in.");

          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });

          // better i think
          // res.render("extra.ejs",{errmessage:"Registered, now logging in."});
        }
      }
      );


    }
  } catch (err) {
    console.log(err);
    
  // res.redirect("/");
  res.render("extra.ejs",{errmessage:"error Occur retry."});

  }

//     if (checkResult.rows.length > 0) {
//       res.send("Email already exists. Try logging in.");
//     } else {
//       //hashing the password and saving it in the database
//       bcrypt.hash(password, saltRounds, async (err, hash) => {
//         if (err) {
//           console.error("Error hashing password:", err);
//         } else {
//           console.log("Hashed Password:", hash);
//           await db.query(
//             "INSERT INTO users (email, password) VALUES ($1, $2)",
//             [email, hash]
//           );
//           res.render("secrets.ejs");
//         }
//       });
//     }
//   } catch (err) {
//     console.log(err);
//   }
});

// app.post("/login", async (req, res) => {
//   const email = req.body.username;
//   const loginPassword = req.body.password;
passport.use(
  // here username and password are the names of the input fields in the login form that here passed as arguments
  new Strategy(async function verify(username, password, cb) {
  try {
    const result = await db.query("SELECT * FROM userbt WHERE email = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(password, storedHashedPassword, (err, result) => {
        if (err) {
          console.error("Error comparing passwords:", err);
          return cb(err);

        } else {
          if (result) {
            // res.render("secrets.ejs");
            return cb(null, user);
          } else {
            // res.send("Incorrect Password");
            // return cb(null, false , {errmessage: "Incorrect Password"});
            return cb(null, false);
            // res.render("extra.ejs",{errmessage:"Incorrect Password"});

          }
        }
      });
    } else {
      // res.send("User not found");
      // res.render("extra.ejs",{errmessage:"User not found"});
      return cb(null, false);


    }
  } catch (err) {
    console.log(err);
    res.render("extra.ejs",{errmessage:"error Occur retry."});

  }
})
);

passport.serializeUser((user, cb)=>{
  cb(null, user);
}
);
passport.deserializeUser((user, cb)=>{
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
