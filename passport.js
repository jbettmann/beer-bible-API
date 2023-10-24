const passport = require("passport"),
  LocalStrategy = require("passport-local").Strategy,
  Models = require("./models.js"),
  passportJWT = require("passport-jwt");

let Users = Models.User,
  JWTStrategy = passportJWT.Strategy,
  ExtractJWT = passportJWT.ExtractJwt;

// HTTP Authentication. Takes email and password from request body and uses Mongoose to check database
passport.use(
  new LocalStrategy(
    {
      emailField: "email",
      passwordField: "password", // password doesnt not get check here.
      // if match, callback is executed. This is login endpoint
    },
    (email, password, callback) => {
      console.log(email + "  " + password);
      Users.findOne({ email: email }, (error, user) => {
        // if error occures
        if (error) {
          console.log(error);
          return callback(error);
        }
        // in no user is found, message passed to callback.
        if (!user) {
          console.log("incorrect email");
          return callback(null, false, {
            message: "Incorrect email or password.",
          });
        }
        // Hashes password enterd when logging in before comparing to password in database
        if (!user.validatePassword(password)) {
          console.log("incorrect password");
          return callback(null, false, { message: "Incorrect password." });
        }
        console.log("finished");
        return callback(null, user);
      });
    }
  )
);

// Authenticates users on JWT summited alongside request
passport.use(
  new JWTStrategy(
    {
      // Extracts JWT from header of HTTP request.
      jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
      // Verifies singature of JWT. Client is who it says it is.
      secretOrKey: process.env.PASSPORT_SECRET,
    },
    (jwtPayload, callback) => {
      return Users.findById(jwtPayload._id)
        .then((user) => {
          return callback(null, user);
        })
        .catch((error) => {
          return callback(error);
        });
    }
  )
);
