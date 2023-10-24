// creates endpoint for registered users to log in.
// Authenticates login request via basic HTTP authentication and generate JWT for user

const passport = require("passport");
require("./passport"); // Your local passport.js file

/* POST login. */
module.exports = (router) => {
  router.post("/login", (req, res) => {
    passport.authenticate("local", { session: false }, (error, user, info) => {
      if (error || !user) {
        return res.status(400).json({
          message: "Something is not right",
          user: user,
        });
      }
      req.login(user, { session: false }, (error) => {
        if (error) {
          res.send(error);
        }
        return res.json({ user });
      });
    })(req, res);
  });
};
