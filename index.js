const express = require("express"),
  bodyParser = require("body-parser"), // middleware for req body parsing
  uuid = require("uuid"), //Universally Unique Identifier. Generate a unique ID
  morgan = require("morgan"),
  mongoose = require("mongoose"), // Intergrates mongoose into file
  Models = require("./models.js"), // allows access to database schema
  cors = require("cors"); // Cross-Orgin Resourse Sharing

const { check, validationResult } = require("express-validator");

// Refer to models named in models.js
const Users = Models.User;
const Beers = Models.Beer;
const Breweries = Models.Brewery;
const Categories = Models.Category;

const Movies = Models.Movie;

// allows Mongoose to conncect to database to perform CRUD operations on doc
mongoose.connect(
  process.env.CONNECTION_URI || "mongodb://localhost:27017/BeerBibleDB",
  { useNewUrlParser: true, useUnifiedTopology: true }
);

const app = express();

// List of allowed domains
let allowedOrigins = [
  "http://localhost:8080",
  "http://testsite.com",
  "http://localhost:1234",
  "http://localhost:4200",
  "https://bettsmyflix.netlify.app",
  "https://jbettmann.github.io",
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      // If a specific origin isn't found on the list of allowed origins
      if (allowedOrigins.indexOf(origin) === -1) {
        let message = `The CORS policy for this application doesn't all access from origin ${origin}`;
        return callback(new Error(message), false);
      }
      return callback(null, true);
    },
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

let auth = require("./auth")(app); // (app) ensures Express is available in auth.js file
const passport = require("passport");
require("./passport");

/**
 * Logs basic request data in terminal using Morgan middleware library
 */
app.use(morgan("common"));

// sends static html page documentation.html
app.use(express.static("public"));

// sends response below to homepage
app.get("/", (req, res) => {
  res.send(`myFlix. All the greats, in one place!`);
});

let handleError = (err) => {
  console.error(err);
  console.log(err);
  res.status(500).send(`Error: ${err}`);
};

// ************************** BeerBible API ************************************************

/**
 * POST: Creates new user; Username, Password & Email are required fields!
 * Request body: Bearer token, JSON with user information
 * @returns user object
 */
app.post(
  "/users",
  [
    // Validation logic
    //minimum value of 5 characters are only allowed
    check("username", "Username is required").isLength({ min: 5 }),

    // field can only contain letters and numbers
    check(
      "username",
      "Username contains non alphanumeric characters - not allowed."
    ).isAlphanumeric(),

    // Chain of methods like .not().isEmpty() which means "opposite of isEmpty" or "is not empty"
    check("password", "Password is required").not().isEmpty(),

    // field must be formatted as an email address
    check("email", "Email does not appear to be valid").isEmail(),
  ],
  (req, res) => {
    // check the validation object for errors
    let errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }
    let hashedPassword = Users.hashPassword(req.body.password);
    // check if user already exists
    Users.findOne({ email: req.body.email })
      .then((user) => {
        // returns if user exists
        if (user) {
          return res
            .status(400)
            .send(`An account with ${req.body.email} already exists`);
          // creates and returns if user DOES NOT exist
        } else {
          Users.create({
            fullName: req.body.fullName,
            // .create takes and object based on schema
            username: req.body.username, // remember 'req.body' is request that user sends
            password: hashedPassword, // Hashes password entered  when registering before storing in MongoDB
            email: req.body.email,
            breweries: [],
          })
            .then((user) => {
              res.status(201).json(user);
            })
            .catch(handleError);
        }
      })
      .catch(handleError);
  }
);

/**
 * POST: Creates new beer; Name & Style are required fields!
 * Request body: Bearer token, JSON with user information
 * @returns beer object
 */
app.post(
  "/:user/:brewery/beers",
  [
    // passport.authenticate("jwt", { session: false }),
    // Validation logic
    //minimum value of 1 characters are only allowed
    check("name", "Beer name is required").isLength({ min: 1 }),

    // field can only contain letters and numbers
    check("style", "Style of beer is required").isLength({ min: 1 }),
  ],
  async (req, res) => {
    // check the validation object for errors
    let errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }

    try {
      const user = await Users.findById(req.params.user);
      if (!user) {
        return res.status(400).send("User not found");
      }

      const brewery = await Breweries.findOne({
        _id: req.params.brewery,
        $or: [{ staff: { $in: [user._id] } }, { owner: user._id }],
      });

      if (!brewery) {
        return res.status(400).send("User is not an admin or owner");
      }

      const beer = new Beers({
        name: req.body.name,
        style: req.body.style,
        abv: req.body.abv,
        category: req.body.category,
        malt: req.body.malt,
        hops: req.body.hops,
        flavorNotes: req.body.flavorNotes,
        aroma: req.body.aroma,
        nameSake: req.body.nameSake,
        notes: req.body.notes,
      });

      /* using save() instead of create() allows us 
      to check if the beer document is valid 
      before saving to database 
      */
      await beer.validate();
      const savedBeer = await beer.save();

      if (savedBeer) {
        brewery.beers.push(savedBeer._id);
        await brewery.save();
        res.status(201).json({ savedBeer });
      } else {
        throw new Error("Beer save operation failed");
      }
    } catch (error) {
      handleError(error);
    }
  }
);

// GET REQUEST ******************

/**
 * GET: Returns a list of ALL users
 * Request body: Bearer token
 * @returns array of user objects
 * @requires passport
 */
app.get(
  "/users",
  // passport.authenticate("jwt", { session: false }),
  (req, res) => {
    Users.find() // .find() grabs data on all documents in collection
      .then((users) => {
        res.status(201).json(users);
      })
      .catch(handleError);
  }
);

/**
 * GET: Returns a list of ALL breweries
 * Request body: Bearer token
 * @returns array of brewery objects
 * @requires passport
 */
app.get(
  "/breweries",
  // passport.authenticate("jwt", { session: false }),
  (req, res) => {
    Breweries.find() // .find() grabs data on all documents in collection
      .then((brewery) => {
        res.status(201).json(brewery);
      })
      .catch(handleError);
  }
);

// ************************** myFlix Movie API ************************************************

/**
 * GET: Returns a list of ALL movies to the user
 * Request body: Bearer token
 * @returns array of movie objects
 * @requires passport
 */
app.get(
  "/movies",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    Movies.find() // .find() grabs data on all documents in collection
      .then((movies) => {
        res.status(201).json(movies);
      })
      .catch(handleError);
  }
);

/**
 * GET: Returns data (description, genre, director, image URL, whether it’s featured or not) about a single movie by title to the user
 * Request body: Bearer token
 * @param title (title of movie)
 * @returns movie object
 * @requires passport
 */
app.get(
  "/movies/:title",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    // condition to find specific user based on Username (similar to WHERE in SQL)
    Movies.findOne({ Title: req.params.title })
      .then((title) => {
        res.json(title);
      })
      .catch(handleError);
  }
);

/**
 * GET: Returns data about a genre (description) by name/title (e.g., “Fantasy”)
 * Request body: Bearer token
 * @param genre (name of genre)
 * @returns genre object
 * @requires passport
 */
app.get(
  "/movies/genres/:genre",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    // condition to find specific user based on Username (similar to WHERE in SQL)
    Movies.findOne({ "Genre.Name": req.params.genre })
      .then((movie) => {
        res.json(movie.Genre.Description);
      })
      .catch(handleError);
  }
);

/**
 * GET: Returns data about a actor by name
 * Request body: Bearer token
 * @param actor (name of actor)
 * @returns actor object
 * @requires passport
 */
app.get(
  "/movies/actors/:actor",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    // condition to find specific user based on Username (similar to WHERE in SQL)
    Movies.find({ Actors: req.params.actor })
      .then((movie) => {
        res.json(movie);
      })
      .catch(handleError);
  }
);

/**
 * GET: Returns data about a director (bio, birth year, death year) by name
 * Request body: Bearer token
 * @param director (name of director)
 * @returns director object
 * @requires passport
 */
app.get(
  "/movies/directors/:director",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    // condition to find specific user based on Username (similar to WHERE in SQL)
    Movies.findOne({ "Director.Name": req.params.director })
      .then((movie) => {
        res.json(movie.Director);
      })
      .catch(handleError);
  }
);

/**
 * GET: Returns data on a single user (user object) by username
 * Request body: Bearer token
 * @param Username
 * @returns user object
 * @requires passport
 */
app.get(
  "/users/:username",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    // condition to find specific user based on Username (similar to WHERE in SQL)
    Users.findOne({ username: req.params.username })
      .then((user) => {
        res.json(user);
      })
      .catch(handleError);
  }
);

/**
 * PUT: Allow users to update their user info (find by username)
 * Request body: Bearer token, updated user info
 * @param Username
 * @returns user object with updates
 * @requires passport
 */
app.put(
  "/users/:Username",
  [
    passport.authenticate("jwt", { session: false }),

    // Validation logic
    //minimum value of 5 characters are only allowed
    check("Username", "Username is required").isLength({ min: 5 }),

    // field can only contain letters and numbers
    check(
      "Username",
      "Username contains non alphanumeric characters - not allowed."
    ).isAlphanumeric(),

    // Chain of methods like .not().isEmpty() which means "opposite of isEmpty" or "is not empty"
    check("Password", "Password is required").not().isEmpty(),

    // field must be formatted as an email address
    check("Email", "Email does not appear to be valid").isEmail(),
  ],
  (req, res) => {
    // check the validation object for errors
    let errors = validationResult(req);
    let hashedPassword = Users.hashPassword(req.body.Password);

    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }
    Users.findOneAndUpdate(
      { Username: req.params.Username },
      {
        $set: {
          Username: req.body.Username,
          Password: hashedPassword,
          Email: req.body.Email,
          Birthday: req.body.Birthday,
        },
      },
      { new: true }, // This line makes sure that the updated document is returned
      (err, updatedUser) => {
        if (err) {
          handleError(err);
        } else {
          res.json(updatedUser);
        }
      }
    );
  }
);

/**
 * POST: Allows users to add a movie to their list of favorites //////////////////////////////////////////////////////////
 * Request body: Bearer token
 * @param username
 * @param movieId
 * @returns user object
 * @requires passport
 */
app.post(
  "/users/:Username/favorites/:movieID",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    Users.findOneAndUpdate(
      { Username: req.params.Username },
      { $addToSet: { FavoriteMovies: req.params.movieID } },
      { new: true }, // This line makes sure that the updated document is returned
      (err, updatedUser) => {
        if (err) {
          handleError(err);
        } else {
          res.json(updatedUser);
        }
      }
    );
  }
);

/**
 * DELETE: Allows users to remove a movie from their list of favorites
 * Request body: Bearer token
 * @param Username
 * @param movieId
 * @returns user object
 * @requires passport
 */
app.delete(
  "/users/:Username/favorites/:movieID",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    Users.findOneAndUpdate(
      { Username: req.params.Username },
      { $pull: { FavoriteMovies: req.params.movieID } },
      { new: true }, // This line makes sure that the updated document is returned
      (err, updatedUser) => {
        if (err) {
          handleError(err);
        } else {
          res.json(updatedUser);
        }
      }
    );
  }
);

/**
 * POST: Allows users to add a movie to their list of to watch
 * Request body: Bearer token
 * @param username
 * @param movieId
 * @returns user object
 * @requires passport
 */
app.post(
  "/users/:Username/ToWatch/:movieID",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    Users.findOneAndUpdate(
      { Username: req.params.Username },
      { $addToSet: { ToWatch: req.params.movieID } },
      { new: true }, // This line makes sure that the updated document is returned
      (err, updatedUser) => {
        if (err) {
          handleError(err);
        } else {
          res.json(updatedUser);
        }
      }
    );
  }
);

/**
 * DELETE: Allows users to remove a movie from their list of to watch
 * Request body: Bearer token
 * @param Username
 * @param movieId
 * @returns user object
 * @requires passport
 */
app.delete(
  "/users/:Username/ToWatch/:movieID",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    Users.findOneAndUpdate(
      { Username: req.params.Username },
      { $pull: { ToWatch: req.params.movieID } },
      { new: true }, // This line makes sure that the updated document is returned
      (err, updatedUser) => {
        if (err) {
          handleError(err);
        } else {
          res.json(updatedUser);
        }
      }
    );
  }
);

/**
 * DELETE: Allows existing users to deregister
 * Request body: Bearer token
 * @param Username
 * @returns success message
 * @requires passport
 */
app.delete(
  "/users/:Username",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    Users.findOneAndRemove({ Username: req.params.Username })
      .then((user) => {
        if (!user) {
          res.status(400).send(`${req.params.Username} was not found.`);
        } else {
          res.status(200).send(`${req.params.Username} was deleted.`);
        }
      })
      .catch(handleError);
  }
);

// catches and logs error if occurs. Should always be defined last
app.use((err, req, res, next) => {
  console.error(err.stack);
  console.log("Error object:", err);
  res
    .status(500)
    .send("Oopps! Something went wrong. Check back in a little later.");
});

// process.env.PORT listens for pre-configured port number or, if not found, set port to pertain port number
const port = process.env.PORT || 8080;
app.listen(port, "0.0.0.0", () => {
  console.log(`Listening on Port ${port}`);
});
