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

let handleError = (res, err) => {
  console.error(err);
  console.log(err);
  res.status(500).send(`Error: ${err}`);
};

// ************************** BeerBible API ************************************************

//  POST/CREATE REQUEST

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
  async (req, res) => {
    // check the validation object for errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }
    // check if user already exists
    try {
      const existingUser = await Users.findOne({ email: req.body.email });
      if (existingUser) {
        return res
          .status(400)
          .send(`An account with ${req.body.email} already exists`);
      }

      const hashedPassword = Users.hashPassword(req.body.password);

      const newUser = new Users({
        fullName: req.body.fullName,
        // .create takes and object based on schema
        username: req.body.username, // remember 'req.body' is request that user sends
        password: hashedPassword, // Hashes password entered  when registering before storing in MongoDB
        email: req.body.email,
        breweries: [],
      });
      // Validate and save the beer
      await newUser.validate();
      const savedUser = await newUser.save();

      res.status(201).json({ savedUser });
    } catch (error) {
      handleError(res, error);
    }
  }
);

/**
 * POST: Creates new brewery; Company Name & Owner are required fields!
 * Request body: Bearer token, JSON with user information
 * @returns brewery object
 */
app.post(
  "/:user/breweries",
  [
    // Validation logic
    //minimum value of 5 characters are only allowed
    check("companyName", "Company Name is required").not().isEmpty(),

    // field can only contain letters and numbers
    // check(
    //   "companyName",
    //   "Company Name contains non alphanumeric characters - not allowed."
    // ).isAlphanumeric(),
  ],
  async (req, res) => {
    // check the validation object for errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }

    try {
      const user = await Users.findById(req.params.user).populate();
      if (!user) {
        return res.status(400).send("User not found");
      }

      // Check if category already exists
      const existingBrewery = user.breweries.find(
        (brewery) => brewery.companyName === req.body.companyName
      );
      if (existingBrewery) {
        return res.status(400).send("Brewery already exists");
      }

      const brewery = new Breweries({
        companyName: req.body.companyName,
        owner: req.params.user,
        admin: [req.params.user],
        staff: [],
        beers: [],
        categories: [],
      });

      // Validate and save the beer
      await brewery.validate();
      const savedBrewery = await brewery.save();

      if (savedBrewery) {
        user.breweries.push(savedBrewery._id);
        await user.save();
        res.status(201).json({ savedBrewery });
      } else {
        throw new Error("Brewery save operation failed");
      }
    } catch (error) {
      handleError(res, error);
    }
  }
);

/**
 * POST: Creates new beer; Name & Style are required fields!
 * Request body: Bearer token, JSON with user information
 * @returns beer object
 */
app.post(
  "/:brewery/beers",
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
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }

    try {
      const brewery = await Breweries.findById(req.params.brewery);
      if (!brewery) {
        return res.status(400).send("Brewery not found");
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

      // Validate and save the beer
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
      handleError(res, error);
    }
  }
);

/**
 * POST: Creates new brewery category; Name is required fields!
 * Request body: Bearer token, JSON with user information
 * @returns category object
 */
app.post(
  "/:brewery/categories",
  [
    // passport.authenticate("jwt", { session: false }),
    // Validation logic
    //minimum value of 1 characters are only allowed
    check("name", "Category name is required").isLength({ min: 1 }),
  ],
  async (req, res) => {
    // check the validation object for errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }

    try {
      // .populates makes sure we have full objects, not just id
      const brewery = await Breweries.findById(req.params.brewery).populate(
        "categories"
      );
      if (!brewery) {
        return res.status(400).send("Brewery not found");
      }
      console.log(brewery);
      // Check if category already exists
      const existingCategory = brewery.categories.find(
        (category) => category.name === req.body.name
      );
      if (existingCategory) {
        return res.status(400).send("Category already exists in the brewery");
      }

      const category = new Categories({
        name: req.body.name,
      });

      // Validate and save the beer
      await category.validate();

      const savedCategory = await category.save();

      if (savedCategory) {
        brewery.categories.push(savedCategory._id);
        await brewery.save();
        res.status(201).json({ savedCategory });
      } else {
        throw new Error("Category save operation failed");
      }
    } catch (error) {
      handleError(res, error);
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
 * GET: Returns data on a single user (user object) by user username
 * Request body: Bearer token
 * @param username
 * @returns user object
 * @requires passport
 */
app.get(
  "/users/:username",
  // passport.authenticate("jwt", { session: false }),
  (req, res) => {
    // condition to find specific user based on username
    Users.findOne({ username: req.params.username })
      .then((user) => {
        res.json(user);
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

/**
 * GET: Returns data on a single brewery (brewery object) by brewery id
 * Request body: Bearer token
 * @param brewery
 * @returns brewery object
 * @requires passport
 */
app.get(
  "/breweries/:breweryId",
  // passport.authenticate("jwt", { session: false }),
  (req, res) => {
    // condition to find specific brewery based on _id
    Breweries.findOne({ _id: req.params.breweryId })
      .then((brewery) => {
        res.json(brewery);
      })
      .catch(handleError);
  }
);

/**
 * GET: Returns a list of ALL beers
 * Request body: Bearer token
 * @returns array of beer objects
 * @requires passport
 */
app.get(
  "/beers",
  // passport.authenticate("jwt", { session: false }),
  (req, res) => {
    Beers.find() // .find() grabs data on all documents in collection
      .then((beers) => {
        res.status(201).json(beers);
      })
      .catch(handleError);
  }
);

/**
 * GET: Returns a list of ALL categories
 * Request body: Bearer token
 * @returns array of categories objects
 * @requires passport
 */
app.get(
  "/categories",
  // passport.authenticate("jwt", { session: false }),
  (req, res) => {
    Categories.find() // .find() grabs data on all documents in collection
      .then((categories) => {
        res.status(201).json(categories);
      })
      .catch(handleError);
  }
);

//  PUT/ UPDATE REQUEST ********************

/**
 * PUT: Update user info
 * Request body: Bearer token, updated user info
 * @param userID
 * @returns user object with updates
 * @requires passport
 */
app.put(
  "/users/:userId",
  [
    // Validation logic
    // passport.authenticate("jwt", { session: false }),
    // Minimum value of 5 characters is required
    check("username", "Username is required").isLength({ min: 5 }),

    // Field can only contain letters and numbers
    check(
      "username",
      "Username contains non-alphanumeric characters - not allowed."
    ).isAlphanumeric(),

    // Password is required
    check("password", "Password is required").not().isEmpty(),

    // Field must be formatted as an email address
    check("email", "Email does not appear to be valid").isEmail(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }

    try {
      const userId = req.params.userId;
      const updateFields = {
        fullName: req.body.fullName,
        username: req.body.username,
        password: req.body.password,
        email: req.body.email,
        breweries: req.body.breweries,
      };

      const existingUser = await Users.findByIdAndUpdate(userId, updateFields, {
        new: true,
      });

      if (!existingUser) {
        return res.status(400).send("User not found");
      }

      res.status(200).json({ existingUser });
    } catch (error) {
      handleError(res, error);
    }
  }
);

/**
 * PUT: Update beer info
 * Request body: Bearer token, updated beer info
 * @param beerId
 * @returns beer object with updates
 * @requires passport
 */
app.put(
  "/:brewery/beers/:beerId",
  [
    // Validation logic
    // passport.authenticate("jwt", { session: false }),
    //minimum value of 5 characters are only allowed
    check("name", "Name is required").not().isEmpty(),

    // Chain of methods like .not().isEmpty() which means "opposite of isEmpty" or "is not empty"
    check("style", "Style is required").not().isEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }

    try {
      const beerId = req.params.beerId;

      const updateFields = {
        name: req.body.name,
        style: req.body.style,
        abv: req.body.abv,
        ibu: req.body.ibu,
        category: req.body.category,
        malt: req.body.malt,
        hops: req.body.hops,
        flavorNotes: req.body.flavorNotes,
        aroma: req.body.aroma,
        nameSake: req.body.nameSake,
        notes: req.body.notes,
      };

      // updates by id and only fields that have changed
      const existingBeer = await Beers.findByIdAndUpdate(beerId, updateFields, {
        new: true,
      });

      if (!existingBeer) {
        return res.status(400).send("Beer not found");
      }

      res.status(200).json({ existingBeer });
    } catch (error) {
      handleError(res, error);
    }
  }
);

app.put(
  "/breweries/:breweryId",
  [
    // Validation logic
    // passport.authenticate("jwt", { session: false }),
    // Minimum value of 1 character is required
    check("companyName", "Company Name is required").isLength({ min: 1 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }

    try {
      const breweryId = req.params.breweryId;
      const updateFields = {
        companyName: req.body.companyName,
        owner: req.body.owner,
        admin: req.body.admin,
        staff: req.body.staff,
        beers: req.body.beers,
        categories: req.body.categories,
      };

      const existingBrewery = await Breweries.findByIdAndUpdate(
        breweryId,
        updateFields,
        { new: true }
      );

      if (!existingBrewery) {
        return res.status(400).send("Brewery not found");
      }

      res.status(200).json({ existingBrewery });
    } catch (error) {
      handleError(res, error);
    }
  }
);

//  DELETE REQUEST *****************
/**
 * DELETE: Deletes brewery
 * Request body: Bearer token
 * @param brewery
 * @returns success message
 * @requires passport
 */
app.delete(
  "/breweries/:brewery",
  // passport.authenticate("jwt", { session: false }),
  (req, res) => {
    Breweries.findOneAndRemove({ _id: req.params.brewery })
      .populate("companyName")
      .then((brewery) => {
        if (!brewery) {
          res.status(400).send(`${brewery.companyName} was not found.`);
        } else {
          res.status(200).send(`${brewery.companyName} was deleted.`);
        }
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
 * GET: Returns data about a  (bio, birth year, death year) by name
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
