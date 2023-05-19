const express = require("express"),
  bodyParser = require("body-parser"), // middleware for req body parsing
  uuid = require("uuid"), //Universally Unique Identifier. Generate a unique ID
  morgan = require("morgan"),
  mongoose = require("mongoose"), // Intergrates mongoose into file
  Models = require("./models.js"), // allows access to database schema
  cors = require("cors"); // Cross-Orgin Resourse Sharing

mongoose.set("strictQuery", true); // handles undefined paths

const { SES } = require("@aws-sdk/client-ses");
// Load AWS SES
const ses = new SES({ apiVersion: "2010-12-01", region: "us-west-2" });

const { check, validationResult } = require("express-validator");

const crypto = require("crypto"); // Generate a random token for invite record

// Refer to models named in models.js
const Users = Models.User;
const Beers = Models.Beer;
const Breweries = Models.Brewery;
const Categories = Models.Category;
const Invites = Models.Invite;

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

//  POST/CREATE REQUEST ***************

/**
 * POST: Sending invitation. Adds brewery to users breweries and user to breweries staff;
 * Request body: Bearer token, JSON with user information & email to invitee required!
 * @returns Invitation accepted message
 */
app.post(
  "/breweries/:breweryId/invite",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const breweryId = req.params.breweryId;
      const { email } = req.body; // email of the user to be invited
      console.log(email);

      // Fetch the brewery from the database
      const brewery = await Breweries.findById(breweryId);
      if (!brewery) {
        return res.status(404).json({ message: "Brewery not found." });
      }

      // Generate a random token and create an invite record in the database
      const token = crypto.randomBytes(16).toString("hex");
      const invite = await new Invites({
        token,
        brewery: breweryId,
        sender: req.user._id,
      }).save();

      // Send email here
      const inviteUrl = `http://localhost:8080/accept-invite?token=${token}`;

      // Specify email parameters
      const emailParams = {
        Destination: {
          /* required */ ToAddresses: [email],
        },
        Message: {
          /* required */
          Body: {
            /* required */
            Text: {
              Charset: "UTF-8",
              Data: `You have been invited to join ${brewery.companyName}! Click the link to join: ${inviteUrl}`,
            },
          },
          Subject: {
            Charset: "UTF-8",
            Data: "Brewery Invitation",
          },
        },
        Source: "hello@jordanbettmann.com" /* required */,
        ReplyToAddresses: ["hello@jordanbettmann.com"],
      };

      // Create the promise and SES service object
      const sendPromise = ses.sendEmail(emailParams);

      // Handle promise's fulfilled/rejected states
      sendPromise
        .then(function (data) {
          console.log(data.MessageId);
        })
        .catch(function (err) {
          console.error(err, err.stack);
        });

      res.status(200).json({ message: "Invitation sent." });
    } catch (error) {
      handleError(res, error);
    }
  }
);

/**
 * POST: Accepting invitation. Adds brewery to users breweries and user to breweries staff;
 * Request body: Bearer token, JSON with user information
 * @returns Invitation accepted message
 */
app.post(
  "/accept-invite",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const { token } = req.body;

      const invite = await Invites.findOne({ token });

      if (!invite) {
        return res
          .status(400)
          .json({ message: "Invalid or expired invite token." });
      }

      // Add the user to the brewery's staff list and vice versa
      const brewery = await Breweries.findById(invite.brewery);
      const user = await Users.findById(req.user._id);
      const existingStaff = brewery.staff.includes(req.user._id);
      console.log(existingStaff);
      if (existingStaff) {
        return res
          .status(400)
          .json({ message: `${user.email} already exists in brewery!` });
      }
      brewery.staff.push(req.user._id);
      await brewery.save();

      user.breweries.push(brewery._id);
      await user.save();

      // Delete the invite from the database
      await invite.remove();

      res.status(200).json({ message: "Invitation accepted." });
    } catch (error) {
      handleError(res, error);
    }
  }
);

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
  "/users/:user/breweries",
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
  "/breweries/:brewery/beers",
  [
    passport.authenticate("jwt", { session: false }),
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
        companyId: req.params.brewery,
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
  "/breweries/:brewery/categories",
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
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    Breweries.find() // .find() grabs data on all documents in collection
      .then((brewery) => {
        res.status(201).json(brewery);
      })
      .catch(handleError);
  }
);

/**
 * GET: Returns a list of ALL breweries beers
 * Request body: Bearer token
 * @returns array of beer objects
 * @requires passport
 */
app.get(
  "/breweries/:breweryId/beers",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    Beers.find({ companyId: req.params.breweryId }) // find my companyId
      .then((beers) => {
        res.status(201).json(beers);
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
    const hashedPassword = Users.hashPassword(req.body.password);
    try {
      const userId = req.params.userId;
      const updateFields = {
        fullName: req.body.fullName,
        username: req.body.username,
        password: hashedPassword,
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
 * @param breweryId
 * @returns beer object with updates
 * @requires passport
 */
app.put(
  "/breweries/:breweryId/beers/:beerId",
  [
    // Validation logic
    passport.authenticate("jwt", { session: false }),
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
      const breweryId = req.params.breweryId;

      const beer = await Beers.findById(beerId);
      if (!beer || beer.companyId.toString() !== breweryId) {
        return res
          .status(400)
          .send("Beer not found or does not belong to this brewery");
      }

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

/**
 * PUT: Update brewery info
 * Request body: Bearer token, updated brewery info
 * @param breweryId
 * @returns brewery object with updates
 * @requires passport
 */
app.put(
  "/breweries/:breweryId",
  [
    // Validation logic
    passport.authenticate("jwt", { session: false }),
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
        admin: req.body.admin,
        staff: req.body.staff,
        categories: req.body.categories,
      };

      const existingBrewery = await Breweries.findById(breweryId);

      if (!existingBrewery) {
        return res.status(400).send("Brewery not found");
      }

      const updatedBrewery = await Breweries.findByIdAndUpdate(
        breweryId,
        updateFields,
        { new: true }
      );

      res.status(200).json({ updatedBrewery });
    } catch (error) {
      handleError(res, error);
    }
  }
);

/**
 * PUT: Add an admin
 * Request body: Bearer token
 * @param breweryId
 * @param userId
 * @returns brewery object with updates
 * @requires passport
 */
app.put(
  "/breweries/:breweryId/admins/:userId",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      const breweryId = req.params.breweryId;
      const userId = req.params.userId;

      const brewery = await Breweries.findById(breweryId);
      const user = await Users.findById(userId);

      // Check if brewery and user exist
      if (!brewery || !user) {
        return res.status(400).json({ error: "Brewery or User not found" });
      }

      // Add user to admin array if not already present
      await Breweries.findByIdAndUpdate(breweryId, {
        $addToSet: { admin: userId },
      });

      res.status(200).json({ message: "Admin added successfully" });
    } catch (error) {
      handleError(res, error);
    }
  }
);

/**
 * PUT: Update Brewery Owner
 * Request body: Bearer token
 * @param breweryId
 * @param newOwnerId
 * @returns brewery object with updates
 * @requires passport
 */
app.put(
  "/breweries/:breweryId/owner/:newOwnerId",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const breweryId = req.params.breweryId;
    const newOwnerId = req.params.newOwnerId;

    try {
      const brewery = await Breweries.findById(breweryId);

      // Check if brewery exists
      if (!brewery) {
        return res.status(400).json({ error: "Brewery not found" });
      }

      // Check if new owner is part of the staff
      if (!brewery.staff.includes(newOwnerId)) {
        return res
          .status(400)
          .json({ error: "New owner must be a member of the staff" });
      }

      // Update the brewery document
      await Breweries.findByIdAndUpdate(breweryId, { owner: newOwnerId });

      return res.status(200).json({ message: "Owner updated successfully" });
    } catch (error) {
      handleError(res, error);
    }
  }
);

//  DELETE REQUEST *****************

/**
 * DELETE: Deletes admin from breweries admin
 * Request body: Bearer token
 * @param breweryId
 * @param userId
 * @returns success message
 * @requires passport
 */
app.delete(
  "/breweries/:breweryId/admin/:userId",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const breweryId = req.params.breweryId;
    const userId = req.params.userId;

    try {
      const brewery = await Breweries.findById(breweryId);

      // Check if brewery exists
      if (!brewery) {
        return res.status(400).json({ error: "Brewery not found" });
      }

      // Check if user is an admin
      if (!brewery.admin.includes(userId)) {
        return res
          .status(400)
          .json({ error: "User is not an admin in this brewery" });
      }

      // Check if user is an owner
      if (brewery.owner == userId) {
        return res
          .status(400)
          .json({ error: "Owner can not be removed from admins" });
      }

      // Update the brewery document
      await Breweries.findByIdAndUpdate(breweryId, {
        $pull: { admin: userId },
      });

      return res.status(200).json({ message: "Admin removed successfully" });
    } catch (error) {
      handleError(res, error);
    }
  }
);

/**
 * DELETE: Deletes brewery
 * Request body: Bearer token
 * @param breweryId
 * @returns success message
 * @requires passport
 */
app.delete(
  "/breweries/:breweryId",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }
    try {
      const breweryId = req.params.breweryId;
      const brewery = await Breweries.findById(breweryId);

      if (!brewery) {
        return res.status(400).send(`Brewery not found.`);
      }

      // Remove brewery from all staff members' breweries array
      await Users.updateMany(
        { _id: { $in: brewery.staff } },
        { $pull: { breweries: breweryId } }
      );

      // Delete the brewery
      await Breweries.findByIdAndRemove(breweryId);

      res.status(200).send(`${brewery.companyName} was deleted.`);
    } catch (error) {
      handleError(res, error);
    }
  }
);

/**
 * DELETE: Deletes beer
 * Request body: Bearer token
 * @param breweryId
 * @param beerId
 * @returns success message
 * @requires passport
 */
app.delete(
  "/breweries/:breweryId/beers/:beerId",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }
    try {
      const beer = await Beers.findByIdAndDelete(req.params.beerId);

      if (!beer) {
        res.status(400).send(`Beer was not found.`);
      } else {
        res.status(200).send(`${beer.name} was deleted.`);
      }
    } catch (error) {
      handleError(res, error);
    }
  }
);

/**
 * DELETE: Deletes User from Breweries Staff array
 * Request body: Bearer token
 * @param breweryId
 * @param userId
 * @returns success message
 * @requires passport
 */
app.delete(
  "/breweries/:breweryId/staff/:userId",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const breweryId = req.params.breweryId;
    const userId = req.params.userId;

    try {
      const brewery = await Breweries.findById(breweryId);
      const user = await Users.findById(userId);

      // Check if brewery exists
      if (!brewery) {
        return res.status(400).json({ error: "Brewery not found" });
      }
      // Check if User exists
      if (!user) {
        return res.status(400).json({ error: "User not found" });
      }

      // Check if user is owner of brewery
      if (brewery.owner.toString() === userId) {
        return res
          .status(400)
          .json({ error: "Owner cannot be removed from staff" });
      }

      // Check if user is in the staff array
      if (!brewery.staff.includes(userId)) {
        return res
          .status(400)
          .json({ error: "Staff member not found in this brewery" });
      }

      // Update the brewery document
      await Breweries.findByIdAndUpdate(breweryId, {
        $pull: { staff: userId, admin: userId },
      });

      // Check if brewery is in users breweries array
      if (!user.breweries.includes(breweryId)) {
        return res
          .status(400)
          .json({ error: "Brewery not found in users breweries" });
      }

      // Update users breweries array
      await Users.findByIdAndUpdate(userId, {
        $pull: { breweries: breweryId },
      });

      return res
        .status(200)
        .json({ message: "Staff member removed successfully" });
    } catch (error) {
      handleError(res, error);
    }
  }
);

/**
 * DELETE: Deletes Brewery from Users brewery array
 * Request body: Bearer token
 * @param userId
 * @param breweryId
 * @returns success message
 * @requires passport
 */
app.delete(
  "/users/:userId/breweries/:breweryId",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const userId = req.params.userId;
    const breweryId = req.params.breweryId;

    try {
      const user = await Users.findById(userId);

      // Check if user exists
      if (!user) {
        return res.status(400).json({ error: "User not found" });
      }

      // Check if brewery is in user's breweries array
      if (!user.breweries.includes(breweryId)) {
        return res
          .status(400)
          .json({ error: "Brewery not found in user's breweries" });
      }

      // Update user's breweries array
      await Users.findByIdAndUpdate(userId, {
        $pull: { breweries: breweryId },
      });

      return res.status(200).json({
        message: "Brewery removed successfully from user's breweries",
      });
    } catch (error) {
      handleError(res, error);
    }
  }
);

/**
 * DELETE: Deletes User account
 * Request body: Bearer token
 * @param userId
 * @returns success message
 * @requires passport
 */
app.delete(
  "/users/:userId",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const userId = req.params.userId;

    try {
      const user = await Users.findById(userId);

      // Check if user exists
      if (!user) {
        return res.status(400).json({ error: "User not found" });
      }

      // Check if user is an owner of any breweries
      const breweries = await Breweries.find({ owner: userId });

      if (breweries.length > 0) {
        return res.status(400).json({
          error: `${user.fullName} is an owner of ${breweries}. Please reassign ownership before deleting account.`,
        });
      }

      // Delete user's account
      await Users.findByIdAndDelete(userId);

      return res
        .status(200)
        .json({ message: `${user.fullName} was deleted successfully` });
    } catch (error) {
      handleError(res, error);
    }
  }
);

// catches and logs error if occurs. Should always be defined last
app.use((err, req, res, next) => {
  console.error(err.stack);
  console.log("Error object:", err);
  res
    .status(500)
    .send("Oops! Something went wrong. Check back in a little later.");
});

// process.env.PORT listens for pre-configured port number or, if not found, set port to pertain port number
const port = process.env.PORT || 8080;
app.listen(port, "0.0.0.0", () => {
  console.log(`Listening on Port ${port}`);
});
