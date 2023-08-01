const express = require("express"),
  bodyParser = require("body-parser"), // middleware for req body parsing
  uuid = require("uuid"), //Universally Unique Identifier. Generate a unique ID
  morgan = require("morgan"),
  mongoose = require("mongoose"), // Intergrates mongoose into file
  Models = require("./models.js"), // allows access to database schema
  cors = require("cors"), // Cross-Orgin Resourse Sharing
  jwt = require("jsonwebtoken"),
  nodemailer = require("nodemailer");

require("dotenv").config();
const { OAuth2Client } = require("google-auth-library");

function verifyJWT(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(403).send("A token is required for authentication");
  }

  const token = authHeader.split(" ")[1]; // Bearer <token>

  try {
    const decoded = jwt.verify(token, process.env.NEXTAUTH_SECRET);

    req.user = decoded;
  } catch (err) {
    console.log(err);
    return res.status(401).json("Invalid Token");
  }
  return next();
}

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

// allows Mongoose to conncect to database to perform CRUD operations on doc
mongoose.connect(
  // process.env.CONNECTION_URI defined in Vercel
  process.env.CONNECTION_URI || "mongodb://localhost:27017/BeerBibleDB",
  { useNewUrlParser: true, useUnifiedTopology: true }
);

const app = express();

// List of allowed domains
let allowedOrigins = [
  "http://localhost:8080",
  "http://localhost:3000",
  "http://testsite.com",
  "https://beer-bible-api.vercel.app",
  "beer-bible-api-git-main-jbettmann.vercel.app",
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
  res.send(`Beers are flowin! Cheers!`);
});

let handleError = (res, err) => {
  console.error(err);

  res.status(500).send(`Error: ${err}`);
};

// ************************** BeerBible API ************************************************

//  POST/CREATE REQUEST ***************

/**
 * POST: Sending invitation. Adds brewery to users breweries and user to breweries staff;
 * Request body: Bearer token, JSON with user information & email to invitee required!
 * @returns Invitation accepted message
 */
app.post("/breweries/:breweryId/invite", verifyJWT, async (req, res) => {
  try {
    const breweryId = req.params.breweryId;
    const { email, isAdmin } = req.body; // email of the user to be invited

    // Fetch the brewery from the database
    const brewery = await Breweries.findById(breweryId)
      .populate("owner")
      .populate("staff");
    if (!brewery) {
      return res.status(404).json({ message: "Brewery not found." });
    }

    // check if invitee is already a staff member
    if (brewery.staff.some((staffMember) => staffMember.email === email)) {
      return res.status(400).json({
        message: `${email} is already a staff member of ${brewery.companyName}.`,
      });
    }

    // Generate a random token and create an invite record in the database
    const token = crypto.randomBytes(16).toString("hex");

    // Send email here
    const inviteUrl = `http://localhost:3000/accept-invite?token=${token}`;
    // `https://beer-bible-api.vercel.app/accept-invite?token=${token}`

    const oauth2Client = new OAuth2Client(
      process.env.GMAIL_CLIENT,
      process.env.GMAIL_SECRET,
      "https://developers.google.com/oauthplayground" // This field is for the redirect URL
    );

    oauth2Client.setCredentials({
      refresh_token: process.env.GMAIL_OAUTH_REFRESH,
    });

    const response = await oauth2Client.refreshAccessToken();
    let transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        type: "OAuth2",
        user: process.env.GMAIL_EMAIL,
        clientId: process.env.GMAIL_CLIENT,
        clientSecret: process.env.GMAIL_SECRET,
        refreshToken: process.env.GMAIL_OAUTH_REFRESH,
        accessToken: response.credentials.access_token, // Access token obtained from the OAuth2 client
      },
    });

    // send mail with defined transport object
    let info = await transporter.sendMail({
      from: '"BeerFlo" <no-reply@beerflo.com>', // sender address
      to: email, // list of receivers
      subject: `Join ${brewery.companyName} on BeerFlo!`, // Subject line
      text: `You've been invited to join ${brewery.companyName}! Accept Invite! ${inviteUrl}`, // plain text body
      html: `<h3>You've been invited!</h3> 
      <p><strong>${brewery.companyName}</strong> wants you to join their team on BeerFlo!</p>
      <a href="${inviteUrl}" style="display: inline-block; font-weight: 400; color: #fff; text-align: center; vertical-align: middle; cursor: pointer; background-color: #007bff; border: 1px solid transparent; padding: .375rem .75rem; font-size: 1rem; line-height: 1.5; border-radius: .25rem; transition: color .15s ease-in-out,background-color .15s ease-in-out,border-color .15s ease-in-out,box-shadow .15s ease-in-out; text-decoration: none;">Join The Crew!</a>`, // html body
    });

    console.log("Message sent: %s", info.messageId);

    const invite = await new Invites({
      token,
      brewery: breweryId,
      sender: req.user.id,
      isAdmin: isAdmin,
    }).save();

    res
      .status(200)
      .json({ message: `Invitation sent to ${email}`, email: email });
  } catch (error) {
    handleError(res, error);
  }
});

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

      const newUser = new Users({
        fullName: req.body.fullName,
        // .create takes and object based on schema

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
  "/breweries",
  [
    verifyJWT,
    // Validation logic
    //minimum value of 1 characters are only allowed
    check("companyName", "Company Name is required").not().isEmpty(),
  ],
  async (req, res) => {
    // check the validation object for errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }

    console.log(req.user.id);
    try {
      const user = await Users.findById(req.user.id);

      if (!user) {
        return res.status(400).send("User not found");
      }

      // Check if brewery already exists
      const existingBrewery = user.breweries.find(
        (brewery) => brewery.companyName === req.body.companyName
      );
      if (existingBrewery) {
        return res.status(400).send("Brewery already exists");
      }
      const brewery = new Breweries({
        companyName: req.body.companyName,
        image: req.body.image,
        owner: req.user.id,
        admin: [],
        staff: [],
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
  "/breweries/:breweryId/beers",
  [
    verifyJWT,
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
    const userId = req.user.id;

    try {
      const brewery = await Breweries.findById(req.params.breweryId);

      if (!brewery) {
        return res.status(400).send("Brewery not found");
      }

      // Check if the user is the owner or an admin of the brewery

      if (
        brewery.owner.toString() !== userId.toString() ||
        !brewery.admin.includes(userId)
      ) {
        return res.status(403).send(`Only admin or owner can create a beer`);
      }

      const beer = new Beers({
        companyId: req.params.breweryId,
        image: req.body.image,
        name: req.body.name,
        style: req.body.style,
        abv: req.body.abv,
        ibu: req.body.ibu,
        category: req.body.category,
        malt: req.body.malt,
        hops: req.body.hops,
        description: req.body.description,
        nameSake: req.body.nameSake,
        notes: req.body.notes,
        releasedOn: req.body.releasedOn,
      });

      // Validate and save the beer
      await beer.validate();
      const savedBeer = await beer.save();

      if (savedBeer) {
        res.status(201).json(savedBeer);
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
  "/breweries/:breweryId/categories",
  [
    verifyJWT,
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
      const brewery = await Breweries.findById(req.params.breweryId).populate(
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
        res.status(201).json(savedCategory);
      } else {
        throw new Error("Category save operation failed");
      }
    } catch (error) {
      handleError(res, error);
    }
  }
);

/**
 * POST: Returns data on breweries (array of brewery objects) user is
 * apart of staff array. getBreweries is nextjs
 * Request body: Bearer token, JSON with array of brewery ids
 * @param breweries
 * @returns array of brewery objects
 * @requires passport
 */
app.post("/users/breweries", verifyJWT, async (req, res) => {
  // Note: Changed to POST to allow sending an array of ids
  // gets user from token verifyJWT
  const authUser = req.user.id;
  const breweryIds = req.body.breweryIds;

  console.log({ authUser, breweryIds });
  try {
    // checks if breweries exist and if user requesting data is in staff array
    const breweries = await Breweries.find({
      _id: { $in: breweryIds },
      $or: [{ staff: authUser }, { admin: authUser }, { owner: authUser }],
    }).populate("categories");

    if (breweries.length === 0) {
      return res
        .status(401)
        .json("You are not authorized to view these breweries");
    }

    return res.status(200).json({ breweries });
  } catch (error) {
    handleError(error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// GET REQUEST ******************

/**
 * GET: Accepting invitation. Adds brewery to users breweries and user to breweries staff;
 * Request: Bearer token from logged in user in header, token from URL param
 * @returns Invitation accepted message
 */
app.get("/accept-invite", verifyJWT, async (req, res) => {
  try {
    const { token } = req.query;

    const invite = await Invites.findOne({ token });

    if (!invite) {
      return res
        .status(400)
        .json({ message: "Invalid or expired invite token." });
    }

    // Add the user to the brewery's staff list and vice versa
    const brewery = await Breweries.findById(invite.brewery);
    const user = await Users.findById(req.user.id);

    if (!brewery || !user) {
      return res.status(400).json({ message: `User or Brewery don't exists!` });
    }
    brewery.staff.push(req.user.id);
    if (invite.isAdmin) {
      // check if user is an admin
      brewery.admin.push(req.user.id); // add user to admins
    }
    await brewery.save();

    user.breweries.push(brewery._id);
    await user.save();

    // Delete the invite from the database
    await invite.remove();

    res.status(200).json({ message: "Invitation accepted.", brewery: brewery });
  } catch (error) {
    handleError(res, error);
  }
});

/**
 * GET: Returns a list of ALL users
 * Request body: Bearer token
 * @returns array of user objects
 * @requires passport
 */
app.get("/users", verifyJWT, (req, res) => {
  Users.find() // .find() grabs data on all documents in collection
    .then((users) => {
      res.status(201).json(users);
    })
    .catch(handleError);
});

/**
 * GET: Returns data on a single user (user object) by user username
 * Request body: Bearer token
 * @param username
 * @returns user object
 * @requires passport
 */
app.get("/users/:email", verifyJWT, (req, res) => {
  // condition to find specific user based on username
  Users.findOne({ email: req.params.email })
    .populate("breweries")
    .then((user) => {
      res.json(user);
    })
    .catch(handleError);
});

/**
 * GET: Returns a list of ALL breweries
 * Request body: Bearer token
 * @returns array of brewery objects
 * @requires passport
 */
app.get("/breweries", verifyJWT, (req, res) => {
  Breweries.find() // .find() grabs data on all documents in collection
    .then((brewery) => {
      res.status(201).json(brewery);
    })
    .catch(handleError);
});

/**
 * GET: Returns a list of ALL breweries beers
 * Request body: Bearer token
 * @returns array of beer objects
 * @requires passport
 */
app.get("/breweries/:breweryId/beers", verifyJWT, (req, res) => {
  Beers.find({ companyId: req.params.breweryId })
    .populate("category") // find my companyId
    .then((beers) => {
      res.status(201).json(beers);
    })
    .catch(handleError);
});

//  Created POST request to handle array of brewery ids
/**
 * GET: Returns data on a single brewery (brewery object)
 * by brewery id only if user is apart of staff array.
 * Request body: Bearer token
 * @param brewery
 * @returns brewery object
 * @requires passport
 */
app.get("/breweries/:breweryId", verifyJWT, async (req, res) => {
  // gets user from token verifyJWT
  const authUser = req.user.id;

  try {
    // checks if brewery exists and if user requesting data is in staff array
    const brewery = await Breweries.findOne({
      _id: req.params.breweryId,
      $or: [{ staff: authUser }, { owner: authUser }],
    })
      .populate("staff")
      .populate("categories")
      .populate("admin")
      .populate("owner");

    if (!brewery) {
      return res
        .status(401)
        .json("You are not authorized to view this brewery");
    }

    return res.status(200).json(brewery);
  } catch (error) {
    handleError(error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET: Returns a list of ALL beers
 * Request body: Bearer token
 * @returns array of beer objects
 * @requires passport
 */
app.get("/beers", verifyJWT, (req, res) => {
  Beers.find()
    .populate("category") // .find() grabs data on all documents in collection
    .then((beers) => {
      res.status(201).json(beers);
    })
    .catch(handleError);
});

/**
 * GET: Returns a list of ALL categories
 * Request body: Bearer token
 * @returns array of categories objects
 * @requires passport
 */
app.get("/categories", verifyJWT, (req, res) => {
  Categories.find() // .find() grabs data on all documents in collection
    .then((categories) => {
      res.status(201).json(categories);
    })
    .catch(handleError);
});

//  PUT/ UPDATE REQUEST ****************************************************

/**
 * PUT: Update user info
 * Request body: Bearer token, updated user info
 * @param userID
 * @returns user object with updates
 * @requires passport
 */
app.put(
  "/users/:userId",

  // Validation logic
  verifyJWT,

  async (req, res) => {
    try {
      const userId = req.params.userId;
      const updateFields = {
        fullName: req.body.fullName,
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
    verifyJWT,
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
        description: req.body.description,
        // aroma: req.body.aroma,
        nameSake: req.body.nameSake,
        notes: req.body.notes,
        image: req.body.image,
        archived: req.body.archived,
        releasedOn: req.body.releasedOn,
        companyId: breweryId,
      };

      // updates by id and only fields that have changed
      const existingBeer = await Beers.findByIdAndUpdate(beerId, updateFields, {
        new: true,
      });

      if (!existingBeer) {
        return res.status(400).send("Beer not found");
      }

      res.status(200).json(existingBeer);
    } catch (error) {
      handleError(res, error);
    }
  }
);

/**
 * PUT: Updates a category; Name is required fields!
 * Request body: Bearer token, JSON with new category name
 * @returns updated category object
 */
app.put(
  "/categories/:categoryId",
  [
    verifyJWT,
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
      // Find the category by id and update
      const updatedCategory = await Categories.findByIdAndUpdate(
        req.params.categoryId,
        { name: req.body.name },
        { new: true }
      );

      if (!updatedCategory) {
        return res.status(400).send("Category not found");
      }

      res.status(200).json(updatedCategory);
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
    verifyJWT,
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
        image: req.body.image,
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
app.put("/breweries/:breweryId/admins/:userId", verifyJWT, async (req, res) => {
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
});

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
  verifyJWT,
  async (req, res) => {
    const breweryId = req.params.breweryId;
    const newOwnerId = req.params.newOwnerId;
    const owner = req.user.id;

    try {
      const brewery = await Breweries.findById(breweryId).populate("owner");

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

      // Check if current user is the owner
      if (brewery.owner._id.toString() !== owner) {
        return res.status(400).json({
          error: `${brewery.owner.fullName} is the only one allowed to reassign a new owner to ${brewery.companyName}`,
        });
      }

      // Update the brewery document
      await Breweries.findByIdAndUpdate(
        breweryId,
        { owner: newOwnerId },
        { new: true }
      );

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
  verifyJWT,
  async (req, res) => {
    const breweryId = req.params.breweryId;
    const userId = req.params.userId;
    const authUser = req.user.id;

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

      // Check if authUser is the owner or another admin
      if (
        authUser.toString() !== brewery.owner.toString() ||
        !brewery.admin.includes(authUser)
      ) {
        return res.status(400).json({
          error: "Only the owner or another admin can remove an admin",
        });
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
app.delete("/breweries/:breweryId", verifyJWT, async (req, res) => {
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

    // Check if the user who made the request is the owner of the brewery
    if (req.user.id.toString() !== brewery.owner.toString()) {
      return res
        .status(403)
        .send("You are not authorized to delete this brewery.");
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
});

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
  verifyJWT,
  async (req, res) => {
    const authUser = req.user.id;
    const { breweryId, beerId } = req.params;

    try {
      const brewery = await Breweries.findById(breweryId);

      if (!brewery) {
        return res.status(400).json({
          error: `Brewery was not found.`,
        });
      }

      // Check if authUser is the owner or another admin
      if (
        authUser.toString() !== brewery.owner.toString() ||
        !brewery.admin.includes(authUser)
      ) {
        return res.status(400).json({
          error: "Only the owner or another admin can delete a beer",
        });
      }

      const beer = await Beers.findOneAndDelete({
        _id: beerId,
        companyId: breweryId,
      });

      if (!beer) {
        return res.status(400).send(`Beer was not found.`);
      }
      res.status(200).send(`${beer.name} was deleted.`);
    } catch (error) {
      handleError(res, error);
    }
  }
);

/**
 * DELETE: Deletes category
 * Request body: Bearer token
 * @param breweryId
 * @param categoryId
 * @returns success message
 */
app.delete(
  "/breweries/:breweryId/categories/:categoryId",
  verifyJWT,
  async (req, res) => {
    const authUser = req.user.id;
    const { breweryId, categoryId } = req.params;

    try {
      const brewery = await Breweries.findById(breweryId);

      if (!brewery) {
        return res.status(400).json({
          error: `Brewery was not found.`,
        });
      }

      // Check if authUser is the owner or another admin
      if (
        authUser.toString() !== brewery.owner.toString() ||
        !brewery.admin.includes(authUser)
      ) {
        return res.status(400).json({
          error: "Only the owner or another admin can delete a category",
        });
      }

      // Check if there are beers associated with this category
      const beersWithCategory = await Beers.find({
        category: categoryId, // Adjusted here: assuming categories field is an array in Beers schema
        companyId: breweryId,
      });

      if (beersWithCategory.length > 0) {
        return res.status(400).json({
          error:
            "Category cannot be deleted while it still has associated beers",
        });
      }

      const category = await Categories.findOneAndDelete({
        _id: categoryId,
      });

      if (!category) {
        return res.status(400).send(`${category.name} category was not found.`);
      }

      // If the category exists in the brewery's categories array, remove it
      if (brewery.categories.includes(categoryId)) {
        await Breweries.findByIdAndUpdate(breweryId, {
          $pull: { categories: categoryId },
        });
      }

      res.status(200).json({ message: `${category.name} was deleted.` });
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
  verifyJWT,
  async (req, res) => {
    const breweryId = req.params.breweryId;
    const userId = req.params.userId;
    const authUser = req.user.id;
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
      if (brewery.owner.toString() === userId.toString()) {
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

      // Check if authUser is the owner or another admin
      if (
        authUser.toString() !== brewery.owner.toString() ||
        !brewery.admin.includes(authUser)
      ) {
        return res.status(400).json({
          error: "Only the owner or another admin can remove staff members",
        });
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
        .json({ message: `${user.fullName} successfully removed from staff.` });
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
  verifyJWT,
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
          .json({ error: `Brewery not found in your breweries` });
      }

      // Update user's breweries array
      await Users.findByIdAndUpdate(userId, {
        $pull: { breweries: breweryId },
      });

      return res.status(200).json({
        message: "Brewery removed successfully from your breweries",
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
app.delete("/users/:userId", verifyJWT, async (req, res) => {
  const userId = req.params.userId;
  const authUser = req.user.id;
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

    if (authUser !== userId) {
      return res
        .status(400)
        .json({ error: `Only ${user.fullName} can delete this account` });
    }
    // Delete user's account
    await Users.findByIdAndDelete(userId);

    return res
      .status(200)
      .json({ message: `${user.fullName} was deleted successfully` });
  } catch (error) {
    handleError(res, error);
  }
});

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

// Export the Express API
module.exports = app;
