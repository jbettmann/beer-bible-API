const mongoose = require("mongoose"),
  bcrypt = require("bcrypt"); // hashes user password and compares everytime user logs in

// user schema
const userSchema = mongoose.Schema({
  fullName: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
  email: { type: String, required: true },
  breweries: [
    { type: mongoose.Schema.Types.ObjectId, ref: "Brewery", default: [] },
  ],
});

// brewery schema
const brewerySchema = mongoose.Schema({
  companyName: { type: String, required: true },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  admin: [{ type: mongoose.Schema.Types.ObjectId, ref: "User", default: [] }],
  staff: [{ type: mongoose.Schema.Types.ObjectId, ref: "User", default: [] }],
  categories: [
    { type: mongoose.Schema.Types.ObjectId, ref: "Category", default: [] },
  ],
});

// beer schema
const beerSchema = mongoose.Schema({
  companyId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Brewery",
    required: true,
    index: true, // increases read performance but decreases write/update/delete
  },
  name: { type: String, required: true },
  style: { type: String, required: true },
  abv: Number,
  ibu: Number,
  category: [String],
  malt: [String],
  hops: [String],
  flavorNotes: String,
  aroma: String,
  nameSake: String,
  notes: String,
});

// invite schema
const inviteSchema = mongoose.Schema({
  token: { type: String, required: true },
  brewery: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Brewery",
    required: true,
  },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  createdAt: { type: Date, required: true, default: Date.now, expires: "24h" },
});

// category schema
const categorySchema = mongoose.Schema({
  name: { type: String, required: true },
});

// Movie schema being defined for Movies Collection. It follows a syntax of Key: {Value}, format.
let movieSchema = mongoose.Schema({
  Title: { type: String, required: true },
  Description: { type: String, required: true },
  Genre: {
    Name: String,
    Description: String,
  },
  Director: {
    Name: String,
    Bio: String,
  },
  ImageUrl: String,
  Release: String,
  Featured: Boolean,
  Actors: [String],
});

// User schema being defined for Users Collection
// let userSchema = mongoose.Schema({
//   Username: { type: String, required: true }, // MUST have a username and MUST be a string
//   Password: { type: String, required: true },
//   Email: { type: String, required: true },
//   Birthday: Date, // Must be a value of the date type Date
//   // defines value will be an ObjectID by way of ref: 'Movie' ('Movie' name of model which links movieSchema to database)
//   FavoriteMovies: [{ type: mongoose.Schema.Types.ObjectId, ref: "Movie" }],
//   ToWatch: [{ type: mongoose.Schema.Types.ObjectId, ref: "Movie" }],
// });

// Function hashes users summited password
userSchema.statics.hashPassword = (password) => {
  return bcrypt.hashSync(password, 10);
};

// Function compares submitted hashed password with hashed password stored in database
userSchema.methods.validatePassword = function (password) {
  return bcrypt.compareSync(password, this.password);
};

// Creation for db, will come out lowercase and plurals. eg. db.beers
const Beer = mongoose.model("Beer", beerSchema);
const User = mongoose.model("User", userSchema);
const Brewery = mongoose.model("Brewery", brewerySchema);
const Category = mongoose.model("Category", categorySchema);
const Invite = mongoose.model("Invite", inviteSchema);

// Watch capital letters and plurals. Below will make db.movies and db.users
let Movie = mongoose.model("Movie", movieSchema);

// export models
module.exports.Beer = Beer;
module.exports.Brewery = Brewery;
module.exports.Category = Category;
module.exports.User = User;
module.exports.Invite = Invite;

module.exports.Movie = Movie;
