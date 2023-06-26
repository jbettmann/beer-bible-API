const mongoose = require("mongoose"),
  bcrypt = require("bcrypt"); // hashes user password and compares everytime user logs in

// user schema
const userSchema = mongoose.Schema({
  fullName: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String },
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
  categories: [{ type: String, default: [] }],
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

// export models
module.exports.Beer = Beer;
module.exports.Brewery = Brewery;
module.exports.Category = Category;
module.exports.User = User;
module.exports.Invite = Invite;
