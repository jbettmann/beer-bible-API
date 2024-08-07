const { body } = require("express-validator");
const mongoose = require("mongoose"),
  bcrypt = require("bcrypt"); // hashes user password and compares everytime user logs in

const notificationSchema = new mongoose.Schema({
  allow: { type: Boolean, default: true }, // or false
  newBeerRelease: {
    email: { type: Boolean, default: true },
    push: { type: Boolean, default: true },
  },
  beerUpdate: {
    email: { type: Boolean, default: true },
    push: { type: Boolean, default: true },
  },
  // ... other fields
});

// user schema
const userSchema = mongoose.Schema(
  {
    fullName: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String },
    breweries: [
      { type: mongoose.Schema.Types.ObjectId, ref: "Brewery", default: [] },
    ],
    image: { type: String, default: null }, // image url from OAuth
    notifications: notificationSchema,
  },
  {
    timestamps: true, // This will create the `createdAt` and `updatedAt` fields automatically
  }
);

// brewery schema
const brewerySchema = mongoose.Schema(
  {
    companyName: { type: String, required: true },
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    admin: [{ type: mongoose.Schema.Types.ObjectId, ref: "User", default: [] }],
    staff: [{ type: mongoose.Schema.Types.ObjectId, ref: "User", default: [] }],
    beers: [{ type: mongoose.Schema.Types.ObjectId, ref: "Beer", default: [] }],
    categories: [
      { type: mongoose.Schema.Types.ObjectId, ref: "Category", default: [] },
    ],
    image: String, // image/logo url to Supabase storage
  },
  {
    timestamps: true, // This will create the `createdAt` and `updatedAt` fields automatically
  }
);

// beer schema
const beerSchema = mongoose.Schema(
  {
    companyId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Brewery",
      required: true,
      index: true, // increases read performance but decreases write/update/delete
    },
    image: String, // image url to Supabase storage
    name: { type: String, required: true },
    style: { type: String, required: true },
    abv: Number,
    ibu: Number,
    category: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Category",
        required: true,
        default: [],
      },
    ],
    malt: [String],
    hops: [String],
    description: String,
    // aroma: String,
    // tastingNotes: String,
    nameSake: String,
    notes: String,
    archived: { type: Boolean, default: false },
    releasedOn: Date,
  },
  {
    timestamps: true, // This will create the `createdAt` and `updatedAt` fields automatically
  }
);

// invite schema
const inviteSchema = mongoose.Schema({
  token: { type: String, required: true },
  brewery: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Brewery",
    required: true,
  },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  isAdmin: Boolean,
  createdAt: { type: Date, required: true, default: Date.now, expires: "24h" },
});

// category schema
const categorySchema = mongoose.Schema(
  {
    name: { type: String, required: true },
  },
  {
    timestamps: true, // This will create the `createdAt` and `updatedAt` fields automatically
  }
);

// Function hashes users summited password
userSchema.statics.hashPassword = (password) => {
  return bcrypt.hashSync(password, 10);
};

// Function compares submitted hashed password with hashed password stored in database
userSchema.methods.validatePassword = function(password) {
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
