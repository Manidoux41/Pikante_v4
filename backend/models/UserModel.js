import mongoose from "mongoose";
import uniqueValidator from "mongoose-unique-validator";

/****************creation of the User = unique schema: true prevents connections with the same address*******/
const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
});

/***************methode plugin validation sécurité*******************************************************/
UserSchema.plugin(uniqueValidator);

const User = mongoose.model("User", UserSchema);

export default User;
