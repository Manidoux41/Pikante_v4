import bcrypt from "bcrypt";
import User from "../models/UserModel.js";
import jsonWebToken from "jsonwebtoken";

/**********************************user registration and password hashing***********************/
export const signup = (req, res, next) => {
  bcrypt
    .hash(req.body.password, 10)
    .then((hash) => {
      const user = new User({
        email: req.body.email,
        password: hash,
      });
      user
        .save()
        .then(() => res.status(201).json({ message: "New user created" }))
        .catch((error) => res.status(400).json({ error }));
    })
    .catch((error) => res.status(500).json({ error }));
};

/******************************************************User login ********************************/
export const login = (req, res, next) => {
  //user recuperation
  //if user! user => error
  //compare password entered with that of the database / if! valid => error
  //if valid returns a userId and a token
  //token: jsonWebToken.sign = token encoding contains id as
  //payload (data encoded in the token) secret chain to change for production then return to the frontend with our responce
  User.findOne({ email: req.body.email })
    .then((user) => {
      if (!user) {
        return res.status(401).json({ error: "no user found" });
      }
      bcrypt
        .compare(req.body.password, user.password)
        .then((valid) => {
          if (!valid) {
            return res.status(401).json({ error: "Password is not valid" });
          }
          res.status(200).json({
            userId: user._id,
            token: jsonWebToken.sign(
              { userId: user._id },
              process.env.RANDOM_TOKEN_SECRET,
              { expiresIn: "24h" }
            ),
          });
        })
        .catch((error) => res.status(500).json({ error }));
    })
    .catch((error) => res.status(500).json({ error }));
};
