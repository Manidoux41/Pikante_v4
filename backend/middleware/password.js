import passwordValidator from "password-validator";

// Create a schema
const validPasswordschema = new passwordValidator();

// Add properties to it
validPasswordschema
  .is()
  .min(5) // Minimum length 8
  .is()
  .max(50) // Maximum length 100
  // .has().uppercase() // Must have uppercase letters
  .has()
  .lowercase() // Must have lowercase letters
  // .has().digits() // Must have at least  digits*/
  .has()
  .not()
  .spaces() // Should not have spaces
  .is()
  .not()
  .oneOf(["Passw0rd", "Password123"]); // Blacklist these values

const password = (req, res, next) => {
  if (validPasswordschema.validate(req.body.password)) {
    next();
  } else {
    return res
      .status(400)
      .json({
        error:
          "Le mot de passe n'est pas  fort " +
          validPasswordschema.validate("req.body.password", { list: true }),
      });
  }
};

export default password;
/*
console.log("****************************************");
console.log(validPasswordschema.validate('req.body.password', { list: true }));
console.log("****************************************");
*/
