import jsonWebToken from "jsonwebtoken";
//verify () method of the jsonwebtoken package allows you to check the validity of a // token (on an incoming request, for example).
//Management of identification errors
export const auth = (req, res, next) => {
  try {
    const token = req.headers.authorization.split(" ")[1]; //recup token headers =>table =>second el
    const decodedToken = jsonWebToken.verify(
      token,
      process.env.RANDOM_TOKEN_SECRET
    ); //verif token/key
    const userId = decodedToken.userId; //recup userId token
    req.auth = { userId: userId };
    if (req.body.userId && req.body.userId !== userId) {
      throw " Invalid UserId";
    } else {
      next();
    }
  } catch {
    res.status(401).json({
      error: new Error("Invalid request !"),
    });
  }
};
