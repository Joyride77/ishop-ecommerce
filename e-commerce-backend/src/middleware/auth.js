const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
  const token =
    req.header("x-access-token") || req.body.token || req.query.token;
  if (!token) return res.status(401).send("Access Denied");

  try {
    const verified = jwt.verify(token, process.env.TOKEN_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(400).send("Invalid Token");
  }
  return next();
};

module.exports = verifyToken;
