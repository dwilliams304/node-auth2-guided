// AUTHENTICATION
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('../../config/');

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if(token){
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if(err) next({status: 401, message: `bad token! : ${err.message}`}) //not good to have this much information in prod, okay for dev
      else {
        req.decodedJWT = decoded;
        next();
      }
    });
  }
  else next({status: 401, message: 'No token!'})
}

// AUTHORIZATION
const checkRole = role => (req, res, next) => {
  if(req.decodedJWT && req.decodedJWT.role === role) next();
  else next({status: 403, message: 'you do not have authorization to access this'})
}

module.exports = {
  restricted,
  checkRole,
}
