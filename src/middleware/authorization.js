const jwt = require('jsonwebtoken');
const User = require('../models/userSchema');

const ensureAuthenticated = async (req, res, next) => {
  const authorizationHeader = req.headers.authorization;
  if (!authorizationHeader) {
    return res.status(401).json({ message: 'Unauthorized Access' });
  }
  const accessToken = authorizationHeader.split(' ')[1];
  try {
    const decodedToken = jwt.verify(
      accessToken,
      process.env.ACCESS_TOKEN_SECRET
    );
    const user = await User.findOne({ _id: decodedToken.userId });
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized Access' });
    }
    if (user.accessToken !== accessToken) {
      return res.status(401).json({ message: 'Unauthorized Access' });
    }
    if (user.expiryTime.getTime() < new Date()) {
      return res.status(401).json({
        message: 'Access Token has expired. Please login again.'
      });
    }
    req.user = user;
    next();
  } catch (error) {
    console.log(error);
    res.status(401).json({ message: 'Unauthorized Access' });
  }
};

const verifyUniqueLogin = async (req, res, next) => {
    const { mobileNumber } = req.body;
    console.log(mobileNumber);
    try {
      const user = await User.findOne({ mobileNumber });
      if (user === null) {
        return res.status(403).json({ message: 'User trying log in is not a registered user.' });
      }
      if (user.sessionId && user.sessionId !== req.session.id) {
        return res.status(400).json({ message: 'User has already logged in.' });
      }
      await User.findByIdAndUpdate(user._id, { sessionId: req.session.id });
      next();
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: 'Something went wrong!' });
    }
};

const checkSubscriptionValidity = async (req, res, next) => {
    const { user } = req;
    if (user.subscriptionEndDate && new Date() > user.subscriptionEndDate) {
      return res.status(401).json({ message: 'Subscription has expired' });
    }
    next();
};

const isAdmin = async (req, res, next) => {
  const authorizationHeader = req.headers.authorization;
  if (!authorizationHeader) {
    return res.status(401).json({ message: 'Unauthorized Access' });
  }
  const accessToken = authorizationHeader.split(' ')[1];
  try {
    const decodedToken = jwt.verify(
      accessToken,
      process.env.ACCESS_TOKEN_SECRET
    );
    const user = await User.findOne({ _id: decodedToken.userId, status: true,  isActive: true, role: "admin"});
    if (!user) {
      return res.status(401).json({ message: 'you must be a admin to perform this operation.' });
    }
    next();
  } catch (error) {
    console.log(error);
    res.status(401).json({ message: 'Unauthorized Access' });
  }
};

module.exports = {
  checkSubscriptionValidity: checkSubscriptionValidity,
  verifyUniqueLogin: verifyUniqueLogin,
  ensureAuthenticated: ensureAuthenticated,
  isAdmin: isAdmin
};