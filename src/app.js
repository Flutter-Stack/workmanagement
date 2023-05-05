const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./models/userSchema');
const auth = require('./middleware/authorization');
const session = require('express-session');
const mongoose = require('mongoose');

const app = express();
// const dotenv = require('dotenv');
// dotenv.config({ path: '../.env'})
require('dotenv').config();

// some configurations for express-session
app.set('trust proxy', 1);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// app.use(logMiddleware);
const defaultPort = 5000;
const secretKey = process.env.SECRET_KEY;
console.log("secretKey");
console.log(secretKey);
const port = process.env.PORT || defaultPort;


app.use(
  session({
    secret: secretKey,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
  })
);

mongoose.connect('mongodb://localhost/workmanagement', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('Error connecting to MongoDB', err));



app.post('/api/register',  async (req, res) => {
  // const { mobileNumber, password, password_confirm } = req.body;
  // console.log(req.body);

  const { email, firstName, lastName, mobileNumber, address,location, password, password_confirm } = req.body;

  if(password !== password_confirm) {
    res.status(400).json({ message: 'Passwords do not match!' });
  }
  // Generate a salt  
  const salt = await bcrypt.genSalt();

  console.log(password);
  const hashedPassword = await bcrypt.hash(password, salt);  
  const newUser = new User({
    email,
    firstName,
    lastName,
    address,
    location,
    mobileNumber,
    // password,
    password: hashedPassword,
    isActive: false,
  });
  try {
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.post('/api/login',auth.verifyUniqueLogin,  async (req, res) => {
  const { mobileNumber, password } = req.body;
  console.log(mobileNumber);
  try {
    const user = await User.findOne({ mobileNumber });
    if (!user) {
      return res.status(400).json({ message: 'Invalid Mobile Number' });
    } 
    if (!user.status) {
      return res.status(400).json({ message: 'User is blocked' });
    }
    if (!user.isActive) {
      return res.status(403).json({ message: 'user is not active' });
    }
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ message: 'Incorrect Password' });
    }
    const accessToken = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '2h' } // assuming a user's access token is valid for 2 hours
    );

    const expiryTime = new Date().setHours(new Date().getHours() + 2); // timestamp for 2 hours from current time
    // add the device ID to the user's deviceIds array
    // const { deviceId } = req.body;
    // user.deviceIds.push(deviceId);

    await User.findByIdAndUpdate(user._id, { accessToken, expiryTime });
    req.session.user = { id: user._id };
    res.status(201).json({ accessToken , message: 'Logged in successfully'});
  } catch (error) {
      console.log(error);
      res.status(500).json({ message: 'Something went wrong!' });
  }
});

// profile info storing in register itself so I can alter it.
app.post('/api/users-profile', auth.ensureAuthenticated, async (req, res) => {
  try {
    // create a new user profile instance with data from the request body
    const userProfile = new UserProfile(req.body);

    // save the user profile to the database
    await userProfile.save();

    res.status(201).send(userProfile);
  } catch (error) {
    res.status(400).send(error);
  }
});

app.get('/api/users', auth.ensureAuthenticated, async (req, res) => {
    if (req.user.role !== 'admin') {
      return res.status(401).json({ message: 'Unauthorized Access' });
    }
    const users = await User.find({});
    res.json(users);
});

app.put('/api/users/:id', auth.ensureAuthenticated, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(401).json({ message: 'Unauthorized Access' });
    }
    const { id } = req.params;
    const { status } = req.body;
    await User.findByIdAndUpdate(id, { status });
    res.json({ message: `User ${status ? 'enabled' : 'disabled'}` });
});


app.get('/api/restricted', auth.checkSubscriptionValidity, async (req, res) => {
  res.json({ message: 'This API endpoint can only be accessed with an active subscription' });
});

app.post('/api/subscribe', auth.ensureAuthenticated, async (req, res) => {
  const { user } = req;
  const subscriptionEndDate = new Date();
  subscriptionEndDate.setFullYear(subscriptionEndDate.getFullYear() + 1);
  await User.findByIdAndUpdate(user._id, { subscriptionEndDate });
  res.json({ message: 'Subscribed successfully for one year' });
});


// app.post('/logout', (req, res) => {
//   const { deviceId } = req.body;

//   // remove the device ID from the user's deviceIds array
//   user.deviceIds = user.deviceIds.filter((id) => id !== deviceId);

//   // save the updated user
//   user.save();

//   // send the response
//   res.json({ message: 'Logged out from current device' });
// });

app.patch('/api/activate/:id', auth.isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (user) {
      user.isActive = true;
      await user.save();
      res.json({ message: 'User activated successfully' });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.patch('/api/unblock/:id', auth.isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (user) {
      user.status = true;
      await user.save();
      res.json({ message: 'User unblocked successfully' });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


app.patch('/api/block/:id', auth.isAdmin ,async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (user) {
      user.status = true;
      await user.save();
      res.json({ message: 'User blocked successfully' });
    } else {
      res.status(404).json({ message: 'User not found' });
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// router.post('/login', async (req, res) => {
//   const { username, password } = req.body;
//   try {
//     const user = await User.findOne({ username });
//     if (user && user.isActive && user.password === password) {
//       res.json({ message: 'Login successful' });
//     } else {
//       res.status(401).json({ message: 'Invalid credentials' });
//     }
//   } catch (err) {
//     res.status(500).json({ message: err.message });
//   }
// });



// Assuming you have Express listen on port 3000
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

