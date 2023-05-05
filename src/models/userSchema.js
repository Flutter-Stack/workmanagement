const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: String,
  address: {
    street: String,
    city: String,
    state: String,
    country: String,
    zip: String
  },
  location: {
    type: { type: String },
    coordinates: [Number]
  },  
  mobileNumber: {
    type: String,
    required: true,
    unique: true // no two users can have same mobile number
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['admin', 'user'],
    default: 'user' // default role is user
  },
  status: {
    type: Boolean,
    default: true // default status is active block
  },
  accessToken: {
    type: String
  },
  expiryTime: {
    type: Date
  },
  sessionId: {
    type: String,
    unique: true, // no two users can have same session ID
    sparse: true // allows null or unique values (this is important for first time login)
  },
  subscriptionEndDate: {
    type: Date
  },
  isActive: { type: Boolean, default: false }, // active 
// other user fields
// , deviceIds: [String],
});

module.exports = mongoose.model('User', userSchema);