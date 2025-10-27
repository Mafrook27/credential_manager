const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, index: true},
  username: { type: String, required: true, unique: true, index: true },
  email: { type: String, required: true, unique: true, index: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin','staff'], default: 'staff', index: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
lastLogin: { type: Date },


 
});
userSchema.index({ username: 1, email: 1 }); // Compound index for username and email

userSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});


module.exports = mongoose.model('ware_user', userSchema);
