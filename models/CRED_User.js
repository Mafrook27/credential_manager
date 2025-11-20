const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: { type: String, index: true, required: true },
  email: { type: String, index: true, unique: true, required: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["user", "admin"], default: "user" },
  isVerified: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  isDeleted: { type: Boolean, default: false },
  deletedAt: { type: Date },
  deletedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'C_User' },
  rejectedAt: { type: Date },
  rejectedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'C_User' },
  resetToken: { type: String },
  resetTokenExpiry: { type: Date },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { versionKey: false });

userSchema.index({ role: 1 });

userSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});


module.exports = mongoose.model("C_User", userSchema);







