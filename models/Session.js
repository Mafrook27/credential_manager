const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  refreshToken: {
    type: String,
    required: true
  },
  refreshCount: {
    type: Number,
    default: 0
  },
  expiresAt: {
    type: Date,
    required: true
  },
  userAgent: {
    type: String
  },
  ipAddress: {
    type: String
  },
  active: {                    // ✅ ADD THIS
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// Auto-delete expired sessions
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Index for faster lookups
sessionSchema.index({ userId: 1 });
sessionSchema.index({ refreshToken: 1 });
sessionSchema.index({ active: 1 });  // ✅ ADD THIS for faster queries

module.exports = mongoose.model("Session", sessionSchema);
