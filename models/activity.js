                                                                                                                                                   
const mongoose = require('mongoose');

const activityLogSchema = new mongoose.Schema({

  requestId: { type: String, required: true, unique: true, index: true },
  timestamp: { type: Date, default: Date.now, index: true },
  

  method: { type: String, required: true },
  url: { type: String, required: true },
  route: String,
  

  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'C_User', index: true },
  userEmail: String,
  userName: String,
  userRole: String,
  isAuthenticated: { type: Boolean, default: false },
  

  operation: String,
  resourceId: String,

  statusCode: Number,
  responseTime: Number,
  isSlowResponse: { type: Boolean, default: false },
  slowThreshold: Number,
  

  ipAddress: { type: String, index: true },
  userAgent: String,
  geolocation: {
    country: String,
    region: String,
    city: String,
    timezone: String,
    latitude: Number,
    longitude: Number
  },
  

  hasError: { type: Boolean, default: false, index: true },
  errorMessage: { type: String, default: null },
  errorStack: { type: String, default: null }
}, {
  timestamps: false
});


activityLogSchema.index({ userId: 1, timestamp: -1 });
activityLogSchema.index({ operation: 1, timestamp: -1 });
activityLogSchema.index({ isSlowResponse: 1, timestamp: -1 });
activityLogSchema.index({ hasError: 1, timestamp: -1 });

// activityLogSchema.index(
//   { timestamp: 1 }, 
//   // { expireAfterSeconds: 90 * 24 * 60 * 60 }
// );

module.exports = mongoose.model('ActivityLog', activityLogSchema);
