


const mongoose = require("mongoose");
const logger  =require('../util/Logger');
const auditSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "C_User", required: true },
  credential: { type: mongoose.Schema.Types.ObjectId, ref: "Credential", required: true },
  credentialOwner: { type: mongoose.Schema.Types.ObjectId, ref: "C_User", required: true },
  serviceName: { type: String, required: true },
  action: { type: String, enum: ["view", "update", "delete", "share", "revoke","decrypt","create"], required: true },
  targetUser: { type: mongoose.Schema.Types.ObjectId, ref: "C_User" },
  ipAddress: { type: String },
  userAgent: { type: String },
  timestamp: { type: Date, default: Date.now }
}, { versionKey: false });


auditSchema.index({ timestamp: -1 });
auditSchema.index({ user: 1, timestamp: -1 });
auditSchema.index({ credential: 1, timestamp: -1 });
auditSchema.index({ credentialOwner: 1, timestamp: -1 });
auditSchema.index({ timestamp: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 });


// ---- Make Logs Immutable ----
auditSchema.pre("updateOne", function(next) {
  next(new Error("Audit logs are immutable — cannot update"));
});
auditSchema.pre("findOneAndUpdate", function(next) {
  next(new Error("Audit logs are immutable — cannot update"));
});
auditSchema.pre("deleteOne", function(next) {
  next(new Error("Audit logs are immutable — cannot delete"));
});
auditSchema.post('save', function (doc) {
  logger.debug(`🧾 Audit log created: ${doc.action} by ${doc.user} on ${doc.credential} at ${doc.timestamp}`);
});

module.exports = mongoose.model("Audit", auditSchema);
   
