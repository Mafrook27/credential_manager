

const mongoose = require("mongoose");

const credentialSchema = new mongoose.Schema({
  subInstance: { type: mongoose.Schema.Types.ObjectId, ref: "SubInstance", required: true },
  rootInstance: { type: mongoose.Schema.Types.ObjectId, ref: "RootInstance", required: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "C_User", required: true },
  sharedWith: [{ type: mongoose.Schema.Types.ObjectId, ref: "C_User" }],
 
  username: { type: String, required: true },
  password: { type: String, required: true },    
  url: { type: String },
  notes: { type: String },
  lastAccessed: { type: Date },
  createdAt: { type: Date, default: Date.now }
}, { versionKey: false });
credentialSchema.index({ createdBy: 1 });
credentialSchema.index({ sharedWith: 1 });
credentialSchema.index({ serviceName: 1 });
credentialSchema.index({ rootInstance: 1 });
credentialSchema.index({ createdBy: 1, 'sharedWith': 1, serviceName: 1 });
module.exports = mongoose.model("Credential", credentialSchema);
