const mongoose = require("mongoose");


const rootInstanceSchema = new mongoose.Schema({
 serviceName: { type: String, required: true },  // like "Gmail", "AWS", "Azure", "GitHub"
  subInstances: [{ type: mongoose.Schema.Types.ObjectId, ref: "SubInstance" }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "C_User", required: true },
  createdAt: { type: Date, default: Date.now }
}, { versionKey: false });

// Indexes
rootInstanceSchema.index({ createdBy: 1 });
rootInstanceSchema.index({ type: 1 });
rootInstanceSchema.index({ createdBy: 1, type: 1 });
rootInstanceSchema.index({ serviceName: 1 });

module.exports = mongoose.model("RootInstance", rootInstanceSchema);